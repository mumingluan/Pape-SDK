package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	directUpstreamClient = &http.Client{Transport: &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}}
	collectedRouteSequence atomic.Uint64
	archiveNameCleaner     = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
)

type archivedRequest struct {
	CapturedAt    string      `json:"captured_at"`
	Reason        string      `json:"reason"`
	Method        string      `json:"method"`
	URL           string      `json:"url"`
	Protocol      string      `json:"protocol"`
	RemoteAddress string      `json:"remote_address"`
	Headers       http.Header `json:"headers"`
	ContentLength int64       `json:"content_length"`
}

type archivedResponse struct {
	Status        string      `json:"status"`
	StatusCode    int         `json:"status_code"`
	Protocol      string      `json:"protocol"`
	Headers       http.Header `json:"headers"`
	ContentLength int64       `json:"content_length"`
}

func officialTextJSON(c *gin.Context, payload any) {
	raw, err := json.Marshal(payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Header("Access-Control-Allow-Origin", "*")
	c.Data(http.StatusOK, "text/plain; charset=utf-8", raw)
}

func (a *App) shouldCollect(c *gin.Context) bool {
	return a.cfg.Proxy.CollectRoute && isProxyInternalRequest(c.Request)
}

func (a *App) apiUpstreamAuthority() string {
	return authorityWithDefaultPort(a.cfg.Hosts.API, 12101)
}

func authorityWithDefaultPort(host string, port int) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func (a *App) forwardUpstream(c *gin.Context, defaultAuthority string, collect bool, reason string, requireJSON bool) {
	requestBody, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "read request body: " + err.Error()})
		return
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(requestBody))
	target, authority, err := upstreamTarget(c.Request, defaultAuthority)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	out, err := http.NewRequestWithContext(c.Request.Context(), c.Request.Method, target.String(), bytes.NewReader(requestBody))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	out.Host = authority
	copyUpstreamHeaders(out.Header, c.Request.Header)
	// Let Go negotiate and decode compression so JSON validation and archives see the complete body.
	out.Header.Del("Accept-Encoding")

	archiveDir := ""
	if collect {
		archiveDir, err = a.createRouteArchive(c.Request, target, requestBody, reason)
		if err != nil {
			log.Printf("[collect_route] create archive failed: %v", err)
			archiveDir = ""
		}
	}
	started := time.Now()
	resp, err := directUpstreamClient.Do(out)
	if err != nil {
		log.Printf("[upstream] %s %s failed: %v", c.Request.Method, target, err)
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error(), "upstream": target.String()})
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "read upstream response: " + err.Error()})
		return
	}
	if requireJSON {
		var parsed any
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		if err := decoder.Decode(&parsed); err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": "upstream returned invalid JSON: " + err.Error(), "upstream": target.String()})
			return
		}
	}
	if archiveDir != "" {
		if err := saveArchivedResponse(archiveDir, resp, body); err != nil {
			log.Printf("[collect_route] save response failed: %v", err)
		}
	}
	copyResponseHeaders(c.Writer.Header(), resp.Header)
	c.Status(resp.StatusCode)
	_, _ = c.Writer.Write(body)
	log.Printf("[upstream] %s %s -> status=%d bytes=%d reason=%s duration=%s",
		c.Request.Method, target, resp.StatusCode, len(body), reason, time.Since(started).Round(time.Millisecond))
}

func upstreamTarget(r *http.Request, defaultAuthority string) (*url.URL, string, error) {
	authority := strings.TrimSpace(r.Header.Get("X-Pape-Original-Host"))
	if authority == "" && isPapegamesHost(requestHostname(r)) {
		authority = r.Host
	}
	if authority == "" {
		authority = defaultAuthority
	}
	if authority == "" || !isPapegamesHost(authorityHostname(authority)) {
		return nil, "", fmt.Errorf("cannot determine Papegames upstream for host %q", r.Host)
	}
	scheme := strings.TrimSpace(r.Header.Get("X-Pape-Original-Scheme"))
	if scheme == "" {
		scheme = "https"
	}
	target := &url.URL{Scheme: scheme, Host: authority, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
	return target, authority, nil
}

func copyUpstreamHeaders(dst, src http.Header) {
	for name, values := range src {
		if isHopHeader(name) || strings.HasPrefix(strings.ToLower(name), "x-pape-") || strings.EqualFold(name, "Host") {
			continue
		}
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

func copyResponseHeaders(dst, src http.Header) {
	for name, values := range src {
		if isHopHeader(name) || strings.EqualFold(name, "Content-Length") {
			continue
		}
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

func isHopHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade":
		return true
	default:
		return false
	}
}

func (a *App) createRouteArchive(r *http.Request, target *url.URL, body []byte, reason string) (string, error) {
	sequence := collectedRouteSequence.Add(1)
	name := fmt.Sprintf("%s_%06d_%s_%s_%s",
		time.Now().Format("20060102T150405.000000000"), sequence, r.Method,
		authorityHostname(target.Host), strings.Trim(target.Path, "/"))
	name = strings.Trim(archiveNameCleaner.ReplaceAllString(name, "_"), "_")
	if len(name) > 180 {
		name = name[:180]
	}
	dir := a.cfg.Resolve(filepath.Join("collected_route", name))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	metadata := archivedRequest{
		CapturedAt: time.Now().Format(time.RFC3339Nano), Reason: reason, Method: r.Method,
		URL: target.String(), Protocol: r.Proto, RemoteAddress: r.RemoteAddr,
		Headers: r.Header.Clone(), ContentLength: r.ContentLength,
	}
	if err := writeArchiveJSON(filepath.Join(dir, "request.json"), metadata); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "request.body"), body, 0o644); err != nil {
		return "", err
	}
	return dir, nil
}

func saveArchivedResponse(dir string, resp *http.Response, body []byte) error {
	metadata := archivedResponse{
		Status: resp.Status, StatusCode: resp.StatusCode, Protocol: resp.Proto,
		Headers: resp.Header.Clone(), ContentLength: int64(len(body)),
	}
	if err := writeArchiveJSON(filepath.Join(dir, "response.json"), metadata); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "response.body"), body, 0o644)
}

func writeArchiveJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}
