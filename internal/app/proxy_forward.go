package app

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"pape-sdk/internal/data"
)

type proxyGateTargets struct {
	httpAuthorities   map[string]struct{}
	tunnelAuthorities map[string]struct{}
}

func loadProxyGateTargets(path string) (*proxyGateTargets, error) {
	obj, err := data.LoadJSONC(path)
	if err != nil {
		return nil, err
	}
	targets := &proxyGateTargets{
		httpAuthorities:   make(map[string]struct{}),
		tunnelAuthorities: make(map[string]struct{}),
	}
	lists, _ := obj["game_config_serverlists"].([]any)
	for _, item := range lists {
		server, _ := item.(map[string]any)
		extra, _ := server["extra"].(map[string]any)
		if rawURL, _ := extra["login_url"].(string); strings.TrimSpace(rawURL) != "" {
			loginURL, err := url.Parse(rawURL)
			if err != nil || loginURL.Hostname() == "" || (loginURL.Scheme != "http" && loginURL.Scheme != "https") {
				return nil, fmt.Errorf("invalid serverlist extra.login_url %q", rawURL)
			}
			authority, err := normalizeProxyAuthority(loginURL.Host, loginURL.Scheme)
			if err != nil {
				return nil, fmt.Errorf("invalid serverlist extra.login_url %q: %w", rawURL, err)
			}
			targets.httpAuthorities[authority] = struct{}{}
			targets.tunnelAuthorities[authority] = struct{}{}
		}
		if addr, _ := extra["addr"].(string); strings.TrimSpace(addr) != "" {
			authority, err := normalizeProxyAuthority(addr, "")
			if err != nil {
				return nil, fmt.Errorf("invalid serverlist extra.addr %q: %w", addr, err)
			}
			targets.tunnelAuthorities[authority] = struct{}{}
		}
	}
	return targets, nil
}

func (t *proxyGateTargets) allowsHTTP(r *http.Request) bool {
	if t == nil {
		return false
	}
	scheme := r.URL.Scheme
	if scheme == "" {
		scheme = "http"
	}
	authority := r.URL.Host
	if authority == "" {
		authority = r.Host
	}
	normalized, err := normalizeProxyAuthority(authority, scheme)
	if err != nil {
		return false
	}
	_, ok := t.httpAuthorities[normalized]
	return ok
}

func (t *proxyGateTargets) allowsTunnel(authority string) bool {
	if t == nil {
		return false
	}
	normalized, err := normalizeProxyAuthority(authority, "https")
	if err != nil {
		return false
	}
	_, ok := t.tunnelAuthorities[normalized]
	return ok
}

func normalizeProxyAuthority(authority, scheme string) (string, error) {
	host := authorityHostname(authority)
	if host == "" {
		return "", fmt.Errorf("empty host")
	}
	port := ""
	if splitHost, splitPort, err := net.SplitHostPort(authority); err == nil {
		host, port = strings.Trim(splitHost, "[]"), splitPort
	}
	if port == "" {
		switch strings.ToLower(scheme) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return "", fmt.Errorf("missing port")
		}
	}
	return net.JoinHostPort(strings.ToLower(strings.TrimSuffix(host, ".")), port), nil
}

func (p *proxyServer) serveForwardHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	out := r.Clone(r.Context())
	out.RequestURI = ""
	if out.URL.Scheme == "" {
		out.URL.Scheme = "http"
	}
	if out.URL.Host == "" {
		out.URL.Host = out.Host
	}
	removeProxyHopHeaders(out.Header)
	out.Header.Del("Proxy-Authorization")
	resp, err := p.forwardTransport.RoundTrip(out)
	if err != nil {
		log.Printf("[proxy] %s %s upstream failed: %v", r.Method, out.URL, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	removeProxyHopHeaders(resp.Header)
	copyProxyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	n, copyErr := io.Copy(w, resp.Body)
	log.Printf("[proxy] %s %s -> ordinary upstream status=%d bytes=%d proto=%s duration=%s",
		r.Method, out.URL, resp.StatusCode, n, resp.Proto, time.Since(started).Round(time.Millisecond))
	if copyErr != nil {
		log.Printf("[proxy] %s %s response copy failed: %v", r.Method, out.URL, copyErr)
	}
}

func (p *proxyServer) serveStorageHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/admin/") {
		http.NotFound(w, r)
		return
	}
	started := time.Now()
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.URL.Scheme = p.storageTarget.Scheme
	out.URL.Host = p.storageTarget.Host
	out.Host = p.storageTarget.Host
	removeProxyHopHeaders(out.Header)
	out.Header.Del("Proxy-Authorization")
	response, err := p.forwardTransport.RoundTrip(out)
	if err != nil {
		log.Printf("[proxy] storage %s %s failed: %v", r.Method, r.URL.RequestURI(), err)
		http.Error(w, "storage unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	removeProxyHopHeaders(response.Header)
	copyProxyHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	written, copyErr := io.Copy(w, response.Body)
	log.Printf("[proxy] storage %s %s -> %s status=%d bytes=%d duration=%s",
		r.Method, r.URL.RequestURI(), p.storageTarget, response.StatusCode, written,
		time.Since(started).Round(time.Millisecond))
	if copyErr != nil {
		log.Printf("[proxy] storage response copy failed: %v", copyErr)
	}
}

func (p *proxyServer) serveTunnel(w http.ResponseWriter, r *http.Request) {
	upstream, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		log.Printf("[proxy] CONNECT %s ordinary upstream failed: %v", r.Host, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "proxy connection does not support hijacking", http.StatusInternalServerError)
		return
	}
	clientConn, buffered, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[proxy] CONNECT %s hijack failed: %v", r.Host, err)
		return
	}
	defer clientConn.Close()
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	log.Printf("[proxy] CONNECT %s -> ordinary TCP tunnel", r.Host)
	clientReader := io.Reader(clientConn)
	if buffered.Reader.Buffered() > 0 {
		clientReader = buffered.Reader
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, clientReader)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, upstream)
		done <- struct{}{}
	}()
	<-done
}

func removeProxyHopHeaders(header http.Header) {
	for _, name := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		header.Del(name)
	}
}

func copyProxyHeaders(dst, src http.Header) {
	for name, values := range src {
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}
