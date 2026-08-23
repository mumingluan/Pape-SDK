package app

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"pape-sdk/server/internal/config"
)

func TestParameterUsesConfigAndOfficialHeaders(t *testing.T) {
	temp := t.TempDir()
	configDir := filepath.Join(temp, "config")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "parameter.json"), []byte(`{"PreDownload_Switch":"1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	a := &App{cfg: &config.Config{BaseDir: temp, ConfigDir: "./config"}}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "https://api-deepspace.papegames.com:12101/v1/gameconfig/parameter?key=PreDownload_Switch", nil)
	a.parameter(c)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	parameter := payload["gameConfigParameter"].(map[string]any)
	if parameter["value"] != "1" {
		t.Fatalf("parameter value = %#v", parameter["value"])
	}
}

func TestSDKClientReflectsRequestedVersion(t *testing.T) {
	temp := t.TempDir()
	configDir := filepath.Join(temp, "config")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "sdkclient.json"), []byte(`{"config":{"realname":1},"ret":0}`), 0o644); err != nil {
		t.Fatal(err)
	}
	a := &App{cfg: &config.Config{BaseDir: temp, ConfigDir: "./config"}}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "https://api-deepspace.papegames.com:12101/v1/conf/sdkclient?sdkversion=2.1.7.20", nil)
	a.sdkClient(c)

	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["sdkversion"] != "2.1.7.20" {
		t.Fatalf("sdkversion = %#v", payload["sdkversion"])
	}
}

func TestCollectRouteForwardsAndArchivesCompleteExchange(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.RequestURI() != "/unimplemented?x=1" {
			t.Errorf("upstream request = %s %s", r.Method, r.URL.RequestURI())
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != "request-body" {
			t.Errorf("upstream body = %q", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	originalClient := directUpstreamClient
	directUpstreamClient = testUpstreamClient(t, upstream)
	defer func() { directUpstreamClient = originalClient }()

	temp := t.TempDir()
	a := &App{cfg: &config.Config{BaseDir: temp, Proxy: config.Proxy{CollectRoute: true}}}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	request := httptest.NewRequest(http.MethodPost, "https://missing.papegames.com/unimplemented?x=1", strings.NewReader("request-body"))
	request = request.WithContext(context.WithValue(request.Context(), proxyInternalContextKey{}, true))
	c.Request = request
	a.forwardUpstream(c, "", true, "unimplemented_route", true)

	if recorder.Code != http.StatusCreated || recorder.Body.String() != `{"ok":true}` {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
	entries, err := os.ReadDir(filepath.Join(temp, "collected_route"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("archive count = %d", len(entries))
	}
	archive := filepath.Join(temp, "collected_route", entries[0].Name())
	for name, want := range map[string]string{
		"request.body":  "request-body",
		"response.body": `{"ok":true}`,
	} {
		raw, err := os.ReadFile(filepath.Join(archive, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != want {
			t.Errorf("%s = %q", name, raw)
		}
	}
	for _, name := range []string{"request.json", "response.json"} {
		if _, err := os.Stat(filepath.Join(archive, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestMissingConfigFallsBackToOriginalUpstreamPath(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() != "/v1/gameconfig/patchlist?clientid=1068" {
			t.Errorf("upstream URI = %q", r.URL.RequestURI())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"patch":"official"}`)
	}))
	defer upstream.Close()
	originalClient := directUpstreamClient
	directUpstreamClient = testUpstreamClient(t, upstream)
	defer func() { directUpstreamClient = originalClient }()

	_, port, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	temp := t.TempDir()
	a := &App{cfg: &config.Config{
		BaseDir: temp, ConfigDir: "./missing",
		Hosts: config.Hosts{API: "api-test.papegames.com:" + port},
	}}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8088/v1/gameconfig/patchlist?clientid=1068", nil)
	a.dataJSON(c, "patchlist.json", true)
	if recorder.Code != http.StatusOK || recorder.Body.String() != `{"patch":"official"}` {
		t.Fatalf("fallback response = %d %q", recorder.Code, recorder.Body.String())
	}
}

func testUpstreamClient(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	serverAddress := server.Listener.Addr().String()
	transport := &http.Transport{
		Proxy:           nil,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Test server certificate only.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, serverAddress)
		},
	}
	return &http.Client{Transport: transport}
}
