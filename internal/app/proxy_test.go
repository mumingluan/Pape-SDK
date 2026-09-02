package app

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pape-sdk/internal/config"
)

func TestPapegamesHost(t *testing.T) {
	tests := map[string]bool{
		"papegames.com":                  true,
		"passport.papegames.com":         true,
		"PASSPORT.PAPEGAMES.COM.":        true,
		"notpapegames.com":               false,
		"papegames.com.attacker.invalid": false,
	}
	for host, want := range tests {
		if got := isPapegamesHost(host); got != want {
			t.Errorf("isPapegamesHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestProxyRoutesPublicStorageHostToLocalStorage(t *testing.T) {
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/" {
			t.Errorf("storage request = %s %s", r.Method, r.URL.Path)
		}
		if r.Host == "storage-deepspace.papegames.com" {
			t.Errorf("storage request retained public Host")
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != "object" {
			t.Errorf("storage body = %q", body)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer storage.Close()
	target, err := url.Parse(storage.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := &proxyServer{
		storageHost: "storage-deepspace.papegames.com", storageTarget: target,
		forwardTransport: http.DefaultTransport.(*http.Transport).Clone(),
	}
	request := httptest.NewRequest(http.MethodPost, "https://storage-deepspace.papegames.com/", strings.NewReader("object"))
	request.Host = "storage-deepspace.papegames.com"
	recorder := httptest.NewRecorder()
	p.serveInternal(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "https://storage-deepspace.papegames.com/admin/v1/upload-tokens", nil)
	request.Host = "storage-deepspace.papegames.com"
	recorder = httptest.NewRecorder()
	p.serveInternal(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("public admin status = %d", recorder.Code)
	}
}

func TestProxyDirectlyForwardsExplicitNonPapegamesStorageHost(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/object.bin" {
			t.Errorf("upstream path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := &proxyServer{
		directHosts:      map[string]struct{}{target.Hostname(): {}},
		forwardTransport: http.DefaultTransport.(*http.Transport).Clone(),
	}
	request := httptest.NewRequest(http.MethodGet, upstream.URL+"/object.bin", nil)
	request.Host = target.Host
	recorder := httptest.NewRecorder()
	p.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "http://not-allowed.example/object.bin", nil)
	request.Host = request.URL.Host
	recorder = httptest.NewRecorder()
	p.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("unknown host status=%d, want %d", recorder.Code, http.StatusForbidden)
	}
}

func TestNewProxyHandlerAllowsNonPapegamesStoragePublicHost(t *testing.T) {
	temp := t.TempDir()
	_, caCertPEM, caKeyPEM := testCA(t)
	certPath := filepath.Join(temp, "ca.pem")
	keyPath := filepath.Join(temp, "ca.key")
	if err := os.WriteFile(certPath, caCertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, caKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{BaseDir: temp, Storage: config.Storage{
		BaseURL: "http://127.0.0.1:65287", PublicHost: "pape-storage.fatui.xyz",
	}, Proxy: config.Proxy{Enabled: true, CACertificatePath: certPath, CAPrivateKeyPath: keyPath}}
	handler, err := newProxyHandler(cfg, http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	p, ok := handler.(*proxyServer)
	if !ok {
		t.Fatalf("proxy handler type = %T", handler)
	}
	if !p.allowsDirectHost("PAPE-STORAGE.FATUI.XYZ.") {
		t.Fatal("configured storage host was not added to the direct allowlist")
	}
	if p.allowsDirectHost("other.fatui.xyz") {
		t.Fatal("unconfigured sibling host was added to the direct allowlist")
	}
	if p.storageTarget != nil {
		t.Fatal("non-Papegames storage host was still configured for MITM forwarding")
	}
}

func TestProxyRoutesPapegamesHTTPSInternallyOverHTTP2(t *testing.T) {
	temp := t.TempDir()
	caCert, caCertPEM, caKeyPEM := testCA(t)
	certPath := filepath.Join(temp, "ca.pem")
	keyPath := filepath.Join(temp, "ca.key")
	if err := os.WriteFile(certPath, caCertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, caKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	internal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("internal path = %q", r.URL.Path)
		}
		switch r.Host {
		case "deep.api.papegames.com":
			if r.ProtoMajor != 2 {
				t.Errorf("internal protocol = %s, want HTTP/2", r.Proto)
			}
		case "passport.papegames.com":
			if r.ProtoMajor != 1 {
				t.Errorf("IP CONNECT internal protocol = %s, want HTTP/1.1", r.Proto)
			}
		default:
			t.Errorf("internal Host = %q", r.Host)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	cfg := &config.Config{BaseDir: temp, Proxy: config.Proxy{
		Enabled:           true,
		UseHTTP2:          true,
		CACertificatePath: certPath,
		CAPrivateKeyPath:  keyPath,
	}}
	proxyHandler, err := newProxyHandler(cfg, internal)
	if err != nil {
		t.Fatal(err)
	}
	proxyHTTP := httptest.NewServer(proxyHandler)
	defer proxyHTTP.Close()
	proxyURL, err := url.Parse(proxyHTTP.URL)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	client := &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		ForceAttemptHTTP2: true,
		TLSClientConfig:   testTLSConfig(roots),
	}}
	resp, err := client.Get("https://deep.api.papegames.com/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	for _, name := range []string{proxyLeafCert, proxyLeafKey} {
		if _, err := os.Stat(filepath.Join(temp, filepath.FromSlash(name))); err != nil {
			t.Errorf("generated %s: %v", name, err)
		}
	}

	rawConn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer rawConn.Close()
	if _, err := io.WriteString(rawConn, "CONNECT 203.107.60.165:12101 HTTP/1.1\r\nHost: 203.107.60.165:12101\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	connectResponse, err := http.ReadResponse(bufio.NewReader(rawConn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if connectResponse.StatusCode != http.StatusOK {
		t.Fatalf("IP CONNECT status = %d, want %d", connectResponse.StatusCode, http.StatusOK)
	}
	tlsConn := tls.Client(rawConn, &tls.Config{
		RootCAs:    roots,
		ServerName: "passport.papegames.com",
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(tlsConn, "GET /healthz HTTP/1.1\r\nHost: passport.papegames.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	ipResponse, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	defer ipResponse.Body.Close()
	if ipResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("IP CONNECT internal status = %d, want %d", ipResponse.StatusCode, http.StatusNoContent)
	}
}

func TestProxyRejectsNonPapegamesTraffic(t *testing.T) {
	p := &proxyServer{internal: http.NotFoundHandler()}
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "http://example.com/test", nil),
		httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil),
	} {
		request.Host = request.URL.Host
		response := httptest.NewRecorder()
		p.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Errorf("%s %s status = %d, want %d", request.Method, request.Host, response.Code, http.StatusForbidden)
		}
	}
}

func TestProxyAcceptsIPConnectForDeferredTLSValidation(t *testing.T) {
	if host := authorityHostname("203.107.60.165:12101"); net.ParseIP(host) == nil {
		t.Fatalf("authorityHostname returned non-IP %q", host)
	}
	if isPapegamesHost(authorityHostname("example.com:443")) {
		t.Fatal("example.com unexpectedly accepted as Papegames")
	}
}

func testTLSConfig(roots *x509.CertPool) *tls.Config {
	return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
}

func testCA(t *testing.T) (*x509.Certificate, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := cryptorand.Int(cryptorand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Pape Proxy Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return cert,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
