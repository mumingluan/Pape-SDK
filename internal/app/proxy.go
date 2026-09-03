package app

import (
	"bufio"
	"context"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"pape-sdk/internal/config"
)

const (
	proxyLeafCert = "data/pape.pem"
	proxyLeafKey  = "data/pape.key"
)

type proxyServer struct {
	internal         http.Handler
	tlsConfig        *tls.Config
	forwardTransport *http.Transport
	gateTargets      *proxyGateTargets
	useHTTP2         bool
	allowAll         bool
	storageHost      string
	storageTarget    *url.URL
	directHosts      map[string]struct{}
}

type proxyInternalContextKey struct{}

func isProxyInternalRequest(r *http.Request) bool {
	proxied, _ := r.Context().Value(proxyInternalContextKey{}).(bool)
	return proxied
}

type proxyCertificateManager struct {
	ca          *x509.Certificate
	caKey       crypto.Signer
	defaultCert tls.Certificate
	mu          sync.Mutex
	cache       map[string]*tls.Certificate
}

func newProxyHandler(cfg *config.Config, internal http.Handler) (http.Handler, error) {
	if strings.TrimSpace(cfg.Proxy.CACertificatePath) == "" || strings.TrimSpace(cfg.Proxy.CAPrivateKeyPath) == "" {
		return nil, errors.New("proxy.ca_certificate_path and proxy.ca_private_key_path are required when proxy is enabled")
	}
	caCertPath := cfg.Resolve(cfg.Proxy.CACertificatePath)
	caKeyPath := cfg.Resolve(cfg.Proxy.CAPrivateKeyPath)
	caCert, caKey, err := loadCA(caCertPath, caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load proxy CA: %w", err)
	}
	leafCertPath := cfg.Resolve(proxyLeafCert)
	leafKeyPath := cfg.Resolve(proxyLeafKey)
	leaf, generated, err := loadOrCreateProxyLeaf(caCert, caKey, leafCertPath, leafKeyPath)
	if err != nil {
		return nil, fmt.Errorf("prepare proxy certificate: %w", err)
	}
	if generated {
		log.Printf("[proxy] generated Papegames certificate: %s, %s", leafCertPath, leafKeyPath)
	}
	var gateTargets *proxyGateTargets
	if cfg.Proxy.PassthroughGameAddress {
		gateTargets, err = loadProxyGateTargets(cfg.ConfigPath("serverlist.json"))
		if err != nil {
			return nil, fmt.Errorf("load proxy gate targets: %w", err)
		}
		log.Printf("[proxy] loaded gate allowlist: http=%d tunnel=%d", len(gateTargets.httpAuthorities), len(gateTargets.tunnelAuthorities))
	}
	certificates := &proxyCertificateManager{
		ca:          caCert,
		caKey:       caKey,
		defaultCert: leaf,
		cache:       make(map[string]*tls.Certificate),
	}
	nextProtos := []string{"http/1.1"}
	if cfg.Proxy.UseHTTP2 {
		nextProtos = []string{"h2", "http/1.1"}
	}
	p := &proxyServer{
		internal:    internal,
		gateTargets: gateTargets,
		allowAll:    cfg.Proxy.PassthroughAllUnknown,
		directHosts: make(map[string]struct{}),
		tlsConfig: &tls.Config{
			GetCertificate: certificates.GetCertificate,
			MinVersion:     tls.VersionTLS12,
			NextProtos:     nextProtos,
		},
		forwardTransport: &http.Transport{
			Proxy:                 nil,
			ForceAttemptHTTP2:     cfg.Proxy.UseHTTP2,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
		useHTTP2: cfg.Proxy.UseHTTP2,
	}
	storageAuthority := strings.TrimSpace(cfg.Storage.PublicHost)
	if storageAuthority == "" {
		if endpoint, err := url.Parse(strings.TrimSpace(cfg.Storage.Endpoint)); err == nil {
			storageAuthority = endpoint.Host
		}
	}
	if storageAuthority != "" {
		storageHost := authorityHostname(storageAuthority)
		if storageHost == "" {
			return nil, fmt.Errorf("invalid storage public host %q", storageAuthority)
		}
		if strings.TrimSpace(cfg.Storage.ProxyBaseURL) != "" && isPapegamesHost(storageHost) {
			storageTarget, err := url.Parse(cfg.Storage.ProxyBaseURL)
			if err != nil || storageTarget.Scheme == "" || storageTarget.Host == "" {
				return nil, fmt.Errorf("invalid storage.proxy_base_url %q", cfg.Storage.ProxyBaseURL)
			}
			p.storageHost = storageHost
			p.storageTarget = storageTarget
			log.Printf("[proxy] storage host %s -> %s", storageHost, storageTarget)
		} else {
			p.directHosts[storageHost] = struct{}{}
			log.Printf("[proxy] storage host %s added to direct allowlist", storageHost)
		}
	}
	return p, nil
}

func (m *proxyCertificateManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hello.ServerName)), ".")
	if host == "" || host == "papegames.com" || (strings.HasSuffix(host, ".papegames.com") && strings.Count(host, ".") == 2) {
		return &m.defaultCert, nil
	}
	if !isPapegamesHost(host) {
		return nil, fmt.Errorf("unexpected MITM server name %q", host)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if cert := m.cache[host]; cert != nil {
		return cert, nil
	}
	cert, _, _, err := createProxyLeaf(m.ca, m.caKey, host, []string{host})
	if err != nil {
		return nil, err
	}
	m.cache[host] = &cert
	log.Printf("[proxy] generated in-memory certificate for %s", host)
	return &cert, nil
}

func (p *proxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.serveConnect(w, r)
		return
	}
	if p.gateTargets.allowsHTTP(r) {
		p.serveForwardHTTP(w, r)
		return
	}
	if p.allowsDirectHost(requestHostname(r)) {
		p.serveForwardHTTP(w, r)
		return
	}
	if isPapegamesHost(requestHostname(r)) {
		if r.URL.Scheme == "" {
			r.URL.Scheme = "http"
		}
		p.serveInternal(w, r)
		return
	}
	if p.allowAll {
		p.serveForwardHTTP(w, r)
		return
	}
	p.rejectNonPapegames(w, r)
}

func (p *proxyServer) serveConnect(w http.ResponseWriter, r *http.Request) {
	host := authorityHostname(r.Host)
	if p.gateTargets.allowsTunnel(r.Host) {
		p.serveTunnel(w, r)
		return
	}
	if p.allowsDirectHost(host) {
		p.serveTunnel(w, r)
		return
	}
	if isPapegamesHost(host) {
		p.serveMITMConnect(w, r)
		return
	}
	if p.allowAll {
		p.serveTunnel(w, r)
		return
	}
	connectByIP := net.ParseIP(host) != nil
	if !connectByIP {
		p.rejectNonPapegames(w, r)
		return
	}
	if connectByIP {
		log.Printf("[proxy] CONNECT %s uses an IP; deferring Papegames validation to TLS SNI/HTTP Host", r.Host)
	}
	p.serveMITMConnect(w, r)
}

func (p *proxyServer) allowsDirectHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	_, ok := p.directHosts[host]
	return ok
}

func (p *proxyServer) serveMITMConnect(w http.ResponseWriter, r *http.Request) {
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
		log.Printf("[proxy] CONNECT %s response failed: %v", r.Host, err)
		return
	}
	if err := buffered.Flush(); err != nil {
		log.Printf("[proxy] CONNECT %s flush failed: %v", r.Host, err)
		return
	}

	conn := net.Conn(clientConn)
	if buffered.Reader.Buffered() > 0 {
		conn = &readerConn{Conn: clientConn, reader: buffered.Reader}
	}
	tlsConn := tls.Server(conn, p.tlsConfig.Clone())
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		log.Printf("[proxy] CONNECT %s TLS handshake failed: %v", r.Host, err)
		return
	}
	state := tlsConn.ConnectionState()
	proto := state.NegotiatedProtocol
	log.Printf("[proxy] CONNECT %s -> internal TLS (%s, sni=%q)", r.Host, displayProtocol(proto), state.ServerName)
	if p.useHTTP2 && proto == "h2" {
		(&http2.Server{}).ServeConn(tlsConn, &http2.ServeConnOpts{Handler: http.HandlerFunc(p.serveInternal)})
		return
	}
	server := &http.Server{
		Handler:           http.HandlerFunc(p.serveInternal),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	if err := server.Serve(newSingleConnListener(tlsConn)); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		log.Printf("[proxy] CONNECT %s HTTP serving failed: %v", r.Host, err)
	}
}

func (p *proxyServer) rejectNonPapegames(w http.ResponseWriter, r *http.Request) {
	log.Printf("[proxy] %s %s rejected: non-Papegames host", r.Method, r.Host)
	http.Error(w, "proxy only permits papegames.com", http.StatusForbidden)
}

func (p *proxyServer) serveInternal(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	if p.storageTarget != nil && strings.EqualFold(requestHostname(r), p.storageHost) {
		p.serveStorageHTTP(w, r)
		return
	}
	if !isPapegamesHost(requestHostname(r)) {
		p.rejectNonPapegames(w, r)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), proxyInternalContextKey{}, true))
	if r.URL.Scheme == "" {
		r.URL.Scheme = "https"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}
	recorder := &proxyResponseWriter{ResponseWriter: w}
	p.internal.ServeHTTP(recorder, r)
	log.Printf("[proxy] %s %s://%s%s -> internal status=%d bytes=%d proto=%s duration=%s",
		r.Method, r.URL.Scheme, r.Host, r.URL.RequestURI(), recorder.statusCode(), recorder.bytes,
		r.Proto, time.Since(started).Round(time.Millisecond))
}

type proxyResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *proxyResponseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *proxyResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

func (w *proxyResponseWriter) statusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func (w *proxyResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *proxyResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response writer does not support hijacking")
	}
	return hijacker.Hijack()
}

func (w *proxyResponseWriter) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return http.ErrNotSupported
}

func (w *proxyResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type readerConn struct {
	net.Conn
	reader io.Reader
}

func (c *readerConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

type singleConnListener struct {
	conn     net.Conn
	accepted bool
	done     chan struct{}
	close    sync.Once
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	return &singleConnListener{conn: conn, done: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.accepted {
		<-l.done
		return nil, net.ErrClosed
	}
	l.accepted = true
	return &closeNotifyConn{Conn: l.conn, closed: l.signalClosed}, nil
}

func (l *singleConnListener) signalClosed()  { l.close.Do(func() { close(l.done) }) }
func (l *singleConnListener) Close() error   { l.signalClosed(); return nil }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

type closeNotifyConn struct {
	net.Conn
	closed func()
}

func (c *closeNotifyConn) Close() error {
	err := c.Conn.Close()
	c.closed()
	return err
}

func requestHostname(r *http.Request) string {
	if r.URL != nil && r.URL.Hostname() != "" {
		return r.URL.Hostname()
	}
	return authorityHostname(r.Host)
}

func authorityHostname(authority string) string {
	host, _, err := net.SplitHostPort(authority)
	if err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(authority, "[]")
}

func isPapegamesHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	return host == "papegames.com" || strings.HasSuffix(host, ".papegames.com")
}

func displayProtocol(proto string) string {
	if proto == "" {
		return "http/1.1"
	}
	return proto
}

func loadCA(certPath, keyPath string) (*x509.Certificate, crypto.Signer, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read certificate %s: %w", certPath, err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("%s does not contain a PEM certificate", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if !cert.IsCA {
		return nil, nil, fmt.Errorf("%s is not a CA certificate", certPath)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read private key %s: %w", keyPath, err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("%s does not contain a PEM private key", keyPath)
	}
	key, err := parseSigner(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func parseSigner(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported CA private key format")
}

func loadOrCreateProxyLeaf(ca *x509.Certificate, caKey crypto.Signer, certPath, keyPath string) (tls.Certificate, bool, error) {
	if leaf, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil && proxyLeafValid(leaf, ca) {
		return leaf, false, nil
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return tls.Certificate{}, false, err
	}
	leaf, certPEM, keyPEM, err := createProxyLeaf(ca, caKey, "*.papegames.com", []string{"papegames.com", "*.papegames.com"})
	if err != nil {
		return tls.Certificate{}, false, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, false, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, false, err
	}
	return leaf, true, nil
}

func createProxyLeaf(ca *x509.Certificate, caKey crypto.Signer, commonName string, dnsNames []string) (tls.Certificate, []byte, []byte, error) {
	key, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := cryptorand.Int(cryptorand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	notAfter := time.Now().AddDate(2, 0, 0)
	if ca.NotAfter.Before(notAfter) {
		notAfter = ca.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName, Organization: []string{"Pape SDK Local Proxy"}},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(cryptorand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	leaf, err := tls.X509KeyPair(certPEM, keyPEM)
	return leaf, certPEM, keyPEM, err
}

func proxyLeafValid(leaf tls.Certificate, ca *x509.Certificate) bool {
	if len(leaf.Certificate) == 0 {
		return false
	}
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		return false
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, err = cert.Verify(x509.VerifyOptions{
		DNSName:     "passport.papegames.com",
		Roots:       roots,
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err == nil
}
