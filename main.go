// Command agent-proxy is a Phase 3a prototype of a MITM credential injection
// proxy for containerized AI coding agents.
//
// It accepts HTTPS CONNECT tunnels, performs TLS inspection on allowlisted
// destinations using on-the-fly generated certificates, injects/replaces
// Authorization headers, and forwards to the real destination.
//
// This is a research prototype — NOT production-ready. It hardcodes a single
// destination and credential for validation of the TLS interception hot path.
//
// Usage:
//
//	agent-proxy \
//	  -listen :18080 \
//	  -dest api.github.com \
//	  -token ghp_xxxxx \
//	  -ca-cert ca.crt -ca-key ca.key
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

func main() {
	configPath := flag.String("config", "", "path to YAML config file")
	flag.Parse()

	if *configPath == "" {
		fmt.Fprintf(os.Stderr, "usage: agent-proxy -config <path>\n")
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	cfg, rules, err := LoadConfig(*configPath)
	if err != nil {
		slog.Error("config load failed", "error", err)
		os.Exit(1)
	}

	ca, caKey, err := loadOrGenerateCA(cfg.CA.CertFile, cfg.CA.KeyFile)
	if err != nil {
		slog.Error("ca setup failed", "error", err)
		os.Exit(1)
	}
	slog.Info("ca ready", "subject", ca.Subject.CommonName, "not_after", ca.NotAfter)

	certCache := newCertCache(ca, caKey)

	slog.Info("rules loaded", "rules", rules.String())

	p := &proxy{
		rules:     rules,
		certCache: certCache,
	}

	ln, err := listen(cfg.Listen)
	if err != nil {
		slog.Error("listen failed", "error", err)
		os.Exit(1)
	}
	slog.Info("listening", "addr", ln.Addr())

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			slog.Error("accept", "error", err)
			continue
		}
		go p.handleConn(conn)
	}
}

// listen binds a net.Listener based on the configured address. A
// "unix://" prefix creates a Unix domain socket with mode 0600
// (enforced via umask for atomic creation). The path must be absolute.
// Any other value is interpreted as a TCP address. Stale socket files
// are removed before binding; non-socket files at the path produce an
// error.
func listen(address string) (net.Listener, error) {
	if !strings.HasPrefix(address, "unix://") {
		return net.Listen("tcp", address)
	}
	path := strings.TrimPrefix(address, "unix://")
	if path == "" {
		return nil, fmt.Errorf("listen unix: empty path")
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("listen unix %q: path must be absolute", path)
	}

	// Check for existing file and remove if it's a stale socket.
	info, err := os.Stat(path)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("listen path %q exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket %q: %w", path, err)
		}
	case errors.Is(err, fs.ErrNotExist):
		// Path doesn't exist — proceed to bind.
	default:
		return nil, fmt.Errorf("stat listen path %q: %w", path, err)
	}

	// Set umask 0o177 so the socket is created with mode 0600
	// atomically (closes the TOCTOU window between net.Listen and
	// os.Chmod). syscall.Umask returns the previous value.
	oldMask := syscall.Umask(0o177)
	defer syscall.Umask(oldMask)

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen unix %q: %w", path, err)
	}
	// Belt-and-braces: also chmod explicitly, in case umask was
	// overridden by an LSM or the kernel created the node with
	// unexpected permissions.
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("chmod socket %q: %w", path, err)
	}
	return ln, nil
}

// proxy holds the configuration for the MITM proxy.
type proxy struct {
	rules     *RuleSet
	certCache *certCache

	// allowPassthrough controls whether CONNECT to non-ruled hosts is
	// permitted. If false (default), non-ruled destinations are rejected.
	allowPassthrough bool

	// transport is used for forwarding intercepted requests upstream.
	// If nil, http.DefaultTransport is used.
	transport http.RoundTripper
}

func (p *proxy) roundTripper() http.RoundTripper {
	if p.transport != nil {
		return p.transport
	}
	return http.DefaultTransport
}

// handleConn reads the initial HTTP request from the client. If it's a
// CONNECT to the intercepted destination, we perform MITM. Otherwise we
// tunnel blindly (passthrough).
func (p *proxy) handleConn(clientConn net.Conn) {
	defer clientConn.Close()
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic in connection handler", "panic", r)
		}
	}()

	br := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(br)
	if err != nil {
		slog.Debug("read request failed", "error", err)
		return
	}

	if req.Method != http.MethodConnect {
		fmt.Fprintf(clientConn, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
		return
	}

	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host) // S2: case-insensitive host matching.

	slog.Debug("connect", "host", host, "dest", req.Host)

	if rule := p.rules.Match(host); rule != nil {
		p.handleMITM(clientConn, br, req, host, rule)
	} else if p.allowPassthrough {
		p.handlePassthrough(clientConn, br, req)
	} else {
		slog.Warn("connect_denied", "host", host)
		fmt.Fprintf(clientConn, "HTTP/1.1 403 Forbidden\r\n\r\n")
	}
}

// handleMITM performs TLS interception: we tell the client CONNECT succeeded,
// perform a TLS handshake using a generated cert, read the plaintext HTTP
// request, inject credentials, and forward to the real destination.
func (p *proxy) handleMITM(clientConn net.Conn, br *bufio.Reader, connectReq *http.Request, destHost string, rule *Rule) {
	// Tell client CONNECT succeeded. We don't pre-dial upstream here;
	// each HTTP request is forwarded independently via the transport.
	fmt.Fprintf(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	// TLS handshake with the client using a generated cert for the dest host.
	tlsCert, err := p.certCache.getCert(destHost)
	if err != nil {
		slog.Error("cert generation failed", "host", destHost, "error", err)
		return
	}

	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		NextProtos:   []string{"http/1.1"}, // Phase 3a: HTTP/1.1 only; H2 in next phase.
	})
	// G1: timeout on client TLS handshake to prevent slow-client DoS.
	hsCtx, hsCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer hsCancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		slog.Error("client tls handshake failed", "error", err)
		return
	}
	defer tlsConn.Close()

	// S1: Verify SNI matches the CONNECT host.
	cs := tlsConn.ConnectionState()
	sniHost := strings.ToLower(cs.ServerName)
	if sniHost != "" && sniHost != destHost {
		slog.Warn("sni_mismatch",
			"connect_host", destHost,
			"sni", sniHost,
		)
		return
	}

	slog.Debug("mitm_tls_established",
		"host", destHost,
		"client_proto", cs.NegotiatedProtocol,
		"sni", sniHost,
	)

	// Read/write loop: read HTTP/1.1 requests from client, inject header,
	// forward to upstream, relay response back.
	clientBuf := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(clientBuf)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				slog.Debug("read inner request", "error", err)
			}
			return
		}

		// Enforce host consistency (U1 resolution: CONNECT host == Host header).
		reqHost := strings.ToLower(req.Host)
		if h, _, err := net.SplitHostPort(reqHost); err == nil {
			reqHost = h
		}
		if reqHost != destHost {
			slog.Warn("host_mismatch",
				"connect_host", destHost,
				"request_host", reqHost,
			)
			resp := &http.Response{
				StatusCode: http.StatusBadRequest,
				Status:     "400 Bad Request",
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     http.Header{"Content-Type": {"text/plain"}},
				Body:       io.NopCloser(strings.NewReader("host mismatch: CONNECT host != request Host header\n")),
			}
			resp.Write(tlsConn)
			return
		}

		// Enforce per-rule method allowlist (G2).
		if len(rule.AllowMethods) > 0 {
			allowed := false
			for _, m := range rule.AllowMethods {
				if m == req.Method {
					allowed = true
					break
				}
			}
			if !allowed {
				slog.Warn("method_blocked",
					"host", destHost,
					"method", req.Method,
					"allow_methods", rule.AllowMethods,
				)
				resp := &http.Response{
					StatusCode: http.StatusMethodNotAllowed,
					Status:     "405 Method Not Allowed",
					Proto:      "HTTP/1.1",
					ProtoMajor: 1,
					ProtoMinor: 1,
					Header: http.Header{
						"Content-Length": {"0"},
						"Allow":          {strings.Join(rule.AllowMethods, ", ")},
					},
					Body:          io.NopCloser(strings.NewReader("")),
					ContentLength: 0,
				}
				resp.Write(tlsConn)
				if req.Close {
					return
				}
				continue
			}
		}

		// Inject credential via the mutator.
		if err := rule.Mutator.MutateRequest(context.Background(), req); err != nil {
			slog.Error("credential injection failed", "host", destHost, "error", err)
			// E1: write 502 instead of bare connection teardown.
			errResp := &http.Response{
				StatusCode:    http.StatusBadGateway,
				Status:        "502 Bad Gateway",
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        http.Header{"Content-Length": {"0"}},
				Body:          io.NopCloser(strings.NewReader("")),
				ContentLength: 0,
			}
			errResp.Write(tlsConn)
			if req.Close {
				return
			}
			continue
		}
		slog.Debug("credential_injected",
			"host", destHost,
			"method", req.Method,
			"path", req.URL.Path,
		)

		// Fix the request URL for direct connection (not proxy form).
		req.URL.Scheme = "https"
		req.URL.Host = destHost
		req.RequestURI = "" // Required for http.Client / Transport.

		// Forward to upstream.
		resp, err := p.roundTripper().RoundTrip(req)
		if err != nil {
			slog.Error("upstream request failed", "error", err)
			errResp := &http.Response{
				StatusCode:    http.StatusBadGateway,
				Status:        "502 Bad Gateway",
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        http.Header{"Content-Length": {"0"}},
				Body:          io.NopCloser(strings.NewReader("")),
				ContentLength: 0,
			}
			errResp.Write(tlsConn)
			// C1: continue the keep-alive loop; don't kill the session
			// on a single upstream failure. Only break if the client
			// asked to close.
			if req.Close {
				return
			}
			continue
		}

		slog.Debug("upstream_response",
			"status", resp.StatusCode,
			"method", req.Method,
			"path", req.URL.Path,
		)

		// Invoke response mutation (e.g., OAuth token caching/replacement).
		if err := rule.Mutator.MutateResponse(context.Background(), req, resp); err != nil {
			slog.Error("response mutation failed", "host", destHost, "error", err)
			resp.Body.Close()
			errResp := &http.Response{
				StatusCode:    http.StatusBadGateway,
				Status:        "502 Bad Gateway",
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        http.Header{"Content-Length": {"0"}},
				Body:          io.NopCloser(strings.NewReader("")),
				ContentLength: 0,
			}
			errResp.Write(tlsConn)
			if req.Close {
				return
			}
			continue
		}

		// C2: set resp.Request so resp.Write knows the method (HEAD
		// responses must not write a body).
		resp.Request = req

		// R1: ensure resp.Body is always closed, even on write errors.
		writeErr := resp.Write(tlsConn)
		resp.Body.Close()
		if writeErr != nil {
			slog.Debug("write response to client", "error", writeErr)
			return
		}

		// If the response indicated connection close, stop.
		if resp.Close || req.Close {
			return
		}
	}
}

// handlePassthrough tunnels the connection directly without inspection.
func (p *proxy) handlePassthrough(clientConn net.Conn, _ *bufio.Reader, connectReq *http.Request) {
	destAddr := connectReq.Host
	if _, _, err := net.SplitHostPort(destAddr); err != nil {
		destAddr = destAddr + ":443"
	}

	upstreamConn, err := net.DialTimeout("tcp", destAddr, 10*time.Second)
	if err != nil {
		slog.Error("passthrough dial failed", "dest", destAddr, "error", err)
		fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer upstreamConn.Close()

	fmt.Fprintf(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	// R2: set idle timeout on passthrough connections to prevent
	// indefinite goroutine hangs on stale connections.
	idleTimeout := 5 * time.Minute
	deadline := time.Now().Add(idleTimeout)
	clientConn.SetDeadline(deadline)
	upstreamConn.SetDeadline(deadline)

	// Bidirectional copy.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(upstreamConn, clientConn)
		upstreamConn.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(clientConn, upstreamConn)
		clientConn.Close()
	}()
	wg.Wait()
}

// ---- Certificate generation and caching ----

// certCache generates and caches TLS certificates for intercepted hosts.
type certCache struct {
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	mu    sync.RWMutex
	certs map[string]*tls.Certificate
}

func newCertCache(ca *x509.Certificate, caKey *ecdsa.PrivateKey) *certCache {
	return &certCache{
		ca:    ca,
		caKey: caKey,
		certs: make(map[string]*tls.Certificate),
	}
}

func (c *certCache) getCert(host string) (*tls.Certificate, error) {
	c.mu.RLock()
	if cert, ok := c.certs[host]; ok {
		c.mu.RUnlock()
		return cert, nil
	}
	c.mu.RUnlock()

	// Generate under write lock.
	c.mu.Lock()
	defer c.mu.Unlock()
	// Double-check after acquiring write lock.
	if cert, ok := c.certs[host]; ok {
		return cert, nil
	}

	cert, err := c.generateCert(host)
	if err != nil {
		return nil, err
	}
	c.certs[host] = cert
	slog.Debug("cert_generated", "host", host)
	return cert, nil
}

func (c *certCache) generateCert(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, c.ca, &key.PublicKey, c.caKey)
	if err != nil {
		return nil, fmt.Errorf("sign leaf cert: %w", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER, c.ca.Raw},
		PrivateKey:  key,
	}
	return tlsCert, nil
}

// loadOrGenerateCA loads a CA from PEM files or generates an ephemeral one.
func loadOrGenerateCA(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if certPath != "" && keyPath != "" {
		return loadCA(certPath, keyPath)
	}
	return generateEphemeralCA()
}

func loadCA(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read ca cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("no PEM block in ca cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca cert: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read ca key: %w", err)
	}
	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("no PEM block in ca key")
	}
	// G2: try SEC 1 (EC PRIVATE KEY) first, then PKCS8 (PRIVATE KEY).
	keyRaw, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		pkcs8Key, pkcs8Err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if pkcs8Err != nil {
			return nil, nil, fmt.Errorf("parse ca key (tried EC and PKCS8): EC=%w, PKCS8=%v", err, pkcs8Err)
		}
		ecKey, ok := pkcs8Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("ca key is PKCS8 but not ECDSA (got %T)", pkcs8Key)
		}
		keyRaw = ecKey
	}

	return cert, keyRaw, nil
}

func generateEphemeralCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ca key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "agent-proxy ephemeral CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("self-sign ca: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse generated ca: %w", err)
	}

	// Write to temp files for debugging / client trust store injection.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tmpDir, _ := os.MkdirTemp("", "agent-proxy-ca-*")
	os.WriteFile(tmpDir+"/ca.crt", certPEM, 0644)
	os.WriteFile(tmpDir+"/ca.key", keyPEM, 0600)
	// S5: only log the cert path (public), not the key path.
	slog.Info("ephemeral ca written", "cert", tmpDir+"/ca.crt")

	return cert, key, nil
}
