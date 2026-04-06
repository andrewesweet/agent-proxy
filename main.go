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
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

func main() {
	listen := flag.String("listen", ":18080", "proxy listen address")
	destHost := flag.String("dest", "api.github.com", "destination host to intercept (all others are passthrough)")
	token := flag.String("token", "", "bearer token to inject for the destination host")
	headerName := flag.String("header", "Authorization", "header name for credential injection")
	headerPrefix := flag.String("header-prefix", "token ", "prefix before the token value (e.g., 'Bearer ', 'token ')")
	caCertPath := flag.String("ca-cert", "", "path to CA certificate PEM (generated if empty)")
	caKeyPath := flag.String("ca-key", "", "path to CA private key PEM (generated if empty)")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	// Load or generate CA.
	ca, caKey, err := loadOrGenerateCA(*caCertPath, *caKeyPath)
	if err != nil {
		slog.Error("ca setup failed", "error", err)
		os.Exit(1)
	}
	slog.Info("ca ready", "subject", ca.Subject.CommonName, "not_after", ca.NotAfter)

	certCache := newCertCache(ca, caKey)

	// Build rules from CLI flags. In future phases this will come from
	// a config file or per-container socket identity.
	rules := NewRuleSet(Rule{
		Host:    *destHost,
		Mutator: StaticTokenMutator(*headerName, *headerPrefix+*token),
	})
	slog.Info("rules loaded", "rules", rules.String())

	p := &proxy{
		rules:     rules,
		certCache: certCache,
	}

	ln, err := net.Listen("tcp", *listen)
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

// proxy holds the configuration for the MITM proxy.
type proxy struct {
	rules     *RuleSet
	certCache *certCache

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

	br := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(br)
	if err != nil {
		slog.Debug("read request failed", "error", err)
		return
	}

	if req.Method != http.MethodConnect {
		// Non-CONNECT: out of scope for this prototype.
		fmt.Fprintf(clientConn, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
		return
	}

	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	slog.Debug("connect", "host", host, "dest", req.Host)

	if mutator := p.rules.Match(host); mutator != nil {
		p.handleMITM(clientConn, br, req, host, mutator)
	} else {
		p.handlePassthrough(clientConn, br, req)
	}
}

// handleMITM performs TLS interception: we tell the client CONNECT succeeded,
// perform a TLS handshake using a generated cert, read the plaintext HTTP
// request, inject credentials, and forward to the real destination.
func (p *proxy) handleMITM(clientConn net.Conn, br *bufio.Reader, connectReq *http.Request, destHost string, mutator CredentialMutator) {
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
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		slog.Error("client tls handshake failed", "error", err)
		return
	}
	defer tlsConn.Close()

	slog.Debug("mitm_tls_established",
		"host", destHost,
		"client_proto", tlsConn.ConnectionState().NegotiatedProtocol,
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
		reqHost := req.Host
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

		// Inject credential via the mutator.
		if err := mutator(req); err != nil {
			slog.Error("credential injection failed", "host", destHost, "error", err)
			return
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
				StatusCode: http.StatusBadGateway,
				Status:     "502 Bad Gateway",
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader("")),
			}
			errResp.Write(tlsConn)
			return
		}

		slog.Debug("upstream_response",
			"status", resp.StatusCode,
			"method", req.Method,
			"path", req.URL.Path,
		)

		// Write response back to client.
		if err := resp.Write(tlsConn); err != nil {
			slog.Debug("write response to client", "error", err)
			return
		}
		resp.Body.Close()

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

	// Bidirectional copy.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(upstreamConn, clientConn)
	}()
	go func() {
		defer wg.Done()
		io.Copy(clientConn, upstreamConn)
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
	keyRaw, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca key: %w", err)
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
	slog.Info("ephemeral ca written", "dir", tmpDir)

	return cert, key, nil
}
