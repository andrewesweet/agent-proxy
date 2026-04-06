package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestMITMInjection verifies the core MITM hot path:
//  1. Client sends CONNECT to proxy targeting the destination host
//  2. Proxy terminates TLS using a generated cert signed by the test CA
//  3. Client sends an HTTP request through the decrypted tunnel
//  4. Proxy injects the Authorization header
//  5. Upstream receives the injected credential
//  6. Response is relayed back to the client
func TestMITMInjection(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"login":"test-agent","id":1}`)
	}))
	defer upstream.Close()

	upstreamAddr := upstream.Listener.Addr().String()

	ca, caKey, err := generateEphemeralCA()
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}

	cc := newCertCache(ca, caKey)

	p := &proxy{
		transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if h, _, _ := net.SplitHostPort(addr); h == "test.example.com" {
					addr = upstreamAddr
				}
				return net.DialTimeout(network, addr, 5*time.Second)
			},
		},
		rules: NewRuleSet(Rule{
			Host:    "test.example.com",
			Mutator: StaticGitHubTokenMutator("ghp_FAKE_TEST_TOKEN_12345"),
		}),
		certCache: cc,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleConn(conn)
		}
	}()

	proxyCA := x509.NewCertPool()
	proxyCA.AddCert(ca)

	proxyConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer proxyConn.Close()

	fmt.Fprintf(proxyConn, "CONNECT test.example.com:443 HTTP/1.1\r\nHost: test.example.com:443\r\n\r\n")
	br := bufio.NewReader(proxyConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	tlsConn := tls.Client(proxyConn, &tls.Config{
		ServerName: "test.example.com",
		RootCAs:    proxyCA,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	defer tlsConn.Close()

	req := "GET /user HTTP/1.1\r\nHost: test.example.com\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(tlsConn, req); err != nil {
		t.Fatalf("write request: %v", err)
	}

	innerResp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("read inner response: %v", err)
	}
	defer innerResp.Body.Close()

	body, _ := io.ReadAll(innerResp.Body)

	if gotAuth != "token ghp_FAKE_TEST_TOKEN_12345" {
		t.Errorf("upstream got Authorization = %q, want %q", gotAuth, "token ghp_FAKE_TEST_TOKEN_12345")
	}
	if innerResp.StatusCode != 200 {
		t.Errorf("response status = %d, want 200", innerResp.StatusCode)
	}
	if !strings.Contains(string(body), "test-agent") {
		t.Errorf("response body = %q, want to contain 'test-agent'", string(body))
	}

	t.Logf("MITM injection verified: upstream received Authorization=%q", gotAuth)
	t.Logf("Response body: %s", string(body))
}

// TestHostMismatchRejection verifies the U1 resolution: if the Host header
// doesn't match the CONNECT host, the proxy rejects the request.
func TestHostMismatchRejection(t *testing.T) {
	ca, caKey, err := generateEphemeralCA()
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	cc := newCertCache(ca, caKey)

	p := &proxy{
		rules: NewRuleSet(Rule{
			Host:    "test.example.com",
			Mutator: StaticBearerMutator("secret"),
		}),
		certCache: cc,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleConn(conn)
		}
	}()

	proxyCA := x509.NewCertPool()
	proxyCA.AddCert(ca)

	proxyConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer proxyConn.Close()

	fmt.Fprintf(proxyConn, "CONNECT test.example.com:443 HTTP/1.1\r\nHost: test.example.com:443\r\n\r\n")
	br := bufio.NewReader(proxyConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("CONNECT response: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT = %d", resp.StatusCode)
	}

	tlsConn := tls.Client(proxyConn, &tls.Config{
		ServerName: "test.example.com",
		RootCAs:    proxyCA,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("tls: %v", err)
	}
	defer tlsConn.Close()

	req := "GET /user HTTP/1.1\r\nHost: evil.example.com\r\nConnection: close\r\n\r\n"
	io.WriteString(tlsConn, req)

	innerResp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	defer innerResp.Body.Close()

	if innerResp.StatusCode != 400 {
		t.Errorf("status = %d, want 400 (host mismatch)", innerResp.StatusCode)
	}

	body, _ := io.ReadAll(innerResp.Body)
	if !strings.Contains(string(body), "host mismatch") {
		t.Errorf("body = %q, want 'host mismatch'", string(body))
	}

	t.Logf("Host mismatch correctly rejected: status=%d body=%q", innerResp.StatusCode, string(body))
}

// TestPassthrough verifies that non-intercepted hosts are tunneled
// transparently without TLS termination.
func TestPassthrough(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "passthrough-ok")
		fmt.Fprintf(w, "hello from upstream")
	}))
	defer upstream.Close()

	ca, caKey, _ := generateEphemeralCA()
	cc := newCertCache(ca, caKey)

	p := &proxy{
		rules: NewRuleSet(Rule{
			Host:    "intercepted.example.com",
			Mutator: StaticBearerMutator("secret"),
		}),
		allowPassthrough: true, // Passthrough test needs this enabled.
		certCache:        cc,
	}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleConn(conn)
		}
	}()

	proxyConn, _ := net.Dial("tcp", ln.Addr().String())
	defer proxyConn.Close()

	upAddr := upstream.Listener.Addr().String()
	fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upAddr, upAddr)
	br := bufio.NewReader(proxyConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT = %d", resp.StatusCode)
	}

	upstreamCA := x509.NewCertPool()
	upstreamCA.AddCert(upstream.Certificate())
	tlsConn := tls.Client(proxyConn, &tls.Config{
		RootCAs:            upstreamCA,
		ServerName:         upAddr[:strings.Index(upAddr, ":")],
		InsecureSkipVerify: true,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("upstream tls: %v", err)
	}
	defer tlsConn.Close()

	io.WriteString(tlsConn, "GET / HTTP/1.1\r\nHost: other.example.com\r\nConnection: close\r\n\r\n")
	innerResp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	defer innerResp.Body.Close()

	if innerResp.StatusCode != 200 {
		t.Errorf("passthrough status = %d, want 200", innerResp.StatusCode)
	}
	if innerResp.Header.Get("X-Test") != "passthrough-ok" {
		t.Errorf("missing passthrough header")
	}

	body, _ := io.ReadAll(innerResp.Body)
	t.Logf("Passthrough verified: %s", string(body))
}
