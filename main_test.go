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
	"net/url"
	"strings"
	"testing"
	"time"
)

// testMutator is a test helper implementing CredentialMutator with
// configurable callbacks.
type testMutator struct {
	onRequest  func(context.Context, *http.Request) error
	onResponse func(context.Context, *http.Request, *http.Response) error
}

func (m *testMutator) MutateRequest(ctx context.Context, req *http.Request) error {
	if m.onRequest != nil {
		return m.onRequest(ctx, req)
	}
	return nil
}

func (m *testMutator) MutateResponse(ctx context.Context, req *http.Request, resp *http.Response) error {
	if m.onResponse != nil {
		return m.onResponse(ctx, req, resp)
	}
	return nil
}

// TestMutateResponseCalled verifies that MutateResponse is called after
// a successful upstream response and before writing to the client.
func TestMutateResponseCalled(t *testing.T) {
	var mutateResponseCalled bool

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	ca, caKey, _ := generateEphemeralCA()
	cc := newCertCache(ca, caKey)
	upstreamAddr := upstream.Listener.Addr().String()

	mutator := &testMutator{
		onRequest: func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "Bearer test")
			return nil
		},
		onResponse: func(_ context.Context, _ *http.Request, _ *http.Response) error {
			mutateResponseCalled = true
			return nil
		},
	}

	p := &proxy{
		transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if h, _, _ := net.SplitHostPort(addr); h == "test.example.com" {
					addr = upstreamAddr
				}
				return net.DialTimeout(network, addr, 5*time.Second)
			},
		},
		rules:     NewRuleSet(Rule{Host: "test.example.com", Mutator: mutator}),
		certCache: cc,
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

	proxyCA := x509.NewCertPool()
	proxyCA.AddCert(ca)
	doProxyRequest(t, ln.Addr().String(), "test.example.com", proxyCA)

	if !mutateResponseCalled {
		t.Error("MutateResponse was not called")
	}
}

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

// TestOAuthRefreshFlow verifies the complete OAuth token exchange flow:
// 1. Client sends POST /token with dummy refresh_token
// 2. Proxy swaps for real refresh_token, forwards to token endpoint
// 3. Token endpoint returns real access_token
// 4. Proxy caches real access_token, returns dummy to client
// 5. Client sends API request with dummy access_token
// 6. Proxy replaces with real access_token, forwards to API
// 7. API endpoint receives real access_token, returns 200
func TestOAuthRefreshFlow(t *testing.T) {
	var gotRefreshToken string
	var gotAPIAuth string

	// Mock token endpoint: expects real refresh_token, returns real access_token.
	tokenEndpoint := newTestTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		vals, _ := url.ParseQuery(string(body))
		gotRefreshToken = vals.Get("refresh_token")

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"ya29.real-access-token","expires_in":3600,"token_type":"Bearer"}`)
	})
	defer tokenEndpoint.Close()

	// Mock API endpoint: expects real access_token.
	apiEndpoint := newTestTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAPIAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"projects":[{"id":"test-project"}]}`)
	})
	defer apiEndpoint.Close()

	ca, caKey, _ := generateEphemeralCA()
	cc := newCertCache(ca, caKey)

	tokenAddr := tokenEndpoint.Listener.Addr().String()
	apiAddr := apiEndpoint.Listener.Addr().String()

	refreshMutator := NewOAuthRefreshMutator("real-refresh-token-secret")

	p := &proxy{
		transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				switch h, _, _ := net.SplitHostPort(addr); h {
				case "oauth2.googleapis.com":
					addr = tokenAddr
				case "cloudresourcemanager.googleapis.com":
					addr = apiAddr
				}
				return net.DialTimeout(network, addr, 5*time.Second)
			},
		},
		rules: NewRuleSet(
			Rule{Host: "oauth2.googleapis.com", Mutator: refreshMutator},
			Rule{Host: "cloudresourcemanager.googleapis.com", Mutator: NewOAuthBearerMutator(refreshMutator)},
		),
		certCache: cc,
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

	proxyCA := x509.NewCertPool()
	proxyCA.AddCert(ca)

	// Step 1: Token refresh — POST /token with dummy refresh_token.
	tokenRespBody := doProxyPost(t, ln.Addr().String(), "oauth2.googleapis.com", "/token",
		"grant_type=refresh_token&refresh_token=dummy-container-token&client_id=764086051850-test.apps.googleusercontent.com",
		proxyCA)

	// Verify: proxy sent real refresh_token to upstream.
	if gotRefreshToken != "real-refresh-token-secret" {
		t.Errorf("token endpoint got refresh_token = %q, want %q", gotRefreshToken, "real-refresh-token-secret")
	}

	// Verify: client received dummy access_token (not real).
	if strings.Contains(tokenRespBody, "ya29.real-access-token") {
		t.Error("client received real access token — should have received dummy")
	}
	if !strings.Contains(tokenRespBody, DummyAccessToken) {
		t.Errorf("client response missing dummy token %q, got: %s", DummyAccessToken, tokenRespBody)
	}

	// Step 2: API request — GET /v1/projects with dummy access_token.
	apiRespBody := doProxyRequest(t, ln.Addr().String(), "cloudresourcemanager.googleapis.com", proxyCA)

	// Verify: proxy sent real access_token to upstream API.
	if gotAPIAuth != "Bearer ya29.real-access-token" {
		t.Errorf("API endpoint got Authorization = %q, want %q", gotAPIAuth, "Bearer ya29.real-access-token")
	}

	// Verify: client received the API response.
	if !strings.Contains(apiRespBody, "test-project") {
		t.Errorf("API response = %q, want to contain 'test-project'", apiRespBody)
	}

	t.Logf("OAuth flow verified: refresh_token swapped, access_token cached and injected")
}

// TestMethodBlockedByAllowMethods verifies that a request whose method
// is not in the rule's AllowMethods is rejected with 405 and not
// forwarded to upstream.
func TestMethodBlockedByAllowMethods(t *testing.T) {
	var upstreamHit bool
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	ca, caKey, _ := generateEphemeralCA()
	cc := newCertCache(ca, caKey)
	upstreamAddr := upstream.Listener.Addr().String()

	p := &proxy{
		transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if h, _, _ := net.SplitHostPort(addr); h == "test.example.com" {
					addr = upstreamAddr
				}
				return net.DialTimeout(network, addr, 5*time.Second)
			},
		},
		rules: NewRuleSet(Rule{
			Host:         "test.example.com",
			Mutator:      StaticBearerMutator("test"),
			AllowMethods: []string{"GET", "HEAD"},
		}),
		certCache: cc,
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

	proxyCA := x509.NewCertPool()
	proxyCA.AddCert(ca)

	status := doProxyPostStatus(t, ln.Addr().String(), "test.example.com", "/api", "data=evil", proxyCA)
	if status != 405 {
		t.Errorf("status = %d, want 405", status)
	}
	if upstreamHit {
		t.Error("upstream was hit despite POST not in AllowMethods")
	}
}

// doProxyPostStatus sends a POST through the proxy and returns the
// response status code.
func doProxyPostStatus(t *testing.T, proxyAddr, destHost, path, body string, proxyCA *x509.CertPool) int {
	t.Helper()

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", destHost, destHost)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT failed: %v status=%d", err, resp.StatusCode)
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: destHost,
		RootCAs:    proxyCA,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("tls: %v", err)
	}
	defer tlsConn.Close()

	reqStr := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		path, destHost, len(body), body)
	io.WriteString(tlsConn, reqStr)

	innerResp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer innerResp.Body.Close()
	return innerResp.StatusCode
}

// doProxyPost sends a POST request through the proxy and returns the response body.
func doProxyPost(t *testing.T, proxyAddr, destHost, path, body string, proxyCA *x509.CertPool) string {
	t.Helper()

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", destHost, destHost)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("CONNECT response: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT = %d", resp.StatusCode)
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: destHost,
		RootCAs:    proxyCA,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("tls: %v", err)
	}
	defer tlsConn.Close()

	reqStr := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		path, destHost, len(body), body)
	if _, err := io.WriteString(tlsConn, reqStr); err != nil {
		t.Fatalf("write request: %v", err)
	}

	innerResp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer innerResp.Body.Close()

	respBody, _ := io.ReadAll(innerResp.Body)
	return string(respBody)
}
