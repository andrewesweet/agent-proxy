package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)


func TestStaticTokenMutator(t *testing.T) {
	m := StaticTokenMutator("X-API-Key", "sk-test-123")
	req, _ := http.NewRequest("GET", "https://example.com/api", nil)

	if err := m.MutateRequest(context.Background(), req); err != nil {
		t.Fatalf("mutator error: %v", err)
	}
	if got := req.Header.Get("X-API-Key"); got != "sk-test-123" {
		t.Errorf("header = %q, want %q", got, "sk-test-123")
	}
}

func TestStaticBearerMutator(t *testing.T) {
	m := StaticBearerMutator("ya29.fake-token")
	req, _ := http.NewRequest("GET", "https://example.com/api", nil)

	m.MutateRequest(context.Background(), req)
	if got := req.Header.Get("Authorization"); got != "Bearer ya29.fake-token" {
		t.Errorf("header = %q, want %q", got, "Bearer ya29.fake-token")
	}
}

func TestStaticGitHubTokenMutator(t *testing.T) {
	m := StaticGitHubTokenMutator("ghp_xxxx")
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)

	m.MutateRequest(context.Background(), req)
	if got := req.Header.Get("Authorization"); got != "token ghp_xxxx" {
		t.Errorf("header = %q, want %q", got, "token ghp_xxxx")
	}
}

func TestRuleSetMatch(t *testing.T) {
	rs := NewRuleSet(
		Rule{Host: "api.github.com", Mutator: StaticGitHubTokenMutator("gh-pat")},
		Rule{Host: "registry.npmjs.org", Mutator: StaticBearerMutator("npm-token"), AllowMethods: []string{"GET", "HEAD"}},
		Rule{Host: "api.anthropic.com", Mutator: StaticTokenMutator("x-api-key", "sk-ant-xxx")},
	)

	tests := []struct {
		host    string
		wantNil bool
	}{
		{"api.github.com", false},
		{"registry.npmjs.org", false},
		{"api.anthropic.com", false},
		{"unknown.example.com", true},
		{"", true},
	}

	for _, tt := range tests {
		r := rs.Match(tt.host)
		if tt.wantNil && r != nil {
			t.Errorf("Match(%q) = non-nil, want nil", tt.host)
		}
		if !tt.wantNil && r == nil {
			t.Errorf("Match(%q) = nil, want non-nil", tt.host)
		}
	}

	// Verify AllowMethods is carried through.
	r := rs.Match("registry.npmjs.org")
	if r == nil || len(r.AllowMethods) != 2 {
		t.Errorf("expected AllowMethods=[GET HEAD], got %v", r)
	}
}

func TestRuleSetHosts(t *testing.T) {
	rs := NewRuleSet(
		Rule{Host: "a.example.com", Mutator: StaticBearerMutator("x")},
		Rule{Host: "b.example.com", Mutator: StaticBearerMutator("y")},
	)
	hosts := rs.Hosts()
	if len(hosts) != 2 || hosts[0] != "a.example.com" || hosts[1] != "b.example.com" {
		t.Errorf("Hosts() = %v, want [a.example.com b.example.com]", hosts)
	}
}

// TestMultiDestinationMITM verifies that the proxy can intercept multiple
// destinations with different credentials simultaneously.
func TestMultiDestinationMITM(t *testing.T) {
	// Two upstream servers expecting different credentials.
	var gotAuthA, gotAuthB string

	upstreamA := newTestTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuthA = r.Header.Get("Authorization")
		w.Write([]byte(`{"service":"A"}`))
	})
	defer upstreamA.Close()

	upstreamB := newTestTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuthB = r.Header.Get("x-api-key")
		w.Write([]byte(`{"service":"B"}`))
	})
	defer upstreamB.Close()

	ca, caKey, _ := generateEphemeralCA()
	cc := newCertCache(ca, caKey)

	addrA := upstreamA.Listener.Addr().String()
	addrB := upstreamB.Listener.Addr().String()

	p := &proxy{
		transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				switch h, _, _ := net.SplitHostPort(addr); h {
				case "service-a.example.com":
					addr = addrA
				case "service-b.example.com":
					addr = addrB
				}
				return net.DialTimeout(network, addr, 5*time.Second)
			},
		},
		rules: NewRuleSet(
			Rule{Host: "service-a.example.com", Mutator: StaticGitHubTokenMutator("pat-A")},
			Rule{Host: "service-b.example.com", Mutator: StaticTokenMutator("x-api-key", "key-B")},
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

	// Request to service A.
	respA := doProxyRequest(t, ln.Addr().String(), "service-a.example.com", proxyCA)
	if gotAuthA != "token pat-A" {
		t.Errorf("service A got Authorization = %q, want %q", gotAuthA, "token pat-A")
	}
	t.Logf("Service A: auth=%q body=%s", gotAuthA, respA)

	// Request to service B.
	respB := doProxyRequest(t, ln.Addr().String(), "service-b.example.com", proxyCA)
	if gotAuthB != "key-B" {
		t.Errorf("service B got x-api-key = %q, want %q", gotAuthB, "key-B")
	}
	t.Logf("Service B: auth=%q body=%s", gotAuthB, respB)
}

func TestOAuthRefreshMutator_AccessToken_ColdStart(t *testing.T) {
	m := NewOAuthRefreshMutator("real-refresh-token")
	_, err := m.AccessToken()
	if err == nil {
		t.Fatal("expected error on cold start, got nil")
	}
}

func TestOAuthRefreshMutator_AccessToken_Valid(t *testing.T) {
	m := NewOAuthRefreshMutator("real-refresh-token")
	m.mu.Lock()
	m.cachedToken = "ya29.real-token"
	m.cachedExpiry = time.Now().Add(30 * time.Minute)
	m.mu.Unlock()

	token, err := m.AccessToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "ya29.real-token" {
		t.Errorf("token = %q, want %q", token, "ya29.real-token")
	}
}

func TestOAuthRefreshMutator_AccessToken_Expired(t *testing.T) {
	m := NewOAuthRefreshMutator("real-refresh-token")
	m.mu.Lock()
	m.cachedToken = "ya29.expired-token"
	m.cachedExpiry = time.Now().Add(-1 * time.Minute)
	m.mu.Unlock()

	_, err := m.AccessToken()
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

func TestOAuthRefreshMutator_MutateRequest_SwapsToken(t *testing.T) {
	m := NewOAuthRefreshMutator("real-refresh-token")
	body := "grant_type=refresh_token&refresh_token=dummy-token&client_id=test"
	req, _ := http.NewRequest("POST", "https://oauth2.googleapis.com/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := m.MutateRequest(context.Background(), req); err != nil {
		t.Fatalf("MutateRequest error: %v", err)
	}

	newBody, _ := io.ReadAll(req.Body)
	vals, _ := url.ParseQuery(string(newBody))
	if got := vals.Get("refresh_token"); got != "real-refresh-token" {
		t.Errorf("refresh_token = %q, want %q", got, "real-refresh-token")
	}
	if got := vals.Get("grant_type"); got != "refresh_token" {
		t.Errorf("grant_type = %q, want %q", got, "refresh_token")
	}
	if got := vals.Get("client_id"); got != "test" {
		t.Errorf("client_id = %q, want %q", got, "test")
	}
	if req.ContentLength != int64(len(newBody)) {
		t.Errorf("ContentLength = %d, want %d", req.ContentLength, int64(len(newBody)))
	}
}

func TestOAuthRefreshMutator_MutateRequest_NonRefreshGrant(t *testing.T) {
	m := NewOAuthRefreshMutator("real-refresh-token")
	body := "grant_type=client_credentials&client_id=test"
	req, _ := http.NewRequest("POST", "https://oauth2.googleapis.com/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := m.MutateRequest(context.Background(), req); err != nil {
		t.Fatalf("MutateRequest error: %v", err)
	}

	newBody, _ := io.ReadAll(req.Body)
	if strings.Contains(string(newBody), "real-refresh-token") {
		t.Error("non-refresh grant should not contain real refresh token")
	}
}

func TestOAuthRefreshMutator_MutateRequest_WrongPath(t *testing.T) {
	m := NewOAuthRefreshMutator("real-refresh-token")
	body := "grant_type=refresh_token&refresh_token=dummy"
	req, _ := http.NewRequest("POST", "https://oauth2.googleapis.com/revoke", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := m.MutateRequest(context.Background(), req); err != nil {
		t.Fatalf("MutateRequest error: %v", err)
	}

	newBody, _ := io.ReadAll(req.Body)
	if strings.Contains(string(newBody), "real-refresh-token") {
		t.Error("wrong path should not contain real refresh token")
	}
}

func TestOAuthRefreshMutator_MutateRequest_GetMethod(t *testing.T) {
	m := NewOAuthRefreshMutator("real-refresh-token")
	req, _ := http.NewRequest("GET", "https://oauth2.googleapis.com/token", nil)

	if err := m.MutateRequest(context.Background(), req); err != nil {
		t.Fatalf("MutateRequest error: %v", err)
	}
	// No panic, no error — GET is a no-op.
}

func TestOAuthRefreshMutator_MutateRequest_V4Path(t *testing.T) {
	m := NewOAuthRefreshMutator("real-refresh-token")
	body := "grant_type=refresh_token&refresh_token=dummy-token"
	req, _ := http.NewRequest("POST", "https://oauth2.googleapis.com/oauth2/v4/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := m.MutateRequest(context.Background(), req); err != nil {
		t.Fatalf("MutateRequest error: %v", err)
	}

	newBody, _ := io.ReadAll(req.Body)
	vals, _ := url.ParseQuery(string(newBody))
	if got := vals.Get("refresh_token"); got != "real-refresh-token" {
		t.Errorf("refresh_token = %q, want %q", got, "real-refresh-token")
	}
}

func TestOAuthRefreshMutator_MutateResponse_CachesAndReplaces(t *testing.T) {
	m := NewOAuthRefreshMutator("real-refresh-token")
	tokenResp := `{"access_token":"ya29.real-token","expires_in":3600,"token_type":"Bearer"}`

	req, _ := http.NewRequest("POST", "https://oauth2.googleapis.com/token", nil)
	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          io.NopCloser(strings.NewReader(tokenResp)),
		ContentLength: int64(len(tokenResp)),
	}

	if err := m.MutateResponse(context.Background(), req, resp); err != nil {
		t.Fatalf("MutateResponse error: %v", err)
	}

	// Check the token was cached.
	token, err := m.AccessToken()
	if err != nil {
		t.Fatalf("AccessToken error after MutateResponse: %v", err)
	}
	if token != "ya29.real-token" {
		t.Errorf("cached token = %q, want %q", token, "ya29.real-token")
	}

	// Check the response body was modified.
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "ya29.real-token") {
		t.Error("response body still contains real access token")
	}
	if !strings.Contains(string(body), DummyAccessToken) {
		t.Errorf("response body missing dummy token %q", DummyAccessToken)
	}

	// Check Content-Length matches the actual body.
	if resp.ContentLength != int64(len(body)) {
		t.Errorf("ContentLength = %d, body length = %d", resp.ContentLength, len(body))
	}
}

func TestOAuthRefreshMutator_MutateResponse_MasksRotatedRefreshToken(t *testing.T) {
	m := NewOAuthRefreshMutator("real-refresh-token")
	tokenResp := `{"access_token":"ya29.real","expires_in":3600,"refresh_token":"1//new-rotated-token","token_type":"Bearer"}`

	req, _ := http.NewRequest("POST", "https://oauth2.googleapis.com/token", nil)
	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          io.NopCloser(strings.NewReader(tokenResp)),
		ContentLength: int64(len(tokenResp)),
	}

	if err := m.MutateResponse(context.Background(), req, resp); err != nil {
		t.Fatalf("MutateResponse error: %v", err)
	}

	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "1//new-rotated-token") {
		t.Error("response body still contains rotated refresh token")
	}
	if !strings.Contains(string(body), DummyRefreshToken) {
		t.Errorf("response body missing dummy refresh token %q", DummyRefreshToken)
	}
}

func TestOAuthRefreshMutator_MutateResponse_NonTokenEndpoint(t *testing.T) {
	m := NewOAuthRefreshMutator("real-refresh-token")
	originalBody := `{"data":"unchanged"}`

	req, _ := http.NewRequest("GET", "https://oauth2.googleapis.com/tokeninfo", nil)
	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          io.NopCloser(strings.NewReader(originalBody)),
		ContentLength: int64(len(originalBody)),
	}

	if err := m.MutateResponse(context.Background(), req, resp); err != nil {
		t.Fatalf("MutateResponse error: %v", err)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != originalBody {
		t.Errorf("body = %q, want %q (non-token endpoint should be unchanged)", string(body), originalBody)
	}
}

func TestOAuthBearerMutator_OverwritesUnconditionally(t *testing.T) {
	m := NewOAuthRefreshMutator("real-refresh-token")
	m.mu.Lock()
	m.cachedToken = "ya29.real-token"
	m.cachedExpiry = time.Now().Add(30 * time.Minute)
	m.mu.Unlock()

	bearer := NewOAuthBearerMutator(m)
	req, _ := http.NewRequest("GET", "https://cloudresourcemanager.googleapis.com/v1/projects", nil)
	req.Header.Set("Authorization", "Bearer "+DummyAccessToken)

	if err := bearer.MutateRequest(context.Background(), req); err != nil {
		t.Fatalf("MutateRequest error: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer ya29.real-token" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer ya29.real-token")
	}
}

func TestOAuthBearerMutator_OverwritesArbitraryValue(t *testing.T) {
	m := NewOAuthRefreshMutator("real-refresh-token")
	m.mu.Lock()
	m.cachedToken = "ya29.real-token"
	m.cachedExpiry = time.Now().Add(30 * time.Minute)
	m.mu.Unlock()

	bearer := NewOAuthBearerMutator(m)
	req, _ := http.NewRequest("GET", "https://example.com/api", nil)
	req.Header.Set("Authorization", "Bearer some-completely-different-value")

	if err := bearer.MutateRequest(context.Background(), req); err != nil {
		t.Fatalf("MutateRequest error: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer ya29.real-token" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer ya29.real-token")
	}
}

func TestOAuthBearerMutator_ErrorOnEmptyCache(t *testing.T) {
	m := NewOAuthRefreshMutator("real-refresh-token")
	bearer := NewOAuthBearerMutator(m)
	req, _ := http.NewRequest("GET", "https://example.com/api", nil)

	err := bearer.MutateRequest(context.Background(), req)
	if err == nil {
		t.Fatal("expected error on empty cache, got nil")
	}
}

func TestMutatorsDoNotLeakViaLogValue(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	static := StaticTokenMutator("Authorization", "Bearer SECRET_TOKEN_123")
	refresh := NewOAuthRefreshMutator("REAL_REFRESH_TOKEN_456")
	bearer := NewOAuthBearerMutator(refresh)

	logger.Info("mutators", "s", static, "r", refresh, "b", bearer)

	out := buf.String()
	if strings.Contains(out, "SECRET_TOKEN_123") {
		t.Errorf("log leaked static token: %s", out)
	}
	if strings.Contains(out, "REAL_REFRESH_TOKEN_456") {
		t.Errorf("log leaked refresh token: %s", out)
	}
}

// ---- test helpers ----

func newTestTLSServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(handler)
}

func doProxyRequest(t *testing.T, proxyAddr, destHost string, proxyCA *x509.CertPool) string {
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

	fmt.Fprintf(tlsConn, "GET /test HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", destHost)
	innerResp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer innerResp.Body.Close()

	body, _ := io.ReadAll(innerResp.Body)
	return string(body)
}
