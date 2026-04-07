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
		Rule{Host: "registry.npmjs.org", Mutator: StaticBearerMutator("npm-token")},
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
		m := rs.Match(tt.host)
		if tt.wantNil && m != nil {
			t.Errorf("Match(%q) = non-nil, want nil", tt.host)
		}
		if !tt.wantNil && m == nil {
			t.Errorf("Match(%q) = nil, want non-nil", tt.host)
		}
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
