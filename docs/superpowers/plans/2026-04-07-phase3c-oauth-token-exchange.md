# Phase 3c: OAuth Token Exchange Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade CredentialMutator from a function type to an interface and add OAuth authorized_user ADC flow interception that keeps all credentials out of the container.

**Architecture:** The `CredentialMutator` interface adds `MutateRequest` and `MutateResponse` methods. `OAuthRefreshMutator` intercepts `POST /token` requests to swap dummy refresh tokens for real ones, then caches the real access token from the response and returns a dummy to the container. `OAuthBearerMutator` unconditionally replaces Authorization headers on API hosts with the cached real token via a `TokenProvider` interface.

**Tech Stack:** Go 1.25, stdlib only (no external dependencies)

**Spec:** `docs/superpowers/specs/2026-04-07-phase3c-oauth-token-exchange-design.md`

---

## File Structure

| File | Responsibility | Action |
|------|---------------|--------|
| `credential.go` | `CredentialMutator` interface, `staticTokenMutator`, `TokenProvider`, `OAuthRefreshMutator`, `OAuthBearerMutator`, `Rule`, `RuleSet` | Modify |
| `main.go` | Proxy core — update call sites from func to interface, add `MutateResponse` to MITM loop | Modify |
| `credential_test.go` | Unit tests for all mutators and rule matching | Modify |
| `main_test.go` | Integration tests including end-to-end OAuth refresh flow | Modify |

---

### Task 1: Upgrade CredentialMutator to Interface

Convert the `CredentialMutator` function type to an interface. Wrap existing static mutators in a struct. All existing tests must continue to pass.

**Files:**
- Modify: `credential.go` (full file — type change, struct wrappers, constructors)
- Modify: `main.go:243` (call site: `mutator(req)` → `mutator.MutateRequest(...)`)
- Modify: `credential_test.go` (update call syntax in all tests)

- [ ] **Step 1: Update existing tests to use the new interface call syntax**

In `credential_test.go`, change all `m(req)` calls to `m.MutateRequest(context.Background(), req)`. These tests will fail to compile until the interface is implemented.

```go
// TestStaticTokenMutator — change line 21:
if err := m.MutateRequest(context.Background(), req); err != nil {

// TestStaticBearerMutator — change line 33:
m.MutateRequest(context.Background(), req)

// TestStaticGitHubTokenMutator — change line 43:
m.MutateRequest(context.Background(), req)
```

Add `"context"` to the import block.

- [ ] **Step 2: Run tests to verify they fail to compile**

Run: `go test -v -count=1 ./...`
Expected: compilation error — `m.MutateRequest undefined`

- [ ] **Step 3: Implement the CredentialMutator interface and staticTokenMutator**

Replace the contents of `credential.go` with:

```go
package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// CredentialMutator modifies HTTP requests and responses to inject credentials.
// MutateRequest is called before forwarding to upstream.
// MutateResponse is called after a successful upstream response, before
// writing to the client. It is NOT called when RoundTrip returns an error.
type CredentialMutator interface {
	MutateRequest(ctx context.Context, req *http.Request) error
	MutateResponse(ctx context.Context, req *http.Request, resp *http.Response) error
}

// staticTokenMutator sets a fixed header value on every request.
type staticTokenMutator struct {
	headerName  string
	headerValue string
}

func (m *staticTokenMutator) MutateRequest(_ context.Context, req *http.Request) error {
	req.Header.Set(m.headerName, m.headerValue)
	return nil
}

func (m *staticTokenMutator) MutateResponse(_ context.Context, _ *http.Request, _ *http.Response) error {
	return nil
}

// StaticTokenMutator returns a CredentialMutator that sets a fixed header
// value on every request. Suitable for PATs, API keys, and registry tokens.
// Panics if headerName is empty or contains invalid characters.
func StaticTokenMutator(headerName, headerValue string) CredentialMutator {
	// S4: validate header name at construction time.
	if headerName == "" {
		panic("empty header name")
	}
	for _, c := range headerName {
		if c <= ' ' || c == ':' || c >= 0x7f {
			panic(fmt.Sprintf("invalid character %q in header name %q", c, headerName))
		}
	}
	return &staticTokenMutator{headerName: headerName, headerValue: headerValue}
}

// StaticBearerMutator is a convenience wrapper for Authorization: Bearer tokens.
func StaticBearerMutator(token string) CredentialMutator {
	return StaticTokenMutator("Authorization", "Bearer "+token)
}

// StaticGitHubTokenMutator is a convenience wrapper for GitHub PATs,
// which use "token" prefix instead of "Bearer".
func StaticGitHubTokenMutator(token string) CredentialMutator {
	return StaticTokenMutator("Authorization", "token "+token)
}

// Rule maps a destination host to a credential mutator.
type Rule struct {
	// Host is the destination hostname to match (exact match).
	// Wildcard support (*.example.com) is planned for Phase 3d.
	Host string

	// Mutator injects credentials into requests to this host.
	Mutator CredentialMutator
}

// RuleSet holds an ordered list of rules and provides lookup by host.
type RuleSet struct {
	rules []Rule
}

// NewRuleSet creates a RuleSet from the given rules. Host values are
// normalized to lowercase.
func NewRuleSet(rules ...Rule) *RuleSet {
	normalized := make([]Rule, len(rules))
	for i, r := range rules {
		r.Host = strings.ToLower(r.Host)
		normalized[i] = r
	}
	return &RuleSet{rules: normalized}
}

// Match returns the CredentialMutator for the given host, or nil if no
// rule matches. Host comparison is case-insensitive. First match wins.
func (rs *RuleSet) Match(host string) CredentialMutator {
	host = strings.ToLower(host)
	for _, r := range rs.rules {
		if r.Host == host {
			return r.Mutator
		}
	}
	return nil
}

// Hosts returns the list of destination hosts that have rules configured.
func (rs *RuleSet) Hosts() []string {
	hosts := make([]string, len(rs.rules))
	for i, r := range rs.rules {
		hosts[i] = r.Host
	}
	return hosts
}

// String returns a summary of the ruleset for logging.
func (rs *RuleSet) String() string {
	return fmt.Sprintf("RuleSet{%d rules, hosts=%v}", len(rs.rules), rs.Hosts())
}
```

- [ ] **Step 4: Update main.go call site**

In `main.go:243`, change:

```go
// Old:
if err := mutator(req); err != nil {
```

to:

```go
// New:
if err := mutator.MutateRequest(context.Background(), req); err != nil {
```

Add `"context"` to the import block in `main.go` if not already present.

- [ ] **Step 5: Run tests to verify all pass**

Run: `go test -v -count=1 ./...`
Expected: all 9 existing tests pass

- [ ] **Step 6: Commit**

```bash
git add credential.go credential_test.go main.go
git commit -m "refactor: upgrade CredentialMutator from function type to interface

Converts CredentialMutator to a two-method interface (MutateRequest,
MutateResponse) and wraps static token mutators in staticTokenMutator
struct. Prepares for Phase 3c OAuth mutators that need response hooks."
```

---

### Task 2: Add MutateResponse to the MITM Loop

Wire `MutateResponse` into the proxy's request/response cycle, called after a successful `RoundTrip` and before `resp.Write`.

**Files:**
- Modify: `main.go:282-304` (MITM loop, after `RoundTrip` success, before `resp.Write`)
- Modify: `main_test.go` (add test verifying MutateResponse is called)

- [ ] **Step 1: Write a test that verifies MutateResponse is called**

Add to `main_test.go`:

```go
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
```

Add `"context"` to the import block if not already present.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -count=1 -run TestMutateResponseCalled ./...`
Expected: FAIL — `MutateResponse was not called`

- [ ] **Step 3: Add MutateResponse call to the MITM loop**

In `main.go`, after the `upstream_response` log line (around line 286) and before the `resp.Request = req` line, add:

```go
		// Invoke response mutation (e.g., OAuth token caching/replacement).
		if err := mutator.MutateResponse(context.Background(), req, resp); err != nil {
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
```

- [ ] **Step 4: Run tests to verify all pass**

Run: `go test -v -count=1 ./...`
Expected: all tests pass including `TestMutateResponseCalled`

- [ ] **Step 5: Commit**

```bash
git add main.go main_test.go
git commit -m "feat: wire MutateResponse into MITM loop

MutateResponse is called after a successful RoundTrip and before writing
the response to the client. On error, writes 502 and continues the
keep-alive loop. Not called on the RoundTrip error path."
```

---

### Task 3: TokenProvider Interface and OAuthRefreshMutator Skeleton

Define the `TokenProvider` interface and the `OAuthRefreshMutator` struct with its constructor and `AccessToken()` method. No request/response logic yet — just the token cache.

**Files:**
- Modify: `credential.go` (add `TokenProvider`, `OAuthRefreshMutator` struct, constructor, `AccessToken`)
- Modify: `credential_test.go` (add token cache tests)

- [ ] **Step 1: Write tests for AccessToken (cold start and expiry)**

Add to `credential_test.go`:

```go
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
```

Add `"time"` to the import block if not already present.

- [ ] **Step 2: Run tests to verify they fail to compile**

Run: `go test -v -count=1 ./...`
Expected: compilation error — `NewOAuthRefreshMutator` undefined

- [ ] **Step 3: Implement TokenProvider and OAuthRefreshMutator skeleton**

Add to `credential.go` (after the `StaticGitHubTokenMutator` function, before the `Rule` type):

```go
// TokenProvider returns the current access token for upstream API calls.
type TokenProvider interface {
	AccessToken() (string, error)
}

// DummyAccessToken is the sentinel access token returned to the container.
// It is not a secret — its purpose is to keep real tokens out of container
// memory and logs.
const DummyAccessToken = "ya29.proxy-sentinel"

// DummyRefreshToken is the sentinel refresh token substituted in token
// endpoint responses when Google rotates the refresh token.
const DummyRefreshToken = "1//proxy-sentinel-refresh"

// OAuthRefreshMutator handles the oauth2.googleapis.com token endpoint.
// It swaps dummy refresh tokens for real ones on requests, and caches
// real access tokens from responses (returning dummies to the container).
type OAuthRefreshMutator struct {
	realRefreshToken string

	mu           sync.RWMutex
	cachedToken  string
	cachedExpiry time.Time
}

// NewOAuthRefreshMutator creates a mutator for the OAuth token endpoint.
// realRefreshToken is the host-side real refresh token that will be
// substituted into token refresh requests.
func NewOAuthRefreshMutator(realRefreshToken string) *OAuthRefreshMutator {
	return &OAuthRefreshMutator{
		realRefreshToken: realRefreshToken,
	}
}

// AccessToken returns the cached real access token if it is still valid.
// Returns an error if no token is cached or if the token has expired.
func (m *OAuthRefreshMutator) AccessToken() (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cachedToken == "" {
		return "", fmt.Errorf("no access token cached (container must call token endpoint first)")
	}
	if time.Now().After(m.cachedExpiry) {
		return "", fmt.Errorf("cached access token expired")
	}
	return m.cachedToken, nil
}

// MutateRequest is implemented in a later task.
func (m *OAuthRefreshMutator) MutateRequest(_ context.Context, _ *http.Request) error {
	return nil // placeholder
}

// MutateResponse is implemented in a later task.
func (m *OAuthRefreshMutator) MutateResponse(_ context.Context, _ *http.Request, _ *http.Response) error {
	return nil // placeholder
}
```

Add `"sync"` and `"time"` to the import block in `credential.go`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -v -count=1 ./...`
Expected: all tests pass including the three new AccessToken tests

- [ ] **Step 5: Commit**

```bash
git add credential.go credential_test.go
git commit -m "feat: add TokenProvider interface and OAuthRefreshMutator skeleton

Defines the token cache with expiry tracking and AccessToken() method.
MutateRequest and MutateResponse are placeholders — implemented in
subsequent tasks."
```

---

### Task 4: OAuthRefreshMutator.MutateRequest — Refresh Token Swap

Implement the request-side logic: detect `POST /token` with `grant_type=refresh_token`, swap the dummy refresh token for the real one.

**Files:**
- Modify: `credential.go` (replace MutateRequest placeholder)
- Modify: `credential_test.go` (add request mutation tests)

- [ ] **Step 1: Write tests for MutateRequest**

Add to `credential_test.go`:

```go
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
		t.Errorf("ContentLength = %d, want %d", req.ContentLength, len(newBody))
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
```

Add `"io"`, `"net/url"`, and `"strings"` to the import block if not already present.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -count=1 -run TestOAuthRefreshMutator_MutateRequest ./...`
Expected: FAIL — tests pass vacuously (placeholder returns nil) but the SwapsToken test fails because the body is unchanged

- [ ] **Step 3: Implement MutateRequest**

Replace the `MutateRequest` placeholder in `credential.go`:

```go
// isTokenRefreshRequest returns true if the request is a POST to a Google
// OAuth token endpoint with grant_type=refresh_token.
func isTokenEndpoint(req *http.Request) bool {
	if req.Method != http.MethodPost {
		return false
	}
	p := req.URL.Path
	return p == "/token" || p == "/oauth2/v4/token"
}

// MutateRequest swaps the dummy refresh_token for the real one in token
// refresh requests. Non-refresh requests are passed through unchanged.
func (m *OAuthRefreshMutator) MutateRequest(_ context.Context, req *http.Request) error {
	if !isTokenEndpoint(req) {
		return nil
	}
	if req.Body == nil {
		return nil
	}

	bodyBytes, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		return fmt.Errorf("read token request body: %w", err)
	}

	vals, err := url.ParseQuery(string(bodyBytes))
	if err != nil {
		// Not a form body — pass through unchanged.
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))
		return nil
	}

	if vals.Get("grant_type") != "refresh_token" {
		// Not a refresh request — restore original body unchanged.
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))
		return nil
	}

	vals.Set("refresh_token", m.realRefreshToken)
	encoded := vals.Encode()
	req.Body = io.NopCloser(strings.NewReader(encoded))
	req.ContentLength = int64(len(encoded))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(encoded)), nil
	}

	return nil
}
```

Add `"bytes"`, `"io"`, and `"net/url"` to the import block in `credential.go`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -v -count=1 ./...`
Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add credential.go credential_test.go
git commit -m "feat: implement OAuthRefreshMutator.MutateRequest

Swaps the dummy refresh_token for the real one in POST /token requests
with grant_type=refresh_token. Handles both /token and /oauth2/v4/token
paths. Non-refresh requests pass through unchanged. Body and
ContentLength are correctly restored in all paths."
```

---

### Task 5: OAuthRefreshMutator.MutateResponse — Token Caching and Replacement

Implement the response-side logic: parse the token endpoint response, cache the real access token with expiry, replace `access_token` and any rotated `refresh_token` with dummies.

**Files:**
- Modify: `credential.go` (replace MutateResponse placeholder)
- Modify: `credential_test.go` (add response mutation tests)

- [ ] **Step 1: Write tests for MutateResponse**

Add to `credential_test.go`:

```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -count=1 -run TestOAuthRefreshMutator_MutateResponse ./...`
Expected: FAIL — placeholder returns nil without caching or replacing anything

- [ ] **Step 3: Implement MutateResponse**

Replace the `MutateResponse` placeholder in `credential.go`:

```go
// MutateResponse caches the real access token from the token endpoint
// response and replaces it (and any rotated refresh token) with dummy
// sentinel values before the response reaches the container.
func (m *OAuthRefreshMutator) MutateResponse(_ context.Context, req *http.Request, resp *http.Response) error {
	if !isTokenEndpoint(req) {
		return nil
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("read token response body: %w", err)
	}

	var tokenData map[string]any
	if err := json.Unmarshal(bodyBytes, &tokenData); err != nil {
		// Not valid JSON — pass through unchanged (might be an error response).
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		resp.ContentLength = int64(len(bodyBytes))
		return nil
	}

	// Cache the real access token with expiry.
	if accessToken, ok := tokenData["access_token"].(string); ok && accessToken != "" {
		expiresIn := 3600.0 // default 1 hour
		if ei, ok := tokenData["expires_in"].(float64); ok {
			expiresIn = ei
		}
		expiry := time.Now().Add(time.Duration(expiresIn)*time.Second - 60*time.Second)

		m.mu.Lock()
		m.cachedToken = accessToken
		m.cachedExpiry = expiry
		m.mu.Unlock()

		tokenData["access_token"] = DummyAccessToken
	}

	// Mask any rotated refresh token.
	if _, ok := tokenData["refresh_token"]; ok {
		tokenData["refresh_token"] = DummyRefreshToken
	}

	modified, err := json.Marshal(tokenData)
	if err != nil {
		return fmt.Errorf("marshal modified token response: %w", err)
	}

	resp.Body = io.NopCloser(bytes.NewReader(modified))
	resp.ContentLength = int64(len(modified))
	delete(resp.Header, "Transfer-Encoding")
	resp.TransferEncoding = nil

	return nil
}
```

Add `"encoding/json"` to the import block in `credential.go`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -v -count=1 ./...`
Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add credential.go credential_test.go
git commit -m "feat: implement OAuthRefreshMutator.MutateResponse

Caches the real access token with expiry from the token endpoint
response, replaces access_token with a dummy sentinel, and masks any
rotated refresh_token. Updates Content-Length and clears
Transfer-Encoding to match the modified body."
```

---

### Task 6: OAuthBearerMutator

Implement the API-host mutator that unconditionally replaces the Authorization header with the cached real token via TokenProvider.

**Files:**
- Modify: `credential.go` (add `OAuthBearerMutator`)
- Modify: `credential_test.go` (add bearer mutator tests)

- [ ] **Step 1: Write tests for OAuthBearerMutator**

Add to `credential_test.go`:

```go
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
```

- [ ] **Step 2: Run tests to verify they fail to compile**

Run: `go test -v -count=1 -run TestOAuthBearerMutator ./...`
Expected: compilation error — `NewOAuthBearerMutator` undefined

- [ ] **Step 3: Implement OAuthBearerMutator**

Add to `credential.go` (after `OAuthRefreshMutator`):

```go
// OAuthBearerMutator handles API hosts by replacing the Authorization
// header with the real access token from a TokenProvider.
type OAuthBearerMutator struct {
	tokenProvider TokenProvider
}

// NewOAuthBearerMutator creates a mutator for API hosts. It reads the
// current access token from the given TokenProvider on each request.
func NewOAuthBearerMutator(tp TokenProvider) *OAuthBearerMutator {
	return &OAuthBearerMutator{tokenProvider: tp}
}

// MutateRequest unconditionally replaces the Authorization header with
// the cached real access token. Returns an error if no valid token is
// available (cold start or expiry).
func (m *OAuthBearerMutator) MutateRequest(_ context.Context, req *http.Request) error {
	token, err := m.tokenProvider.AccessToken()
	if err != nil {
		return fmt.Errorf("oauth bearer: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

// MutateResponse is a no-op for API hosts.
func (m *OAuthBearerMutator) MutateResponse(_ context.Context, _ *http.Request, _ *http.Response) error {
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -v -count=1 ./...`
Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add credential.go credential_test.go
git commit -m "feat: add OAuthBearerMutator for API host token injection

Unconditionally replaces the Authorization header with the cached real
access token from a TokenProvider. Returns an error (502 to client) if
no valid token is available."
```

---

### Task 7: End-to-End OAuth Refresh Flow Test

Integration test that wires up mock token endpoint + mock API endpoint through the full proxy, verifying the complete flow: dummy refresh_token → real refresh → cached real access_token → injected on API calls → dummy returned to client.

**Files:**
- Modify: `main_test.go` (add `TestOAuthRefreshFlow`)

- [ ] **Step 1: Write the end-to-end test**

Add to `main_test.go`:

```go
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

	// Verify: Content-Length is correct.
	// (Checked implicitly by http.ReadResponse succeeding.)

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
```

Add `"net/url"` to the import block.

- [ ] **Step 2: Run test to verify it passes**

Run: `go test -v -count=1 -run TestOAuthRefreshFlow ./...`
Expected: PASS — the full flow works end-to-end

- [ ] **Step 3: Run all tests with race detector**

Run: `go test -v -count=1 -race ./...`
Expected: all tests pass with no race conditions detected

- [ ] **Step 4: Commit**

```bash
git add main_test.go
git commit -m "test: add end-to-end OAuth refresh flow integration test

Verifies the complete flow: dummy refresh_token swap, real token caching,
dummy returned to client, real token injected on subsequent API calls.
Uses mock token and API endpoints through the full MITM proxy."
```

---

### Task 8: Adversarial Code Review

Commission an adversarial code review of the completed implementation.

- [ ] **Step 1: Run all tests one final time**

Run: `go test -v -count=1 -race ./...`
Expected: all tests pass

- [ ] **Step 2: Commission adversarial review**

Launch a Sonnet 4.6 subagent to perform an adversarial code review of all changed files. The review should cover security, concurrency, correctness, resource leaks, and test coverage — same structure as `docs/code-review-phase3b.md`.

- [ ] **Step 3: Address findings**

Fix any High or Critical findings. Document Medium/Low findings that are deferred.

- [ ] **Step 4: Final commit**

Commit the review document and any fixes.

```bash
git add docs/code-review-phase3c.md credential.go main.go credential_test.go main_test.go
git commit -m "fix: address findings from Phase 3c adversarial code review"
```

---

## Task Dependency Graph

```
Task 1 (interface upgrade)
    │
    ▼
Task 2 (MutateResponse in MITM loop)
    │
    ▼
Task 3 (TokenProvider + OAuthRefreshMutator skeleton)
    │
    ├─────────────────────┐
    ▼                     ▼
Task 4 (MutateRequest)   Task 5 (MutateResponse)
    │                     │
    └──────┬──────────────┘
           ▼
    Task 6 (OAuthBearerMutator)
           │
           ▼
    Task 7 (end-to-end test)
           │
           ▼
    Task 8 (adversarial review)
```

Tasks 4 and 5 can be done in either order (they modify different methods of the same struct) but are shown as parallel possibilities, not requirements.
