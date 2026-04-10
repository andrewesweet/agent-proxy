package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
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
	// mu protects all mutable fields below: cachedToken, cachedExpiry,
	// and realRefreshToken (which may be updated on token rotation).
	mu               sync.RWMutex
	realRefreshToken string
	cachedToken      string
	cachedExpiry     time.Time
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

// isTokenEndpoint returns true if the request is a POST to a Google
// OAuth token endpoint.
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

	m.mu.RLock()
	realToken := m.realRefreshToken
	m.mu.RUnlock()
	vals.Set("refresh_token", realToken)
	encoded := vals.Encode()
	req.Body = io.NopCloser(strings.NewReader(encoded))
	req.ContentLength = int64(len(encoded))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(encoded)), nil
	}

	return nil
}

// MutateResponse caches the real access token from the token endpoint
// response and replaces it (and any rotated refresh token) with dummy
// sentinel values before the response reaches the container.
func (m *OAuthRefreshMutator) MutateResponse(_ context.Context, req *http.Request, resp *http.Response) error {
	if !isTokenEndpoint(req) {
		return nil
	}

	// S3: only process successful token responses.
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("read token response body: %w", err)
	}

	// C1: decompress gzip-encoded responses before parsing.
	if ce := resp.Header.Get("Content-Encoding"); ce == "gzip" {
		gr, err := gzip.NewReader(bytes.NewReader(bodyBytes))
		if err != nil {
			return fmt.Errorf("decompress token response: %w", err)
		}
		bodyBytes, err = io.ReadAll(gr)
		gr.Close()
		if err != nil {
			return fmt.Errorf("read decompressed token response: %w", err)
		}
		resp.Header.Del("Content-Encoding")
	}

	var tokenData map[string]any
	if err := json.Unmarshal(bodyBytes, &tokenData); err != nil {
		// E2: log when token endpoint returns non-JSON.
		slog.Warn("token endpoint returned non-JSON response",
			"content_type", resp.Header.Get("Content-Type"),
			"body_len", len(bodyBytes),
		)
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		resp.ContentLength = int64(len(bodyBytes))
		return nil
	}

	// Extract the real access token and compute expiry — but don't commit
	// to the cache until after json.Marshal succeeds (S1).
	var accessToken string
	var expiry time.Time
	if at, ok := tokenData["access_token"].(string); ok && at != "" {
		accessToken = at
		expiresIn := 3600.0 // default 1 hour
		if ei, ok := tokenData["expires_in"].(float64); ok {
			expiresIn = ei
		}
		// S4: clamp skew for small expires_in values.
		ttl := time.Duration(expiresIn) * time.Second
		skew := 60 * time.Second
		if ttl < skew*2 {
			skew = ttl / 2
		}
		expiry = time.Now().Add(ttl - skew)

		tokenData["access_token"] = DummyAccessToken
	}

	// S2: capture and update rotated refresh token.
	var rotatedRefreshToken string
	if rt, ok := tokenData["refresh_token"].(string); ok {
		rotatedRefreshToken = rt
		tokenData["refresh_token"] = DummyRefreshToken
	}

	modified, err := json.Marshal(tokenData)
	if err != nil {
		return fmt.Errorf("marshal modified token response: %w", err)
	}

	// S1: only commit cache after serialisation succeeds.
	if accessToken != "" {
		m.mu.Lock()
		m.cachedToken = accessToken
		m.cachedExpiry = expiry
		// S2: update real refresh token if Google rotated it.
		if rotatedRefreshToken != "" {
			m.realRefreshToken = rotatedRefreshToken
		}
		m.mu.Unlock()
	}

	resp.Body = io.NopCloser(bytes.NewReader(modified))
	resp.ContentLength = int64(len(modified))
	delete(resp.Header, "Transfer-Encoding")
	resp.TransferEncoding = nil

	return nil
}

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

// Rule maps a destination host to a credential mutator and optional
// method allowlist.
type Rule struct {
	// Host is the destination hostname to match (exact match).
	// Wildcard support (*.example.com) is planned for Phase 3d-2.
	Host string

	// Mutator injects credentials into requests to this host.
	Mutator CredentialMutator

	// AllowMethods, if non-empty, restricts credential injection to
	// requests using one of the listed HTTP methods. Empty means all
	// methods are permitted. Values must be uppercase HTTP method
	// tokens (GET, HEAD, POST, etc.) — validation is performed by
	// LoadConfig at startup.
	AllowMethods []string
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

// Match returns the rule for the given host, or nil if no rule matches.
// Host comparison is case-insensitive. First match wins.
func (rs *RuleSet) Match(host string) *Rule {
	host = strings.ToLower(host)
	for i := range rs.rules {
		if rs.rules[i].Host == host {
			return &rs.rules[i]
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
