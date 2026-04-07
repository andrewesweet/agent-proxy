package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
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

	vals.Set("refresh_token", m.realRefreshToken)
	encoded := vals.Encode()
	req.Body = io.NopCloser(strings.NewReader(encoded))
	req.ContentLength = int64(len(encoded))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(encoded)), nil
	}

	return nil
}

// MutateResponse is implemented in a later task.
func (m *OAuthRefreshMutator) MutateResponse(_ context.Context, _ *http.Request, _ *http.Response) error {
	return nil // placeholder
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
