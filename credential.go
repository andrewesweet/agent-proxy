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
