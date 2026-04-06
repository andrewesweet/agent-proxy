package main

import (
	"fmt"
	"net/http"
	"strings"
)

// CredentialMutator modifies an HTTP request to inject credentials.
// It receives the full request so it can inspect method, path, and headers
// to decide what to inject (supporting multi-header auth like AWS SigV4,
// or body-based auth like OAuth token refresh).
type CredentialMutator func(req *http.Request) error

// StaticTokenMutator returns a CredentialMutator that sets a fixed header
// value on every request. Suitable for PATs, API keys, and registry tokens.
func StaticTokenMutator(headerName, headerValue string) CredentialMutator {
	return func(req *http.Request) error {
		req.Header.Set(headerName, headerValue)
		return nil
	}
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
