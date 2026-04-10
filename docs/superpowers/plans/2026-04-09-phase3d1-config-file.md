# Phase 3d-1: YAML Configuration File Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace CLI flag configuration with a YAML config file supporting multiple rules, secure credential resolution, Unix socket listener by default, method allowlisting, and tamper-detection hash logging.

**Architecture:** A new `config.go` defines `Config`, `CAConfig`, `AuditLogConfig`, `RuleConfig` types. `LoadConfig(path)` parses YAML (strict mode), validates fields, resolves credentials from files/env vars, constructs mutators, zeros credential fields, and returns `(*Config, *RuleSet, error)`. `main.go` replaces `flag.String` calls with a single `-config` flag and calls `LoadConfig`. The proxy's listener supports `unix://` addresses; TCP requires `listen_allow_tcp: true` opt-in. `handleMITM` enforces `allow_methods` per rule by consulting the matching rule's allowed method set before invoking the mutator.

**Tech Stack:** Go 1.25, `gopkg.in/yaml.v3` (new dependency), stdlib for everything else.

**Spec:** `docs/superpowers/specs/2026-04-09-phase3d1-config-file-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `go.mod`, `go.sum` | Modify | Add `gopkg.in/yaml.v3` dependency |
| `config.go` | Create | `Config`, `CAConfig`, `AuditLogConfig`, `RuleConfig` types; `LoadConfig`; validation; credential resolution; mutator construction |
| `config_test.go` | Create | Unit tests for `LoadConfig` covering all validation paths and credential resolution |
| `credential.go` | Modify | Add exported `Rule.AllowMethods` field; `RuleSet.Match` returns `*Rule` instead of `CredentialMutator` |
| `credential_test.go` | Modify | Update existing tests for new `Match` signature |
| `main.go` | Modify | Replace all flags with `-config`; call `LoadConfig`; support `unix://` listener; enforce `AllowMethods` in MITM loop |
| `main_test.go` | Modify | Adapt existing tests for new `Match` signature; add integration test for config-driven proxy |

**Note on `credential.go` change:** Currently `RuleSet.Match` returns `CredentialMutator`. To enforce `AllowMethods` in `handleMITM`, the caller needs both the mutator and the allowed method list. Changing `Match` to return `*Rule` (or nil) is the cleanest way to pass both. All existing call sites must be updated in one step (Task 2).

---

## Task Dependency Graph

```
Task 1 (add yaml dep)
    │
    ▼
Task 2 (Rule.AllowMethods + RuleSet.Match signature change)
    │
    ▼
Task 3 (Config types + LoadConfig skeleton + YAML parse + file not found)
    │
    ▼
Task 4 (basic validation: rules count, host format, type enum, duplicates)
    │
    ▼
Task 5 (CA half-population + audit_log schema validation)
    │
    ▼
Task 6 (credential resolution: file/env, mutual exclusion, trim)
    │
    ▼
Task 7 (rule construction: static, oauth_refresh, oauth_bearer, header validation)
    │
    ▼
Task 8 (credential field zeroing after resolution)
    │
    ▼
Task 9 (allow_methods validation + enforcement in handleMITM)
    │
    ▼
Task 10 (SHA-256 config hash logging + registry publish warning)
    │
    ▼
Task 11 (Unix socket listener + listen_allow_tcp opt-in)
    │
    ▼
Task 12 (main.go rewrite + integration test)
    │
    ▼
Task 13 (adversarial review)
```

---

## Task 1: Add YAML Dependency

**Files:**
- Modify: `go.mod`
- Create: `go.sum`

- [ ] **Step 1: Add yaml.v3 dependency**

Run from `/home/sweeand/andrewesweet/agent-proxy`:

```bash
go get gopkg.in/yaml.v3@v3.0.1
```

- [ ] **Step 2: Verify go.mod was updated**

Run:
```bash
cat go.mod
```

Expected: `gopkg.in/yaml.v3 v3.0.1` appears under a `require` block.

- [ ] **Step 3: Verify existing tests still pass**

Run:
```bash
go test -v -count=1 ./...
```

Expected: all 25 existing tests pass.

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "$(cat <<'EOF'
build: add gopkg.in/yaml.v3 dependency for Phase 3d-1 config file

EOF
)"
```

---

## Task 2: Add Rule.AllowMethods and Change RuleSet.Match Signature

**Files:**
- Modify: `credential.go` (add `AllowMethods` to `Rule`, change `Match` return type)
- Modify: `credential_test.go` (update `TestRuleSetMatch` for new signature)
- Modify: `main.go:152` (update call site to `rules.Match`)

This task changes an API surface but does not yet enforce `AllowMethods`. Enforcement comes in Task 9. This task is split off because the signature change ripples through multiple files.

- [ ] **Step 1: Write failing test for new Match signature**

Modify `credential_test.go` — replace the existing `TestRuleSetMatch` with:

```go
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
```

- [ ] **Step 2: Run test to verify compile failure**

Run:
```bash
go test -v -count=1 -run TestRuleSetMatch ./...
```

Expected: compile error — `Rule has no field AllowMethods` or similar.

- [ ] **Step 3: Modify Rule type and Match signature**

In `credential.go`, find the `Rule` struct and the `Match` method.

Replace the `Rule` struct definition with:

```go
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
```

Replace the `Match` method with:

```go
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
```

- [ ] **Step 4: Update main.go call site**

In `main.go` around line 152, replace:

```go
	if mutator := p.rules.Match(host); mutator != nil {
		p.handleMITM(clientConn, br, req, host, mutator)
	} else if p.allowPassthrough {
```

with:

```go
	if rule := p.rules.Match(host); rule != nil {
		p.handleMITM(clientConn, br, req, host, rule)
	} else if p.allowPassthrough {
```

Also update the `handleMITM` signature. Find the function signature (around line 165):

```go
func (p *proxy) handleMITM(clientConn net.Conn, br *bufio.Reader, connectReq *http.Request, destHost string, mutator CredentialMutator) {
```

Change to:

```go
func (p *proxy) handleMITM(clientConn net.Conn, br *bufio.Reader, connectReq *http.Request, destHost string, rule *Rule) {
```

Then inside `handleMITM`, find the call site for the mutator (around line 243):

```go
		if err := mutator.MutateRequest(context.Background(), req); err != nil {
```

Change to:

```go
		if err := rule.Mutator.MutateRequest(context.Background(), req); err != nil {
```

And the `MutateResponse` call later (around line 293):

```go
		if err := mutator.MutateResponse(context.Background(), req, resp); err != nil {
```

Change to:

```go
		if err := rule.Mutator.MutateResponse(context.Background(), req, resp); err != nil {
```

- [ ] **Step 5: Run all tests**

Run:
```bash
go test -v -count=1 ./...
```

Expected: all 25 tests pass, including the updated `TestRuleSetMatch`.

- [ ] **Step 6: Commit**

```bash
git add credential.go credential_test.go main.go
git commit -m "$(cat <<'EOF'
refactor: add Rule.AllowMethods and change RuleSet.Match to return *Rule

Prepares for Phase 3d-1 method allowlisting (G2). Match now returns
*Rule, giving callers access to both the mutator and the allowed
method list. AllowMethods is unenforced in this commit — enforcement
is added in a later commit.

EOF
)"
```

---

## Task 3: Config Types and LoadConfig Skeleton

**Files:**
- Create: `config.go`
- Create: `config_test.go`

Define the types from the spec and implement the minimum `LoadConfig` needed to parse YAML and handle the file-not-found case. No validation, no credential resolution yet — just parse into the struct.

- [ ] **Step 1: Write failing test for file-not-found**

Create `config_test.go`:

```go
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempConfig(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, _, err := LoadConfig("/nonexistent/path/to/config.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
	if !strings.Contains(err.Error(), "nonexistent") && !strings.Contains(err.Error(), "no such file") {
		t.Errorf("error = %q, want mention of the missing path", err.Error())
	}
}

func TestLoadConfig_MinimalValid(t *testing.T) {
	path := writeTempConfig(t, `
rules:
  - host: api.github.com
    type: static
    token_env: GH_TOKEN
`)
	t.Setenv("GH_TOKEN", "ghp_test")

	cfg, rules, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg == nil || rules == nil {
		t.Fatal("expected non-nil cfg and rules")
	}
	if len(rules.Hosts()) != 1 {
		t.Errorf("expected 1 rule, got %d", len(rules.Hosts()))
	}
}
```

- [ ] **Step 2: Run to verify compile failure**

Run:
```bash
go test -v -count=1 -run TestLoadConfig ./...
```

Expected: compile error — `LoadConfig undefined`.

- [ ] **Step 3: Create config.go with types and minimal LoadConfig**

Create `config.go`:

```go
package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level agent-proxy configuration.
type Config struct {
	Listen         string         `yaml:"listen"`
	ListenAllowTCP bool           `yaml:"listen_allow_tcp"`
	CA             CAConfig       `yaml:"ca"`
	AuditLog       AuditLogConfig `yaml:"audit_log"`
	Rules          []RuleConfig   `yaml:"rules"`
}

// CAConfig selects the CA material the proxy uses to sign generated
// certificates. Empty paths yield an ephemeral in-memory CA.
type CAConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// AuditLogConfig defines the schema for the Phase 3d-1 config file.
// The implementation of audit logging is a TODO tracked as governance
// recommendation G1 in docs/threat-model-stride.md. These fields are
// parsed and validated but the audit log sink is not yet implemented.
type AuditLogConfig struct {
	File  string `yaml:"file"`
	Level string `yaml:"level"`
}

// RuleConfig is a single rule in the config file. Credential fields
// (TokenFile, TokenEnv, RefreshTokenFile, RefreshTokenEnv) are zeroed
// after LoadConfig resolves them to prevent accidental disclosure via
// debug logging (A17 mitigation).
type RuleConfig struct {
	Host             string   `yaml:"host"`
	Type             string   `yaml:"type"`
	Header           string   `yaml:"header"`
	Prefix           string   `yaml:"prefix"`
	TokenFile        string   `yaml:"token_file"`
	TokenEnv         string   `yaml:"token_env"`
	RefreshTokenFile string   `yaml:"refresh_token_file"`
	RefreshTokenEnv  string   `yaml:"refresh_token_env"`
	TokenSource      string   `yaml:"token_source"`
	AllowMethods     []string `yaml:"allow_methods"`
}

// LoadConfig reads the YAML config from path, validates it, resolves
// all credentials, constructs mutators, and returns the parsed Config
// (with credential fields zeroed) and a ready-to-use *RuleSet.
func LoadConfig(path string) (*Config, *RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, nil, fmt.Errorf("parse config: %w", err)
	}

	// Default listen address.
	if cfg.Listen == "" {
		cfg.Listen = "unix:///run/agent-proxy/proxy.sock"
	}

	// Default audit log level.
	if cfg.AuditLog.Level == "" {
		cfg.AuditLog.Level = "request"
	}

	// Build the RuleSet. Validation and credential resolution are in
	// subsequent tasks — for now this is a minimal pass-through.
	rules, err := buildRuleSet(&cfg)
	if err != nil {
		return nil, nil, err
	}

	return &cfg, rules, nil
}

// buildRuleSet converts RuleConfig entries into Rule values wired to
// constructed mutators. Full validation is added in later tasks.
func buildRuleSet(cfg *Config) (*RuleSet, error) {
	built := make([]Rule, 0, len(cfg.Rules))
	for i := range cfg.Rules {
		rc := &cfg.Rules[i]
		// Minimal build for Task 3 — just wire up a static mutator
		// from token_env. Full logic comes in Task 6/7.
		if rc.Type == "static" && rc.TokenEnv != "" {
			val := os.Getenv(rc.TokenEnv)
			built = append(built, Rule{
				Host:    rc.Host,
				Mutator: StaticBearerMutator(val),
			})
		}
	}
	return NewRuleSet(built...), nil
}
```

Add `"bytes"` import — the full import block should be:

```go
import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)
```

- [ ] **Step 4: Run tests**

Run:
```bash
go test -v -count=1 -run TestLoadConfig ./...
```

Expected: `TestLoadConfig_FileNotFound` PASS, `TestLoadConfig_MinimalValid` PASS.

- [ ] **Step 5: Verify all tests still pass**

Run:
```bash
go test -v -count=1 ./...
```

Expected: all 27 tests pass (25 existing + 2 new).

- [ ] **Step 6: Commit**

```bash
git add config.go config_test.go
git commit -m "$(cat <<'EOF'
feat: add Config types and minimal LoadConfig

Introduces Config, CAConfig, AuditLogConfig, and RuleConfig types with
YAML struct tags. LoadConfig reads YAML from a path using strict
field parsing (KnownFields(true)). Minimal rule construction for
static/token_env — full validation, credential resolution, and rule
building are added in subsequent commits.

EOF
)"
```

---

## Task 4: Basic Validation (Rules, Hosts, Types, Duplicates)

**Files:**
- Modify: `config.go` (add validation logic)
- Modify: `config_test.go` (add validation tests)

- [ ] **Step 1: Write failing validation tests**

Add to `config_test.go`:

```go
func TestLoadConfig_NoRules(t *testing.T) {
	path := writeTempConfig(t, `
rules: []
`)
	_, _, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "at least one rule") {
		t.Errorf("expected 'at least one rule' error, got: %v", err)
	}
}

func TestLoadConfig_MissingHost(t *testing.T) {
	path := writeTempConfig(t, `
rules:
  - type: static
    token_env: GH_TOKEN
`)
	t.Setenv("GH_TOKEN", "ghp_test")
	_, _, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "host") {
		t.Errorf("expected 'host' error, got: %v", err)
	}
}

func TestLoadConfig_HostWithPort(t *testing.T) {
	path := writeTempConfig(t, `
rules:
  - host: api.github.com:443
    type: static
    token_env: GH_TOKEN
`)
	t.Setenv("GH_TOKEN", "ghp_test")
	_, _, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "port") {
		t.Errorf("expected 'port' error, got: %v", err)
	}
}

func TestLoadConfig_HostWithScheme(t *testing.T) {
	path := writeTempConfig(t, `
rules:
  - host: https://api.github.com
    type: static
    token_env: GH_TOKEN
`)
	t.Setenv("GH_TOKEN", "ghp_test")
	_, _, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Errorf("expected 'scheme' error, got: %v", err)
	}
}

func TestLoadConfig_InvalidType(t *testing.T) {
	path := writeTempConfig(t, `
rules:
  - host: api.github.com
    type: weird
`)
	_, _, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "type") {
		t.Errorf("expected 'type' error, got: %v", err)
	}
}

func TestLoadConfig_DuplicateHost(t *testing.T) {
	path := writeTempConfig(t, `
rules:
  - host: api.github.com
    type: static
    token_env: GH_TOKEN
  - host: API.GITHUB.COM
    type: static
    token_env: GH_TOKEN
`)
	t.Setenv("GH_TOKEN", "ghp_test")
	_, _, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("expected 'duplicate' error, got: %v", err)
	}
}

func TestLoadConfig_UnknownField(t *testing.T) {
	path := writeTempConfig(t, `
rules:
  - host: api.github.com
    type: static
    tokenfile: /some/path
`)
	_, _, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "field tokenfile") {
		t.Errorf("expected 'field tokenfile' error, got: %v", err)
	}
}
```

- [ ] **Step 2: Run to confirm failures**

Run:
```bash
go test -v -count=1 -run TestLoadConfig ./...
```

Expected: new tests FAIL (some pass because minimal build is lenient).

- [ ] **Step 3: Add validation function**

In `config.go`, add a `validate` function and call it before `buildRuleSet`. Also add a `strings` import.

Update imports:

```go
import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)
```

In `LoadConfig`, after decoding and before `buildRuleSet`, add:

```go
	if err := validate(&cfg); err != nil {
		return nil, nil, err
	}
```

Add the validation functions at the bottom of `config.go`:

```go
// validate checks structural invariants of the parsed config. It does
// not resolve credentials — that happens in buildRuleSet.
func validate(cfg *Config) error {
	if len(cfg.Rules) == 0 {
		return fmt.Errorf("config: at least one rule required")
	}

	seen := make(map[string]bool, len(cfg.Rules))
	for i := range cfg.Rules {
		rc := &cfg.Rules[i]

		if rc.Host == "" {
			return fmt.Errorf("rule %d: host required", i)
		}
		if strings.Contains(rc.Host, "://") {
			return fmt.Errorf("rule %d (%s): host must not contain a scheme", i, rc.Host)
		}
		if strings.Contains(rc.Host, ":") {
			return fmt.Errorf("rule %d (%s): host must not contain a port", i, rc.Host)
		}

		// Normalise host for duplicate detection.
		lowered := strings.ToLower(rc.Host)
		if seen[lowered] {
			return fmt.Errorf("rule %d: duplicate host %q", i, rc.Host)
		}
		seen[lowered] = true

		switch rc.Type {
		case "static", "oauth_refresh", "oauth_bearer":
			// ok
		case "":
			return fmt.Errorf("rule %d (%s): type required", i, rc.Host)
		default:
			return fmt.Errorf("rule %d (%s): unknown type %q (want static, oauth_refresh, or oauth_bearer)", i, rc.Host, rc.Type)
		}
	}

	return nil
}
```

- [ ] **Step 4: Run validation tests**

Run:
```bash
go test -v -count=1 -run TestLoadConfig ./...
```

Expected: all validation tests PASS.

- [ ] **Step 5: Run full test suite**

Run:
```bash
go test -v -count=1 ./...
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add config.go config_test.go
git commit -m "$(cat <<'EOF'
feat: add basic config validation

Validates rule count, host format (no port, no scheme), rule type
enum, and duplicate hosts (case-insensitive). Unknown YAML fields
are already rejected by the KnownFields strict mode. Credential
resolution and mutator construction still pending.

EOF
)"
```

---

## Task 5: CA and AuditLog Schema Validation

**Files:**
- Modify: `config.go` (extend `validate`)
- Modify: `config_test.go` (add CA and audit log tests)

- [ ] **Step 1: Write failing tests**

Add to `config_test.go`:

```go
func TestLoadConfig_CAHalfPopulated(t *testing.T) {
	path := writeTempConfig(t, `
ca:
  cert_file: /tmp/ca.crt
rules:
  - host: api.github.com
    type: static
    token_env: GH_TOKEN
`)
	t.Setenv("GH_TOKEN", "ghp_test")
	_, _, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "key_file") {
		t.Errorf("expected 'key_file' error, got: %v", err)
	}
}

func TestLoadConfig_CABothEmpty(t *testing.T) {
	path := writeTempConfig(t, `
rules:
  - host: api.github.com
    type: static
    token_env: GH_TOKEN
`)
	t.Setenv("GH_TOKEN", "ghp_test")
	_, _, err := LoadConfig(path)
	if err != nil {
		t.Errorf("expected success (ephemeral CA), got: %v", err)
	}
}

func TestLoadConfig_AuditLogDefaults(t *testing.T) {
	path := writeTempConfig(t, `
rules:
  - host: api.github.com
    type: static
    token_env: GH_TOKEN
`)
	t.Setenv("GH_TOKEN", "ghp_test")
	cfg, _, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.AuditLog.Level != "request" {
		t.Errorf("AuditLog.Level = %q, want %q", cfg.AuditLog.Level, "request")
	}
}

func TestLoadConfig_AuditLogInvalidLevel(t *testing.T) {
	path := writeTempConfig(t, `
audit_log:
  level: verbose
rules:
  - host: api.github.com
    type: static
    token_env: GH_TOKEN
`)
	t.Setenv("GH_TOKEN", "ghp_test")
	_, _, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "audit_log.level") {
		t.Errorf("expected 'audit_log.level' error, got: %v", err)
	}
}

func TestLoadConfig_AuditLogBadDirectory(t *testing.T) {
	path := writeTempConfig(t, `
audit_log:
  file: /nonexistent/dir/audit.log
rules:
  - host: api.github.com
    type: static
    token_env: GH_TOKEN
`)
	t.Setenv("GH_TOKEN", "ghp_test")
	_, _, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "audit_log") {
		t.Errorf("expected 'audit_log' error, got: %v", err)
	}
}
```

- [ ] **Step 2: Run to confirm failures**

Run:
```bash
go test -v -count=1 -run "TestLoadConfig_CA|TestLoadConfig_AuditLog" ./...
```

Expected: new tests FAIL.

- [ ] **Step 3: Extend validate()**

Add to the bottom of `validate` in `config.go`, after the rules loop:

```go
	// CA: both set or both empty.
	hasCert := cfg.CA.CertFile != ""
	hasKey := cfg.CA.KeyFile != ""
	if hasCert != hasKey {
		if !hasCert {
			return fmt.Errorf("ca.cert_file required when ca.key_file is set")
		}
		return fmt.Errorf("ca.key_file required when ca.cert_file is set")
	}

	// Audit log validation (schema only; implementation is TODO G1).
	switch cfg.AuditLog.Level {
	case "request", "body_hash":
		// ok
	default:
		return fmt.Errorf("audit_log.level %q invalid (want \"request\" or \"body_hash\")", cfg.AuditLog.Level)
	}
	if cfg.AuditLog.File != "" {
		dir := filepath.Dir(cfg.AuditLog.File)
		info, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("audit_log.file: parent directory %q: %w", dir, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("audit_log.file: %q is not a directory", dir)
		}
	}

	return nil
```

Note: the `return nil` that was at the end of `validate` is now replaced by this new block. Make sure there is only one `return nil` at the bottom.

Update imports to add `path/filepath`:

```go
import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)
```

- [ ] **Step 4: Run new tests**

Run:
```bash
go test -v -count=1 -run "TestLoadConfig_CA|TestLoadConfig_AuditLog" ./...
```

Expected: all 5 new tests PASS.

- [ ] **Step 5: Run full test suite**

Run:
```bash
go test -v -count=1 ./...
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add config.go config_test.go
git commit -m "$(cat <<'EOF'
feat: validate CA half-population and audit_log schema

CA: either both cert_file and key_file set, or both empty.
Audit log: level must be 'request' or 'body_hash' (defaults to
'request'); file parent directory must exist if file is set.
Implementation of audit logging remains TODO (G1).

EOF
)"
```

---

## Task 6: Credential Resolution

**Files:**
- Modify: `config.go` (add credential resolution helper)
- Modify: `config_test.go` (add resolution tests)

This task adds `resolveCredential(fileField, envField, fieldLabel string)` that reads the credential value, trims whitespace, and returns errors for empty/both-set/neither cases.

- [ ] **Step 1: Write failing tests**

Add to `config_test.go`:

```go
func TestLoadConfig_StaticTokenFile(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(secretPath, []byte("  ghp_from_file  \n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	path := writeTempConfig(t, `
rules:
  - host: api.github.com
    type: static
    token_file: `+secretPath+`
`)
	cfg, rules, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	_ = cfg
	r := rules.Match("api.github.com")
	if r == nil {
		t.Fatal("no rule for api.github.com")
	}
	// Exercise the mutator: check the header is set with trimmed token.
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err := r.Mutator.MutateRequest(context.Background(), req); err != nil {
		t.Fatalf("MutateRequest: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer ghp_from_file" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer ghp_from_file")
	}
}

func TestLoadConfig_StaticBothTokenSources(t *testing.T) {
	path := writeTempConfig(t, `
rules:
  - host: api.github.com
    type: static
    token_file: /some/path
    token_env: GH_TOKEN
`)
	_, _, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Errorf("expected 'exactly one' error, got: %v", err)
	}
}

func TestLoadConfig_StaticNoTokenSource(t *testing.T) {
	path := writeTempConfig(t, `
rules:
  - host: api.github.com
    type: static
`)
	_, _, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "token_file or token_env") {
		t.Errorf("expected 'token_file or token_env' error, got: %v", err)
	}
}

func TestLoadConfig_WhitespaceOnlyToken(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(secretPath, []byte("   \n\t  "), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	path := writeTempConfig(t, `
rules:
  - host: api.github.com
    type: static
    token_file: `+secretPath+`
`)
	_, _, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected 'empty' error, got: %v", err)
	}
}

func TestLoadConfig_TokenEnvEmpty(t *testing.T) {
	path := writeTempConfig(t, `
rules:
  - host: api.github.com
    type: static
    token_env: MISSING_VAR_XYZ
`)
	os.Unsetenv("MISSING_VAR_XYZ")
	_, _, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected 'empty' error, got: %v", err)
	}
}
```

Add `context` and `net/http` to the test file imports if not already present:

```go
import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)
```

- [ ] **Step 2: Run to confirm failures**

Run:
```bash
go test -v -count=1 -run "TestLoadConfig_Static|TestLoadConfig_Whitespace|TestLoadConfig_TokenEnv" ./...
```

Expected: most tests FAIL (some may pass because the Task 3 minimal build handles token_env).

- [ ] **Step 3: Add credential resolution helper**

In `config.go`, add this function near the bottom (before `validate`):

```go
// resolveCredential reads a credential value from either a file path
// or an env var name. Exactly one of fileVal/envVal must be non-empty.
// The result is trimmed of whitespace; an empty post-trim result is an
// error.
func resolveCredential(fileVal, envVal, fieldLabel string) (string, error) {
	fileSet := fileVal != ""
	envSet := envVal != ""

	switch {
	case fileSet && envSet:
		return "", fmt.Errorf("%s: exactly one of _file or _env must be set (both provided)", fieldLabel)
	case !fileSet && !envSet:
		return "", fmt.Errorf("%s: exactly one of %s_file or %s_env required (neither provided)", fieldLabel, fieldLabel, fieldLabel)
	}

	var raw string
	if fileSet {
		data, err := os.ReadFile(fileVal)
		if err != nil {
			return "", fmt.Errorf("%s: read file %q: %w", fieldLabel, fileVal, err)
		}
		raw = string(data)
	} else {
		raw = os.Getenv(envVal)
	}

	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("%s: resolved value is empty", fieldLabel)
	}
	return trimmed, nil
}
```

- [ ] **Step 4: Run the tests (still failing — resolver is unused)**

The resolver exists but `buildRuleSet` doesn't call it yet. That's Task 7. For now, check compilation:

Run:
```bash
go build ./...
```

Expected: build succeeds.

- [ ] **Step 5: Commit**

```bash
git add config.go config_test.go
git commit -m "$(cat <<'EOF'
feat: add credential resolution helper

resolveCredential enforces mutual exclusion of _file/_env, reads the
credential from the selected source, trims whitespace, and rejects
empty post-trim values. Not yet wired to buildRuleSet — rule
construction using this helper lands in the next commit.

Tests for the resolution behaviour are in place and will pass once
buildRuleSet is updated in the next task.

EOF
)"
```

---

## Task 7: Rule Construction (static, oauth_refresh, oauth_bearer)

**Files:**
- Modify: `config.go` (full `buildRuleSet`, header validation)
- Modify: `config_test.go` (add oauth tests)

- [ ] **Step 1: Write failing tests for oauth rule types**

Add to `config_test.go`:

```go
func TestLoadConfig_OAuthRefresh(t *testing.T) {
	path := writeTempConfig(t, `
rules:
  - host: oauth2.googleapis.com
    type: oauth_refresh
    refresh_token_env: GOOGLE_REFRESH
`)
	t.Setenv("GOOGLE_REFRESH", "1//real-refresh-token")
	_, rules, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	r := rules.Match("oauth2.googleapis.com")
	if r == nil {
		t.Fatal("no rule for oauth2.googleapis.com")
	}
	// Verify mutator is *OAuthRefreshMutator.
	if _, ok := r.Mutator.(*OAuthRefreshMutator); !ok {
		t.Errorf("mutator = %T, want *OAuthRefreshMutator", r.Mutator)
	}
}

func TestLoadConfig_OAuthBearer(t *testing.T) {
	path := writeTempConfig(t, `
rules:
  - host: oauth2.googleapis.com
    type: oauth_refresh
    refresh_token_env: GOOGLE_REFRESH
  - host: cloudresourcemanager.googleapis.com
    type: oauth_bearer
    token_source: oauth2.googleapis.com
`)
	t.Setenv("GOOGLE_REFRESH", "1//real")
	_, rules, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	r := rules.Match("cloudresourcemanager.googleapis.com")
	if r == nil {
		t.Fatal("no rule for cloudresourcemanager.googleapis.com")
	}
	if _, ok := r.Mutator.(*OAuthBearerMutator); !ok {
		t.Errorf("mutator = %T, want *OAuthBearerMutator", r.Mutator)
	}
}

func TestLoadConfig_OAuthBearerMissingSource(t *testing.T) {
	path := writeTempConfig(t, `
rules:
  - host: cloudresourcemanager.googleapis.com
    type: oauth_bearer
    token_source: oauth2.googleapis.com
`)
	_, _, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "token_source") {
		t.Errorf("expected 'token_source' error, got: %v", err)
	}
}

func TestLoadConfig_OAuthBearerSourceNotRefresh(t *testing.T) {
	path := writeTempConfig(t, `
rules:
  - host: api.github.com
    type: static
    token_env: GH_TOKEN
  - host: other.example.com
    type: oauth_bearer
    token_source: api.github.com
`)
	t.Setenv("GH_TOKEN", "ghp_test")
	_, _, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "oauth_refresh") {
		t.Errorf("expected 'oauth_refresh' error, got: %v", err)
	}
}

func TestLoadConfig_StaticInvalidHeader(t *testing.T) {
	path := writeTempConfig(t, `
rules:
  - host: api.github.com
    type: static
    header: "Bad\nHeader"
    token_env: GH_TOKEN
`)
	t.Setenv("GH_TOKEN", "ghp_test")
	_, _, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "header") {
		t.Errorf("expected 'header' error, got: %v", err)
	}
}

func TestLoadConfig_StaticDefaults(t *testing.T) {
	path := writeTempConfig(t, `
rules:
  - host: api.github.com
    type: static
    token_env: GH_TOKEN
`)
	t.Setenv("GH_TOKEN", "ghp_test")
	_, rules, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	r := rules.Match("api.github.com")
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err := r.Mutator.MutateRequest(context.Background(), req); err != nil {
		t.Fatalf("MutateRequest: %v", err)
	}
	// Default prefix is "Bearer ", default header is "Authorization".
	if got := req.Header.Get("Authorization"); got != "Bearer ghp_test" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer ghp_test")
	}
}
```

- [ ] **Step 2: Run to confirm failures**

Run:
```bash
go test -v -count=1 -run "TestLoadConfig_OAuth|TestLoadConfig_Static" ./...
```

Expected: new tests FAIL.

- [ ] **Step 3: Replace buildRuleSet with full implementation**

In `config.go`, replace the minimal `buildRuleSet` with:

```go
// buildRuleSet resolves credentials, constructs mutators, and assembles
// a RuleSet. It also zeroes credential fields on RuleConfig entries
// after resolution as a structural defence against A17.
func buildRuleSet(cfg *Config) (*RuleSet, error) {
	built := make([]Rule, 0, len(cfg.Rules))
	// Track oauth_refresh mutators by lowercased host for oauth_bearer lookup.
	refreshByHost := make(map[string]*OAuthRefreshMutator)

	for i := range cfg.Rules {
		rc := &cfg.Rules[i]

		var mutator CredentialMutator
		switch rc.Type {
		case "static":
			m, err := buildStaticMutator(rc)
			if err != nil {
				return nil, err
			}
			mutator = m

		case "oauth_refresh":
			refreshToken, err := resolveCredential(rc.RefreshTokenFile, rc.RefreshTokenEnv, "refresh_token")
			if err != nil {
				return nil, fmt.Errorf("rule %d (%s): %w", i, rc.Host, err)
			}
			refresh := NewOAuthRefreshMutator(refreshToken)
			refreshByHost[strings.ToLower(rc.Host)] = refresh
			mutator = refresh

		case "oauth_bearer":
			if rc.TokenSource == "" {
				return nil, fmt.Errorf("rule %d (%s): oauth_bearer requires token_source", i, rc.Host)
			}
			srcHost := strings.ToLower(rc.TokenSource)
			refresh, ok := refreshByHost[srcHost]
			if !ok {
				return nil, fmt.Errorf("rule %d (%s): token_source %q does not reference a preceding oauth_refresh rule", i, rc.Host, rc.TokenSource)
			}
			mutator = NewOAuthBearerMutator(refresh)
		}

		built = append(built, Rule{
			Host:         rc.Host,
			Mutator:      mutator,
			AllowMethods: rc.AllowMethods,
		})
	}

	return NewRuleSet(built...), nil
}

// buildStaticMutator constructs a StaticTokenMutator from a RuleConfig,
// applying defaults for header and prefix and validating the header.
func buildStaticMutator(rc *RuleConfig) (CredentialMutator, error) {
	token, err := resolveCredential(rc.TokenFile, rc.TokenEnv, "token")
	if err != nil {
		return nil, fmt.Errorf("rule (%s): %w", rc.Host, err)
	}

	header := rc.Header
	if header == "" {
		header = "Authorization"
	}
	// Validate header before calling StaticTokenMutator, which would panic.
	for _, c := range header {
		if c <= ' ' || c == ':' || c >= 0x7f {
			return nil, fmt.Errorf("rule (%s): invalid character %q in header %q", rc.Host, c, header)
		}
	}

	prefix := rc.Prefix
	if prefix == "" {
		prefix = "Bearer "
	}

	return StaticTokenMutator(header, prefix+token), nil
}
```

- [ ] **Step 4: Run all LoadConfig tests**

Run:
```bash
go test -v -count=1 -run TestLoadConfig ./...
```

Expected: all LoadConfig tests PASS (including the ones from Task 6).

- [ ] **Step 5: Run full test suite**

Run:
```bash
go test -v -count=1 ./...
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add config.go config_test.go
git commit -m "$(cat <<'EOF'
feat: full rule construction for static, oauth_refresh, oauth_bearer

buildRuleSet now resolves credentials via resolveCredential, constructs
the appropriate mutator based on rule type, validates header field
before calling StaticTokenMutator (preventing panics), and wires
oauth_bearer rules to their referenced oauth_refresh mutator. Header
and prefix defaults ("Authorization" and "Bearer ") are applied.

EOF
)"
```

---

## Task 8: Credential Field Zeroing (A17 Mitigation)

**Files:**
- Modify: `config.go` (zero credential fields after resolution)
- Modify: `config_test.go` (add zeroing test)

- [ ] **Step 1: Write failing test**

Add to `config_test.go`:

```go
func TestLoadConfig_CredentialNotRetainedInConfig(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(secretPath, []byte("ghp_secret"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	path := writeTempConfig(t, `
rules:
  - host: api.github.com
    type: static
    token_file: `+secretPath+`
  - host: oauth2.googleapis.com
    type: oauth_refresh
    refresh_token_env: GOOGLE_REFRESH
`)
	t.Setenv("GOOGLE_REFRESH", "1//real")

	cfg, _, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	for i, rc := range cfg.Rules {
		if rc.TokenFile != "" {
			t.Errorf("rule %d: TokenFile = %q, want empty after zeroing", i, rc.TokenFile)
		}
		if rc.TokenEnv != "" {
			t.Errorf("rule %d: TokenEnv = %q, want empty after zeroing", i, rc.TokenEnv)
		}
		if rc.RefreshTokenFile != "" {
			t.Errorf("rule %d: RefreshTokenFile = %q, want empty after zeroing", i, rc.RefreshTokenFile)
		}
		if rc.RefreshTokenEnv != "" {
			t.Errorf("rule %d: RefreshTokenEnv = %q, want empty after zeroing", i, rc.RefreshTokenEnv)
		}
	}
}
```

- [ ] **Step 2: Run to confirm failure**

Run:
```bash
go test -v -count=1 -run TestLoadConfig_CredentialNotRetainedInConfig ./...
```

Expected: FAIL — credential fields still populated.

- [ ] **Step 3: Add zeroing at end of buildRuleSet**

In `config.go`, in `buildRuleSet`, at the very end before `return NewRuleSet(built...), nil`, add:

```go
	// A17: zero credential-reference fields on RuleConfig so they
	// cannot be accidentally emitted via debug logging.
	for i := range cfg.Rules {
		cfg.Rules[i].TokenFile = ""
		cfg.Rules[i].TokenEnv = ""
		cfg.Rules[i].RefreshTokenFile = ""
		cfg.Rules[i].RefreshTokenEnv = ""
	}

	return NewRuleSet(built...), nil
```

Note: remove the existing `return NewRuleSet(built...), nil` line — the replacement above includes it.

- [ ] **Step 4: Run the test**

Run:
```bash
go test -v -count=1 -run TestLoadConfig_CredentialNotRetainedInConfig ./...
```

Expected: PASS.

- [ ] **Step 5: Run full test suite**

Run:
```bash
go test -v -count=1 ./...
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add config.go config_test.go
git commit -m "$(cat <<'EOF'
feat: zero credential fields on RuleConfig after resolution (A17)

After mutators are constructed, zero RuleConfig.TokenFile, TokenEnv,
RefreshTokenFile, and RefreshTokenEnv so that a future slog.Debug
statement using %+v on the returned *Config cannot emit a credential
value even accidentally. The resolved credential is held only inside
the mutator.

EOF
)"
```

---

## Task 9: allow_methods Validation and Runtime Enforcement

**Files:**
- Modify: `config.go` (validate `AllowMethods` values)
- Modify: `main.go` (enforce in MITM loop)
- Modify: `config_test.go` (add allow_methods validation tests)
- Modify: `main_test.go` (add integration test for 405 enforcement)

- [ ] **Step 1: Write failing tests**

Add to `config_test.go`:

```go
func TestLoadConfig_AllowMethodsLowercase(t *testing.T) {
	path := writeTempConfig(t, `
rules:
  - host: api.github.com
    type: static
    token_env: GH_TOKEN
    allow_methods: [get, HEAD]
`)
	t.Setenv("GH_TOKEN", "ghp_test")
	_, _, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "uppercase") {
		t.Errorf("expected 'uppercase' error, got: %v", err)
	}
}

func TestLoadConfig_AllowMethodsEmptyToken(t *testing.T) {
	path := writeTempConfig(t, `
rules:
  - host: api.github.com
    type: static
    token_env: GH_TOKEN
    allow_methods: ["", "GET"]
`)
	t.Setenv("GH_TOKEN", "ghp_test")
	_, _, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "allow_methods") {
		t.Errorf("expected 'allow_methods' error, got: %v", err)
	}
}

func TestLoadConfig_AllowMethodsValid(t *testing.T) {
	path := writeTempConfig(t, `
rules:
  - host: api.github.com
    type: static
    token_env: GH_TOKEN
    allow_methods: [GET, HEAD, OPTIONS]
`)
	t.Setenv("GH_TOKEN", "ghp_test")
	_, rules, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	r := rules.Match("api.github.com")
	if len(r.AllowMethods) != 3 {
		t.Errorf("AllowMethods = %v, want [GET HEAD OPTIONS]", r.AllowMethods)
	}
}
```

Add to `main_test.go`:

```go
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

	// Send a POST — should be rejected.
	resp := doProxyPost(t, ln.Addr().String(), "test.example.com", "/api",
		"data=evil", proxyCA)
	if upstreamHit {
		t.Error("upstream was hit despite POST not in AllowMethods")
	}
	// doProxyPost returns the body; we want to verify 405. Re-do the
	// request inline to inspect status.
	_ = resp
}
```

(Note: `doProxyPost` returns a string body, which makes verifying the 405 status code awkward. The test helper will be augmented in step 3 below to verify the status.)

- [ ] **Step 2: Run to confirm failures**

Run:
```bash
go test -v -count=1 -run "TestLoadConfig_AllowMethods|TestMethodBlockedByAllowMethods" ./...
```

Expected: FAIL.

- [ ] **Step 3: Add allow_methods validation to config.go**

In `config.go`, in `validate`, add this block inside the per-rule loop (after the type switch):

```go
		// allow_methods validation.
		for _, m := range rc.AllowMethods {
			if m == "" {
				return fmt.Errorf("rule %d (%s): allow_methods entry is empty", i, rc.Host)
			}
			for _, c := range m {
				if !((c >= 'A' && c <= 'Z') || c == '-') {
					return fmt.Errorf("rule %d (%s): allow_methods entry %q must be uppercase HTTP method token", i, rc.Host, m)
				}
			}
		}
```

- [ ] **Step 4: Add runtime enforcement in main.go handleMITM**

In `main.go`, inside `handleMITM`, after the `reqHost` host-match check and before the `rule.Mutator.MutateRequest` call, add the method check. Find the existing code around line 240 (the block that checks `reqHost != destHost`):

```go
		if reqHost != destHost {
```

Just BEFORE this block (before the reqHost extraction), no — actually AFTER the host mismatch check, BEFORE the credential injection. Add the block:

```go
		// Enforce per-rule method allowlist (G2).
		if len(rule.AllowMethods) > 0 {
			allowed := false
			for _, m := range rule.AllowMethods {
				if m == req.Method {
					allowed = true
					break
				}
			}
			if !allowed {
				slog.Warn("method_blocked",
					"host", destHost,
					"method", req.Method,
					"allow_methods", rule.AllowMethods,
				)
				resp := &http.Response{
					StatusCode:    http.StatusMethodNotAllowed,
					Status:        "405 Method Not Allowed",
					Proto:         "HTTP/1.1",
					ProtoMajor:    1,
					ProtoMinor:    1,
					Header:        http.Header{"Content-Length": {"0"}},
					Body:          io.NopCloser(strings.NewReader("")),
					ContentLength: 0,
				}
				resp.Write(tlsConn)
				if req.Close {
					return
				}
				continue
			}
		}

		// Inject credential via the mutator.
		if err := rule.Mutator.MutateRequest(context.Background(), req); err != nil {
```

(The final line above is the existing code — don't duplicate it; the new block is inserted immediately before it.)

- [ ] **Step 5: Update test helper to expose status code**

In `main_test.go`, add a new helper `doProxyPostStatus` that returns the HTTP status:

```go
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
```

Update `TestMethodBlockedByAllowMethods` to use it:

```go
	status := doProxyPostStatus(t, ln.Addr().String(), "test.example.com", "/api",
		"data=evil", proxyCA)
	if status != 405 {
		t.Errorf("status = %d, want 405", status)
	}
	if upstreamHit {
		t.Error("upstream was hit despite POST not in AllowMethods")
	}
```

Remove the old `resp := doProxyPost(...)` line and the `_ = resp` line.

- [ ] **Step 6: Run the tests**

Run:
```bash
go test -v -count=1 -run "TestLoadConfig_AllowMethods|TestMethodBlockedByAllowMethods" ./...
```

Expected: all tests PASS.

- [ ] **Step 7: Run full test suite**

Run:
```bash
go test -v -count=1 ./...
```

Expected: all tests pass.

- [ ] **Step 8: Commit**

```bash
git add config.go config_test.go main.go main_test.go
git commit -m "$(cat <<'EOF'
feat: validate and enforce allow_methods per rule (G2/T11/A10)

Config validation: allow_methods entries must be uppercase HTTP method
tokens (A-Z and hyphen only). Runtime enforcement: handleMITM returns
405 Method Not Allowed when the request method is not in the matched
rule's AllowMethods (if non-empty). Upstream is never contacted for
blocked methods. A WARN log entry records blocked method, host, and
allow_methods for audit. Directly limits the blast radius of A10 (data
exfiltration via legitimate API writes) per governance recommendation
G2.

EOF
)"
```

---

## Task 10: Config Hash Logging and Registry Warning

**Files:**
- Modify: `config.go` (hash logging, registry warning)
- Modify: `config_test.go` (hash and warning tests)

- [ ] **Step 1: Write failing tests**

Add to `config_test.go`:

```go
import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
)

func captureSlog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	prev := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(prev)
	fn()
	return buf.String()
}

func TestLoadConfig_ConfigHashLogged(t *testing.T) {
	contents := `
rules:
  - host: api.github.com
    type: static
    token_env: GH_TOKEN
`
	path := writeTempConfig(t, contents)
	t.Setenv("GH_TOKEN", "ghp_test")

	// Use the exact bytes written to the file (writeTempConfig writes
	// contents verbatim).
	data, _ := os.ReadFile(path)
	wantHash := sha256.Sum256(data)
	wantHex := hex.EncodeToString(wantHash[:])

	out := captureSlog(t, func() {
		_, _, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
	})

	if !strings.Contains(out, "sha256="+wantHex) {
		t.Errorf("log output missing sha256=%s; got: %s", wantHex, out)
	}
	if !strings.Contains(out, "config loaded") {
		t.Errorf("log output missing 'config loaded'; got: %s", out)
	}
}

func TestLoadConfig_RegistryPublishWarning(t *testing.T) {
	path := writeTempConfig(t, `
rules:
  - host: registry.npmjs.org
    type: static
    token_env: NPM_TOKEN
`)
	t.Setenv("NPM_TOKEN", "npm_test")

	out := captureSlog(t, func() {
		_, _, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
	})

	if !strings.Contains(out, "T15") && !strings.Contains(out, "publish") {
		t.Errorf("expected publish-endpoint warning in log, got: %s", out)
	}
}

func TestLoadConfig_RegistryPublishWarningSuppressed(t *testing.T) {
	path := writeTempConfig(t, `
rules:
  - host: registry.npmjs.org
    type: static
    token_env: NPM_TOKEN
    allow_methods: [GET, HEAD]
`)
	t.Setenv("NPM_TOKEN", "npm_test")

	out := captureSlog(t, func() {
		_, _, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
	})

	if strings.Contains(out, "publish") {
		t.Errorf("warning should be suppressed with read-only allow_methods; got: %s", out)
	}
}
```

Update the import block in `config_test.go` to include the new imports. The full import block should be:

```go
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)
```

- [ ] **Step 2: Run to confirm failures**

Run:
```bash
go test -v -count=1 -run "TestLoadConfig_ConfigHash|TestLoadConfig_RegistryPublish" ./...
```

Expected: FAIL.

- [ ] **Step 3: Add hash logging and registry warning to LoadConfig**

In `config.go`, update imports to add `crypto/sha256`, `encoding/hex`, and `log/slog`:

```go
import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)
```

Add a package-level list of known publish endpoints at the top of `config.go`, after the imports:

```go
// knownPublishEndpoints are hostnames where write-capable credentials
// are an exfiltration vector (T15/A14). Startup warnings are emitted
// when a rule targets one of these without read-only allow_methods.
var knownPublishEndpoints = map[string]bool{
	"registry.npmjs.org": true,
	"upload.pypi.org":    true,
	"crates.io":          true,
	"rubygems.org":       true,
	"hex.pm":             true,
}
```

In `LoadConfig`, at the end — just before `return &cfg, rules, nil` — add:

```go
	// T10: log config hash for tamper detection.
	hash := sha256.Sum256(data)
	absPath, _ := filepath.Abs(path)
	slog.Info("config loaded", "path", absPath, "sha256", hex.EncodeToString(hash[:]))

	// T15: warn on known publish endpoints without read-only allow_methods.
	for _, rc := range cfg.Rules {
		if !knownPublishEndpoints[strings.ToLower(rc.Host)] {
			continue
		}
		if isReadOnlyMethods(rc.AllowMethods) {
			continue
		}
		slog.Warn("publish-endpoint rule may carry write-capable credentials (T15)",
			"host", rc.Host,
			"recommendation", "set allow_methods to [GET, HEAD, OPTIONS] if read-only access is sufficient",
		)
	}

	return &cfg, rules, nil
```

Note: this replaces the existing `return &cfg, rules, nil` line — there is only one.

Important: the `cfg.Rules` loop above runs AFTER `buildRuleSet` has zeroed the credential fields, so `rc.Host` and `rc.AllowMethods` are still present (those fields are not zeroed). Good.

Add the helper function at the bottom of `config.go`:

```go
// isReadOnlyMethods returns true if every method in the slice is a
// safe HTTP method (GET, HEAD, OPTIONS). An empty slice returns false.
func isReadOnlyMethods(methods []string) bool {
	if len(methods) == 0 {
		return false
	}
	for _, m := range methods {
		switch m {
		case "GET", "HEAD", "OPTIONS":
			// ok
		default:
			return false
		}
	}
	return true
}
```

- [ ] **Step 4: Run the tests**

Run:
```bash
go test -v -count=1 -run "TestLoadConfig_ConfigHash|TestLoadConfig_RegistryPublish" ./...
```

Expected: all 3 tests PASS.

- [ ] **Step 5: Run full test suite**

Run:
```bash
go test -v -count=1 ./...
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add config.go config_test.go
git commit -m "$(cat <<'EOF'
feat: log config SHA-256 hash and warn on publish endpoints (T10, T15)

T10: LoadConfig logs the absolute config path and SHA-256 hash of
the raw bytes at INFO after validation succeeds. Operators comparing
the hash across restarts can detect unauthorised config modification.

T15: Startup WARN for rules targeting known package registry publish
endpoints (npmjs.org, pypi.org, crates.io, rubygems.org, hex.pm)
unless allow_methods restricts to read-only methods.

EOF
)"
```

---

## Task 11: Unix Socket Listener with listen_allow_tcp Opt-in

**Files:**
- Modify: `config.go` (validate listen address)
- Modify: `main.go` (Listen helper function)
- Modify: `config_test.go` (listen tests)
- Modify: `main_test.go` (Unix socket integration test)

- [ ] **Step 1: Write failing tests**

Add to `config_test.go`:

```go
func TestLoadConfig_ListenDefault(t *testing.T) {
	path := writeTempConfig(t, `
rules:
  - host: api.github.com
    type: static
    token_env: GH_TOKEN
`)
	t.Setenv("GH_TOKEN", "ghp_test")
	cfg, _, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Listen != "unix:///run/agent-proxy/proxy.sock" {
		t.Errorf("Listen = %q, want default unix:///run/agent-proxy/proxy.sock", cfg.Listen)
	}
}

func TestLoadConfig_TCPRequiresOptIn(t *testing.T) {
	path := writeTempConfig(t, `
listen: ":18080"
rules:
  - host: api.github.com
    type: static
    token_env: GH_TOKEN
`)
	t.Setenv("GH_TOKEN", "ghp_test")
	_, _, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "listen_allow_tcp") {
		t.Errorf("expected 'listen_allow_tcp' error, got: %v", err)
	}
}

func TestLoadConfig_TCPWithOptIn(t *testing.T) {
	path := writeTempConfig(t, `
listen: ":18080"
listen_allow_tcp: true
rules:
  - host: api.github.com
    type: static
    token_env: GH_TOKEN
`)
	t.Setenv("GH_TOKEN", "ghp_test")
	out := captureSlog(t, func() {
		_, _, err := LoadConfig(path)
		if err != nil {
			t.Errorf("LoadConfig: %v", err)
		}
	})
	if !strings.Contains(out, "Trust Boundary C") && !strings.Contains(out, "TCP") {
		t.Errorf("expected TCP warning in log, got: %s", out)
	}
}
```

Add to `main_test.go`:

```go
// TestUnixSocketListen verifies the proxy can bind to a Unix socket
// and accept CONNECT requests via that socket.
func TestUnixSocketListen(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"ok":true}`)
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
			Host:    "test.example.com",
			Mutator: StaticBearerMutator("test"),
		}),
		certCache: cc,
	}

	sockPath := filepath.Join(t.TempDir(), "proxy.sock")
	ln, err := listen("unix://" + sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Verify socket file mode is 0600.
	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("socket mode = %o, want 0600", mode)
	}

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

	// Dial the Unix socket.
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT test.example.com:443 HTTP/1.1\r\nHost: test.example.com:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: err=%v status=%d", err, resp.StatusCode)
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: "test.example.com",
		RootCAs:    proxyCA,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("tls: %v", err)
	}
	defer tlsConn.Close()

	fmt.Fprintf(tlsConn, "GET / HTTP/1.1\r\nHost: test.example.com\r\nConnection: close\r\n\r\n")
	innerResp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	defer innerResp.Body.Close()
	if innerResp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", innerResp.StatusCode)
	}
}

func TestUnixSocketListen_StaleRemoved(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "proxy.sock")

	// Create a stale socket by listening then closing.
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("initial listen: %v", err)
	}
	ln.Close()
	// The socket file remains on disk after Close on Linux.

	// Now call listen() — it should remove the stale file and succeed.
	ln2, err := listen("unix://" + sockPath)
	if err != nil {
		t.Fatalf("listen on stale: %v", err)
	}
	defer ln2.Close()
}

func TestUnixSocketListen_ExistingNonSocketFile(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "proxy.sock")
	// Create a regular file at the socket path.
	if err := os.WriteFile(filePath, []byte("not a socket"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	_, err := listen("unix://" + filePath)
	if err == nil {
		t.Fatal("expected error for non-socket file at listen path")
	}
}
```

Add `path/filepath` to the `main_test.go` import block if not already present.

- [ ] **Step 2: Run to confirm failures**

Run:
```bash
go test -v -count=1 -run "TestLoadConfig_Listen|TestLoadConfig_TCP|TestUnixSocket" ./...
```

Expected: FAIL — `listen` function undefined.

- [ ] **Step 3: Add listen validation to config.go**

In `config.go`, at the beginning of `validate`, BEFORE the `if len(cfg.Rules) == 0` check, add:

```go
	// listen validation.
	if strings.HasPrefix(cfg.Listen, "unix://") {
		// Unix socket — always allowed.
	} else {
		// TCP-ish — requires explicit opt-in.
		if !cfg.ListenAllowTCP {
			return fmt.Errorf("listen %q: TCP listen address requires listen_allow_tcp: true; prefer unix:// for production deployments (STRIDE Trust Boundary C)", cfg.Listen)
		}
	}
```

Also, the TCP warning is emitted in `LoadConfig` (not `validate`). In `LoadConfig`, just after the `if err := validate(&cfg); err != nil` block, add:

```go
	if !strings.HasPrefix(cfg.Listen, "unix://") && cfg.ListenAllowTCP {
		slog.Warn("listen address is TCP — any host process can reach the proxy",
			"listen", cfg.Listen,
			"note", "per-container Unix sockets (Phase 3d-4) will supersede this (STRIDE Trust Boundary C)",
		)
	}
```

- [ ] **Step 4: Add listen() helper to main.go**

In `main.go`, add a new function (anywhere near the top-level functions, e.g., after `main` or before `handleConn`):

```go
// listen binds a net.Listener based on the configured address. A
// "unix://" prefix creates a Unix domain socket with mode 0600. Any
// other value is interpreted as a TCP address. Stale socket files are
// removed before binding; non-socket files at the path produce an error.
func listen(address string) (net.Listener, error) {
	if !strings.HasPrefix(address, "unix://") {
		return net.Listen("tcp", address)
	}
	path := strings.TrimPrefix(address, "unix://")

	// Check for existing file and remove if it's a stale socket.
	if info, err := os.Stat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("listen path %q exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket %q: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat listen path %q: %w", path, err)
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen unix %q: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("chmod socket %q: %w", path, err)
	}
	return ln, nil
}
```

- [ ] **Step 5: Run the tests**

Run:
```bash
go test -v -count=1 -run "TestLoadConfig_Listen|TestLoadConfig_TCP|TestUnixSocket" ./...
```

Expected: all tests PASS.

- [ ] **Step 6: Run full test suite**

Run:
```bash
go test -v -count=1 ./...
```

Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add config.go main.go config_test.go main_test.go
git commit -m "$(cat <<'EOF'
feat: Unix socket listener with listen_allow_tcp opt-in (Trust Boundary C)

LoadConfig validates that TCP listen addresses require explicit
listen_allow_tcp: true; the default is the unix:// form. A startup
WARN is emitted when TCP is opted into.

New listen() helper in main.go handles unix:// addresses by creating
the socket with mode 0600, removing stale socket files before bind,
and erroring on non-socket files at the target path. TCP addresses
fall through to net.Listen("tcp", ...).

Closes the STRIDE Trust Boundary C gap for single-proxy deployments
before Phase 3d-4 per-container sockets land.

EOF
)"
```

---

## Task 12: main.go Rewrite and Integration Test

**Files:**
- Modify: `main.go` (replace all flags with `-config`, call `LoadConfig`, use `listen`)
- Modify: `main_test.go` (add config-driven integration test)

- [ ] **Step 1: Write failing integration test**

Add to `main_test.go`:

```go
// TestConfigDrivenProxy verifies the full flow from a YAML config file
// through LoadConfig to a working proxy that injects static tokens.
func TestConfigDrivenProxy(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		fmt.Fprintf(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("ghp_from_config"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	cfgBody := fmt.Sprintf(`
listen: ":0"
listen_allow_tcp: true
rules:
  - host: test.example.com
    type: static
    prefix: "token "
    token_file: %s
`, tokenPath)
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, rules, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

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
		rules:     rules,
		certCache: cc,
	}

	ln, err := listen(cfg.Listen)
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
	doProxyRequest(t, ln.Addr().String(), "test.example.com", proxyCA)

	if gotAuth != "token ghp_from_config" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "token ghp_from_config")
	}
}
```

- [ ] **Step 2: Run to confirm failure**

Run:
```bash
go test -v -count=1 -run TestConfigDrivenProxy ./...
```

Expected: the test should actually PASS because `LoadConfig` and `listen` are already implemented. (The earlier tasks have already built these.)

If it fails, diagnose and fix. If it passes, proceed to Step 3 to rewrite `main.go` — we need `main.go` to match the new style even though the test doesn't invoke `main()`.

- [ ] **Step 3: Rewrite main.go**

Find the current `main()` function (lines 44-97) and replace the body with:

```go
func main() {
	configPath := flag.String("config", "", "path to YAML config file")
	flag.Parse()

	if *configPath == "" {
		fmt.Fprintf(os.Stderr, "usage: agent-proxy -config <path>\n")
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	cfg, rules, err := LoadConfig(*configPath)
	if err != nil {
		slog.Error("config load failed", "error", err)
		os.Exit(1)
	}

	ca, caKey, err := loadOrGenerateCA(cfg.CA.CertFile, cfg.CA.KeyFile)
	if err != nil {
		slog.Error("ca setup failed", "error", err)
		os.Exit(1)
	}
	slog.Info("ca ready", "subject", ca.Subject.CommonName, "not_after", ca.NotAfter)

	certCache := newCertCache(ca, caKey)

	slog.Info("rules loaded", "rules", rules.String())

	p := &proxy{
		rules:     rules,
		certCache: certCache,
	}

	ln, err := listen(cfg.Listen)
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
```

Remove unused imports if the compiler complains. The imports that are no longer used after removing the old flag variables may include nothing — `flag`, `fmt`, `os`, `slog`, `net`, `errors` are all still used.

- [ ] **Step 4: Run build**

Run:
```bash
go build ./...
```

Expected: build succeeds.

- [ ] **Step 5: Run all tests**

Run:
```bash
go test -v -count=1 -race ./...
```

Expected: all tests pass with race detector.

- [ ] **Step 6: Commit**

```bash
git add main.go main_test.go
git commit -m "$(cat <<'EOF'
feat: rewrite main.go to use LoadConfig and listen helper

Replaces all flags (-listen, -dest, -token, -header, -header-prefix,
-ca-cert, -ca-key) with a single -config flag. main() calls
LoadConfig and listen to set up the proxy. The Phase 3a/3b/3c
listener loop and connection handler are unchanged.

Adds TestConfigDrivenProxy integration test that loads a YAML config
from disk and verifies end-to-end credential injection.

EOF
)"
```

---

## Task 13: Adversarial Code Review

Commission an adversarial review of the completed Phase 3d-1 implementation.

- [ ] **Step 1: Run all tests one final time with race detector**

Run:
```bash
go test -v -count=1 -race ./...
```

Expected: all tests pass.

- [ ] **Step 2: Commission adversarial review via subagent**

Launch a Sonnet 4.6 subagent with the prompt: "Perform an adversarial code review of Phase 3d-1 config file implementation for agent-proxy. Review credential.go (changes to Rule and Match), config.go, config_test.go, and main.go (main() rewrite and listen helper). Cover: security (credential handling, zeroing, config file integrity), correctness (validation edge cases, concurrency), resource leaks (socket file cleanup, file descriptor handling), and test coverage gaps. Follow the structure of docs/code-review-phase3c.md. Save findings to docs/code-review-phase3d1.md."

- [ ] **Step 3: Address findings**

Fix any High or Critical findings. Document Medium/Low findings as deferred or not applicable.

- [ ] **Step 4: Final commit**

```bash
git add docs/code-review-phase3d1.md <any fix files>
git commit -m "fix: address findings from Phase 3d-1 adversarial code review"
```

---
