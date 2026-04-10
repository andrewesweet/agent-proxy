package main

import (
	"context"
	"net/http"
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
	// No need to set GH_TOKEN — validation fails on missing host
	// before credential resolution is attempted.
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
	if got := req.Header.Get("Authorization"); got != "Bearer ghp_test" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer ghp_test")
	}
}

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
