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
