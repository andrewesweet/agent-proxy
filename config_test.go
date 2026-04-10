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
