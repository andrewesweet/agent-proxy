package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

	if err := validate(&cfg); err != nil {
		return nil, nil, err
	}

	// Build the RuleSet. Validation and credential resolution are in
	// subsequent tasks — for now this is a minimal pass-through.
	rules, err := buildRuleSet(&cfg)
	if err != nil {
		return nil, nil, err
	}

	return &cfg, rules, nil
}

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
}

// buildRuleSet converts RuleConfig entries into Rule values wired to
// constructed mutators. Full validation is added in later tasks.
func buildRuleSet(cfg *Config) (*RuleSet, error) {
	built := make([]Rule, 0, len(cfg.Rules))
	for i := range cfg.Rules {
		rc := &cfg.Rules[i]
		// Minimal build for Task 3 — just wire up a static mutator
		// from token_env. Full logic comes in Task 6.
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
