package main

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

	if !strings.HasPrefix(cfg.Listen, "unix://") && cfg.ListenAllowTCP {
		slog.Warn("listen address is TCP — any host process can reach the proxy",
			"listen", cfg.Listen,
			"note", "per-container Unix sockets (Phase 3d-4) will supersede this (STRIDE Trust Boundary C)",
		)
	}

	// Build the RuleSet. Validation and credential resolution are in
	// subsequent tasks — for now this is a minimal pass-through.
	rules, err := buildRuleSet(&cfg)
	if err != nil {
		return nil, nil, err
	}

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
}

// validate checks structural invariants of the parsed config. It does
// not resolve credentials — that happens in buildRuleSet.
func validate(cfg *Config) error {
	// listen validation.
	if strings.HasPrefix(cfg.Listen, "unix://") {
		// Unix socket — always allowed.
	} else {
		// TCP — requires explicit opt-in.
		if !cfg.ListenAllowTCP {
			return fmt.Errorf("listen %q: TCP listen address requires listen_allow_tcp: true; prefer unix:// for production deployments (STRIDE Trust Boundary C)", cfg.Listen)
		}
	}

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

		// allow_methods validation: uppercase ASCII letters only.
		for _, m := range rc.AllowMethods {
			if m == "" {
				return fmt.Errorf("rule %d (%s): allow_methods entry is empty", i, rc.Host)
			}
			for _, c := range m {
				if c < 'A' || c > 'Z' {
					return fmt.Errorf("rule %d (%s): allow_methods entry %q must be uppercase HTTP method token (A-Z only)", i, rc.Host, m)
				}
			}
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

// buildRuleSet resolves credentials, constructs mutators, and assembles
// a RuleSet.
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

	// A17: zero credential-reference fields on RuleConfig so they
	// cannot be accidentally emitted via debug logging.
	for i := range cfg.Rules {
		cfg.Rules[i].TokenFile = ""
		cfg.Rules[i].TokenEnv = ""
		cfg.Rules[i].RefreshTokenFile = ""
		cfg.Rules[i].RefreshTokenEnv = ""
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
