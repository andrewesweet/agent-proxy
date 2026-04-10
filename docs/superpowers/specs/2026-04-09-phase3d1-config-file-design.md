# Phase 3d-1: YAML Configuration File

**Date:** 2026-04-09
**Status:** Approved
**Scope:** Replace CLI flags with YAML config supporting multiple rules and secure credential resolution

---

## Goal

Replace the single-destination CLI flag interface with a YAML config file
that supports multiple rules with different mutator types, secure credential
resolution (file or env var, never inline), and validation at startup.

## Config File Schema

```yaml
# Listen address. Unix socket (unix://) is the default and recommended form
# — it restricts reachability to processes with filesystem access to the
# socket path. TCP requires explicit opt-in via listen_allow_tcp: true
# because a TCP listener is reachable from any process on the host
# (STRIDE Trust Boundary C).
listen: "unix:///run/agent-proxy/proxy.sock"
# listen: ":18080"          # TCP form — requires listen_allow_tcp: true
# listen_allow_tcp: false   # must be true to use a TCP listen address

ca:
  cert_file: ""     # path to CA cert PEM (ephemeral if empty)
  key_file: ""      # path to CA key PEM (ephemeral if empty)

# Audit log configuration (schema defined; implementation TODO — see
# governance recommendation G1 in docs/threat-model-stride.md).
audit_log:
  file: ""          # append-only audit log path; empty = stderr (journal)
  level: "request"  # "request" or "body_hash"

rules:
  # Static token injection (GitHub PAT) — read-only
  - host: api.github.com
    type: static
    header: Authorization           # default if omitted
    prefix: "token "                # prepended to token value, default "Bearer "
    token_file: "/run/secrets/gh"   # prod: systemd LoadCredential → tmpfs
    # token_env: GH_TOKEN           # dev alternative
    allow_methods: [GET, HEAD, OPTIONS]  # restrict to read-only methods

  # WARNING: publish-capable credentials are an exfiltration vector (T15).
  # Restrict with allow_methods if read-only access is sufficient.
  # - host: registry.npmjs.org
  #   type: static
  #   token_file: "/run/secrets/npm"
  #   allow_methods: [GET, HEAD]    # omit only if publish is intentionally needed

  # OAuth refresh token exchange (Google ADC)
  - host: oauth2.googleapis.com
    type: oauth_refresh
    refresh_token_file: "/run/secrets/google-refresh"
    # refresh_token_env: GOOGLE_REFRESH_TOKEN

  # OAuth bearer injection (Google API hosts) — read-only
  - host: cloudresourcemanager.googleapis.com
    type: oauth_bearer
    token_source: oauth2.googleapis.com
    allow_methods: [GET, HEAD, OPTIONS]

  - host: aiplatform.googleapis.com
    type: oauth_bearer
    token_source: oauth2.googleapis.com
```

## Credential Resolution

Every credential has two resolution variants:
- `_file` — read contents from a file path at startup
- `_env` — read from a named environment variable at startup

Rules:
- Exactly one of the two must be set. Error if both. Error if neither.
- No inline credential values exist in the schema. There is no `token:`
  field — nothing to accidentally commit to source control.
- Resolution happens once at startup. The proxy reads all secrets into
  memory, validates them, and discards the file/env references.
- For production: use systemd `LoadCredential` to place secrets on tmpfs
  (`0400`, owned by proxy UID). The config file references the
  `$CREDENTIALS_DIRECTORY/<name>` path via `_file`.
- For dev: use `_env` to read from environment variables.

### Credential Field Zeroing (A17 mitigation)

After resolution, credential values are stored **only** inside the
constructed mutator objects. They are never retained on `RuleConfig` or
`Config` structs. Immediately after the mutator is constructed, the
following `RuleConfig` fields are zeroed (set to empty string):
`TokenFile`, `TokenEnv`, `RefreshTokenFile`, `RefreshTokenEnv`.

This is a structural defence against A17 (debug log credential leakage):
a future `slog.Debug("config", "cfg", cfg)` or `%+v` statement on the
returned `*Config` cannot emit a credential value even accidentally,
because the fields are empty by the time `LoadConfig` returns. The
resolved credential value is held only inside the mutator, which does
not implement `fmt.Stringer` or `slog.LogValuer`.

A test `TestLoadConfig_CredentialNotRetainedInConfig` verifies this
invariant.

## Config Types

```go
type Config struct {
    Listen          string         `yaml:"listen"`
    ListenAllowTCP  bool           `yaml:"listen_allow_tcp"`
    CA              CAConfig       `yaml:"ca"`
    AuditLog        AuditLogConfig `yaml:"audit_log"`
    Rules           []RuleConfig   `yaml:"rules"`
}

type CAConfig struct {
    CertFile string `yaml:"cert_file"`
    KeyFile  string `yaml:"key_file"`
}

// AuditLogConfig anchors the schema for the Phase 3d-1 config file.
// The implementation of audit logging is a TODO — see governance
// recommendation G1 in docs/threat-model-stride.md. These fields are
// parsed and validated in Phase 3d-1 but the audit log sink itself is
// implemented in a subsequent phase.
type AuditLogConfig struct {
    File  string `yaml:"file"`  // append-only path; empty = stderr
    Level string `yaml:"level"` // "request" (default) or "body_hash"
}

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
    AllowMethods     []string `yaml:"allow_methods"` // nil = all methods
}
```

## Validation (fail fast at startup)

1. `listen` defaults to `"unix:///run/agent-proxy/proxy.sock"` if empty.
2. At least one rule required.
3. Each rule: `host` required (bare hostname — no port, no scheme;
   error if `host` contains `:` or `://`). `type` must be `static`,
   `oauth_refresh`, or `oauth_bearer`.
4. `static`: exactly one of `token_file`/`token_env` required. Resolve
   the value immediately. Trim whitespace from resolved value. Error
   if result is empty. Validate `header` against HTTP header name
   rules before constructing the mutator (no panics). `header`
   defaults to `"Authorization"`. `prefix` defaults to `"Bearer "`.
5. `oauth_refresh`: exactly one of `refresh_token_file`/`refresh_token_env`
   required. Same resolution and trim/empty check.
6. `oauth_bearer`: `token_source` required. Lookup uses case-insensitive
   (lowercased) exact match against the `host` field of a previously
   processed rule with `type: oauth_refresh`. Error message names both
   the bearer rule host and the missing/invalid source host.
   `oauth_bearer` hard-codes `Authorization: Bearer` — this is
   deliberate (Google APIs require it) and not configurable.
7. Duplicate hosts are an error. Comparison is case-insensitive
   (lowercased), consistent with `NewRuleSet`.
8. `ca`: if exactly one of `cert_file`/`key_file` is set, error naming
   the missing field. Both empty = ephemeral CA. Both set = load from
   files.
9. Unknown YAML fields are rejected (strict parsing). This prevents
   silent misconfiguration from typos like `tokenfile` instead of
   `token_file`.
10. Config file not found or unreadable: error with the OS-level message.
11. **Config integrity logging (T10).** After all validation succeeds,
    log the absolute path of the config file and the SHA-256 hash of
    its raw bytes at INFO level:
    `config loaded path=/etc/agent-proxy/config.yaml sha256=<hex>`.
    This provides a tamper-detection baseline in the systemd journal.
    Operators comparing the hash across restarts can detect unauthorised
    config modification.
12. **`allow_methods` validation (G2/T11).** If set on a rule, each
    value must be a valid HTTP method token (uppercase letters only,
    non-empty, no whitespace). If nil or empty, all methods are
    permitted. At request time (in `handleMITM`, before mutator
    invocation), if the incoming request method is not in the rule's
    `allow_methods`, the proxy returns `405 Method Not Allowed` with a
    log entry at WARN level naming the blocked method, host, and rule.
    Rules without `allow_methods` inject credentials for all methods.
13. **`listen` address validation (Trust Boundary C).** Default is
    `unix:///run/agent-proxy/proxy.sock`. If `listen` begins with
    `unix://`, the proxy creates a Unix domain socket at the specified
    path. If the parent directory does not exist, error. If the path
    already exists as a stale socket, remove it before binding (error
    if the path exists and is not a socket). File permissions on the
    created socket: `0600` (proxy user only). Any other `listen` value
    is interpreted as a TCP address (e.g., `:18080`, `127.0.0.1:18080`)
    and is permitted **only** if `listen_allow_tcp: true` is set
    explicitly. Otherwise error with: `TCP listen address requires
    listen_allow_tcp: true; prefer unix:// for production deployments
    (STRIDE Trust Boundary C)`. When a TCP listener is used, emit a
    startup WARNING: `listen address is TCP — any host process can
    reach the proxy; per-container Unix sockets (Phase 3d-4) will
    supersede this`.
14. **`audit_log` validation (G1, schema only).** `audit_log.file`: if
    set, the parent directory must exist and be writable at startup.
    `audit_log.level`: if set, must be `"request"` or `"body_hash"`;
    defaults to `"request"` if empty. These fields are validated but
    the audit log sink is **not yet implemented** — this is a known
    TODO tracked as governance recommendation G1. A rule set with
    `audit_log` fields parses successfully; the values are held on the
    returned `*Config` for use by the future audit log implementation.
15. **Registry publish endpoint warning (T15/A14).** For each `static`
    rule whose `host` matches a known registry publish endpoint
    pattern (`registry.npmjs.org`, `upload.pypi.org`, `crates.io`,
    `rubygems.org`, `hex.pm`), emit a startup WARNING:
    `rule for <host> may carry publish-capable credentials — this
    enables T15 (package registry exfiltration); restrict with
    allow_methods if read-only access is sufficient`. The warning is
    suppressed if the rule already has `allow_methods` set to
    read-only methods (`GET`, `HEAD`, `OPTIONS`). Does not block
    startup — informational only.

## LoadConfig API

```go
func LoadConfig(path string) (*Config, *RuleSet, error)
```

- Parses YAML from `path`.
- Validates all fields and resolves all credentials.
- Constructs mutators: `StaticTokenMutator` for `static`,
  `NewOAuthRefreshMutator` for `oauth_refresh`,
  `NewOAuthBearerMutator` for `oauth_bearer` (wired to the referenced
  refresh mutator's `TokenProvider`).
- Returns the parsed `Config` (for `listen` and `ca` fields) and a
  fully constructed `*RuleSet` ready for the proxy.
- On any validation or resolution error, returns a descriptive error
  message naming the offending rule (by host) and the specific problem.

## CLI Changes

Replace all flags with a single `-config` flag:

```
agent-proxy -config /etc/agent-proxy/config.yaml
```

Error with usage message if `-config` is omitted.

Removed flags: `-listen`, `-dest`, `-token`, `-header`, `-header-prefix`,
`-ca-cert`, `-ca-key`.

## YAML Dependency

`gopkg.in/yaml.v3` — added to `go.mod`.

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `config.go` | Create | Config types, `LoadConfig()`, validation, credential resolution, mutator construction |
| `config_test.go` | Create | Config loading, validation, error cases, credential resolution |
| `credential.go` | No change | Mutator types unchanged |
| `main.go` | Modify | Replace flag parsing with `LoadConfig` call |

## main.go Changes

```go
func main() {
    configPath := flag.String("config", "", "path to YAML config file")
    flag.Parse()

    if *configPath == "" {
        fmt.Fprintf(os.Stderr, "usage: agent-proxy -config <path>\n")
        os.Exit(1)
    }

    // ... logger setup ...

    cfg, rules, err := LoadConfig(*configPath)
    // ... error handling ...

    ca, caKey, err := loadOrGenerateCA(cfg.CA.CertFile, cfg.CA.KeyFile)
    // ... rest unchanged ...

    p := &proxy{
        rules:     rules,
        certCache: certCache,
    }
    // ... listener on cfg.Listen ...
}
```

## Tests

### Unit tests (config_test.go)

- `TestLoadConfig_Valid` — full config with all rule types, verify
  parsed correctly and RuleSet matches expected hosts
- `TestLoadConfig_Defaults` — omitted `listen`, `header`, `prefix`
  get defaults
- `TestLoadConfig_MissingHost` — error with descriptive message
- `TestLoadConfig_InvalidType` — error
- `TestLoadConfig_DuplicateHost` — error
- `TestLoadConfig_StaticBothTokenSources` — both `token_file` and
  `token_env` set, error
- `TestLoadConfig_StaticNoTokenSource` — neither set, error
- `TestLoadConfig_OAuthBearerBadSource` — `token_source` references
  nonexistent host, error
- `TestLoadConfig_OAuthBearerSourceNotRefresh` — `token_source`
  references a `static` rule, error
- `TestLoadConfig_TokenFile` — reads token from temp file, whitespace
  trimmed
- `TestLoadConfig_TokenEnv` — reads token from env var
- `TestLoadConfig_WhitespaceOnlyToken` — file/env containing only
  whitespace is rejected as empty after trim
- `TestLoadConfig_HostWithPort` — `host: api.github.com:443` rejected
- `TestLoadConfig_HostWithScheme` — `host: https://api.github.com` rejected
- `TestLoadConfig_CAHalfPopulated` — only `cert_file` set, error
- `TestLoadConfig_UnknownField` — misspelled field rejected
- `TestLoadConfig_FileNotFound` — nonexistent config path, clear error
- `TestLoadConfig_InvalidHeader` — header with invalid chars rejected
  (not a panic)
- `TestLoadConfig_ConfigHashLogged` — startup log entry contains
  `sha256=<hex>` matching the actual file hash (T10)
- `TestLoadConfig_AllowMethodsValidated` — invalid method tokens
  rejected; `405 Method Not Allowed` returned at request time for
  method not in `allow_methods` (G2)
- `TestLoadConfig_UnixListenDefault` — omitted `listen` yields
  `unix:///run/agent-proxy/proxy.sock`
- `TestLoadConfig_TCPRequiresExplicitOptIn` — TCP `listen` without
  `listen_allow_tcp: true` is rejected with the documented error
- `TestLoadConfig_TCPWithOptIn` — TCP listen with `listen_allow_tcp:
  true` accepted, startup WARNING emitted
- `TestLoadConfig_UnixSocketStaleRemoved` — existing socket file at
  path is removed before bind; existing non-socket file causes error
- `TestLoadConfig_AuditLogSchemaOnly` — `audit_log` fields parse and
  validate (directory exists, level valid); implementation is TODO
- `TestLoadConfig_RegistryPublishWarning` — startup WARNING emitted
  for `registry.npmjs.org` rule without read-only `allow_methods`
- `TestLoadConfig_RegistryPublishWarningSuppressed` — no warning when
  `allow_methods: [GET, HEAD]` is set
- `TestLoadConfig_CredentialNotRetainedInConfig` — after `LoadConfig`
  returns, `RuleConfig.TokenFile`, `TokenEnv`, `RefreshTokenFile`,
  and `RefreshTokenEnv` are all empty on the returned `*Config`
  (A17 structural defence)

### Integration test (main_test.go)

- Existing `TestOAuthRefreshFlow` adapted to use config-driven setup
  (or a new `TestConfigDrivenProxy` that loads from a temp YAML file)
- `TestMethodBlockedByAllowMethods` — request with disallowed method
  through the proxy returns 405 and is not forwarded upstream
- `TestUnixSocketListen` — proxy binds to a Unix socket and accepts
  CONNECT via that socket

## Security Properties

### Restart-required credential revocation (T18, G4)

Config reload on SIGHUP is deliberately deferred. The current
behaviour — credentials loaded once at startup, held in memory for the
process lifetime — is the **safer** default: there is no TOCTOU window
during which a partially-applied config could inject a revoked or
tampered credential.

The operator-facing implication is that credential revocation requires
a process restart. This is the intended incident-response procedure for
G4 (Incident Response).

When SIGHUP reload is added in a future phase, it must include request
draining and atomic rule replacement per T18.

### Incident response: credential revocation procedure

To immediately stop injection of a specific credential:

1. Rotate the real credential at the provider (GitHub, GCP, etc.) to
   make the stored value invalid.
2. Update (or remove) the credential file referenced by `token_file`
   or `refresh_token_file`, or unset the env var referenced by
   `token_env` / `refresh_token_env`.
3. Restart the proxy: `systemctl restart agent-proxy`. The proxy
   re-reads the config and resolves credentials at startup.
4. In-flight requests that started before the restart will complete
   with the old (now-revoked) credential value; this window is bounded
   by the TCP/Unix socket connection timeout. For immediate cutoff of
   in-flight requests, stop the proxy service entirely before step 3.

The proxy does not support hot credential rotation without restart in
Phase 3d-1. Operators must document this restart procedure in their
incident-response runbook (G4).

## Out of Scope

- Config reload on SIGHUP (future; see Security Properties above)
- Per-container rule sections (Phase 3d-4)
- Wildcard host matching (Phase 3d-2)
- Inline credential values (deliberately excluded for security)
- **Audit log implementation** (G1) — schema is defined in this spec
  but the audit log sink itself is a TODO tracked as governance
  recommendation G1. A future phase will implement append-only audit
  logging with per-request records (timestamp, session ID, method,
  host, path, status, optional request-body SHA-256) written to the
  path specified by `audit_log.file`.
