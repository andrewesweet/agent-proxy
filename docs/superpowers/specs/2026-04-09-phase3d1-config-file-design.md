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
listen: ":18080"    # proxy listen address (default ":18080")

ca:
  cert_file: ""     # path to CA cert PEM (ephemeral if empty)
  key_file: ""      # path to CA key PEM (ephemeral if empty)

rules:
  # Static token injection (GitHub PAT)
  - host: api.github.com
    type: static
    header: Authorization           # default if omitted
    prefix: "token "                # prepended to token value, default "Bearer "
    token_file: "/run/secrets/gh"   # prod: systemd LoadCredential → tmpfs
    # token_env: GH_TOKEN           # dev alternative

  # OAuth refresh token exchange (Google ADC)
  - host: oauth2.googleapis.com
    type: oauth_refresh
    refresh_token_file: "/run/secrets/google-refresh"
    # refresh_token_env: GOOGLE_REFRESH_TOKEN

  # OAuth bearer injection (Google API hosts)
  - host: cloudresourcemanager.googleapis.com
    type: oauth_bearer
    token_source: oauth2.googleapis.com

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

## Config Types

```go
type Config struct {
    Listen string       `yaml:"listen"`
    CA     CAConfig     `yaml:"ca"`
    Rules  []RuleConfig `yaml:"rules"`
}

type CAConfig struct {
    CertFile string `yaml:"cert_file"`
    KeyFile  string `yaml:"key_file"`
}

type RuleConfig struct {
    Host              string `yaml:"host"`
    Type              string `yaml:"type"`
    Header            string `yaml:"header"`
    Prefix            string `yaml:"prefix"`
    TokenFile         string `yaml:"token_file"`
    TokenEnv          string `yaml:"token_env"`
    RefreshTokenFile  string `yaml:"refresh_token_file"`
    RefreshTokenEnv   string `yaml:"refresh_token_env"`
    TokenSource       string `yaml:"token_source"`
}
```

## Validation (fail fast at startup)

1. `listen` defaults to `":18080"` if empty.
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

### Integration test (main_test.go)

- Existing `TestOAuthRefreshFlow` adapted to use config-driven setup
  (or a new `TestConfigDrivenProxy` that loads from a temp YAML file)

## Out of Scope

- Config reload on SIGHUP (future)
- Per-container rule sections (Phase 3d-4)
- Wildcard host matching (Phase 3d-2)
- Inline credential values (deliberately excluded for security)
