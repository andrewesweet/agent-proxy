# Threat-Informed Spec Revisions: Phase 3d-1 Config File Design

**Date:** 2026-04-06
**Reviewer role:** Security architect
**Target spec:** `docs/superpowers/specs/2026-04-09-phase3d1-config-file-design.md`
**Threat models consulted:**
- `docs/threat-model.md` (T1–T18)
- `docs/threat-model-red-team.md` (A1–A18)
- `docs/threat-model-stride.md` (STRIDE analysis, G1–G5)
- `docs/threat-model-owasp-update.md` (OWASP LLM/Agentic AI alignment)

---

## A. Threats the Spec Currently Addresses Well

**T10 (Proxy Config Tampering) — partial credit.**
The spec already includes strict YAML parsing (reject unknown fields, validation item 9), rejection of host values containing `:` or `://` (validation item 3), and one-time credential resolution at startup with no inline secret values. These are the three structural mitigations called out in the T10 description. See section B for the remaining gap.

**A18 (Token Endpoint Field Injection) — partial credit.**
The `oauth_refresh` rule hard-codes the `Authorization: Bearer` header and the `oauth_bearer` rule hard-codes `Authorization: Bearer`. The spec does not expose `scope`, `client_id`, or other token endpoint fields to the config — they are not configurable, which eliminates the operator misconfiguration vector for those fields. See section C for the runtime sanitisation gap.

**Credential resolution security.**
No inline secret values in the schema, mutual exclusion between `_file` and `_env`, and immediate resolution at startup with whitespace trimming and empty-string rejection are all good. The `token_env` path avoids leaving sensitive values in config files checked into version control.

**Validation strictness.**
Duplicate host detection, case-insensitive host normalisation, `oauth_bearer` source linkage validation, and `CAConfig` half-population rejection all reduce the operator-error surface that contributes to T10.

---

## B. Threats the Spec Inadequately Addresses

### B1. T10 — Config File Integrity: SHA-256 Hash Logging at Startup

**Gap.** The T10 entry in `threat-model.md` explicitly states: *"Consider: log SHA-256 hash of config at startup for tamper detection."* The spec does not mention this. T10 notes that without tamper detection, a compromised host process with write access to the config path can redirect credential injection without detection until the proxy is restarted.

**Revision.** Add a new item to the **Validation** section:

> 11. At startup, after all validation succeeds, log the absolute path of the config file and its SHA-256 hash at INFO level: `config loaded path=/etc/agent-proxy/config.yaml sha256=<hex>`. This provides a tamper-detection baseline in the systemd journal. If the hash changes between restarts without an operator-initiated change, the discrepancy is detectable via log comparison.

The implementation is one `crypto/sha256` call on the raw YAML bytes before parsing. This is trivially cheap and satisfies the T10 residual risk entry.

---

### B2. T18 — TOCTOU on Config Change: Document Restart-Required Behaviour as a Security Property

**Gap.** The spec notes config reload is out of scope for Phase 3d-1 (deferred to a future phase). T18 explicitly calls this out as a design requirement: *"the config reload mechanism must include request draining and atomic rule replacement to prevent TOCTOU windows."* The spec's Out of Scope section simply says "Config reload on SIGHUP (future)" with no guidance on the security implications.

The spec's current behaviour — config read once at startup, no reload — is actually the *safer* of the two options: an operator cannot accidentally create a TOCTOU window by sending SIGHUP at the wrong moment. However, this means that when credential revocation is needed, the operator must restart the process, and any in-flight requests that started before the restart will complete with the old (now-revoked) credential.

**Revision.** Add a **Security Properties** note to the Out of Scope section:

> Config reload on SIGHUP is deliberately deferred. The current behaviour — credentials loaded once at startup, held in memory for the process lifetime — is the safer default: there is no TOCTOU window during which a partially-applied config could inject a revoked or tampered credential. The operator-facing implication is that credential revocation requires a process restart. This is documented as the intended incident-response procedure for G4 (Incident Response). When SIGHUP reload is added in a future phase, it must include request draining and atomic rule replacement per T18.

---

### B3. G2 — Least-Privilege Credential Injection: Method Allowlisting in Rules

**Gap.** G2 from the STRIDE model and OWASP governance checklist requires rules to distinguish read-only from write-capable credential injection. T11 identifies this as an active architectural enabler of A10 (data exfiltration via legitimate API writes) and A14 (package registry publish exfiltration). The spec introduces no `methods` or `allow_methods` field and provides no mechanism for operators to restrict which HTTP methods a rule will inject credentials for.

This is the correct phase in which to add this — Phase 3d-1 introduces the rule schema. Adding it later requires a schema change that may break existing config files.

**Revision.** Add an optional `allow_methods` field to `RuleConfig`:

```go
type RuleConfig struct {
    // ... existing fields ...
    AllowMethods []string `yaml:"allow_methods"` // default: nil (all methods)
}
```

Add to the schema example comment block:
```yaml
  # GitHub PAT — read-only: only allow safe methods
  - host: api.github.com
    type: static
    token_file: "/run/secrets/gh"
    allow_methods:
      - GET
      - HEAD
      - OPTIONS
```

Add to the Validation section:

> 12. `allow_methods`: if set, each value must be a valid HTTP method token (uppercase, no whitespace). If empty or omitted, all methods are permitted. At request time, if the incoming method is not in `allow_methods`, the proxy returns `405 Method Not Allowed` with a log entry at WARN level naming the blocked method, host, and rule.

Add a note on T11/G2:

> Rules without `allow_methods` inject credentials for all HTTP methods, including POST, PUT, PATCH, and DELETE. Operators running agents on write-capable credentials (GitHub PATs with `repo` scope, registry publish tokens) SHOULD set `allow_methods` to the minimum set required. This directly limits the blast radius of T11 (Credential Scope Excessive Agency) and A10 (data exfiltration via legitimate API writes).

The implementation impact is minimal: one method check in `handleMITM` before header injection.

---

## C. Threats the Spec Should Address But Doesn't Mention

### C1. S8/F9 (STRIDE Trust Boundary C) — TCP Listen Exposes Proxy to All Host Processes

**Threat.** The STRIDE model identifies **Trust Boundary C** as an unprotected surface: the proxy currently listens on `:18080` TCP, which is reachable from *any* process on the host, not just containers. The STRIDE doc states: *"Any compromised host process can send CONNECT requests to the proxy and receive real-credential-injected responses. This boundary does not exist in the ideal architecture."* Phase 3d per-container Unix sockets are the planned fix, but Phase 3d-1 (this spec) re-exposes this boundary by introducing a `listen` field that defaults to a TCP address.

**Current spec behaviour.** The `listen` field defaults to `":18080"` — a TCP socket accessible from the entire host. There is no Unix socket option in the schema.

**Revision.** The spec should add a Unix socket listen option and change the production guidance:

Add to `Config` (or as an alternative listen format):
```yaml
listen: "unix:///run/agent-proxy/proxy.sock"  # preferred for Phase 3d+ deployments
listen: ":18080"                               # TCP fallback for development only
```

Add a validation rule:

> 13. `listen`: if the value begins with `unix://`, the proxy creates a Unix domain socket at the specified path. If the path's parent directory does not exist, error. If the path already exists (stale socket), remove it before binding. File permissions on the created socket: `0600` (proxy user only). TCP listeners (any other value) are permitted but emit a startup WARNING: `listen address is TCP — any host process can reach the proxy; prefer unix:// for production deployments`.

Add a security note to the `listen` field documentation:

> For production deployments, use a Unix socket path (`unix:///run/agent-proxy/proxy.sock`). A TCP listen address means any host process can send CONNECT requests to the proxy and receive real-credential-injected responses (Trust Boundary C from the STRIDE model). The Unix socket path should be owned by the proxy user and mode `0600`. Per-container socket binding (Phase 3d-4) will supersede this for multi-container deployments.

**Note:** This revision does not require per-container socket isolation to land first. It simply gives operators the option to close Trust Boundary C at the single-proxy level before Phase 3d-4 ships.

---

### C2. G1 — Audit Log: No Audit Log Field in Config

**Threat.** G1 (Tamper-Evident Structured Audit Log) is rated Priority: High in both the STRIDE model and the OWASP update. The governance recommendation requires a structured audit log stream distinct from the debug log, written to an append-only file. The spec introduces no `audit_log` field in the configuration schema. This means the implementation plan will have no hook to wire up G1, and it will remain unaddressed.

**Revision.** Add an `audit_log` section to `Config`:

```go
type AuditLogConfig struct {
    File   string `yaml:"file"`    // path to append-only audit log; empty = stderr
    Level  string `yaml:"level"`   // "request" (default) or "body_hash"
}
```

Schema example:
```yaml
audit_log:
  file: "/var/log/agent-proxy/audit.log"   # opened O_APPEND|O_CREATE, mode 0600
  level: "body_hash"                       # include SHA-256 of request body
```

Add to the Validation section:

> 14. `audit_log.file`: if set, opened with `O_APPEND|O_CREATE`, mode `0600`. Error at startup if the directory does not exist or is not writable. If empty, audit records are written to stderr (systemd journal). `audit_log.level`: must be `"request"` (log timestamp, session ID, method, host, path, HTTP status) or `"body_hash"` (same plus SHA-256 of request body). Defaults to `"request"`. Audit log entries are distinct from slog debug entries and are never suppressed by the slog level.

This gives the implementation plan a concrete schema anchor for G1, and it gives operators a way to satisfy their forensic requirements without code changes.

---

### C3. A17 — Debug Log Credential Leakage: No Structural Redaction Specification

**Threat.** A17 (Credential Leakage via Debug Log Stream) rates impact as Critical if a contributor accidentally logs a credential-adjacent field. The threat model notes: *"there is no systematic redaction or scrubbing mechanism to prevent regression."* The spec documents that credentials are resolved at startup and discarded, but does not specify what happens to credential values after resolution — in particular, whether they are held in a form that could be accidentally logged.

**Revision.** Add a constraint to the **Credential Resolution** section:

> After resolution, credential values (token strings, refresh token strings) are stored in the mutator objects only. They are never stored as fields on `RuleConfig` or `Config` structs. `RuleConfig` fields `TokenFile`, `TokenEnv`, `RefreshTokenFile`, and `RefreshTokenEnv` are zeroed (set to empty string) after the credential is resolved, so that a `%+v` or `slog.Debug("config", "cfg", cfg)` log statement cannot emit a credential value, even accidentally. The resolved credential value is held only inside the constructed mutator, which does not implement `fmt.Stringer` or `slog.LogValuer`.

Add to the test list (`config_test.go`):

> - `TestLoadConfig_CredentialNotRetainedInConfig` — after `LoadConfig` returns, verify that `RuleConfig.TokenFile`, `TokenEnv`, `RefreshTokenFile`, and `RefreshTokenEnv` are all empty on the returned `*Config`.

This is a structural defence against A17 that costs one `= ""` assignment per resolved field and is provable by test.

---

### C4. T15 — Package Registry Exfiltration: No Explicit Warning Against Publish Tokens

**Threat.** T15 (Package Registry as Exfiltration Channel) is rated P2. The threat model notes: *"publish tokens are out of scope for default allowlists; include only when explicitly needed for the task."* The spec has no mechanism to warn operators when they configure rules that point to known publish endpoints, and no guidance in the config examples or documentation discouraging publish-scope credentials.

**Revision.** Add to the **Validation** section:

> 15. At startup, for each `static` rule targeting a host matching a known registry publish endpoint pattern (`registry.npmjs.org`, `upload.pypi.org`, `crates.io`), emit a WARNING: `rule for <host> may carry publish-capable credentials — this enables T15 (package registry exfiltration); restrict with allow_methods if read-only access is sufficient`. This does not block startup — it is informational only.

Add to the schema example (comment on the `static` rule):
```yaml
  # WARNING: if this token has publish scope, configure allow_methods to
  # restrict to read-only methods. See T15 in docs/threat-model.md.
  - host: registry.npmjs.org
    type: static
    token_file: "/run/secrets/npm"
    allow_methods: [GET, HEAD]  # omit if publish is intentionally needed
```

This does not prevent A14/T15 — the proxy cannot inspect request bodies — but it moves the policy guidance from documentation that operators may not read into the operational startup path where it is unavoidable.

---

### C5. G4 — Incident Response: No Config-Level Credential Revocation Path

**Threat.** G4 (Incident Response Playbook) requires a clear revocation procedure. T18 establishes that credential revocation currently requires a process restart. The spec documents neither the revocation procedure nor what happens to in-flight requests during restart. An operator under incident pressure who does not know to restart the proxy will continue injecting a compromised credential.

**Revision.** Add an **Incident Response** subsection to the spec (or to the Out of Scope section):

> **Credential Revocation.** To immediately stop injection of a specific credential:
> 1. Rotate the real credential at the provider (GitHub, GCP, etc.) to make the stored value invalid.
> 2. Update (or remove) the credential file referenced by `token_file` / `refresh_token_file`.
> 3. Restart the proxy: `systemctl restart agent-proxy`. The proxy re-reads the config and resolves credentials at startup. In-flight requests that started before the restart will complete with the old (now-revoked) credential value; this window is bounded by the TCP connection timeout (30s).
>
> The proxy does not support hot credential rotation without restart in Phase 3d-1. SIGHUP reload is a future feature. For the purposes of G4 (Incident Response Playbook), operators must document this restart procedure in their runbook.

---

## D. Threats That Are Out of Scope for This Spec

The following threats from the threat models are not addressable at the config-file layer. They are noted here to be explicit about boundaries.

| Threat | Why Out of Scope for This Spec |
|--------|-------------------------------|
| T1 (Direct Egress Bypass) | nftables enforcement; not a config-file concern |
| T2 (Host/SNI Mismatch) | Runtime enforcement in `handleMITM`; already implemented |
| T3 (Sentinel Token Race) | Runtime `sync.RWMutex` behaviour; not configurable |
| T4 (Token Printing) | `agent-run` wrapper shell alias; not proxy config |
| T5 (DNS Exfiltration) | Network layer; not addressable via YAML config |
| T6 (Container Escape) | Host kernel/runtime hardening; out of proxy scope entirely |
| T7 (Cross-Container Socket Guessing) | Phase 3d-4 per-container socket design |
| T8 (Token Metadata Endpoint Abuse) | Phase 3e; endpoint not yet implemented |
| T9 (Wildcard Rule DNS Rebinding) | U3 IP range validation; wildcard rules are Phase 3d-2 |
| T12 (Denial of Wallet) | Rate limiting (STRIDE P3 recommendation); not in config schema yet |
| T13 (Persistent Memory Poisoning) | Agent memory layer; out of proxy scope entirely |
| T14 (Multi-Agent Confused Deputy) | Phase 3d-4 per-container isolation |
| T16 (Reverse Shell Persistence) | nftables egress; Phase 3d |
| T17 (MCP Tool Descriptor Poisoning) | Agent operator layer; allowlist enforcement already covers proxy side |
| A1 (Response Header Observation) | Upstream response forwarding; not configurable |
| A2 (DNS Poisoning) | U3 IP pinning; not yet implemented |
| A3 (Timing Side Channel) | Runtime behaviour; not configurable |
| A5 (HTTP Request Smuggling) | Runtime parsing; not configurable |
| A7 (CA Key Theft) | File permissions; addressed in systemd unit, not config file |
| A9 (Cert Cache Exhaustion) | LRU eviction; Phase 3d-2 |
| A11 (Shared Token Cache) | Phase 3d-4 per-container isolation |
| G3 (Security Invariant Test Suite) | Test implementation; not a config schema concern |
| G5 (Anomaly Detection) | Metrics/alerting infrastructure; future phase |

---

## Summary: Prioritised Revision List

| Priority | Finding | Spec Section to Change | Effort |
|----------|---------|----------------------|--------|
| P1 | **B1** — Log SHA-256 hash of config at startup (T10) | Validation, item 11 | Trivial (one hash call) |
| P1 | **C1** — Unix socket listen option + TCP warning (Trust Boundary C / STRIDE S8) | Config schema, `listen` field, Validation item 13 | Low (socket binding variant) |
| P2 | **B3** — `allow_methods` field on rules (G2 / T11 / A10) | Config Types, `RuleConfig`; Validation item 12 | Low (one method-check call site) |
| P2 | **C2** — `audit_log` config section (G1) | Config Types, new `AuditLogConfig`; Validation item 14 | Medium (new log sink wiring) |
| P2 | **C3** — Zero `RuleConfig` credential fields after resolution + `LogValuer` suppression (A17) | Credential Resolution section; config_test.go | Trivial |
| P3 | **B2** — Document restart-required behaviour as a security property (T18 / G4) | Out of Scope section | Documentation only |
| P3 | **C4** — Startup warning for registry publish endpoints (T15 / A14) | Validation item 15; schema comments | Trivial |
| P3 | **C5** — Credential revocation procedure (G4) | New Incident Response subsection | Documentation only |
