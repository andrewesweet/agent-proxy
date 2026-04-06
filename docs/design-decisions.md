# MITM Credential Injection — v3 Resolutions

**Date:** 2026-04-05
**Status:** Design decisions addressing v2 adversarial review
**Scope:** Concrete resolutions for U1–U3 and N1–N10 findings

This document does not restate the plan. It resolves each finding with a
specific design decision. Unresolved items are explicitly marked.

---

## Critical

### N1 — Sentinel tokens must be real JWTs (not magic strings)

**Decision.** The sentinel mechanism is redesigned: the proxy issues
structurally valid, cryptographically signed JWTs with plausible claims,
signed by a **proxy-local JWT signing key** (distinct from the MITM CA key).

- Claims: `iss` = `proxy://agent-run`, `sub` = per-container identity,
  `aud` = destination host, `exp` = now + 1h, `iat` = now, `jti` = random
- Signature: ECDSA P-256 using a key generated at `agent-run` startup
- Token is indistinguishable from a real JWT to any offline validator
- When the container sends the JWT on an outbound request, the proxy verifies
  its own signature (fast, offline), matches `jti` to the credential binding,
  and replaces the `Authorization` header with the real token fetched/refreshed
  on the host

**Opaque token case** (gh PAT, JIRA PAT, npm token): the container receives a
plausible-format opaque string (correct length, correct charset) generated
deterministically from the session ID. The tool's format validation passes.
The proxy recognizes the sentinel string by exact match on outbound.

**What this does NOT solve:** tools that call the issuer's tokeninfo endpoint
to validate the JWT before use. Those calls are intercepted by the proxy and
synthesized only if Phase 2 confirms the tool makes them. Google's client
libraries do not call tokeninfo by default in the ADC path — Phase 2 must
confirm this empirically before Phase 3c ships.

### Phase 3c dependency

Phase 3c cannot start until Phase 2 produces the per-tool answer for:

1. Does the tool parse the credential as a JWT?
2. Does the tool verify the JWT signature against a known issuer key?
3. Does the tool call tokeninfo / userinfo before first use?

If (2) is yes for any target tool, the sentinel model is infeasible for that
tool and we fall back to **full host-side token acquisition + network-layer
replacement** — the container gets a real short-lived token scoped to the
proxy's allowlist, accepting the reduced (but still meaningful) isolation.

---

## High

### U1 — Host header vs. SNI vs. CONNECT authority

**Decision.** All three must agree or the request is rejected. Specifically:

1. On CONNECT, record `connectHost` = authority from the CONNECT line
2. On TLS handshake, record `sniHost` = SNI value; reject if `sniHost != connectHost`
3. After TLS termination, record `hostHeader` = `Host:` header; reject if
   `hostHeader != connectHost`
4. Credential selection key is `connectHost` (single source of truth)
5. Log every mismatch at WARN with all three values

This eliminates the Host header / SNI / CONNECT mismatch attack. Implementation
cost: trivial — three string comparisons in the existing CONNECT path.

### U2 — Token-print commands (`gcloud auth print-access-token`)

**Decision.** The MITM proxy cannot protect credentials that tools
deliberately print to stdout. This is out of scope.

**Mitigation:** The `agent-run` wrapper configures the container with a
`gcloud` alias / shell wrapper that rejects `print-access-token` and related
subcommands (`print-identity-token`, `application-default print-access-token`)
with a clear error message pointing to the correct pattern: "make the API
call; the proxy will authenticate it for you."

This is documented as a known limitation. Containers that legitimately need
token material (audit logging, downstream signing) use the **token metadata
endpoint** (see N10) to get claims without the raw token.

### U3 — Wildcard rule scope

**Decision.** Wildcard host rules are restricted in two ways:

1. **Depth-limited:** `*.googleapis.com` matches exactly one label
   (`foo.googleapis.com`), not arbitrary depth (`a.b.googleapis.com`). Deep
   matching requires explicit `**.googleapis.com` and emits a startup warning.
2. **DNS pre-resolution at policy load time:** the proxy resolves wildcard
   suffixes against known-good IP ranges (from the destination's published
   ranges, e.g., Google's `_cloud-netblocks.googleusercontent.com` TXT record).
   Connections to IPs outside the published range for a wildcard-matched host
   are rejected even if the hostname matches.

The second mitigation is optional (off by default) because it creates an
operational dependency on the destination's IP range publication.

### N2 — SO_PEERCRED is insufficient; use per-container sockets

**Decision.** Abandon `SO_PEERCRED` as the primary identity mechanism. Replace
with **one Unix socket per container**, mounted into only that container's
filesystem namespace. Identity derives from which socket was connected to,
not from credentials on the connection.

- `agent-run` creates `/run/agent-proxy/sessions/<session-id>.sock` on the host
- Bind-mounts it read-write into the container at a fixed path
- Proxy listens on each socket in a separate goroutine; the listener goroutine
  knows the session ID without any peer credential lookup
- PID reuse, shared netns, and UID 0 mapping all become irrelevant — the
  identity is the filesystem path, not the connecting process

**Trade-off:** more file descriptors on the host proxy (one listener per
container). At 100 concurrent containers this is ~100 FDs — negligible.

### N3 — Hybrid approach is acknowledged cost

**Decision.** Accept the two-system cost. The alternative (routing SSH/GPG
through the MITM proxy) is infeasible: SSH is not HTTP, and the MITM proxy
operates on HTTP traffic only. Kerberos could be routed through MITM in
principle (the existing spnego-proxy does this) but `agent-proxy` uses the
SPNEGO provider as a library, not a separate binary.

**Mitigation for operational complexity:**

- Single unified audit log format with `auth_path: "ssh-agent"|"spnego"|"mitm"`
  as a discriminator field
- `agent-run` status command shows active credential paths for the current
  session
- Documentation clearly maps each supported tool to its credential path

The two-system claim from the v2 review is slightly misleading: SSH agent
forwarding is a standard OS feature operators already run. The MITM proxy is
the new system. The operational delta is the MITM proxy alone.

### N5 — gRPC, HTTP/2 trailers, flow control

**Decision.** Phase 3a explicitly tests against a gRPC endpoint
(`grpc.googleapis.com` or a local `grpcurl` target). The proxy is built on
`golang.org/x/net/http2` in **reverse-proxy mode**, not on `net/http`'s
high-level handlers. Specifically:

- Use `http2.Server` for the client-facing side with `Handler` that copies
  trailers explicitly via `w.Header().Set("Trailer:...")` then `w.(http.Flusher).Flush()`
- Use `http2.Transport` for the upstream side, which exposes response
  trailers via `resp.Trailer`
- Bridge the two with a per-request pipe that forwards headers, body,
  AND trailers
- For streaming RPCs, bridge the two H2 streams directly so flow control
  windows propagate naturally

gRPC-Web is handled as HTTP/1.1+chunked — the proxy does not re-encode;
it forwards the body byte-for-byte after header modification.

**Test:** Phase 3a includes `grpcurl -plaintext ... list` and
`grpcurl ... server-reflection` as acceptance tests. If these do not work,
Phase 3a does not complete.

### N7 — HTTP_PROXY bypass

**Decision.** `agent-run` uses **network-namespace-level redirect** as the
primary enforcement, not environment variables.

- `agent-run` creates a Linux network namespace for the container (or uses
  the container runtime's existing netns)
- Installs `nftables` rules in that netns: `tcp dport {80, 443} redirect to
  <host-proxy-port>`
- The container cannot bypass this because it does not have `CAP_NET_ADMIN`
  in its own netns (runtime default)
- `HTTP_PROXY` environment variables are no longer needed — this also
  improves UX (one less configuration step)

**Fallback for non-Linux or container runtimes that don't support netns
injection:** explicit `HTTP_PROXY` with documented threat model caveat.
macOS and Windows development hosts use this mode; production deployments
on Linux use netns redirect.

**Implementation dependency:** `agent-run` needs `CAP_NET_ADMIN` on the
host side to install nftables rules. Documented as a prerequisite.

---

## Medium

### N4 — Phase 0 metrics: add failure diagnosis time

**Decision.** Phase 0 DX spike measures three metrics, not one:

1. **Time to first success** — how long from zero to a working request
2. **Time to diagnose failure A** — expired credential injected deliberately
3. **Time to diagnose failure B** — missing shim / unreachable proxy

The decision criterion weights (2) and (3) equally with (1). If the MITM
approach wins on (1) but loses on (2) and (3), the helper-socket or hybrid
approach is preferred for tools where helpers are viable.

### N6 — Ephemeral CA lifecycle

**Decision.** CA lifecycle rules:

- One CA per `agent-run` session, not per invocation of subcommands
- CA TTL = session TTL; default 8 hours; configurable via `--session-ttl`
- On session end, CA is deleted from host disk; container is stopped
- Long-lived agent sessions use **CA renewal**: every 4 hours, `agent-run`
  generates a new leaf CA signed by the session CA, injects it into the
  container, and retires the old leaf after a 15-minute overlap
- Trust-store injection uses **bind mount**, not `update-ca-certificates`:
  `agent-run` writes the CA bundle to a tmpfs, mounts it at the runtime's
  expected CA path (e.g., `/etc/ssl/certs/ca-certificates.crt` is replaced
  with a file containing system CAs + the session CA)
- Startup cost: ~10ms for the bind mount, not 500ms–2s

### N8 — Separate binary is not a security boundary by default

**Decision.** When `spnego-proxy` and `agent-proxy` are deployed on the
same host, they run as **separate systemd services under separate UIDs**:

- `spnego-proxy` runs as `spnego-proxy` user
- `agent-proxy` runs as `agent-proxy` user
- Neither user can read the other's config files
- Both services use `ProtectSystem=strict`, `PrivateTmp=true`, `NoNewPrivileges=yes`
- Documented in `README.md` for the agent-proxy binary as the recommended
  deployment

Single-user developer deployments (macOS developer workstations) run both
as the developer user; documented as a reduced-isolation mode.

### N9 — Tool behavior maintenance

**Decision.** Phase 2 deliverable expands to include:

- Tool version matrix: each tool tested at 3 versions (current stable,
  previous minor, previous major)
- CI job: `tools-matrix.yml` runs Phase 2 empirical tests weekly against
  auto-updated tool installations, alerting on behavior changes
- Shim definitions carry a `compatible_versions` field; proxy warns at
  startup if running against a tool version outside the tested matrix
- Documentation commitment: shim updates for new tool versions are a
  patch-release trigger

This is a real ongoing cost. Budget: ~1 day / month of engineering to
maintain the matrix, plus on-demand work for tool-breaking updates.

### N10 — Token inspection for audit/signing use cases

**Decision.** Add a **token metadata endpoint** exposed via the
per-container Unix socket:

- Endpoint: `GET /metadata/token?aud=<destination>`
- Returns JSON: `{"sub": "...", "iss": "...", "aud": "...", "exp": ...,
  "scopes": [...]}` — claims only, no signature, no raw token
- Applications that need identity for audit logging read this endpoint
  instead of parsing their own credential
- For downstream signing use cases (e.g., a service needs to generate an
  assertion signed by its own identity), the metadata endpoint returns
  enough to construct the assertion; the actual signature is performed by
  a sign-blob endpoint on the same socket: `POST /sign?blob=<base64>`
- Signing is performed by the proxy using the session JWT key

**Limitation:** applications that cannot be modified to use the metadata
endpoint (third-party libraries that hardcode JWT parsing from the
`Authorization` header) still fail. Documented as an application-integration
requirement for audit-heavy workloads.

---

## Dependency Graph

```
Phase 0 (DX spike, includes N4 failure-diagnosis metrics)
     │
     ▼
Phase 1 (literature review)
     │
     ▼
Phase 2 (tool behavior matrix with version range — N9)
     │
     ├─► Answer N1 question: does each tool verify JWT signatures? call tokeninfo?
     │
     ▼
Phase 3a (TLS interception core; N5 gRPC acceptance tests)
     │
     ▼
Phase 3b (CredentialMutator abstraction; singleflight)
     │
     ▼
Phase 3c (OAuth sentinel — conditional on N1 answer from Phase 2)
     │
     ▼
Phase 3d (policy + per-container socket identity — N2; U1 host/SNI checks)
     │
     ▼
Phase 3e (agent-run wrapper; nftables netns redirect — N7; CA lifecycle — N6;
          token metadata endpoint — N10)
     │
     ▼
Phase 3f (shim layer — only if Phase 2 proves necessary)
     │
     ▼
Phase 4 (integration, benchmarks, security verification)
```

**Critical path:** Phase 2 answer to the N1 question gates Phase 3c. If any
target tool verifies JWT signatures against a known issuer, Phase 3c design
changes from "sentinel replacement" to "real short-lived token with
network-layer allowlist enforcement."

## Status of Findings

| ID | Severity | Status |
|----|----------|--------|
| U1 | High | Resolved — three-way agreement required |
| U2 | High | Resolved — print commands out of scope; wrapper blocks them |
| U3 | Medium | Resolved — depth-limited wildcards + optional IP range check |
| N1 | Critical | Partially resolved — design given; depends on Phase 2 empirical data |
| N2 | High | Resolved — per-container sockets replace SO_PEERCRED |
| N3 | High | Acknowledged — cost accepted; mitigations defined |
| N4 | Medium | Resolved — metric redefined |
| N5 | High | Resolved — reverse-proxy H2 architecture; gRPC acceptance tests |
| N6 | Medium | Resolved — bind-mount CA, session lifecycle, renewal overlap |
| N7 | High | Resolved — nftables netns redirect as primary enforcement |
| N8 | Medium | Resolved — separate UIDs + systemd hardening |
| N9 | Medium | Acknowledged — CI matrix + ongoing maintenance budget |
| N10 | Medium | Resolved — metadata endpoint + sign-blob endpoint on per-container socket |

**Remaining open question:** N1 requires empirical data from Phase 2 before
Phase 3c can proceed. This is a scheduled gate, not an unresolved finding.
