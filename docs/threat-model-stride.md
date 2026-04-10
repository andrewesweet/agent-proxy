# STRIDE Threat Model: agent-proxy

**Date:** 2026-04-06
**Status:** Initial formal STRIDE analysis
**Scope:** MITM credential injection proxy for containerized AI coding agents
**Framework:** Microsoft STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)

---

## 1. System Overview and Data Flow Diagram

agent-proxy is a Linux host process that intercepts outbound HTTPS from Podman
containers, performs TLS MITM inspection on allowlisted destinations, substitutes
real credentials for dummy sentinel tokens, and forwards to real upstream API
servers. Containers hold only sentinel values; real credentials never enter
container memory or filesystem.

### Components and Trust Levels

| Component | Trust Level | Notes |
|-----------|-------------|-------|
| AI agent container | **Untrusted** | May be prompt-injected or otherwise compromised |
| agent-proxy process (host) | **Trusted** | Runs as dedicated `agent-proxy` user with systemd hardening |
| Host filesystem (credentials, CA keys) | **Trusted** | Readable only by proxy user |
| Upstream API servers (GitHub, GCP, npm) | **Conditionally trusted** | Trusted to respond authentically; not trusted to be reachable |
| Sibling containers | **Untrusted** | Isolated by per-container Unix sockets (Phase 3d) |

### Data Flow

```
[Container]
    │  CONNECT api.github.com:443  (sentinel token in env/ADC)
    │  via nftables redirect (port 443 → proxy, Phase 3e)
    ▼
[Trust Boundary A: Container → Proxy]
    │
[agent-proxy]
    │  ① Validates CONNECT authority == SNI == Host header
    │  ② Matches host against allowlist rules
    │  ③ Terminates TLS with generated cert (host CA trusted by container)
    │  ④ Reads plaintext request; strips sentinel Authorization header
    │  ⑤ Fetches/caches real credential from host credential store
    │  ⑥ Injects real Authorization header into request
    │  ⑦ Forwards to real upstream over new TLS connection
    │
[Trust Boundary B: Proxy → Upstream]
    │
[Upstream API Server]
    │  Real response (200/401/etc)
    ▼
[agent-proxy]
    │  ⑧ For OAuth token responses: replaces real access_token with sentinel
    │  ⑨ Writes modified response back to container
    ▼
[Container]
    Receives sentinel tokens only; real credentials never in this path
```

### Trust Boundaries

- **Boundary A (Container → Proxy):** Container is fully untrusted. All input
  from the container (CONNECT target, TLS SNI, HTTP Host header, request body)
  must be treated as potentially adversarial.
- **Boundary B (Proxy → Upstream):** Proxy presents real credentials. Upstream
  is trusted to authenticate and respond correctly, but upstream responses flow
  back through the proxy and could contain malicious content the agent processes.
- **Boundary C (Host-local non-container processes → Proxy listen socket):** The
  current Phase 3a prototype listens on `:18080` TCP, which is reachable from
  ANY process on the host — not just from containers. Any compromised host
  process can send CONNECT requests to the proxy and receive real-credential-injected
  responses. This boundary does not exist in the ideal architecture. Planned
  Phase 3d per-container Unix sockets will close this boundary by making the
  proxy's credential-injection endpoint accessible only via bind-mounted socket
  files inside each specific container. Until Phase 3d ships, boundary C is
  unprotected.

---

## 2. STRIDE Analysis by Component

### 2.1 AI Agent Container (Untrusted)

| Boundary/Asset | Category | Threat | Impact | Mitigation | Status |
|---|---|---|---|---|---|
| Container → Proxy: CONNECT request | **Spoofing** | Container spoofs a legitimate CONNECT target (e.g., `api.github.com`) to obtain credentials intended for another destination | Credential injection to wrong host | Three-way agreement: CONNECT authority == SNI == Host header enforced in `handleMITM` (U1) | Mitigated |
| Container → Proxy: CONNECT request | **Spoofing** | Container sends CONNECT to allowlisted host but suppresses SNI, hoping to bypass SNI check | SNI bypass; credential injection without SNI validation | Empty SNI is permitted (A4 — low impact since Host header check still runs) | Partially Mitigated |
| Container → Proxy: identity | **Spoofing** | Container A guesses Container B's Unix socket session ID and connects to obtain B's credentials | Cross-container credential theft | Per-container sockets with cryptographically random session IDs; parent directory NOT bind-mounted (N2, T7) | Deferred to Phase 3d |
| Container → Proxy: OAuth device flow | **Spoofing** | Container performs full OAuth device flow, obtaining a real token that lands in container memory (`auth.json`) | Container holds live credential | Option A (host-side pre-population with sentinel bind-mount) not yet chosen; device-flow isolation design deferred | Deferred to Phase 3c/3d |
| Request body / headers | **Tampering** | Rogue agent crafts HTTP request smuggling payload (CL.TE or TE.CL) to inject a second request with altered path/method to upstream API (A5) | Unauthorized API operations (e.g., DELETE repo) — not credential exfiltration | Go's `http.ReadRequest` and `http.DefaultTransport` use the same parser, reducing CL.TE gaps; proxy unconditionally overwrites `Authorization` | Partially Mitigated |
| Host header | **Tampering** | Agent sends `Host: different.host.com` inside a CONNECT tunnel established for `allowlisted.host.com` | Credential injected to wrong host or allowlist bypass | U1: Host header must equal CONNECT authority; mismatch returns 400 | Mitigated |
| Audit log | **Repudiation** | Agent denies having made a specific API call; no request-level audit trail beyond proxy logs | Unable to prove agent performed destructive action | Proxy logs method and path per request (slog JSON); no request body hashing or tamper-evident log | Partially Mitigated — request body and full header audit not implemented |
| Outbound traffic | **Information Disclosure** | Agent observes response headers (`X-OAuth-Scopes`, `X-RateLimit-*`) to fingerprint real credential scope and identity (A1) | Token scope/identity leak | None — upstream response headers forwarded verbatim | Unmitigated |
| Timing | **Information Disclosure** | Agent measures response latency to determine whether a live real credential is cached in the proxy (A3) | Credential liveness inference | None — proxy does not obfuscate timing | Unmitigated |
| DNS (outbound UDP 53) | **Information Disclosure** | Agent encodes session metadata or timing observations into DNS queries to attacker-controlled nameserver (T5) | Low-bandwidth covert exfiltration channel; cannot carry real tokens | None — DNS is not filtered or proxied | Unmitigated |
| Allowlisted API endpoints | **Information Disclosure** | Agent uses proxy-injected real credential to exfiltrate container filesystem content via GitHub API (create gist, push to repo) (A10) | Data exfiltration through legitimate API operations | None at proxy layer — requires write-scope restriction on injected credentials at policy layer | Unmitigated (by design; policy-layer defense needed) |
| CONNECT to wildcard host | **Information Disclosure** | Agent CONNECT to attacker-controlled subdomain under a wildcard rule (e.g., `evil.googleapis.com`); proxy injects real GCP credential (T9, A2) | Full credential exfiltration to attacker-controlled server | Depth-limited wildcards (U3, planned); optional IP range validation against Google netblocks (off by default) | Partially Mitigated |
| DNS poisoning | **Information Disclosure** | Agent influences host-side DNS resolution to redirect `api.github.com` to attacker IP; proxy injects real PAT into request to attacker server (A2) | Full credential exfiltration | IP pinning at rule-load time (U3, optional, off by default); requires host netns separation | Partially Mitigated |
| Connection flooding | **Denial of Service** | Agent opens thousands of concurrent CONNECT connections to exhaust proxy goroutine pool or file descriptors | Proxy unavailability | No connection-limit or rate-limit per container implemented | Unmitigated |
| Cert cache exhaustion | **Denial of Service** | After wildcard rules ship (Phase 3d), agent CONNECTs to thousands of unique subdomains to fill unbounded cert cache map (A9) | Proxy memory exhaustion | Currently limited (no wildcard rules); LRU eviction planned but not implemented | Deferred to Phase 3d |
| JWKS endpoint observation | **Elevation of Privilege** | Agent observes `kid` in JWKS response substituted by proxy; if signing key is shared across containers, agent can forge id_tokens for sibling container identity (A8) | Cross-container identity impersonation | Per-session signing key (N1 design) but no documented `kid` rotation or per-container JWKS isolation | Partially Mitigated |
| Capabilities inside container | **Elevation of Privilege** | Agent spawns child process that inherits network access and uses it to perform API calls the agent was not explicitly instructed to do | Unauthorized use of injected credentials | Container capability restrictions (Podman rootless defaults); no request-path restriction in proxy | Partially Mitigated |
| Agent persistent memory (CLAUDE.md, ~/.claude/) | **Tampering** | Persistent memory poisoning (T13): malicious repository modifies or plants content in agent persistent memory files (CLAUDE.md, ~/.claude/memory/), altering the agent's behavior in future sessions by modifying persistent state (OWASP: ASI06) | Future sessions exhibit attacker-planted behavior; modification of persistent state affects all subsequent sessions without active attacker presence | Out of scope for agent-proxy — defense at agent memory layer (namespace isolation, memory content validation, clearing between sessions for untrusted projects) | Unmitigated (out of scope) |
| Agent persistent memory (CLAUDE.md, ~/.claude/) | **Spoofing** | Persistent memory poisoning (T13): planted instructions in agent memory impersonate legitimate user-issued instructions — the agent cannot distinguish instructions stored by the legitimate user from those injected by an attacker in a prior session (OWASP: ASI06) | Agent executes attacker's instructions believing them to be legitimate user directives; forensic trail appears as normal present-session activity | Out of scope for agent-proxy — defense at agent memory layer; if T6 (container escape) succeeds, host-side memory files are also at risk | Unmitigated (out of scope) |
| Agent persistent memory (CLAUDE.md, ~/.claude/) | *(Repudiation — side effect)* | T13 side effect: forensic trail shows present-session activity indistinguishable from legitimate, even though the root cause was planted in a prior session | Loss of forensic attribution for past-session planted instructions | Out of scope | Unmitigated (out of scope) |
| Package registry publish endpoint (npm/PyPI/crates.io) | **Information Disclosure** | Package registry exfiltration via proxy-injected publish credentials (T15): agent POSTs a crafted package containing exfiltrated secrets or private code to the registry; proxy injects real publish token; exfiltrated data is publicly accessible on the registry under the developer's name (OWASP: ASI02) | Data exfiltration + supply chain poisoning; secrets embedded in package metadata or README; package published under developer's account | None at proxy layer — proxy cannot distinguish legitimate from adversarial publish; policy defense: exclude publish tokens from default allowlists | Unmitigated (by design; policy-layer defense needed) |
| Package registry publish endpoint (npm/PyPI/crates.io) | **Tampering** | Package registry exfiltration (T15): agent modifies public registry state by publishing a package — a persistent, externally visible write to a shared public resource; poisons the supply chain for other developers who install the package | Supply chain compromise; malicious package visible to all registry users; package may shadow legitimate packages (typosquatting) | None at proxy layer | Unmitigated (by design; policy-layer defense needed) |
| Package registry publish endpoint (npm/PyPI/crates.io) | **Spoofing** | Package registry exfiltration (T15): published package bears the developer's real account identity (because the real publish token is injected by the proxy); other users who install the package attribute it to the legitimate developer | Attribution misdirection; attacker's malicious package appears to originate from a trusted developer | None at proxy layer | Unmitigated (by design) |
| Multi-agent A2A/MCP inter-container calls | **Spoofing** | Multi-agent confused deputy (T14): compromised orchestrator impersonates a legitimate instruction source to the sub-agent — the sub-agent cannot verify that instructions originate from the legitimate orchestrator rather than a compromised one (OWASP: ASI07) | Sub-agent acts on attacker-crafted instructions believing them legitimate; the sub-agent's own credentials are used — no new privileges are granted, but the sub-agent is deceived into using its credentials for attacker-chosen operations | Partial — A2A/MCP authentication at the agent layer; per-container credential scoping (Phase 3d-4) limits blast radius | Deferred to Phase 3d |
| Multi-agent A2A/MCP inter-container calls | **Tampering** | Multi-agent confused deputy (T14): compromised orchestrator tampers with the sub-agent's instruction stream, substituting attacker-chosen API operations for legitimate ones (OWASP: ASI07) | Sub-agent's allowlisted operations become the attacker's tools; attacker achieves API operations scoped to the sub-agent's credentials without directly accessing that container | Partial — per-container credential scoping (Phase 3d-4); A2A/MCP authentication at agent layer | Deferred to Phase 3d |

### 2.2 agent-proxy Process (Host)

| Boundary/Asset | Category | Threat | Impact | Mitigation | Status |
|---|---|---|---|---|---|
| CA private key | **Spoofing** | Attacker reads ephemeral CA key from tmpfs (A7) and uses it to forge TLS certs for allowlisted hosts, enabling a second MITM inside the container | Cross-container MITM; not direct credential exfiltration (real creds still on host) | CA key written 0600 (proxy user only); key path not logged (S5); requires container escape or PID-namespace sharing as precondition | Partially Mitigated |
| Proxy binary / config | **Spoofing** | Compromised host process replaces the proxy binary or its config to redirect credential injection | Complete credential compromise on all containers | Separate `agent-proxy` UID; `ProtectSystem=strict`; binary integrity not verified at runtime | Partially Mitigated |
| Token cache (in-memory) | **Tampering** | Proxy memory is not accessible from container without root, ptrace, or container escape — requires one of these as a precondition | Real cached tokens exposed or corrupted | `NoNewPrivileges=yes`; Podman rootless limits UID 0 mapping; `ptrace` scope restriction via systemd hardening | Partially Mitigated — requires root, ptrace, or container escape as precondition; not fully N/A |
| Real token in transit (proxy→upstream) | **Tampering** | Attacker performs MITM on proxy-to-upstream connection by poisoning host DNS (A2) | Real credential sent to attacker-controlled server | Standard TLS verification by `http.DefaultTransport`; no certificate pinning | Partially Mitigated |
| OAuthRefreshMutator | **Tampering** | Concurrent requests race on the shared `OAuthRefreshMutator` across multiple containers (A11); container receives wrong container's cached token | Cross-container credential confusion | Per-container socket identity (Phase 3d) will bind mutator instances per-container; current prototype shares state | Deferred to Phase 3d |
| Proxy audit logs | **Repudiation** | Log entries for credential injections are not tamper-evident; a compromised host process could delete or alter them | Loss of forensic trail | JSON slog to stderr (systemd journal); no WORM or signed log | Partially Mitigated — systemd journal provides append semantics against proxy-process-level compromise; still Unmitigated against root-level compromise |
| Proxy logs | **Information Disclosure** | Log statement accidentally emits a real token (e.g., Authorization header logged in debug mode) | Real credential in log files readable by log aggregation system | Invariant I6 enforced; logs emit sentinels not real tokens; code review confirmed no header logging | Mitigated |
| Proxy process memory | **Information Disclosure** | Core dump or `/proc/<pid>/mem` read by root process exposes cached real tokens | Full credential exfiltration | `NoNewPrivileges=yes`; `PrivateTmp=true`; Podman rootless limits UID 0 mapping; core dump path restriction not documented | Partially Mitigated |
| Proxy listen socket | **Denial of Service** | Non-container process on host connects to proxy listen socket and sends malformed CONNECT requests | Proxy goroutine exhaustion; log spam | TLS handshake timeout (30s, G1); panic recovery in `handleConn`; no IP allowlist on proxy listen socket | Partially Mitigated |
| Token metadata endpoint (planned) | **Elevation of Privilege** | Rogue agent sends arbitrary blobs to `POST /sign` endpoint on per-container socket; proxy signs them with session JWT key; agent replays signatures in external services (T8) | Signature oracle abuse | Endpoint not yet implemented; design must restrict `aud` claim on signed blobs to allowlisted destinations | Deferred to Phase 3e |
| nftables rules (planned) | **Elevation of Privilege** | Agent with `CAP_NET_ADMIN` (not default) modifies nftables rules in its own netns to bypass port-redirect enforcement | Proxy bypass; unauthenticated egress | Container runtime default drops `CAP_NET_ADMIN`; nftables redirect not yet implemented | Deferred to Phase 3e |

### 2.3 Host Filesystem (Credentials and CA Keys)

| Boundary/Asset | Category | Threat | Impact | Mitigation | Status |
|---|---|---|---|---|---|
| Credential files (refresh tokens, PATs) | **Spoofing** | N/A — files are static secrets read by proxy; no authentication protocol to spoof at this layer | N/A | N/A | N/A |
| Credential files | **Tampering** | Compromised host process overwrites credential files with attacker-controlled values | Proxy injects attacker's credential on all subsequent requests | Separate proxy UID; `ProtectSystem=strict`; file permissions restrict write to proxy user or root | Partially Mitigated |
| Credential files | **Repudiation** | N/A — credential files are not audit records | N/A | N/A | N/A |
| Credential files | **Information Disclosure** | Container escape (T6) allows reading host filesystem; real credentials are exposed | Complete credential compromise | Podman rootless; systemd `PrivateTmp`; credentials readable only by `agent-proxy` user; kernel/runtime patching required | Partially Mitigated — residual risk is known limitation |
| CA key on tmpfs | **Information Disclosure** | CA key readable if container gains access to host process filesystem (A7); enables cross-container MITM | Cross-container MITM (not direct credential exfiltration) | 0600 permissions; key path not logged; tmpfs location not predictable from inside container | Partially Mitigated |
| Credential files | **Denial of Service** | Credential file deleted or corrupted; proxy cannot inject credentials | All authenticated API calls fail for affected container | Not mitigated; depends on operator backup/restore procedures | Unmitigated |
| Credential files | **Elevation of Privilege** | N/A — credential files confer no additional privilege beyond what they represent | N/A | N/A | N/A |

### 2.4 Upstream API Servers (External)

| Boundary/Asset | Category | Threat | Impact | Mitigation | Status |
|---|---|---|---|---|---|
| Upstream TLS certificate | **Spoofing** | Attacker (via DNS poisoning) presents a valid-looking TLS certificate for the upstream host; proxy connects and injects real credential (A2) | Full credential exfiltration | Standard `http.DefaultTransport` TLS validation (system roots); no certificate pinning; U3 IP range pinning optional and off by default | Partially Mitigated |
| Upstream response body | **Tampering** | Compromised upstream returns a crafted response body that causes the agent to take unintended actions (out of scope per threat model) | Agent misbehavior | Out of scope — proxy does not inspect response bodies for semantic safety | N/A (out of scope) |
| Token endpoint response | **Tampering** | Compromised upstream returns a malicious `access_token` value (e.g., a token that grants additional scopes beyond what was requested) | Broader scope than expected; agent behavior affected | `OAuthRefreshMutator.MutateResponse` caches and sanitizes token endpoint responses (strips real tokens, substitutes dummy sentinels); `staticTokenMutator.MutateResponse` and `OAuthBearerMutator.MutateResponse` are both no-ops and do not scrub responses | Conditionally Mitigated (only for `oauth_refresh` rule types; static and oauth_bearer rules do not scrub token endpoint responses) |
| Upstream response | **Repudiation** | Upstream denies having responded to a request; no request ID correlation in proxy logs | N/A | N/A — upstream non-repudiation is outside agent-proxy's scope | N/A |
| Upstream API rate limits | **Denial of Service** | Rogue agent issues flood of requests to allowlisted API (using proxy-injected credentials); upstream rate-limits or bans the real credential | Credential rate-limited or banned | No per-container rate limiting in proxy; agent can exhaust real credential's quota | Unmitigated |
| Upstream | **Information Disclosure** | N/A — proxy does not disclose credentials to upstream beyond what is required for authentication | N/A | N/A | N/A |
| Upstream response headers | **Elevation of Privilege** | Upstream returns headers (e.g., `Set-Cookie`, `X-OAuth-Scopes`) that reveal real account identity or session information usable for lateral movement | Identity fingerprinting (A1) | None — proxy forwards response headers verbatim | Unmitigated |

### 2.5 Multi-Container / Sibling Container Boundary

| Boundary/Asset | Category | Threat | Impact | Mitigation | Status |
|---|---|---|---|---|---|
| Shared CA certificate | **Spoofing** | Container with stolen CA key (A7) uses it to forge TLS certs and MITM sibling container's outbound traffic (A13) | Sibling container traffic inspection; credential observation | Per-session CA with 8h TTL (N6); 0600 key permissions; requires A7 precondition | Partially Mitigated |
| Shared OAuthRefreshMutator | **Spoofing** | In current multi-container prototype, Container B's token endpoint call updates the shared mutator; Container A's next API call uses B's real token | Cross-container credential confusion (A11) | Per-container `OAuthRefreshMutator` instances (Phase 3d) | Deferred to Phase 3d |
| JWKS substitution | **Spoofing** | Agent observes proxy's `kid` in JWKS response and crafts a fake id_token for sibling container's identity (A8) | Cross-container identity impersonation | No per-container `kid` rotation documented | Partially Mitigated |
| Per-container socket paths | **Tampering** | Agent in Container A writes to Container B's Unix socket path if parent directory is bind-mounted (T7) | Unauthorized credential requests from Container A using Container B's identity | Individual socket files bind-mounted (not parent directory); cryptographically random session IDs | Deferred to Phase 3d |
| Shared proxy state | **Denial of Service** | Cert cache exhaustion (A9) from one container affects all containers sharing the proxy process | Proxy DoS affecting all tenants | No LRU eviction; no per-container resource quotas | Unmitigated |
| Cross-container data | **Information Disclosure** | Agent in Container A observes timing patterns correlated with Container B's API activity | Tenant activity inference | None — no timing isolation between containers | Unmitigated |
| Shared proxy process | **Elevation of Privilege** | Agent exploits shared state in proxy (e.g., concurrent mutator race) to gain credentials of a higher-privileged sibling container | Privilege escalation across containers | Per-container socket design (Phase 3d) will isolate mutator state; not yet implemented | Deferred to Phase 3d |

---

## 3. Priority Matrix

### 3.1 STRIDE Findings Cross-Referenced with Existing Threat Models

| STRIDE Finding | Existing Coverage | Notes |
|---|---|---|
| Spoofing — CONNECT/SNI/Host mismatch | T2 (threat-model.md), A4 (red-team) | Well-mitigated; U1 enforced in code |
| Spoofing — socket path guessing (cross-container) | T7 (threat-model.md) | Phase 3d deferred; design sound |
| Spoofing — DNS poisoning to redirect credential injection | A2 (red-team) | High impact; optional mitigation not yet enabled |
| Tampering — HTTP request smuggling | A5 (red-team) | Low credential-exfiltration impact; API abuse possible |
| Tampering — shared OAuthRefreshMutator race | A11 (red-team), T3 (threat-model.md) | Phase 3d deferred; current prototype risk |
| Repudiation — no tamper-evident audit log | Not in existing models | **New finding** — identified by STRIDE |
| Repudiation — no request-body audit trail | Not in existing models | **New finding** — identified by STRIDE |
| Information Disclosure — response header leakage (scope/identity) | A1 (red-team) | Unmitigated by design; feasible right now |
| Information Disclosure — timing side-channel (credential liveness) | A3 (red-team) | Unmitigated; low severity |
| Information Disclosure — DNS exfiltration | T5 (threat-model.md) | Unmitigated; non-credential metadata only |
| Information Disclosure — API data exfiltration via legitimate calls | A10 (red-team) | Unmitigated by design; policy-layer fix needed |
| Information Disclosure — wildcard rule DNS rebinding | T9 (threat-model.md), A2 (red-team) | Partially mitigated; IP pinning off by default |
| Information Disclosure — credential rate limit exhaustion | Not in existing models | **New finding** — identified by STRIDE |
| Information Disclosure — core dump / proc/mem | Not in existing models | **New finding** — partially mitigated |
| Denial of Service — connection flooding | Not in existing models | **New finding** — unmitigated |
| Denial of Service — cert cache exhaustion | A9 (red-team) | Phase 3d deferred |
| Denial of Service — credential file deletion | Not in existing models | **New finding** — unmitigated |
| Denial of Service — upstream rate-limit exhaustion | Not in existing models | **New finding** — unmitigated |
| Denial of Service — Denial of Wallet (API cost exhaustion) | T12 (threat-model.md) | P2 (elevated from P3); financial impact immediate (next billing cycle), not speculative; cross-reference G5 for anomaly detection mitigation |
| Elevation of Privilege — container escape to host credential store | T6 (threat-model.md) | Known limitation; defense-in-depth applied |
| Elevation of Privilege — sign endpoint signature oracle | T8 (threat-model.md) | Phase 3e deferred; endpoint not yet implemented |
| Elevation of Privilege — JWKS kid observation + id_token forgery | A8 (red-team) | Partially mitigated; no `kid` rotation documented |
| Elevation of Privilege — CA key theft enabling cross-container MITM | A7, A13 (red-team) | Partially mitigated; requires container escape precondition |

### 3.2 New Threats Surfaced by STRIDE Not in Either Existing Model

1. **Repudiation — no tamper-evident audit log:** The proxy logs method and path
   per request but does not produce tamper-evident, append-only records. A
   compromised host process can delete or alter log entries. An agent that
   performs destructive API operations (via A10) cannot be definitively attributed.

2. **Repudiation — no request-body audit trail:** The proxy logs that a request
   was forwarded but does not hash or record the request body. For write operations
   (POST, PUT, PATCH, DELETE), there is no forensic record of what was sent.

3. **DoS — connection flooding from container:** The proxy accepts unlimited
   concurrent connections from the container. A rogue agent can open thousands
   of CONNECT connections to exhaust proxy goroutines or file descriptors,
   affecting all containers sharing the proxy process.

4. **DoS — upstream rate-limit exhaustion:** A rogue agent can issue a flood
   of valid API requests (which the proxy dutifully authenticates) to exhaust
   the real credential's API rate limit or trigger account suspension.

5. **DoS — credential file deletion:** If a host process with write access to
   the credential store deletes or corrupts a credential file, the proxy fails
   open (returning 502) but provides no alerting or fallback.

*(Note: Information Disclosure — core dump / `/proc/<pid>/mem` was previously
listed here as item 6 but is already covered in §2.2 under "Proxy process memory |
Information Disclosure". Removed to avoid duplication.)*

---

## 4. Top 5 Priority Recommendations

### P1 — Enable IP Pinning for Wildcard Rules (Addresses: T9, A2, STRIDE-Spoofing-DNS)

**Current state:** U3 IP range validation is optional and off by default. A single
rogue DNS query can redirect an allowlisted hostname to an attacker-controlled IP,
causing the proxy to inject real credentials into an attacker's TLS endpoint.

**Recommendation:** Promote IP range pinning from opt-in to **mandatory for any
rule that carries a write-capable credential**. Resolve at rule-load time and record
the IP with a TTL-based cache (e.g., 5 minutes). Re-resolve on TTL expiry — NOT
per-connection (per-connection DNS resolution creates a new DoS amplification vector
where an attacker can force thousands of DNS lookups per second). If the resolved IP
changes after TTL expiry, fail closed (reject the connection with a log entry) rather
than forwarding to the new IP. For wildcard rules, validate against published IP
ranges (e.g., Google's netblock TXT records). This converts the DNS poisoning
attack from feasible-with-difficult-preconditions to infeasible.

### P2 — Implement Per-Container Credential Isolation (Phase 3d) (Addresses: A11, T7, STRIDE-Tampering-Shared-State)

**Current state:** Multiple containers sharing the proxy process share a single
`OAuthRefreshMutator` instance. Container B's token endpoint call updates the
shared state; Container A's next request injects B's cached real token.

**Recommendation:** Accelerate Phase 3d: bind one `OAuthRefreshMutator` instance
per per-container Unix socket listener. When the socket goroutine is created by
`agent-run`, it is given its own mutator initialized with that container's
credential. No cross-container state sharing. This also eliminates T7 (socket
path guessing) and provides the identity anchor for per-container audit logs.

### P3 — Add Connection Rate Limiting per Container (Addresses: STRIDE-DoS-Connection-Flooding, A9)

**Current state:** The proxy accepts unlimited CONNECT connections. A rogue agent
can exhaust goroutines or file descriptors, causing proxy unavailability for all
containers.

**Recommendation:** Implement a per-socket (per-container) connection semaphore
with a configurable maximum (e.g., 64 concurrent connections per container). Add
a configurable request rate limit (e.g., 100 req/s per container) enforced in
`handleMITM`. This also bounds the cert cache growth rate (A9) until LRU eviction
ships. Connection limits should be logged at WARN when hit.

### P4 — Implement Tamper-Evident Request Audit Log (Addresses: STRIDE-Repudiation, A10)

**Current state:** The proxy logs method and path per forwarded request, but logs
are not tamper-evident and request bodies are not recorded. An agent that exfiltrates
data via legitimate API writes (A10) leaves no forensic trace beyond the proxy's
deletable JSON logs.

**Recommendation:** Add a structured audit log stream (distinct from the debug log)
that records per-request: timestamp, container session ID, method, host, path,
response status code, request body SHA-256 hash (not the body itself), and response
body length. Write this log to a file opened with `O_APPEND` under the proxy user's
home; route it to the systemd journal. For production deployments, forward to an
external SIEM. This does not prevent A10 but provides forensic evidence for
incident response.

Note: P4 is the implementation specification for G1 (Tamper-Evident Structured
Audit Log). G1 is the governance policy name for this requirement; P4 is the
concrete technical design. Treat them as a single recommendation: G1 defines
the what (policy), P4 defines the how (implementation).

### P5 — Restrict the Proxy CA to Allowlisted Hostnames (Invariant I4) (Addresses: A7, A13, STRIDE-Spoofing-CA-Key-Theft)

**Current state:** The proxy CA can sign leaf certificates for any hostname
(Invariant I4 violation documented in Phase 3a). A stolen CA key enables MITM
on any HTTPS server the container trusts, not just allowlisted destinations.

**Recommendation:** Implement a `NameConstraints` extension in the CA certificate
restricting permitted DNS names to the set of allowlisted hostnames (or their
parent domains). This is a standard X.509 extension (`x509.Certificate.PermittedDNSDomains`
in Go). A stolen CA key can then only sign certs for allowlisted destinations —
significantly limiting the impact of A7 and A13. This is a Phase 3d prerequisite
that should be implemented alongside per-container socket identity.

### G1 — Tamper-Evident Structured Audit Log (Priority: High) (Addresses: A10, STRIDE-Repudiation, T12)

**Checklist item:** OWASP LLM Security and Governance Checklist — "Confirm
audit records are secure."

**Current state:** JSON slog to stderr (systemd journal). No per-session
correlation, no request body hashing, deletable by root.

**Required:** Append-only audit log with: timestamp, container session
ID, method, host, path, HTTP status, request-body SHA-256, real
credential identity (not value). Forward to external SIEM for
tamper-evidence.

**Recommendation:** Implement a structured audit log stream distinct from
the debug log. Write to a file opened with `O_APPEND` under the proxy
user's home. For production deployments, forward to an external SIEM.

### G2 — Least-Privilege Credential Injection per Rule (Priority: High) (Addresses: T11, A10)

**Checklist item:** OWASP LLM Security and Governance Checklist — "Implement
least privilege access controls."

**Current state:** Rules inject a single static credential regardless
of operation type.

**Required:** Rules should support read-only and write-capable credential
variants. Write operations (POST/PUT/PATCH/DELETE) trigger audit warnings.
A future mutator could downgrade credential scope where possible (e.g., mint
a read-only derived token).

**Recommendation:** Add `read_only_credential` and `write_credential` fields
to rule configuration. Default to the read-only credential; require explicit
opt-in for write-capable injection. Log a WARN on every write-method
forwarded through a write-capable rule.

### G3 — Security Invariant Test Suite (Priority: Medium) (Addresses: I1–I8 regression prevention)

**Checklist item:** OWASP LLM Security and Governance Checklist — "Establish
continuous testing, evaluation, verification, and validation."

**Current state:** Integration tests cover functional behavior. No tests
directly assert security invariants I1–I8.

**Required:** Automated tests asserting:
- No real credential value appears in container-side byte streams
- Sentinel tokens are rejected at real upstream endpoints
- Three-way CONNECT/SNI/Host agreement enforcement
- CA signing restricted to allowlisted hosts (when NameConstraints are added)

**Recommendation:** Add a `security_invariants_test.go` test file that
directly tests each invariant with adversarial inputs.

### G4 — Incident Response Playbook (Priority: Medium) (Addresses: A10, A2, CA key compromise)

**Checklist item:** OWASP LLM Security and Governance Checklist — "Update the
Incident Response Plan and playbooks."

**Current state:** None.

**Required:** Short runbook covering detection, containment, recovery, and
evidence preservation for:
- Suspected credential exfiltration via A10
- Compromised agent session detection
- CA key compromise
- Upstream DNS poisoning / A2

**Recommendation:** Create `docs/incident-response.md` covering the four
scenarios above with concrete shell commands for log extraction, credential
rotation, and proxy restart procedures.

### G5 — Anomaly Detection / Credential Usage Accounting (Priority: Medium) (Addresses: T12, A10)

**Checklist item:** OWASP LLM Security and Governance Checklist — "Map
workflows, monitoring, and responses."

**Current state:** Per-request slog entries, no aggregation, no baseline,
no alerting.

**Required:** Per-container request rate baseline and anomaly alerting.
Credential usage reports ("container X made N writes to GitHub today").

**Recommendation:** Add a metrics endpoint or periodic log summary that
aggregates: request count per container, write-method count per container,
and unique API paths accessed. Alert when per-container request rate exceeds
a configurable threshold. This directly addresses T12 (Denial of Wallet)
and provides early warning for A10-style gradual exfiltration.

---

## 5. Invariant Gaps Highlighted by STRIDE

The following security invariants (from threat-model.md §6) have gaps exposed or
confirmed by this analysis:

| Invariant | STRIDE Category | Gap |
|-----------|-----------------|-----|
| I4 — CA signs only allowlisted hosts | Spoofing | CA can sign any hostname; NameConstraints not set |
| I5 — Per-container identity unforgeable | Spoofing, Elevation of Privilege | Per-container sockets not yet implemented (Phase 3d) |
| I7 — Allowlist bypass not possible | Information Disclosure | DNS poisoning can redirect allowlisted hostname to attacker IP; IP pinning optional and off |
| (new) — No tamper-evident audit trail | Repudiation | No WORM or signed audit log; request bodies not hashed |
| (new) — No per-container resource quotas | Denial of Service | No connection limits or request rate limits per container |

---

*Cross-references: T1–T18 from threat-model.md, A1–A16 from threat-model-red-team.md,
U1–U3 and N1–N10 from design-decisions.md.*
