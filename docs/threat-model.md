# Threat Model: agent-proxy

**Date:** 2026-04-06
**Status:** Initial version — rogue AI agent focus
**Scope:** MITM credential injection proxy for containerized AI coding agents

---

## Overview

agent-proxy runs on a Linux host and intercepts outbound HTTPS from Podman
containers. It performs TLS inspection on allowlisted destinations, substitutes
real credentials for dummy sentinel tokens, and forwards to real upstream
servers. Containers hold only sentinel tokens; real credentials never enter
container memory or filesystem.

This document focuses on the **rogue AI coding agent** threat — scenarios where
the agent running inside the container attempts to extract, abuse, or exfiltrate
real credentials. Generic infrastructure threats (DDoS, host OS compromise,
supply chain) are out of scope.

---

## 1. Threat Actors

### 1.1 Prompt-Injected Agent (Indirect Adversary)

A legitimate AI coding agent (Claude Code, OpenCode, Copilot) has been
manipulated through its inputs: malicious repository content, crafted tool
output, poisoned documentation, or adversarial prompts embedded in files it
reads. The agent's underlying model is unmodified, but its in-context reasoning
has been redirected by the attacker.

**Capabilities:**
- Can execute arbitrary shell commands within the container
- Can make outbound network connections to allowlisted destinations
- Can read container filesystem and environment
- Cannot (directly) modify its own model weights or system prompt
- Constrained by the container's network policy and capabilities

**Motivations (of the injecting attacker):**
- Exfiltrate credentials to access the developer's private repositories,
  cloud projects, or CI/CD pipelines
- Establish persistent access to the developer's infrastructure
- Perform lateral movement from the container to other systems the developer
  has access to

### 1.2 Compromised AI Agent (Direct Adversary)

The agent model itself has been replaced or fine-tuned by a malicious actor,
or the agent binary has been swapped for a rogue version. The adversary
controls the agent's reasoning directly.

**Capabilities:** All capabilities of the prompt-injected agent, plus:
- Systematic, patient, multi-step attacks not constrained by plausible
  reasoning
- Can coordinate across multiple container sessions
- Can deliberately mimic legitimate behavior to avoid detection

**Motivations:** As above; also includes platform-level attacks on the proxy
itself to expand capabilities.

### 1.3 Malicious Code Execution Inside the Container

The agent wrote and executed code (a build script, test harness, or utility
binary) that itself performs adversarial actions. The original agent prompt
may have been entirely innocent; the attack surface is the agent's output.

**Capabilities:** All capabilities the container grants to executed processes.
By default, this is the same as the agent process itself — same network
access, same filesystem, same environment variables. A container running as
root internally magnifies this.

**Motivations:** Typically a supply-chain attack embedded in a dependency the
agent installs, or deliberate exploitation by a prompt-injected agent that
uses code generation as a layer of indirection.

---

## 2. Assets Under Protection

| Asset | Sensitivity | Location |
|-------|-------------|----------|
| Long-lived refresh tokens (Google OAuth) | Critical | Host filesystem only |
| Personal access tokens (GitHub PATs) | Critical | Host filesystem only |
| Private keys (service accounts, SSH) | Critical | Host filesystem only |
| Short-lived access tokens | High | Proxy memory (cached), never in container |
| Proxy CA private key | High | Host filesystem / tmpfs |
| Proxy JWT signing key | High | Proxy memory (session-scoped) |
| Other containers' sentinel tokens | Medium | Each container's own socket |
| Host system integrity | High | Host |
| Audit log integrity | Medium | Host |

**What containers are permitted to hold:**
- Opaque sentinel strings (deterministic per session, recognized by the proxy)
- Ephemeral fake private keys (service account flow — useless outside proxy)
- Proxy CA certificate (public — not sensitive)

---

## 3. Attack Surfaces

### 3.1 Network Egress

The container's outbound TCP/UDP to the internet. The primary enforcement
mechanism is nftables rules in the container's network namespace that redirect
port 80/443 traffic to the proxy. A rogue agent may attempt to reach the
internet directly by:

- Connecting to IP addresses directly (bypassing DNS-based allowlisting)
- Using non-standard ports
- Using protocols other than TCP (ICMP, UDP, raw sockets)
- Exploiting the passthrough path for non-allowlisted destinations

### 3.2 Proxy Protocol Manipulation

The CONNECT tunnel and TLS handshake present attack surface:

- Host header / SNI / CONNECT authority mismatch attacks
- CONNECT smuggling to reach unauthorized destinations
- HTTP request smuggling after TLS termination
- Malformed requests designed to crash or confuse the proxy

### 3.3 Sentinel Token Side Channels

The proxy replaces real tokens with sentinel strings. A rogue agent may attempt
to infer real token values through:

- Timing differences (does the proxy take longer for certain hosts?)
- Error message content (do 401s from upstream leak credential information?)
- Response header differences between real and synthetic responses
- Log exfiltration (if the proxy logs request bodies or full headers)

### 3.4 Container Escape

Standard container escape vectors apply: kernel exploits, privileged
capabilities, writable host mounts, runc/crun vulnerabilities. A successful
escape reaches the host filesystem where real credentials are stored.

### 3.5 Credential Inference via Tool Abuse

Tools like `gcloud` can be instructed to call `auth print-access-token`. If
the agent can print a real credential to stdout and capture it, the isolation
breaks. Similarly, the token metadata endpoint (planned: `GET /metadata/token`)
could be abused to leak claims or trigger signing operations.

### 3.6 Per-Container Socket Manipulation

In the planned architecture, each container gets a Unix socket at a fixed
path. A rogue agent could attempt to connect to another container's socket
if the path is guessable and the bind mount is mis-configured.

---

## 4. Threat Scenarios

### T1 — Direct Egress Bypass (P2: High)

**Description:** The agent constructs a raw TCP connection to a known API
endpoint IP address (e.g., `140.82.121.5` for `api.github.com`) on port 443
without going through the proxy. The nftables redirect applies only to
connections that traverse the default route; connections to IPs may bypass it
depending on nftables rule specificity.

**Prerequisites:** Agent knows the IP of the target; container has `CAP_NET_RAW`
or can open TCP sockets; nftables rules are incomplete (do not cover all
ports or do not use `redirect` on the raw IP path).

**Impact:** Agent makes authenticated API calls using its sentinel token.
GitHub rejects the sentinel token with a 401. The agent gains nothing — the
sentinel is useless without the proxy. **Real credentials are NOT exposed.**
The risk here is not credential theft but allowlist bypass — the agent could
reach non-allowlisted destinations.

**Current mitigation:** nftables redirect in the container netns covers all
outbound TCP on ports 80 and 443. Non-allowlisted destinations receive a 403
from the proxy (allowPassthrough is false by default).

**Residual risk:** UDP (DNS), ICMP, and non-standard ports are not redirected.
A rogue agent can reach arbitrary internet hosts via DNS-over-UDP (port 53) or
direct connections on non-standard ports. DNS exfiltration is not mitigated.

**Severity: P2**

---

### T2 — Host Header / SNI Mismatch Attack (P2: High)

**Description:** The agent sends a CONNECT request for `api.github.com` (an
allowlisted host), then inside the TLS tunnel sends an HTTP request with
`Host: internal.company.com`. The proxy would select the credential for
`api.github.com` but forward the request to the wrong destination — or inject
GitHub credentials into a request to a different host.

**Prerequisites:** None beyond standard network access; the attack requires
only crafting a non-standard HTTP request.

**Impact:** If unmitigated, the agent could inject valid credentials into
requests to arbitrary HTTPS destinations reachable from the proxy host. This
could enable authentication to non-allowlisted services, or confuse log
analysis.

**Current mitigation:** The proxy enforces three-way agreement (CONNECT
authority == SNI == Host header). Any mismatch causes the proxy to log a
warning and return a 400, aborting the connection. Implementation is in
`handleMITM` — both the SNI check (S1) and the Host header check (U1) are
active.

**Residual risk:** Correctly implemented. No known residual risk for the
host/SNI/CONNECT triple-check. However, wildcard rule depth (U3) is not yet
implemented — a rule for `*.googleapis.com` could match a deeper subdomain
controlled by an attacker if depth-limiting is absent.

**Severity: P2** (well-mitigated; residual only for wildcard rules not yet
deployed)

---

### T3 — Sentinel Token Substitution Race (P3: Medium)

**Description:** The agent deliberately races two concurrent requests through
the proxy: a token-refresh request to the OAuth endpoint and an API call to
the same destination. If the proxy's `OAuthRefreshMutator` writes the cached
real token between the moment the second request reads it and the moment it
injects it into the outgoing request, a timing window might allow the agent to
observe a real token.

**Prerequisites:** Requires the agent to control request timing precisely;
requires an observable side channel (e.g., timing, error message difference).
The real token is never written to the response sent to the container.

**Impact:** Real tokens are cached in proxy memory and never sent to the
container in any response body. The mutation writes a dummy sentinel into the
response before it reaches the container. No race condition in the current code
exposes a real token to the client side of the connection.

**Current mitigation:** `OAuthRefreshMutator` uses a `sync.RWMutex`; the cache
is written only after `json.Marshal` succeeds (S1); the response body returned
to the container always contains the dummy sentinel, not the real token.

**Residual risk:** The race is not exploitable for credential exfiltration
given the current architecture. The container never receives a real token in
any code path. Risk is low.

**Severity: P3**

---

### T4 — Token Printing via Tool Commands (P2: High)

**Description:** The agent, when prompted to display credentials for
"debugging purposes," runs `gcloud auth print-access-token` or
`gcloud auth application-default print-access-token`. If the container holds a
real credential in the ADC file, this command prints it to stdout where the
agent can capture and exfiltrate it.

**Prerequisites:** The agent has access to the `gcloud` CLI and a real ADC file
in the container.

**Impact:** Complete exfiltration of the OAuth access token (short-lived but
usable for up to 1 hour).

**Current mitigation:** By design, the container holds only a dummy sentinel
value in the ADC file. The `gcloud` binary would attempt to print the sentinel,
not a real token. Additionally, the `agent-run` wrapper is planned to install a
shell alias that rejects `print-access-token` with a clear error.

**Residual risk:** If the wrapper alias is absent or bypassed (e.g., the agent
uses the full path `/usr/lib/google-cloud-sdk/bin/gcloud`), the sentinel string
is printed. The sentinel is not a usable credential. However, if the container
ADC file is populated with a real token (operator error in setup), this attack
succeeds. The isolation guarantee depends on the operator never placing real
credentials in the container.

**Severity: P2** (mitigated by design; residual risk from operator
misconfiguration)

---

### T5 — DNS Exfiltration of Derived Secrets (P3: Medium)

**Description:** A rogue agent that cannot exfiltrate credentials directly
may attempt to exfiltrate derived information via DNS. For example, if the
agent can observe the timing of proxy responses or the structure of error
messages, it could encode this information in DNS queries to an
attacker-controlled domain.

**Prerequisites:** Unfiltered outbound UDP port 53; attacker controls a
domain with a logging nameserver; agent can distinguish proxy behavior.

**Impact:** Low-bandwidth exfiltration channel. Unlikely to carry enough
information to reconstruct real credentials (the proxy does not include real
tokens in any observable side channel), but could leak session metadata,
request paths, or timing patterns.

**Current mitigation:** None. DNS is not filtered or proxied. The proxy does
not leak real token values in timing or error messages.

**Residual risk:** DNS exfiltration of non-credential metadata is possible.
Real credentials cannot be exfiltrated this way — the proxy never exposes them
to the container.

**Severity: P3**

---

### T6 — Container Escape to Host Credential Store (P1: Critical)

**Description:** A rogue agent exploits a container runtime vulnerability,
kernel vulnerability, or misconfigured capability (e.g., `CAP_SYS_ADMIN`,
writable `/proc/sys`) to escape the container and access the host filesystem
where real credentials are stored.

**Prerequisites:** An exploitable vulnerability in the container runtime, kernel,
or host configuration; container running with excessive capabilities.

**Impact:** Complete compromise of all credentials stored on the host. The
sentinel model provides no protection against a container escape.

**Current mitigation:** Podman rootless containers with default capabilities.
The proxy and host service run under a separate UID (`agent-proxy` user) with
systemd hardening (`ProtectSystem=strict`, `PrivateTmp=true`,
`NoNewPrivileges=yes`). Credentials should be stored with file permissions
readable only by the proxy user.

**Residual risk:** Container escape remains a critical risk that the proxy
cannot prevent at the application layer. Defense depends on kernel/runtime
patch hygiene, minimal capabilities, and seccomp/AppArmor profiles. This
is a known limitation of any containerization-based isolation.

**Severity: P1**

---

### T7 — Cross-Container Credential Theft via Socket Path Guessing (P2: High)

**Description:** In a multi-container deployment, each container receives a
Unix socket at a predictable path (e.g., `/run/agent-proxy/sessions/<id>.sock`
bind-mounted into the container). A rogue agent in container A could attempt
to connect to container B's socket if the session ID is guessable or if the
bind mount exposes the parent directory.

**Prerequisites:** Session IDs are guessable; or the parent `/run/agent-proxy/sessions/`
directory is bind-mounted rather than individual socket files.

**Impact:** Container A could obtain credentials intended for container B —
enabling cross-tenant credential theft in multi-user or multi-project
deployments.

**Current mitigation (planned):** Per-container sockets are created by
`agent-run` and bind-mounted by path into only that container's filesystem
namespace. The session ID should be a cryptographically random value (128
bits), making guessing infeasible. The parent directory is NOT bind-mounted.

**Residual risk:** Design is sound if implemented correctly. Risk is in
implementation errors (predictable session IDs, directory-level mounts).
This is a Phase 3d item — not yet implemented.

**Severity: P2** (design sound; implementation risk until Phase 3d ships)

---

### T8 — Token Metadata Endpoint Abuse (P3: Medium)

**Description:** The planned token metadata endpoint (`GET /metadata/token?aud=X`
on the per-container socket) returns JWT claims (sub, iss, aud, exp, scopes)
without the raw token. The `POST /sign?blob=<base64>` endpoint performs signing
with the session JWT key. A rogue agent could abuse these endpoints to:
(a) enumerate the proxy's knowledge of the container's identity, or
(b) request signatures over arbitrary blobs for use outside the proxy context.

**Prerequisites:** Access to the per-container Unix socket (the agent always
has this); knowledge of the endpoint API.

**Impact:** (a) Low — metadata is claims only, no raw tokens. (b) Medium —
signed blobs could be replayed if the signing key is trusted outside this
proxy session. The session JWT key is ephemeral; signatures expire with the
session.

**Current mitigation (planned):** Metadata endpoint returns claims only.
Sign endpoint scope should be restricted to blobs the proxy recognizes as
legitimate (e.g., signed assertion payloads with `aud` matching an allowlisted
destination). Unrestricted signing would be a design flaw.

**Residual risk:** The sign endpoint design needs explicit scope restriction to
prevent signature oracle abuse. This must be defined before Phase 3e ships.

**Severity: P3**

---

### T9 — Credential Injection into Non-Allowlisted Destination via Wildcard Rule (P2: High)

**Description:** If a wildcard rule is configured (e.g., `*.googleapis.com`),
a rogue agent could perform a CONNECT to `attacker.googleapis.com` (a
subdomain registered by the attacker, or a DNS rebinding target). The proxy
would match the rule, generate a cert for `attacker.googleapis.com`, inject
real credentials, and forward the request — effectively handing the attacker
real credentials.

**Prerequisites:** A wildcard rule is configured; the attacker controls a
subdomain under the wildcard (or can perform DNS rebinding); the proxy does
not validate IP ranges.

**Impact:** Real credential exfiltration to an attacker-controlled server.

**Current mitigation (planned):** Wildcard rules are depth-limited (one
label only). Optional IP range validation against the destination's published
ranges (e.g., Google's netblock TXT records) is planned as a defence-in-depth
measure (U3).

**Residual risk:** Without IP range validation, the depth limit alone is
insufficient if the attacker can register a subdomain or perform DNS rebinding.
Operators should enable IP range validation for wildcard rules in production.

**Severity: P2**

---

## 5. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│  HOST                                                       │
│                                                             │
│  ┌──────────────────┐        ┌───────────────────────────┐  │
│  │  agent-proxy     │        │  Credential Store         │  │
│  │  (agent-proxy    │◄──────►│  (refresh tokens, PATs,   │  │
│  │   user, systemd) │        │   private keys)           │  │
│  └────────▲─────────┘        │  (proxy user access only) │  │
│           │ Unix socket       └───────────────────────────┘  │
│           │ (per-container)                                  │
│  ─────────┼─────────────────── Trust Boundary A ──────────  │
│           │                    (Container ↔ Proxy)          │
│  ┌────────▼─────────────────────────────┐                   │
│  │  Container (Podman rootless)         │                   │
│  │                                      │                   │
│  │  AI Agent Process                    │                   │
│  │  ┌───────────────────────────────┐   │                   │
│  │  │  Sentinel tokens only        │   │                   │
│  │  │  Ephemeral fake keys         │   │                   │
│  │  │  Proxy CA cert (public)      │   │                   │
│  │  └───────────────────────────────┘   │                   │
│  │                                      │                   │
│  │  nftables: port 80/443 → proxy       │                   │
│  └──────────────────────────────────────┘                   │
│                                                             │
└────────────────────────────────┬────────────────────────────┘
                                 │ Trust Boundary B
                                 │ (Proxy ↔ Upstream)
                          ┌──────▼──────────┐
                          │  Upstream APIs   │
                          │  (GitHub, GCP,   │
                          │   npm, etc.)     │
                          └─────────────────┘
```

**Trust Boundary A — Container to Proxy:**

- Container is untrusted. Any data arriving from the container must be
  treated as potentially adversarial.
- The proxy validates CONNECT authority, SNI, and Host header before
  injecting credentials.
- Credentials flowing toward the container are always sentinels; real tokens
  flow only toward upstream (outbound direction).
- The per-container Unix socket is the identity anchor. The socket path is
  the credential selection key.

**Trust Boundary B — Proxy to Upstream:**

- The proxy presents real credentials to upstream. Upstream is trusted to
  respond authentically.
- The proxy's TLS client verifies upstream certificates normally (no MITM
  in the outbound direction — only inbound from container).
- If an upstream is compromised, it could return malicious responses that
  the agent processes — but this is out of scope for the credential isolation
  model.

**Container to Container:**

- Containers share no network namespace, no filesystem, and no Unix sockets
  (when per-container socket design is correctly deployed).
- Cross-container isolation depends on the operator not sharing mounts or
  network namespaces between containers.

---

## 6. Security Invariants

The following properties MUST hold at all times for the system to provide
its security guarantees. A violation of any invariant is a critical defect.

**I1 — Real credentials never enter the container.**
No real refresh token, PAT, private key, or access token may appear in any
container process's memory, environment, filesystem, or any network response
sent to the container. Only sentinels and ephemeral fake keys are permitted.

**I2 — Credential injection is destination-locked.**
A real credential for destination X may only be injected into a request whose
CONNECT authority, TLS SNI, and HTTP Host header all agree and all equal X.
Any disagreement must cause rejection, not injection.

**I3 — Sentinels are not transferable.**
A sentinel token recognized by the proxy is meaningless outside the proxy
context. Sentinels must not be valid credentials at any real service — they
must be rejected by any upstream that receives them directly.

**I4 — The proxy CA is not a general-purpose CA.**
The proxy CA may only sign leaf certificates for explicitly allowlisted
hostnames. The CA must not be usable to impersonate arbitrary HTTPS servers
outside the allowlist. (Implementation note: the current prototype does not
enforce this — the CA can sign for any hostname. Phase 3d must add hostname
restriction to cert generation.)

**I5 — Per-container identity is unforgeable.**
A container must not be able to obtain credentials intended for another
container. This requires session IDs to be cryptographically random and
Unix socket paths to not be guessable or shared.

**I6 — The proxy does not log real credentials.**
No logging statement in the proxy may emit a real token, refresh token,
private key, or any other sensitive credential. Sentinels may be logged.

**I7 — Allowlist bypass is not possible via the proxy.**
The proxy must not forward authenticated requests to destinations not on
the allowlist, even if the CONNECT target is allowlisted. The three-way
host check (I2) enforces this for the Host header; the nftables enforcement
covers the network layer.

**I8 — Token endpoint responses reaching the container contain only sentinels.**
After a successful OAuth token exchange, the response body written to the
container must contain the dummy access token and dummy refresh token. The
real values must be retained in proxy memory only and must never appear in
the byte stream sent to the container socket.

---

## 7. Invariant Violations in Current Prototype

The following known gaps exist in the Phase 3a prototype relative to the
invariants above. These are scheduled for remediation in later phases.

| Invariant | Gap | Remediation Phase |
|-----------|-----|-------------------|
| I4 | CA signs certs for any hostname, not just allowlisted hosts | Phase 3d |
| I5 | Per-container socket identity not yet implemented | Phase 3d |
| I7 | nftables netns redirect not yet implemented; proxy relies on HTTP_PROXY env var as fallback | Phase 3e |
| I8 | OAuthRefreshMutator implemented but not wired to nftables enforcement | Phase 3e integration |

Invariants I1, I2, I3, I6, and I8 are upheld by the current Phase 3a/3b
implementation for the tested tool set (google-auth, pip, npm, gh).
