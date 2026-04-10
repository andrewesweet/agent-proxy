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

**OWASP:** LLM01 (Indirect Prompt Injection), ASI01 (Agent Goal Hijack)

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

**OWASP:** LLM01 (Indirect Prompt Injection), ASI01 (Agent Goal Hijack)

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

**OWASP:** LLM02 (Sensitive Information Disclosure via model outputs)

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

**OWASP:** ASI02 (Tool Misuse and Exploitation — tool chaining example)

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

**OWASP:** ASI05 (Unexpected Code Execution)

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

### T10 — Proxy Configuration Tampering (P2: High)

**OWASP:** LLM04 (Data and Model Poisoning) — configuration as "trusted
training data" analogue.

**Description:** A host process, supply chain attack, or operator error
modifies the proxy's config file (allowlist rules, credential mappings)
to cause credential injection into attacker-controlled destinations.

**Preconditions:** Write access to the config file, or ability to
substitute the file via another path (symlink, race condition).

**Impact:** Real credentials routed to attacker-controlled endpoints on
every request matching the tampered rule. Potentially affects all
containers sharing the proxy.

**Current mitigation:** Phase 3d-1 must treat the config file as a trust
boundary:
- Config file readable/writable only by proxy user (mode `0600`)
- Strict YAML parsing (reject unknown fields) already planned
- Reject `host` values containing `:` or `://` already planned
- Consider: log SHA-256 hash of config at startup for tamper detection

**Residual risk:** Tamper detection is not yet implemented. A compromised
host process with write access to the config path can redirect credential
injection without detection until the proxy is restarted.

**Severity: P2**

---

### T11 — Credential Scope Excessive Agency (P3: Medium)

**OWASP:** LLM06 (Excessive Agency) — Excessive Permissions sub-category.

**Description:** The proxy injects write-capable credentials
(e.g., GitHub PAT with `repo` scope) where the agent's task only
requires read access. Even without active compromise, this architecture
violates least privilege at the credential level and directly enables
A10 (data exfiltration via legitimate API writes).

**Preconditions:** Static credential configuration without per-operation
scope selection.

**Impact:** A prompt-injected agent can perform write operations
(create gists, push code, delete repos) using credentials that should
have been read-only.

**Current mitigation:** None. The proxy injects whatever credential is
configured for the rule, regardless of the HTTP method used. Active
architectural enabler of A10 — the proxy provides no method-level
friction against write operations.

**Residual risk:** Future enhancement — per-rule read-only/write-capable
credential variants. Rules should select the lowest-scope credential
sufficient for the operation. At minimum, log warnings when write
methods (POST/PUT/PATCH/DELETE) are forwarded.

**Severity: P3** (architectural gap that is an active enabler of A10,
not an independent attack vector by itself)

---

### T12 — Denial of Wallet via Authenticated API Flood (P2: High)

**OWASP:** LLM10 (Unbounded Consumption).

**Description:** A rogue agent floods allowlisted APIs (especially GCP
Vertex AI) with authenticated requests through the proxy, exhausting
usage quotas and generating cost overruns. The proxy currently has no
per-container request rate limiting. A rogue agent can exhaust a GCP
Vertex AI budget in minutes.

**Preconditions:** Active prompt injection, write-capable credentials
on a pay-per-use API.

**Impact:** Financial loss (API quota costs), rate limit exhaustion
affecting legitimate operations, potential account suspension. Financial
impact is immediate (next billing cycle), not speculative.

**Current mitigation:** None at proxy layer. Defense in depth: cloud
provider billing alerts.

**Residual risk:** Per-container rate limiting (already in STRIDE P3
recommendations) would bound this. Until implemented, a rogue agent can
exhaust API quotas without limit.

**Severity: P2** (elevated from P3 — financial impact is immediate and
matches the severity of T9 and T14; a rogue agent can exhaust a GCP
Vertex AI budget within minutes)

---

### T13 — Persistent Memory Poisoning (P3: Medium)

**OWASP:** ASI06 (Memory and Context Poisoning), OWASP Agentic T01.

**Description:** A malicious repository indexes content into the AI
agent's persistent memory (Claude Code's `CLAUDE.md`, `~/.claude/`
memory files, conversation summaries). Subsequent sessions with no
attacker involvement exhibit the planted behavior — a "zero-click"
variant of prompt injection.

**Preconditions:** Agent opens a malicious repository that writes to
or influences the agent's memory store. No active attacker required at
exploitation time.

**Impact:** Delayed, persistent attack surface. Credentials used in
future sessions are at risk from behavior planted in prior sessions.

**Current mitigation:** Out of scope for agent-proxy — defense is at the
agent memory layer (namespace isolation, memory content validation,
clearing between sessions for untrusted projects). Out of scope absent
container escape (T6). If T6 succeeds, a rogue agent can modify
host-side agent memory files (e.g., `CLAUDE.md`, `~/.claude/memory/`),
making T13 exploitable outside any container.

**Residual risk:** agent-proxy cannot mitigate this threat. It is a
known residual risk that operators must address at the agent layer.
**Must be documented as a known threat that agent-proxy cannot mitigate.**

**Severity: P3**

---

### T14 — Multi-Agent Confused Deputy (P2: High)

**OWASP:** ASI07 (Insecure Inter-Agent Communication), OWASP Agentic
T12/T16.

**Description:** In a multi-agent deployment, a compromised orchestrator
agent instructs a sub-agent (via A2A, MCP, or inter-process calls) to
make specific authenticated API calls. The sub-agent's proxy-injected
credentials are used to perform actions the orchestrator cannot perform
directly because its own container has different credential scope.

**Preconditions:** Multi-agent deployment with cross-container
communication. Compromised orchestrator. Per-container credential
isolation alone is insufficient because the attack uses the
sub-agent's legitimate credentials.

**Impact:** Credential scope escalation across container boundaries.
The sub-agent's allowlisted operations become the attacker's tools.

**Current mitigation:** Partial — per-container credential scoping
(Phase 3d-4) limits blast radius per container. Full mitigation requires
A2A/MCP authentication at the agent layer. Add inter-container request
correlation to the audit log. Note: the sub-agent does not gain new
privileges — it uses its own legitimately held credentials while being
deceived by the compromised orchestrator.

**Residual risk:** Until Phase 3d-4 ships, all containers share the same
mutator state. After Phase 3d-4, the cross-agent orchestration path
remains a threat that agent-proxy cannot fully address. A simplified
form is already exploitable today via A11 (shared OAuthRefreshMutator
across containers in the current prototype).

**Severity: P2** (Current — simplified form exploitable now via A11;
near-future — full multi-agent confused deputy as multi-agent deployments
grow)

---

### T15 — Package Registry as Exfiltration Channel (P2: High)

**OWASP:** ASI02 (Tool Misuse and Exploitation), OWASP Agentic T02.

**Description:** An agent uses the proxy-injected npm/PyPI/crates.io
publish credentials to upload a package containing exfiltrated secrets,
private code, or environment data. The proxy sees only a legitimate
POST to the registry's publish endpoint.

**Preconditions:** Write-capable registry token in the proxy's rule set
for a registry that supports user-writable publish.

**Impact:** Supply chain compromise (poisoned package visible to other
users), data exfiltration (secrets embedded in package metadata or
README), attribution attack (package published under the developer's
name).

**Current mitigation:** Same as A10 — the proxy cannot distinguish
legitimate from adversarial publishes.

**Residual risk:** Policy-layer defense: publish tokens are out of scope
for default allowlists; include only when explicitly needed for the task.

Note: T15 is a supply-chain variant of A10, not an independent threat
mechanism. T15 is distinct from A10 in the supply-chain externality
(third-party impact — other users who install the poisoned package) and
the developer attribution angle, but the underlying mechanism (using
proxy-injected write credentials for adversarial API writes) is identical
to A10. See also A14 in the red-team model for a concrete instantiation.

**Severity: P2**

---

### T16 — Reverse Shell Persistence (P2: High)

**OWASP:** ASI05 (Unexpected Code Execution), OWASP Agentic T11.

**Description:** A rogue agent generates and executes code that
establishes a reverse shell listener inside the container. This gives
a human attacker direct control, allowing manual exploitation of all
A1–A13 scenarios at human speed with full context awareness.

**Preconditions:** Arbitrary code execution inside the container
(standard for coding agents).

**Impact:** The "rogue agent" threat actor becomes "rogue agent +
human operator." Attacks can be iteratively refined against specific
proxy behaviors.

**Current mitigation:** None. The current prototype has no egress
filtering for ports outside 80/443. `CAP_NET_BIND_SERVICE` governs
binding ports below 1024 and is irrelevant to outbound reverse shells.
The nftables egress redirect (ports 80/443) is planned for Phase 3d, not
yet implemented. A reverse shell on port 4444 (TCP) works today without
any proxy interaction — no capability restriction prevents outbound TCP
on arbitrary ports.

**Planned mitigation (Phase 3d):** nftables rules blocking all outbound
TCP except via the proxy. This would force reverse shells to use an
allowlisted destination as a covert C2 channel.

**Residual risk:** Even with Phase 3d nftables enforcement, the proxy's
allowlist does not prevent a reverse shell from using allowlisted
destinations as a covert channel (e.g., polling a GitHub Gist for
commands, POSTing output to a webhook). Full mitigation requires both
port-level egress filtering and API-layer request inspection.

**Severity: P2**

---

### T17 — MCP Tool Descriptor Poisoning (P2: High)

**OWASP:** ASI04 (Agentic Supply Chain Vulnerabilities), OWASP Agentic T17.

**Description:** A malicious MCP (Model Context Protocol) server
provides tool descriptors that instruct the agent to probe proxy gaps
— crafting CONNECT requests optimized for T9 (wildcard bypass), A2
(DNS poisoning), or A3 (timing side channel). This creates a supply
chain at the agent's tool invocation layer.

**Preconditions:** Agent configured to use an attacker-controlled MCP
server (legitimate-looking, published on a marketplace, or substituted
via dependency confusion).

**Impact:** The attacker directs the agent's network behavior with
precision, targeting specific known proxy gaps. Unlike generic prompt
injection, this is tuned to the proxy's architecture.

**Current mitigation:** The proxy enforces the allowlist regardless of
MCP instructions.

**Residual risk:** Defense at the agent operator layer: pin MCP server
versions, verify attestation, audit MCP server sources. agent-proxy
cannot prevent a permitted agent action from being directed by a
malicious MCP descriptor.

Note: The attack MECHANISM for T17 is identical to T1.1 (prompt
injection via conversation); T17 is distinct only in the DELIVERY
CHANNEL — a structured, machine-readable MCP tool descriptor rather
than a natural-language instruction embedded in conversation or file
content. MCP descriptors execute without subjective evaluation by the
agent, making this delivery channel potentially more reliable than
generic prompt injection, but the proxy-layer defenses are identical.

**Severity: P3** (reduced from P2 — the mechanism is a specific
delivery-channel variant of prompt injection, not a new class of attack;
proxy-layer defenses cover both equally)

---

### T18 — TOCTOU on Configuration Change (P3: Medium)

**OWASP:** ASI03 (Identity and Privilege Abuse) — workflow authorization
drift.

**Description:** An operator revokes a credential or removes a
destination from the allowlist while an agent session is active.
In-flight requests may still inject the now-revoked credential
because the proxy resolves rules once at startup and does not re-read
on SIGHUP.

**Preconditions:** Configuration change during active session. No
session draining before rule application.

**Impact:** Revoked credentials continue to be used until the proxy
restarts. Policy changes don't take effect as expected.

**Current mitigation:** The current behavior is documented: config is
read once at startup. Note: T18 describes behavior of the PLANNED
Phase 3d-1 config file, not the current prototype — the current
prototype (Phase 3a/3b) has no config file; rules are provided via
CLI flags at startup and cannot be changed without restart. This threat
should be re-framed as a design requirement for Phase 3d-1: the config
reload mechanism must include request draining and atomic rule
replacement to prevent TOCTOU windows.

**Residual risk:** Future: SIGHUP reload with request draining, or
per-session rule snapshot at connection time.

**Severity: P3**

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

Invariants I1, I2, I3, and I6 are upheld by the current Phase 3a/3b
implementation for the tested tool set (google-auth, pip, npm, gh).

I8 is upheld only for `OAuthRefreshMutator` — the `MutateResponse`
method on that type performs token scrubbing and dummy-sentinel
substitution. `OAuthBearerMutator.MutateResponse` and
`staticTokenMutator.MutateResponse` are both no-ops; they do not scrub
responses. I8's coverage therefore depends on which mutator type is
configured for the relevant host. Invariant I8 should be read as:
"applies to hosts configured with an `OAuthRefreshMutator` rule type;
not guaranteed for `static` or `oauth_bearer` rule types."

---

## 8. Known Residual Risks (Out-of-Scope OWASP Items)

agent-proxy operates at the network layer and cannot address the following
OWASP items. Operators must address these at other layers. These are documented
here so that operators understand which threats the proxy explicitly does not
mitigate.

| OWASP Item | Why Out of Scope |
|------------|-----------------|
| LLM01 prompt injection *prevention* | Happens inside the model. Proxy limits blast radius only. |
| LLM02 context window leakage detection | Proxy cannot inspect semantic content of requests. |
| LLM03 AI model supply chain | Model weights and adapters invisible to the proxy. |
| LLM08 vector/embedding weaknesses | No RAG component in agent-proxy. |
| LLM09 misinformation / hallucinated packages | Proxy cannot evaluate truthfulness of agent output. |
| ASI06 memory poisoning *prevention* | Proxy does not control persistent agent memory. See T13. |
| ASI07 inter-agent message authentication | Agent framework responsibility. See T14. |
| ASI09 human-agent trust / social engineering | Proxy has no visibility into conversational output. |
| Governance RACI / legal / training | Organizational, not technical controls. |

These residual risks are inherent to the network-layer credential injection
architecture. Deployments requiring protection against these items must apply
additional controls at the agent, model, and organizational layers.
