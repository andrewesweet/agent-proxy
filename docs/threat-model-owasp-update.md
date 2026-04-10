# Threat Model Update: OWASP LLM and Agentic AI Alignment

**Date:** 2026-04-09
**Source documents:**
- OWASP Top 10 for LLM Applications 2025 (LLM01–LLM10)
- OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10)
- OWASP Agentic AI Threats and Mitigations v1.1 (T01–T17)
- OWASP LLM AI Security and Governance Checklist v1.1

**Scope:** Updates to `threat-model.md`, `threat-model-red-team.md`,
`threat-model-stride.md` based on OWASP guidance.

---

## New Threats to Add

### T10 — Proxy Configuration Tampering

**OWASP mapping:** LLM04 (Data and Model Poisoning) — configuration as
"trusted training data" analogue.

**Description:** A host process, supply chain attack, or operator error
modifies the proxy's config file (allowlist rules, credential mappings)
to cause credential injection into attacker-controlled destinations.

**Preconditions:** Write access to the config file, or ability to
substitute the file via another path (symlink, race condition).

**Impact:** Real credentials routed to attacker-controlled endpoints on
every request matching the tampered rule. Potentially affects all
containers sharing the proxy.

**Severity:** P2

**Mitigation:** Phase 3d-1 must treat the config file as a trust
boundary:
- Config file readable/writable only by proxy user (mode `0600`)
- Strict YAML parsing (reject unknown fields) already planned
- Reject `host` values containing `:` or `://` already planned
- Consider: log SHA-256 hash of config at startup for tamper detection

---

### T11 — Credential Scope Excessive Agency

**OWASP mapping:** LLM06 (Excessive Agency) — Excessive Permissions
sub-category.

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

**Severity:** P3 (architectural gap, not an active attack vector by
itself, but the enabling condition for A10)

**Mitigation:** Future enhancement — per-rule read-only/write-capable
credential variants. Rules should select the lowest-scope credential
sufficient for the operation. At minimum, log warnings when write
methods (POST/PUT/PATCH/DELETE) are forwarded.

---

### T12 — Denial of Wallet via Authenticated API Flood

**OWASP mapping:** LLM10 (Unbounded Consumption).

**Description:** A rogue agent floods allowlisted APIs (especially GCP)
with authenticated requests through the proxy, exhausting usage quotas
and generating cost overruns. The proxy currently has no per-container
request rate limiting.

**Preconditions:** Active prompt injection, write-capable credentials
on a pay-per-use API.

**Impact:** Financial loss (API quota costs), rate limit exhaustion
affecting legitimate operations, potential account suspension.

**Severity:** P3

**Mitigation:** Per-container rate limiting (already in STRIDE P3
recommendations). Defense in depth: cloud provider billing alerts.

---

### T13 — Persistent Memory Poisoning

**OWASP mapping:** ASI06 (Memory and Context Poisoning), OWASP
Agentic T01.

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

**Severity:** P3

**Mitigation:** Out of scope for agent-proxy — defense is at the agent
memory layer (namespace isolation, memory content validation, clearing
between sessions for untrusted projects). **Must be documented as a
known threat that agent-proxy cannot mitigate.**

---

### T14 — Multi-Agent Confused Deputy

**OWASP mapping:** ASI07 (Insecure Inter-Agent Communication), OWASP
Agentic T12/T16.

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

**Severity:** P2 (near-future as multi-agent deployments grow)

**Mitigation:** Partial — per-container credential scoping (Phase 3d-4)
limits blast radius per container. Full mitigation requires A2A/MCP
authentication at the agent layer. Add inter-container request
correlation to the audit log.

---

### T15 — Package Registry as Exfiltration Channel

**OWASP mapping:** ASI02 (Tool Misuse and Exploitation), OWASP Agentic
T02.

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

**Severity:** P2

**Mitigation:** Same as A10 — the proxy cannot distinguish legitimate
from adversarial publishes. Policy-layer defense: publish tokens are
out of scope for default allowlists; include only when explicitly
needed for the task.

---

### T16 — Reverse Shell Persistence

**OWASP mapping:** ASI05 (Unexpected Code Execution), OWASP Agentic T11.

**Description:** A rogue agent generates and executes code that
establishes a reverse shell listener inside the container. This gives
a human attacker direct control, allowing manual exploitation of all
A1–A13 scenarios at human speed with full context awareness.

**Preconditions:** Arbitrary code execution inside the container
(standard for coding agents).

**Impact:** The "rogue agent" threat actor becomes "rogue agent +
human operator." Attacks can be iteratively refined against specific
proxy behaviors.

**Severity:** P2

**Mitigation:** Container capability restrictions (no
`CAP_NET_BIND_SERVICE`, seccomp filters, nftables egress rules
preventing inbound connections). The proxy's allowlist limits C2
destinations for the reverse shell.

---

### T17 — MCP Tool Descriptor Poisoning

**OWASP mapping:** ASI04 (Agentic Supply Chain Vulnerabilities), OWASP
Agentic T17.

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

**Severity:** P2

**Mitigation:** The proxy enforces the allowlist regardless of MCP
instructions. Defense at the agent operator layer: pin MCP server
versions, verify attestation, audit MCP server sources.

---

### T18 — TOCTOU on Configuration Change

**OWASP mapping:** ASI03 (Identity and Privilege Abuse) — workflow
authorization drift.

**Description:** An operator revokes a credential or removes a
destination from the allowlist while an agent session is active.
In-flight requests may still inject the now-revoked credential
because the proxy resolves rules once at startup and does not re-read
on SIGHUP.

**Preconditions:** Configuration change during active session. No
session draining before rule application.

**Impact:** Revoked credentials continue to be used until the proxy
restarts. Policy changes don't take effect as expected.

**Severity:** P3

**Mitigation:** Document the current behavior (config is read once at
startup). Future: SIGHUP reload with request draining, or per-session
rule snapshot at connection time.

---

## Existing Threats to Reframe with OWASP Terminology

| Existing ID | New OWASP Framing |
|-------------|-------------------|
| T1.1, T1.2 (Threat Actors) | **LLM01 (Indirect Prompt Injection)** + **ASI01 (Agent Goal Hijack)** |
| A10 (Data exfiltration via legitimate APIs) | **LLM05 (Improper Output Handling)** + **LLM06 (Excessive Agency)** + **ASI02 (Tool Misuse and Exploitation)** |
| A9, STRIDE DoS findings | **LLM10 (Unbounded Consumption)** |
| A11 (Shared OAuthRefreshMutator) | **ASI03 (Identity and Privilege Abuse) — Memory-based privilege retention** |
| A13 (Sibling container MITM) | **ASI10 (Rogue Agents) — Infectious logic variant** |
| T4 (print-access-token output) | **LLM02 (Sensitive Information Disclosure via model outputs)** |
| T5 (DNS exfiltration) | **ASI02 (Tool Misuse) — tool chaining example from OWASP doc** |
| T6 (Container escape) | **ASI05 (Unexpected Code Execution)** |

---

## Governance Gaps (from OWASP LLM Security and Governance Checklist)

### G1 — Tamper-evident structured audit log (Priority: High)

**Checklist item:** "Confirm audit records are secure."

**Current state:** JSON slog to stderr (systemd journal). No per-session
correlation, no request body hashing, deletable by root.

**Required:** Append-only audit log with: timestamp, container session
ID, method, host, path, HTTP status, request-body SHA-256, real
credential identity (not value). Forward to external SIEM for
tamper-evidence.

**Addresses:** A10 forensics, STRIDE Repudiation findings, Denial of
Wallet detection.

---

### G2 — Least-privilege credential injection per rule (Priority: High)

**Checklist item:** "Implement least privilege access controls."

**Current state:** Rules inject a single static credential regardless
of operation type.

**Required:** Rules should support read-only and write-capable
credential variants. Write operations trigger audit warnings. A future
mutator could downgrade credential scope where possible (e.g., mint
a read-only derived token).

**Addresses:** T11, A10 root cause.

---

### G3 — Security invariant test suite (Priority: Medium)

**Checklist item:** "Establish continuous testing, evaluation,
verification, and validation."

**Current state:** Integration tests cover functional behavior. No
tests directly assert security invariants I1–I8.

**Required:** Automated tests asserting:
- No real credential value appears in container-side byte streams
- Sentinel tokens are rejected at real upstream endpoints
- Three-way CONNECT/SNI/Host agreement enforcement
- CA signing restricted to allowlisted hosts (when NameConstraints are added)

**Addresses:** Regression prevention, governance verifiability.

---

### G4 — Incident response playbook (Priority: Medium)

**Checklist item:** "Update the Incident Response Plan and playbooks."

**Current state:** None.

**Required:** Short runbook covering detection, containment, recovery,
and evidence preservation for:
- Suspected credential exfiltration via A10
- Compromised agent session detection
- CA key compromise
- Upstream DNS poisoning / A2

**Addresses:** Response capability for detected incidents.

---

### G5 — Anomaly detection / credential usage accounting (Priority: Medium)

**Checklist item:** "Map workflows, monitoring, and responses."

**Current state:** Per-request slog entries, no aggregation, no
baseline, no alerting.

**Required:** Per-container request rate baseline and anomaly
alerting. Credential usage reports ("container X made N writes to
GitHub today").

**Addresses:** T12 (Denial of Wallet), gradual A10 exfiltration
detection.

---

## Out-of-Scope OWASP Items

agent-proxy operates at the network layer and cannot address:

| OWASP Item | Why Out of Scope |
|------------|------------------|
| LLM01 prompt injection *prevention* | Happens inside the model. Proxy limits blast radius only. |
| LLM02 context window leakage detection | Proxy cannot inspect semantic content of requests. |
| LLM03 AI model supply chain | Model weights and adapters invisible to the proxy. |
| LLM08 vector/embedding weaknesses | No RAG component in agent-proxy. |
| LLM09 misinformation / hallucinated packages | Proxy cannot evaluate truthfulness of agent output. |
| ASI06 memory poisoning *prevention* | Proxy does not control persistent agent memory. |
| ASI07 inter-agent message authentication | Agent framework responsibility. |
| ASI09 human-agent trust / social engineering | Proxy has no visibility into conversational output. |
| Governance RACI / legal / training | Organizational, not technical controls. |

These should be documented in the threat model as **known residual
risks** — operators must address them at other layers.

---

## Recommended Updates to Existing Documents

**`docs/threat-model.md`:**
- Add T10–T18 as new threat scenarios in Section 4
- Add OWASP mapping column to the threat scenario table in Section 7
- Add "Known Residual Risks" section listing out-of-scope OWASP items
- Annotate T1.1/T1.2 with OWASP terms (LLM01, ASI01)

**`docs/threat-model-red-team.md`:**
- Add A14 (npm publish exfiltration)
- Add A15 (reverse shell persistence)
- Add A16 (MCP tool descriptor poisoning)
- Annotate A10 with LLM05/LLM06/ASI02 framing
- Annotate A11 with ASI03 framing
- Annotate A13 with ASI10 framing

**`docs/threat-model-stride.md`:**
- Add Repudiation row for T13 (memory poisoning — forensic trail loss)
- Add Information Disclosure row for T15 (package registry exfiltration)
- Add Elevation of Privilege row for T14 (multi-agent confused deputy)
- Add recommendations G1–G5 to the top-recommendations section

**`docs/design-decisions.md`:**
- Phase 3d-1 (config file) must document T10 mitigation explicitly
- Phase 3d-4 (per-container identity) must address T14, T18
- Add a new deferred phase for G1 (audit logging) and G2 (credential
  scope selection)
