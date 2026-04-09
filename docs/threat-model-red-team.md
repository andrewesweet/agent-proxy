# Red Team Threat Model: agent-proxy

**Date:** 2026-04-06
**Perspective:** Rogue AI agent inside the Podman container
**Objective:** Exfiltrate real credentials or escalate to host

---

## Attacker Context

I am an AI coding agent running inside a Podman container. I know:
- The proxy injects real credentials on my outbound HTTPS traffic
- I only see dummy sentinel tokens (e.g., `ya29.proxy-sentinel`)
- HTTPS traffic on port 443 is redirected to the proxy via nftables (planned)
- The proxy performs MITM TLS inspection using a CA cert injected into my trust store
- The proxy only intercepts allowlisted destinations; non-listed hosts are rejected (403) by default

---

## A1 — Credential Exfiltration via Response Observation

**Attack:** The proxy injects my real token into the `Authorization` header when it forwards my request upstream. The real server responds with a 200. I observe the *behaviour* of the response — rate limits, account-specific data, error messages — to infer token scope or identity without seeing the token itself. I also observe the `X-OAuth-Scopes`, `X-Accepted-OAuth-Scopes`, `X-RateLimit-*`, and `Link` headers that GitHub returns, which reveal exactly what scopes the real credential has.

**Prerequisites:** Only an allowlisted destination and the ability to read HTTP response headers.

**Impact:** Reveals token scope, identity, and remaining quota. Useful for fingerprinting the credential before attempting lateral movement.

**Does the proxy stop me?** No. The proxy forwards the real upstream response verbatim. It scrubs the injected `Authorization` header from my outgoing request but has no mechanism to strip informational response headers.

**Bypass:** Direct observation — no bypass needed.

**Feasibility:** Feasible. Zero additional attack surface required.

---

## A2 — Redirect a Rule-Matched CONNECT to an Attacker-Controlled IP

**Attack:** The proxy matches CONNECT destinations by hostname (exact string match), then dials the real upstream. But DNS resolution happens on the *host*, not inside the container. If I can influence the host's DNS at the moment of a proxy dial — via a container-scoped DNS server I control, or via DNS cache poisoning on the host's resolver — I can cause `api.github.com` to resolve to an IP I own. The proxy performs the TLS interception, injects my real PAT into the request, and forwards the authenticated request to my server.

**Prerequisites:** Influence over DNS resolution visible to the proxy process on the host. This is hard from inside the container but not impossible if:
- The container shares a network namespace with the host (not the case by default in Podman's rootless mode, but possible with `--network=host`)
- The container can reach a DNS server the host also uses and can poison its cache (TTL 0, NXDOMAIN spoofing)
- The operator has misconfigured split-horizon DNS

**Impact:** Full exfiltration of the real credential to an attacker-controlled endpoint. This is the highest-impact attack in the model.

**Does the proxy stop me?** No. The proxy does not pin destination IPs or validate TLS certificates from upstream servers (it uses `http.DefaultTransport`, which respects system roots but does not pin). The U3 resolution describes optional IP range pinning for wildcard rules but it is off by default and not implemented yet.

**Bypass:** DNS poisoning is the attack; no additional bypass needed.

**Feasibility:** Difficult. Requires influencing host-side DNS, which is non-trivial from inside a container. More realistic in misconfigured environments (shared netns, permissive DNS).

---

## A3 — Credential Exfiltration via Side-Channel Timing on the Token Endpoint

**Attack:** The `OAuthRefreshMutator` caches the real access token after the first successful token exchange. On subsequent API calls, it supplies the cached token without contacting the token endpoint. I can measure round-trip time: if my request to an API host returns faster than expected (because no token-endpoint round trip occurred), I know the proxy has a live cached token. This does not give me the token directly, but tells me the credential is valid and alive — useful for deciding whether to escalate.

More directly: the `OAuthRefreshMutator` calls `AccessToken()` which returns an error if no token is cached. When this error occurs, the proxy responds with `502 Bad Gateway`. I can observe the *timing* of 502s versus 200s to determine whether a real credential is cached.

**Prerequisites:** None beyond making requests to an allowlisted OAuth API host.

**Impact:** Distinguishes live credential from stale one; reduces noise in subsequent attacks.

**Does the proxy stop me?** No.

**Feasibility:** Feasible.

---

## A4 — SNI / Host Header Mismatch to Elicit Credential Injection to Wrong Host (Partially Mitigated)

**Attack:** The U1 resolution requires CONNECT host == Host header == SNI, and the code enforces this. But the SNI check has a gap: if SNI is *empty*, the check is skipped (`if sniHost != "" && sniHost != destHost`). I can deliberately suppress SNI (send `ClientHello` without a `server_name` extension). The proxy will complete the CONNECT and TLS handshake, then check the Host header. If I now set the Host header to an allowlisted destination, the proxy injects credentials and forwards to the CONNECT target, which could differ from the Host header if... wait, no: the Host header is checked against `destHost` (the CONNECT authority), not the CONNECT address. This means an empty SNI only allows a client that knows the right hostname — it does not open a new injection path.

However, there is a subtler issue: the proxy normalises `destHost` from the CONNECT line but does not verify the *port*. `CONNECT api.github.com:443` and `CONNECT api.github.com:8443` both reduce to `api.github.com` after `net.SplitHostPort`. If a rule is defined for `api.github.com`, both CONNECT requests match, and the proxy will attempt to dial port 443 (the Transport default). An attacker cannot redirect credentials to an arbitrary port this way because the real upstream host is always dialled, but this is worth noting.

**Prerequisites:** Control over TLS `ClientHello` — possible for any process inside the container.

**Impact:** Low — the SNI bypass allows omitting SNI but does not redirect credential injection.

**Does the proxy stop me?** Partially. Empty SNI is explicitly allowed.

**Feasibility:** Low impact; Difficult to turn into a credential exfiltration.

---

## A5 — HTTP Request Smuggling Through the Keep-Alive Loop

**Attack:** The proxy reads HTTP/1.1 requests in a keep-alive loop using `http.ReadRequest`. HTTP request smuggling attacks exploit disagreements between how a front-end and back-end parse `Content-Length` vs `Transfer-Encoding: chunked`. Inside the MITM loop, the proxy is both client-facing TLS terminator and upstream forwarder. It reads my request with `http.ReadRequest` (Go's standard library) and forwards with `http.DefaultTransport` (also Go's standard library). Both sides use the same parser, so classic smuggling (CL.TE or TE.CL) is unlikely to work *between proxy and upstream*.

However, within the same TLS connection I control *what* the proxy forwards. If I send a malformed pipelined request where a second request's headers bleed into the first request's body, the proxy might forward a crafted request to the real upstream carrying injected headers — but since the proxy *overwrites* the Authorization header unconditionally, I cannot leverage this to steal the token. What I can do is use a smuggled second request to reach a different *path* on the upstream host under the injected credential (e.g., `DELETE /repos/owner/repo` when I intended `GET /repos`).

**Prerequisites:** Control over the raw HTTP/1.1 byte stream inside the TLS tunnel.

**Impact:** Privilege abuse on the upstream service (destructive API calls), not credential exfiltration.

**Does the proxy stop me?** No explicit smuggling defence. Go's `http.ReadRequest` is reasonably robust but not immune to all edge cases.

**Feasibility:** Difficult. The impact is API abuse rather than credential theft.

---

## A6 — Sentinel Token Abuse Against a Passthrough Host

**Attack:** I know the sentinel token values from the design documents (`ya29.proxy-sentinel`, `1//proxy-sentinel-refresh`). If the proxy has `allowPassthrough = true` for some hosts (e.g., to allow package registries that don't need auth), I can CONNECT to one of those passthrough hosts and include `Authorization: Bearer ya29.proxy-sentinel` in my request. The proxy tunnels this blindly. The real server rejects it with 401. No credential is leaked. However, if any passthrough rule accidentally matches an allowlisted host (misconfiguration), and I can cause the proxy to passthrough instead of intercepting, my sentinel token reaches the upstream instead of the real credential.

More dangerous: the current production default is `allowPassthrough = false`. But the `allowPassthrough` field is on the `proxy` struct and defaults to false. If an operator sets it to true (e.g., for npm public registry), all non-ruled CONNECT destinations become reachable. I can then exfiltrate data over those channels even if no credentials are leaked.

**Prerequisites:** `allowPassthrough = true` in proxy config (not the default).

**Impact:** Data exfiltration over passthrough tunnels; no credential exfiltration.

**Does the proxy stop me?** Yes, by default. If passthrough is disabled, all non-ruled CONNECT requests receive 403.

**Feasibility:** Feasible if operator enables passthrough; blocked by default.

---

## A7 — Ephemeral CA Key Theft via Filesystem Read

**Attack:** When no CA cert/key paths are provided, the proxy generates an ephemeral CA and writes it to a tmpfs directory: `os.WriteFile(tmpDir+"/ca.crt", certPEM, 0644)` and `os.WriteFile(tmpDir+"/ca.key", keyPEM, 0600)`. The cert is world-readable (0644). The key is owner-readable only (0600, proxy user). If I can read `/proc/<proxy-pid>/fd/*` from inside the container — which requires the container to share the host's PID namespace — or if the tmpfs is somehow bind-mounted into the container, I can exfiltrate the CA private key. With the CA key, I can generate leaf certificates for any hostname the proxy would intercept, and I can forge responses from the real upstream — including modifying response bodies.

More critically: if I already have the CA key, I can set up a second proxy inside the container that re-intercepts my own traffic. But I still cannot extract the real credentials because those live in the proxy process on the *host*, not in my containers.

The CA key does not give me credentials; it gives me the ability to MITM my own traffic and the ability to attack any other container that trusts the same CA.

**Prerequisites:** Read access to the host tmpfs from inside the container (requires PID namespace sharing or a bind-mount misconfiguration).

**Impact:** MITM between containers, JWKS spoofing (see A8), cross-container attacks.

**Does the proxy stop me?** Partially. Key is 0600 (requires read access as proxy user or root). The cert path is logged but the key path is not (S5 mitigation), reducing discoverability.

**Feasibility:** Difficult. Requires a container escape precondition.

---

## A8 — JWKS Endpoint Poisoning to Extract id_token Claims

**Attack:** The Phase 2 empirical work shows that the proxy can defeat `id_token.verify_oauth2_token()` by substituting the JWKS at `www.googleapis.com/oauth2/v1/certs`. This is the proxy's *intended* behaviour. But I can exploit it offensively: if I can observe which `kid` (key ID) the proxy substitutes into JWKS responses, I learn the proxy's signing key fingerprint. If the proxy uses the same signing key for multiple containers (shared session key), I can craft a fake id_token signed by the proxy's key and use it to impersonate the agent identity in any service that validates id_tokens via the proxied JWKS endpoint.

**Prerequisites:** Ability to observe a JWKS response from `www.googleapis.com` (requires that host to be in the ruleset) and ability to send an id_token to a service that validates via the same JWKS.

**Impact:** Cross-container identity impersonation.

**Does the proxy stop me?** Not currently — no `kid` rotation or per-container JWKS isolation is documented.

**Feasibility:** Difficult. Requires multiple preconditions and a service that validates id_tokens.

---

## A9 — Exhausting the Certificate Cache to Cause Memory Pressure (DoS)

**Attack:** The certificate cache is an unbounded `map[string]*tls.Certificate`. LRU eviction is noted as "planned" but not implemented. Each cached cert is ~4 KB of DER data. If I can issue CONNECT requests for thousands of unique hostnames (all of which will be rejected with 403 since passthrough is off), the proxy does not reach `getCert` for those. But for the one intercepted host, the cert is cached on first use and never evicted. This is low-risk DoS only.

However, if the proxy is extended to intercept wildcard destinations (Phase 3d), each unique hostname under the wildcard would get its own cached cert entry. At that point, issuing `CONNECT` to `a1.googleapis.com`, `a2.googleapis.com`, ... `a65536.googleapis.com` could exhaust memory.

**Prerequisites:** Wildcard rules (Phase 3d, not yet implemented).

**Impact:** Memory exhaustion DoS on the proxy process.

**Does the proxy stop me?** Currently yes (only one host is intercepted). After Phase 3d: no, without LRU eviction.

**Feasibility:** Infeasible now; Feasible after Phase 3d without LRU.

---

## A10 — Smuggling Data Out via Allowlisted API Requests

**Attack:** I cannot extract the real credential value, but I can use the *capability* the credential grants. The proxy injects the real GitHub PAT into every CONNECT to `api.github.com`. I can use the GitHub API to exfiltrate arbitrary data: create a gist, push to a repo, write to an issue. The proxy has no request body inspection — it injects credentials and forwards the request body verbatim. An AI agent with write access to GitHub can leak code, secrets from the filesystem, or container metadata without touching the proxy's control plane at all.

**Prerequisites:** Write-capable credential for an allowlisted host.

**Impact:** Data exfiltration through legitimate API operations. This is a business-logic bypass, not a cryptographic break.

**Does the proxy stop me?** No. The proxy operates at the transport layer, not the application layer. It does not inspect request bodies or restrict which API endpoints I call.

**Feasibility:** Feasible. This is the most realistic exfiltration path for a capable AI agent.

---

## A11 — Token Endpoint Race Condition (TOCTOU on Cached Token)

**Attack:** The `OAuthRefreshMutator` caches the real access token. Between the time the proxy caches a new token and the time it responds to my request, another container sharing the same `OAuthRefreshMutator` instance reads the freshly cached token. In the current architecture (one proxy process, in-memory state) this only matters if multiple containers use the same mutator. The design says per-container sockets are planned (Phase 3d) but not yet implemented. A current deployment with multiple containers sharing the same proxy process shares a single `OAuthRefreshMutator` — meaning all containers share the same real access token and can observe each other's token-exchange timing.

**Prerequisites:** Multiple containers sharing one proxy process (current prototype state).

**Impact:** Cross-container credential confusion — container B gets tokens meant for container A.

**Does the proxy stop me?** No. Per-container credential isolation is a Phase 3d goal.

**Feasibility:** Feasible in multi-container deployments before Phase 3d.

---

## A12 — Protocol Upgrade to WebSocket to Evade Inspection

**Attack:** Once the proxy establishes a MITM TLS connection to me and I send `GET /ws HTTP/1.1` with `Upgrade: websocket`, Go's `http.DefaultTransport` does not support WebSocket upgrades — it will attempt to read the response as a standard HTTP response. If the upstream does support WebSocket, the transport returns an error and the proxy sends 502. However, if the proxy is extended with H2 support (N5 resolution), similar attacks apply: I can send an H2 `CONNECT` pseudo-request (extended CONNECT, RFC 8441) to establish a tunnel within the already-MITM'd connection, bypassing per-request header injection for subsequent frames.

**Does the proxy stop me?** Phase 3a explicitly advertises only `http/1.1` in the TLS ALPN (`NextProtos: []string{"http/1.1"}`), so H2 is negotiated out. WebSocket upgrades over HTTP/1.1 will fail at the transport layer.

**Feasibility:** Infeasible in Phase 3a. Will require re-evaluation in Phase 3a+ when H2 is enabled.

---

## A13 — Attacking Other Containers via the Shared MITM CA

**Attack:** The proxy's CA cert is injected into my container's trust store. If another container running on the same host trusts the same CA (which it will if `agent-run` reuses the session CA), and if I can somehow deliver a forged TLS certificate to that container (by poisoning its DNS to route traffic through me rather than through the proxy), I can MITM that container's traffic using the shared CA.

**Prerequisites:** CA key (see A7) plus network access to another container's outbound traffic.

**Impact:** MITM on sibling containers, credential exfiltration from those containers.

**Does the proxy stop me?** The N6 CA lifecycle decision (per-session CA, 8h TTL) limits the window. But within a session, a stolen CA key enables cross-container MITM.

**Feasibility:** Difficult. Requires A7 as a precondition.

---

## Summary: Risk Matrix

| ID | Vector | Impact | Feasibility | Mitigated? |
|----|--------|--------|-------------|------------|
| A1 | Response header observation | Scope/identity leak | Feasible | No |
| A2 | DNS poisoning to redirect injected creds | Full credential exfiltration | Difficult | Partially (IP pinning planned, off by default) |
| A3 | Cache timing side-channel | Credential liveness probe | Feasible | No |
| A4 | Empty SNI bypass | Low | Difficult | Partial |
| A5 | HTTP request smuggling | API abuse | Difficult | No |
| A6 | Sentinel token on passthrough host | Data exfiltration | Feasible if passthrough enabled | Default-blocked |
| A7 | Ephemeral CA key theft | Cross-container MITM | Difficult | Partial (0600 perms) |
| A8 | JWKS kid observation | Cross-container impersonation | Difficult | No |
| A9 | Cert cache exhaustion | DoS | Infeasible now | No (planned) |
| A10 | Data exfiltration via legitimate API ops | Data exfiltration | Feasible | No (by design) |
| A11 | Shared mutator TOCTOU | Cross-container credential confusion | Feasible | Phase 3d |
| A12 | WebSocket/H2 upgrade to evade inspection | Inspection bypass | Infeasible (Phase 3a) | Phase 3a ALPN |
| A13 | Sibling container MITM via shared CA | Cross-container exfiltration | Difficult | Partial (CA lifecycle) |

---

## Top Three Findings for Defenders

1. **A10 (data exfiltration via legitimate API)** is the most practical attack and is unmitigable at the proxy layer. Defense must be at the policy layer: write-scope restriction on injected credentials, separate read-only PATs for agent use, audit logging of all API calls made through the proxy with request-body hashing.

2. **A2 (DNS-poisoned upstream redirect)** is the most catastrophic if it succeeds. The proxy should default to IP-pinning the resolved address of intercepted destinations at rule-load time and re-resolving with fail-closed behaviour if the IP changes mid-session. This is described as optional in U3 but should be promoted to mandatory for write-capable credentials.

3. **A11 (shared mutator across containers)** is an architectural gap that affects any multi-container deployment before Phase 3d ships. The fix — per-container `OAuthRefreshMutator` instances bound to per-container sockets — is already in the roadmap. The risk window is the current prototype period.
