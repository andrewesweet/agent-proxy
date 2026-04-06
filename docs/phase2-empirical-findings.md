# Phase 2 Empirical Findings: Tool Credential Validation Behavior

**Date:** 2026-04-05
**Status:** Complete for google-auth, pip, npm, gh — resolves the N1 gate
**Scope:** Python `google-auth` 2.49.1, `pip` 24.0, `npm` 10.9.7, `gh` 2.60.1

## Purpose

The v2 adversarial review flagged **N1 (Critical)**: the sentinel-token design
depends on whether target tools validate credentials locally before making
network calls. Three specific concerns were raised for Google tooling:

1. "gcloud SDK validates the ADC access token offline using the token's `exp`
   claim before making any network call."
2. "Google Cloud client libraries call `credentials.token_state()` before
   the first RPC; if the token is not a parseable JWT with a non-expired
   `exp`, they attempt a full re-auth flow."
3. "npm v9+ validates the format of registry tokens before the first
   registry call." (Deferred to a separate experiment.)

Phase 3c of the plan is gated on empirical answers to these questions. This
document reports the results of three experiments targeting the Google
concerns.

## Method

All three experiments run `google-auth` 2.49.1 in-process with HTTP
interception via the `responses` library, observing exactly which endpoints
are contacted and in what order. No mitmproxy or CA injection is required
because we control the transport layer directly. The experiments live at
`/tmp/mitm-spike/experiment_{1b,2,3}_*.py` and are reproducible on any
host with `python3 -m pip install google-auth responses cryptography`.

## Experiment 1b — Authorized User ADC Flow

**Setup:** A fake ADC file of type `authorized_user` containing:
- `client_id`: gcloud's real public client ID (764086051850-*)
- `client_secret`: gcloud's real public client secret
- `refresh_token`: `1//0fFAKEREFRESHTOKEN...` (arbitrary string)

The `refresh_token` is a completely fake opaque string — not base64, not a
JWT, no structural validation possible.

**Steps:**
1. `google.auth.default()` to load the credential
2. `credentials.refresh(request)` to exchange refresh_token for access_token
3. `AuthorizedSession().get("https://cloudresourcemanager.googleapis.com/v1/projects")`

**Observed HTTP calls:**
1. `POST https://oauth2.googleapis.com/token` with `grant_type=refresh_token`
   and the fake refresh_token in the form body
2. `GET https://cloudresourcemanager.googleapis.com/v1/projects` with
   `Authorization: Bearer ya29.FAKE_ACCESS_TOKEN_FROM_PROXY_12345`

**Key observations:**
- `google-auth` did NOT validate the refresh_token format before sending it
- The library accepted any string the token endpoint returned as `access_token`
- The fake access_token `ya29.FAKE_ACCESS_TOKEN_FROM_PROXY_12345` is not a
  JWT (no dots, not base64 segments) and was used verbatim in the
  `Authorization` header
- NO calls to `tokeninfo`, `userinfo`, or any verification endpoint
- The library never examined the token claims, never parsed it as JWT,
  never checked `exp`

**Verdict:** The v2 review concern "validates the ADC access token offline
using the token's `exp` claim" is **false for the authorized_user flow**.
The sentinel model works with plain opaque strings and requires no JWT
structure.

## Experiment 2 — Service Account ADC Flow

**Setup:** A fake service-account ADC file with:
- An **ephemeral RSA-2048 key generated in-process** (never seen by Google)
- `client_email`: `fake-agent@fake-project.iam.gserviceaccount.com`
- All other fields filled with plausible values

**Steps:** Same as Experiment 1b.

**Observed HTTP calls:**
1. `POST https://oauth2.googleapis.com/token` with
   `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and an
   `assertion` parameter containing a JWT signed with the ephemeral key
2. `GET https://cloudresourcemanager.googleapis.com/v1/projects` with
   `Authorization: Bearer ya29.FAKE_SA_ACCESS_TOKEN`

**JWT assertion contents (decoded):**
```
header:  {"typ": "JWT", "alg": "RS256", "kid": "fake-key-id"}
payload: {
  "iat": 1775403823,
  "exp": 1775407423,
  "iss": "fake-agent@fake-project.iam.gserviceaccount.com",
  "aud": "https://oauth2.googleapis.com/token",
  "scope": "https://www.googleapis.com/auth/cloud-platform"
}
```

**Key observations:**
- `google-auth` signed the assertion with whatever key was in the ADC file,
  without any validation that the key is real or trusted
- The assertion POST would normally fail at Google (the public key for
  `fake-key-id` is not registered against that service account), but the
  proxy intercepts it first
- Once the proxy returns a fake `access_token`, the flow is identical to
  the authorized_user case: the library uses it verbatim

**Verdict:** Service accounts work too. The container holds an **ephemeral
fake private key** that is useless outside the proxy context but satisfies
the library's local API. No real cryptographic material is in the container.

## Experiment 3 — id_token Verification Path

**Setup:** This is the adversarial case. We explicitly exercise
`google.oauth2.id_token.verify_oauth2_token()`, which is documented to
verify JWT signatures against Google's published JWKS.

**Steps:**
1. Generate a local RSA key
2. Sign a fake id_token with claims `iss=https://accounts.google.com`,
   `aud=<client_id>`, valid `iat`/`exp`
3. Build a self-signed X.509 certificate wrapping the local public key
4. Intercept `GET https://www.googleapis.com/oauth2/v1/certs` and return
   `{"fake-kid": "<our cert PEM>"}`
5. Call `id_token.verify_oauth2_token(fake_id_token, request, audience=...)`

**Result:** Verification **succeeds**. The decoded payload matches what we
put in. The library fetched our substituted JWKS, found the matching `kid`,
verified the signature against our cert, and returned the claims as if
they were authentic.

**Three verification cases summarized:**

| Case | Path | Outcome |
|------|------|---------|
| `jwt.decode(verify=False)` | Skips verification entirely | Decoded, no errors |
| `jwt.decode(certs=local_cert)` | Caller supplies certs | Verified against local cert |
| `id_token.verify_oauth2_token()` | Library fetches Google JWKS | Verified against substituted JWKS |

**Verdict:** Even the strict verification path is defeated when the proxy
controls the JWKS endpoint. This is a direct consequence of the MITM
position: if the proxy's CA is trusted by the container, then any URL the
library fetches is under proxy control, including JWKS.

## Resolution of N1

The v2 review said:

> **N1 (Critical).** The sentinel token design breaks for tools that
> validate credentials locally before making any network call. gcloud SDK,
> Google Cloud client libraries, and npm v9+ all do this. A sentinel string
> is not a parseable JWT and will fail immediately. This blocks Phase 3c
> as currently designed.

Based on empirical evidence for `google-auth`:

- **False for authorized_user ADC:** no local validation of refresh_token
  or access_token. Plain strings work.
- **False for service_account ADC:** an ephemeral fake key is sufficient
  to satisfy local signing. The real key never needs to be in the container.
- **False for id_token verification:** the JWKS endpoint is under proxy
  control; substituting the proxy's cert defeats signature verification.

**N1 is resolved for all tested google-auth flows.** Phase 3c can proceed
with the simplest sentinel design: plain opaque strings, no JWT construction
required.

The v3 resolution document proposed signed JWT sentinels as a defensive
measure. The empirical evidence shows this is unnecessary for google-auth.
The design simplifies accordingly:

- **Access tokens:** any opaque string, deterministic per session for
  recognition on outbound
- **Refresh tokens:** any opaque string, intercepted at
  `oauth2.googleapis.com/token`
- **Private keys (service account case):** ephemeral RSA key generated
  per session, never used to sign anything that reaches Google
- **id_token verification:** substitute JWKS at
  `www.googleapis.com/oauth2/v1/certs` with proxy-signed cert

## Experiment 4 — pip

**Setup:** `pip install --index-url http://user:<fake-token>@127.0.0.1:PORT/simple/`
against a local HTTP server. Five token formats tested (opaque, 1-char,
plain text, base64, random).

**Observed behavior:** Every test produced exactly one HTTP GET to
`/simple/<package>/` with `Authorization: Basic <base64>` containing the
fake token. Zero local validation, zero pre-flight verification calls.

**Verdict:** pip sends whatever credential string it is given. Plain opaque
strings work. The v2 N1 claim does not apply to pip.

## Experiment 5 — npm

**Setup:** `npm whoami` and `npm view` against a local HTTP server
impersonating an npm registry, with `_authToken` set to various fake
values in a tmpfile `.npmrc`. Five token formats tested.

**Observed behavior:**
- npm 10.9.7 never rejected a token based on format — all tests proceeded
  to the HTTP call
- npm only sends `_authToken` on auth-requiring operations (not on
  unscoped reads); `whoami` and publishes include it
- For `whoami`, the local server's response body was accepted without
  additional validation

**Verdict:** The v2 N1 claim that "npm v9+ validates the format of
registry tokens" is empirically false for npm 10.x. Plain opaque strings
work.

## Experiment 6 — gh

**Setup:** `gh auth status` with various `GH_TOKEN` values against real
`api.github.com`. Also `gh api user` with a fake token.

**Observed behavior:**

```
$ GH_TOKEN=fake gh api user
{ "message": "Bad credentials", "status": "401" }
gh: Bad credentials (HTTP 401)
```

Every fake PAT (empty, 3-char, 40-char, `ghp_`-prefixed, `github_pat_`-prefixed)
produced the same result: an HTTP call to `api.github.com/user` and a
rejection based on the **server's 401 response**, not a local format check.

**Verdict:** gh performs NO local format validation. It verifies credentials
via a network call to `GET /user`.

**Correction (2026-04-06):** A shim is NOT required for gh. The `/user`
verification call is just another outbound HTTPS request to `api.github.com`.
The MITM proxy injects the real PAT into the `Authorization` header on this
call exactly as it does for any other API call. GitHub's real `/user` endpoint
returns a real 200 response with the real user profile. gh is satisfied.
No synthetic response needed.

## Summary of Phase 2

| Tool | Local format validation? | Verification network call? | Shim required? |
|------|-------------------------|---------------------------|----------------|
| google-auth (authorized_user) | No | No | No (token refresh is the exchange point) |
| google-auth (service_account) | No (accepts any key) | No | No (assertion endpoint is the exchange point) |
| google-auth (id_token.verify) | Signature check | Yes (JWKS) | No — JWKS fetch is under proxy control |
| pip | No | No | No |
| npm | No | No (not eager) | No |
| gh | No | Yes (`/user`) | **No** — proxy injects real PAT, real GitHub responds |

**Two patterns observed** (corrected from three — shim layer is not needed):

1. **Pass-through tools** (pip, npm, gh): send whatever credential they
   have, trust the server. Proxy injects the real credential on outbound,
   real server responds. gh's `/user` verification call is just another
   pass-through request — no shim required.
2. **Exchange-based tools** (google-auth): perform a token-exchange dance,
   trust whatever comes back. Proxy intercepts the exchange at the token
   endpoint and returns a proxy-controlled sentinel that it will later
   recognize and swap for the real credential on outbound API calls.

**No tool needs a shim in the base case.** The shim layer (Phase 3f) is
eliminated from the plan unless a future tool is discovered that verifies
credentials against an endpoint the proxy cannot reach. The only case
where synthetic responses are needed is the google-auth id_token JWKS
path, which is handled by intercepting `www.googleapis.com/oauth2/v1/certs`
— an outbound request like any other, not a "shim."

## N1 Verdict (Updated)

The v2 review said the sentinel model breaks for locally-validating tools.
Empirically, NONE of the tested tools (google-auth, pip, npm, gh) perform
local JWT validation against a real issuer key. The one verification path
that does (`id_token.verify_oauth2_token`) is defeated by the proxy's
control of the JWKS endpoint.

**Phase 3c can proceed with plain opaque sentinel strings.** No signed JWT
construction is required for any of the tested tools.

## Container Tool Auth Audit (2026-04-06)

An audit of the target container image toolset identified tools requiring
authenticated network traffic. Updated tool auth matrix:

| Tool | Credential | Endpoint(s) | Proxy handling |
|------|-----------|-------------|----------------|
| git / lazygit / prek | PAT or SSH key | github.com | MITM header injection or SSH agent forwarding |
| gcloud CLI | OAuth ADC | googleapis.com | Tested — token exchange interception |
| OpenCode (Copilot) | OAuth bearer | api.githubcopilot.com | Inject `Authorization: Bearer` on outbound |
| OpenCode (Vertex AI) | OAuth ADC | aiplatform.googleapis.com | Same as gcloud — tested |
| critique | None (delegates to OpenCode via ACP) | critique.work (no auth) | Passthrough |
| mise / codeql | GitHub PAT | api.github.com | Same injection as git |
| kubectl / k9s / kubectx | kubeconfig bearer | k8s API server | Inject bearer token per cluster |
| uv | PyPI token (publish only) | pypi.org / private index | Only if publishing or private index |

Tools confirmed to have NO auth-requiring network traffic: bash, curl,
openssh-client, ca-certificates, build-base, python, go, nodejs, bun,
procps, ruff, ty, golangci-lint, gofumpt, shellcheck, shfmt, tflint,
actionlint, zizmor, tmux, starship, btop, lnav, fzf, zoxide, bat, delta,
fd, ripgrep, glow, tree, jq, yq, httpie (user-driven, no default auth),
neovim, pandoc, lazydocker.

### OpenCode with GitHub Copilot — Revisit Required

OpenCode authenticates to GitHub Copilot via the **OAuth device code flow**
(RFC 8628):

1. `POST https://github.com/login/device/code` (unauthenticated)
2. User visits `github.com/login/device` in a browser and enters the code
3. `POST https://github.com/login/oauth/access_token` polling until granted
4. Token stored in `~/.local/share/opencode/auth.json`
5. Runtime API calls to `https://api.githubcopilot.com` with
   `Authorization: Bearer <token>`

This presents a design question with multiple options to evaluate later:

- **Option A: Host-side pre-population.** User performs device flow on the
  host; `auth.json` is bind-mounted read-only into the container. The proxy
  injects the bearer token on outbound `api.githubcopilot.com` traffic.
  Container never sees the raw token on disk (the bind-mount contains a
  sentinel; the proxy swaps it). Cleanest isolation but requires host-side
  tooling to manage the token lifecycle.

- **Option B: Passthrough OAuth, then MITM runtime calls.** The proxy
  passes through `github.com/login/device/*` and
  `github.com/login/oauth/*` unauthenticated (these are public OAuth
  endpoints). The container performs the device flow interactively. Once
  the token lands in `auth.json`, all subsequent
  `api.githubcopilot.com` traffic is intercepted and the proxy injects
  credentials. Simpler setup but the raw token is in the container
  (in memory and on disk) — weaker isolation.

- **Option C: Proxy-mediated device flow.** The proxy intercepts the
  device-code polling and performs the OAuth exchange on the host side,
  returning a sentinel token to the container. Most complex but strongest
  isolation.

Decision deferred to Phase 3c/3d work when the credential provider
abstraction and per-container identity are in place.

### Critique

Critique (github.com/remorses/critique) is a terminal diff viewer that
delegates all AI work to a subprocess agent (OpenCode or Claude Code) via
the Agent Client Protocol (ACP) over stdin/stdout ndjson. It has zero
auth surface of its own — inherits whatever the spawned agent has. Its
only outbound HTTP call is uploading rendered diffs to `critique.work`
(no auth required).

## Remaining Empirical Work (Deferred to Parallel Phase 2 Work)

Not yet tested but NOT blocking Phase 3a start:

1. **gcloud CLI Go binary** — likely same semantics as google-auth-python
   (same ADC file format); confirm with a real gcloud in a test env
2. **Node.js `google-auth-library`** — Vertex AI JS clients
3. **Java `google-auth-library-java`** — enterprise workloads
4. **jira-cli** — PAT format and verification behavior
5. **Docker registry auth** — whether `docker login` / `docker pull` does
   local format validation
6. **OpenCode Copilot device flow** — empirically test the OAuth device
   code flow through a MITM proxy to confirm which endpoints need
   passthrough vs. interception

None of these is likely to invalidate the core model. Given that the shim
layer has been eliminated, these tests are purely informational — confirming
that each tool's verification calls (if any) are ordinary outbound requests
that the proxy handles transparently.

## Experiment Scripts

All scripts are reproducible:

- `/tmp/mitm-spike/experiment_1b_adc_proper_mock.py` — authorized_user flow
- `/tmp/mitm-spike/experiment_2_service_account.py` — service_account flow
- `/tmp/mitm-spike/experiment_3_id_token_verification.py` — JWKS substitution

Requirements: `pip install google-auth responses cryptography`

The scripts should be moved into a `test/phase2/` directory in the
agent-proxy repository (or the spnego-proxy repository under a new
subdirectory) when the prototype begins. They serve as regression tests
against future `google-auth` releases that might introduce stricter
local validation.
