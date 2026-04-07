# Adversarial Code Review — Phase 3c

**Date:** 2026-04-06
**Reviewer:** Senior Go Engineer (adversarial)
**Scope:** `credential.go`, `main.go`, `credential_test.go`, `main_test.go`
**Phase:** 3c prototype — OAuthRefreshMutator, OAuthBearerMutator, CredentialMutator interface upgrade

---

## 1. Security Issues

### [Critical] Real access token cached before response body is replaced — `credential.go:196–203`

The write lock is released and `m.cachedToken` is populated **before** the
modified response body is serialised and assigned to `resp.Body`. If
`json.Marshal` at line 210 fails (e.g., a value in `tokenData` is not
JSON-serialisable — possible if a future Google field contains a type that
`map[string]any` cannot round-trip), `MutateResponse` returns an error at line
212. The proxy then closes the original `resp.Body` (already consumed) and sends
a 502 to the client — so the client never sees the real token in the response.

However, the cache now holds the real access token. If the container
subsequently makes an API request, `OAuthBearerMutator.MutateRequest` will
inject the real token. **The cache is in a "token stored but the client got a
502" state.** On a retry, the client will POST again and get a fresh real token
cached. This is not a leak, but it means the proxy injects a real token for an
exchange that the container believes failed. The real risk is with
`json.Marshal` failure: in that case `m.cachedExpiry` is set to a future time,
so the token will be served indefinitely even though the response was never
delivered. Fix: hold the write lock until after `json.Marshal` succeeds, or
only commit the cache after the body is safely serialised.

### [High] MutateResponse does not check HTTP status before caching — `credential.go:190`

```go
if accessToken, ok := tokenData["access_token"].(string); ok && accessToken != "" {
```

There is no check on `resp.StatusCode`. If the token endpoint returns HTTP 200
but with an error JSON body that happens to contain an `access_token` field
(unusual but possible with some OAuth error envelope formats), the proxy caches
it. More importantly, if the upstream returns `4xx` with a body like
`{"access_token":"","error":"invalid_grant"}`, the guard `accessToken != ""`
prevents caching an empty string — good. But a 400 response containing a
non-empty `access_token` (however unlikely) would be cached. The safer approach
is to gate caching on `resp.StatusCode == 200`. Fix: add `if resp.StatusCode !=
http.StatusOK { /* pass through unchanged */ return nil }` before the unmarshal.

### [High] Rotated refresh token silently discarded — `credential.go:205–208`

```go
if _, ok := tokenData["refresh_token"]; ok {
    tokenData["refresh_token"] = DummyRefreshToken
}
```

When Google rotates the refresh token, the new real token appears in the
response and is replaced with `DummyRefreshToken` before the container sees it.
But `OAuthRefreshMutator` **never updates `m.realRefreshToken`**. On the next
refresh cycle, `MutateRequest` will substitute the original (now invalidated)
real refresh token. The token endpoint will return `invalid_grant`, the container
will receive a 502 (or an error response), and the proxy will have no valid real
refresh token until it is restarted and a new one is configured. This is a
correctness failure with security implications: after one rotation cycle, the
proxy permanently loses the ability to mint new access tokens, and the container
cannot recover. Fix: update `m.realRefreshToken` inside the write lock when a
rotated token is present in the response.

### [High] `expires_in: 0` stores an already-expired token — `credential.go:191–195`

```go
expiresIn := 3600.0
if ei, ok := tokenData["expires_in"].(float64); ok {
    expiresIn = ei
}
expiry := time.Now().Add(time.Duration(expiresIn)*time.Second - 60*time.Second)
```

If the token endpoint returns `"expires_in": 0` (or `1` through `59`), the
subtraction of 60 seconds produces a negative or zero duration, and `expiry`
is in the past. `AccessToken()` will immediately return "cached access token
expired" on every call. Every subsequent API request will fail with a 502 until
the container triggers another refresh. The token was real and valid (Google
issues short-lived tokens for some flows), but the proxy discards it. Fix:
clamp the skew subtraction: `skew := 60 * time.Second; if d < skew { skew = d / 2 }`.

### [High] Dummy refresh token in request is not validated against `DummyRefreshToken` — `credential.go:148–165`

`MutateRequest` replaces **any** `refresh_token` value in any `grant_type=refresh_token`
POST to the token endpoint, regardless of whether the container sent the expected
sentinel. If the container sends its own real refresh token (intentionally or via
a misconfiguration), the proxy silently replaces it with the host's real token.
No credential ever reaches the upstream from the container — that is by design.
But the container's real token is consumed without error, giving no signal to the
operator that the sentinel contract is violated. More critically: if the proxy is
accessed by an attacker who can craft a token-endpoint POST (SSRF within the
container, for example), they can trigger a real refresh-token exchange. While
the access token returned will be the dummy, the real token endpoint now has a
record of the exchange and the refresh token's use count is incremented, which
for some providers counts toward revocation. Fix: reject or log a warning when
`vals.Get("refresh_token") != DummyRefreshToken`.

### [Medium] `OAuthRefreshMutator.realRefreshToken` is stored as a plain string — `credential.go:85`

The real refresh token sits in heap memory as a `string` (Go strings are
immutable and cannot be zeroed). A heap dump, core file, or memory-safe
side-channel read by a container process with elevated privileges would expose
it. This is inherent to the in-process model and is noted as a known constraint,
but the type offers no mitigation (a `[]byte` field that is explicitly zeroed on
a `Close()` call would be an improvement). Rate: Medium given the prototype scope.

### [Medium] `isTokenEndpoint` matches path only, not host — `credential.go:117–123`

```go
func isTokenEndpoint(req *http.Request) bool {
    if req.Method != http.MethodPost {
        return false
    }
    p := req.URL.Path
    return p == "/token" || p == "/oauth2/v4/token"
}
```

This function is used as a guard inside `MutateRequest` and `MutateResponse`.
It does not check `req.URL.Host`. If `OAuthRefreshMutator` is accidentally
assigned as the mutator for a different host (e.g., a misconfigured `RuleSet`),
and that host happens to serve a `/token` endpoint, the mutator will swap the
refresh token and attempt to cache an access token from the response. In a
multi-tenant or multi-rule environment, a misrouted request could cause the
proxy to inject the Google refresh token into a non-Google token endpoint.
Fix: check the host as well, or make the host a field of `OAuthRefreshMutator`
and validate it in `isTokenEndpoint`.

### [Medium] JSON marshal of `tokenData` does not preserve field order — `credential.go:210`

`map[string]any` does not preserve insertion order; `json.Marshal` emits fields
in sorted key order. The original response body may have been signed or expected
in a specific order by the container's OAuth library. While access token
responses are not typically signed, this is fragile. More concretely: the
`Content-Type` of the modified response is inherited from the upstream response
header and remains `application/json`, but the body has changed structure (field
order, numeric types for `expires_in`). If `expires_in` was originally an
integer JSON token, round-tripping through `map[string]any` will produce a
`float64`, and re-encoding will emit it as `3600` or `3600.0` depending on
whether the float has a fractional part. `json.Marshal` of a whole-number
`float64` emits it as `3.6e+03` only for large values, so `3600` is safe in
practice, but exotic values could change the representation. Rate: Low in
practice but worth noting.

---

## 2. Concurrency Issues

### [High] Race between MutateResponse cache write and MutateRequest token read — `credential.go:127–165`, `credential.go:170–221`

Consider two concurrent connections to `oauth2.googleapis.com`:

1. Connection A is in `MutateRequest` and reads `m.realRefreshToken` at line 156
   (no lock required, it's read-only after construction — this is safe).
2. Connection B is in `MutateResponse`, holds `m.mu.Lock()` (line 197), writes
   `m.cachedToken` and `m.cachedExpiry`.

This specific pair is safe. However, consider:

1. Connection C is in `MutateRequest` for `OAuthBearerMutator.MutateRequest`
   (which calls `m.AccessToken()` → `m.mu.RLock()`).
2. Connection B is in `MutateResponse`, locks `m.mu` for writing.

`sync.RWMutex` in Go prevents starvation of writers, but a burst of API
requests all holding `RLock` simultaneously will block `MutateResponse` from
updating the cache until all readers release. In a production scenario with
many concurrent API calls, `MutateResponse` can be delayed arbitrarily until
traffic subsides. The write is bounded by request concurrency, not a timeout,
so under heavy load the cache update can be delayed until the token has already
expired. This is a thundering-herd risk: after the token expires, all API
requests fail simultaneously. **Not a correctness bug in the current
single-container prototype, but will matter at scale.** A `singleflight` guard
on the refresh path would mitigate this; that is deferred to Phase 3d.

### [Medium] `cachedToken` and `cachedExpiry` are written together but read separately — `credential.go:103–112`

```go
m.mu.RLock()
defer m.mu.RUnlock()
if m.cachedToken == "" {
    return "", ...
}
if time.Now().After(m.cachedExpiry) {
    return "", ...
}
return m.cachedToken, nil
```

Both fields are read under `RLock` in a single `AccessToken()` call, so they
are consistent. This is safe. However, the pattern is non-obvious: a future
change that reads `m.cachedExpiry` outside the lock (e.g., for a "time until
expiry" metric) would be a race without it being obviously so. The struct fields
should carry a comment noting they are always accessed under `mu`.

---

## 3. Correctness Issues

### [High] Body replaced but `Content-Encoding` not stripped — `credential.go:215–218`

```go
resp.Body = io.NopCloser(bytes.NewReader(modified))
resp.ContentLength = int64(len(modified))
delete(resp.Header, "Transfer-Encoding")
resp.TransferEncoding = nil
```

If the upstream response carries `Content-Encoding: gzip` (or `br`, `deflate`),
`io.ReadAll(resp.Body)` reads the compressed bytes, not the plaintext. The code
then attempts `json.Unmarshal` on compressed bytes, which fails. The failure
path at line 183 passes the compressed body through unchanged with a corrected
`ContentLength` — so no corruption occurs. But the real access token is never
cached. The container receives a gzip-compressed response with the real
access_token still inside, **bypassing the entire credential-stripping
mechanism**. Fix: after reading the body, check `resp.Header.Get("Content-Encoding")`
and decompress before parsing. If decompression is not implemented, return an
error (do not pass through) on non-identity encoding.

Note: in practice `http.Transport` sets `DisableCompression: false` by default
and adds `Accept-Encoding: gzip` to upstream requests, so compressed responses
are common. `http.Transport` automatically decompresses the body for responses
that it compressed itself; however, if `Accept-Encoding` was already set in the
request, transport does NOT decompress. In the MITM path, `MutateRequest` for
`OAuthBearerMutator` only touches `Authorization`, but the container's
`Accept-Encoding: gzip` header passes through unchanged — so the transport will
not auto-decompress. **This is a real risk path.**

### [High] `MutateRequest` reads and consumes `req.Body` without restoring on error — `credential.go:135–138`

```go
bodyBytes, err := io.ReadAll(req.Body)
req.Body.Close()
if err != nil {
    return fmt.Errorf("read token request body: %w", err)
}
```

On read error, the function returns an error with `req.Body` already consumed
and not restored. The caller (`handleMITM` at `main.go:243`) receives the error,
logs it, and returns — which closes the connection. So in practice the destroyed
body does not cause a secondary failure because the connection is torn down.
However, if a future caller catches the error and retries the round-trip without
re-creating the request, it will send an empty body upstream. Fix: restore
`req.Body` on the error path (`req.Body = io.NopCloser(bytes.NewReader(bodyBytes))`
if the partial read succeeded, or use a `TeeReader` to preserve the original).

### [Medium] Non-200 responses from token endpoint are unmarshalled and potentially modified — `credential.go:182–188`

```go
var tokenData map[string]any
if err := json.Unmarshal(bodyBytes, &tokenData); err != nil {
    resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
    resp.ContentLength = int64(len(bodyBytes))
    return nil
}
```

A 400 `invalid_grant` response from Google looks like:
```json
{"error":"invalid_grant","error_description":"Token has been expired or revoked."}
```

This unmarshals successfully into `tokenData`. It contains no `access_token`
field, so the cache is not updated. It may contain no `refresh_token` field, so
the refresh masking is skipped. The body is re-encoded via `json.Marshal` and
returned — field order changes, but content is semantically identical. The
container receives a properly structured error response and can handle it.

**However:** the response has its `Content-Length` rewritten and `Transfer-Encoding`
stripped even for error responses. This is unnecessary and could cause issues
if the error response is chunked and the container's HTTP library relies on
chunked framing. It is a latent correctness risk, not a current bug.

### [Medium] `Content-Length` header not updated after body replacement — `credential.go:216`

`resp.ContentLength = int64(len(modified))` sets the struct field, but does not
update `resp.Header["Content-Length"]`. `http.Response.Write` uses `resp.ContentLength`
(the struct field) to decide what to emit in the header, so in practice the
correct value is written. But any code that inspects `resp.Header.Get("Content-Length")`
directly (e.g., future middleware, or the test helper reading the response
header) will see the original stale value. Fix: call
`resp.Header.Set("Content-Length", strconv.Itoa(len(modified)))` alongside
setting `resp.ContentLength`.

### [Medium] `isTokenEndpoint` accepts `/oauth2/v4/token` but Google has deprecated this path

The code handles both `/token` and `/oauth2/v4/token`. The v4 endpoint was
officially deprecated in 2022 and redirects to `/token`. If the redirect is
followed by `http.Transport`, the redirected request will have path `/token`,
which is still matched. If the redirect is not followed (or if the client uses
a non-standard HTTP client that does not follow redirects), the v4 path is
processed. This is a minor maintenance note: the v4 path should be retained
for backward compatibility but flagged as deprecated in the comment.

### [Low] `OAuthBearerMutator` does not check if request already has no Authorization header

If the container sends an API request with no `Authorization` header, the bearer
mutator unconditionally calls `Header.Set("Authorization", "Bearer "+token)`.
This is the desired behaviour. However, it also means that if the token cache is
cold (container has not yet performed a refresh), the `MutateRequest` returns an
error and the request is rejected with a 502. There is no "wait for token" or
"trigger refresh" capability. The container must always call the token endpoint
before making API calls. This is a protocol ordering constraint that is not
enforced or documented anywhere in the code. Fix: document the ordering
requirement in `OAuthBearerMutator`'s GoDoc, and consider returning a more
descriptive error (e.g., "no valid access token cached; container must POST to
/token first").

---

## 4. Resource Leaks

### [High] Response body from token endpoint is consumed in MutateResponse; if MutateResponse errors, main.go closes it a second time — `main.go:290–306`, `credential.go:175–178`

In `MutateResponse`, `resp.Body` is read and immediately closed at lines
175–178. If the function returns an error, the caller in `main.go` at line 290
calls `resp.Body.Close()`. At this point `resp.Body` is either:

- The original (consumed, already closed) body — second `Close()` on an
  `io.NopCloser` is a no-op, so no panic. But `io.NopCloser` wraps the original
  underlying stream which is already drained; the second close is harmless.
- The replacement `io.NopCloser(bytes.NewReader(bodyBytes))` — also safe to
  close twice.

This is safe in practice because `io.NopCloser` ignores `Close()`. However, if
the body were ever changed to a real closer (e.g., a gzip reader wrapping the
network stream), double-close would be a bug. The code structure is fragile: the
ownership of `resp.Body` should be clearly assigned — either the mutator owns it
(always replaces it before returning), or the caller owns it (mutator never
closes it). Currently the mutator both reads and closes the body but does not
guarantee it is replaced on all error paths (e.g., `json.Marshal` failure at
line 210 does replace it, but the read-error path at line 175 does not).

### [Medium] Token endpoint response body not replaced on `io.ReadAll` error — `credential.go:175–179`

```go
bodyBytes, err := io.ReadAll(resp.Body)
resp.Body.Close()
if err != nil {
    return fmt.Errorf("read token response body: %w", err)
}
```

On read error, `resp.Body` is closed but not replaced. The caller at
`main.go:290` then calls `resp.Body.Close()` again (harmless for NopCloser),
then writes a 502. But since `resp.Body` is now a closed stream, `resp.Write`
would attempt to read from it if there is remaining content — the write to the
client would produce a truncated or empty response body. **The 502 path at
main.go:295 does not write `resp` at all; it constructs a fresh error response.
So no truncation occurs.** The risk is latent — if the error path were ever
changed to pass `resp` through instead of substituting a 502, this would
silently truncate responses.

---

## 5. Error Handling

### [High] `MutateRequest` error causes connection teardown, breaking persistent connections — `main.go:243–246`

```go
if err := mutator.MutateRequest(context.Background(), req); err != nil {
    slog.Error("credential injection failed", "host", destHost, "error", err)
    return
}
```

On `MutateRequest` error (including the expected "no access token cached" error
from `OAuthBearerMutator` on cold start), the proxy returns from `handleMITM`,
closing the TLS connection entirely. The container's HTTP client, which
established this connection for keep-alive reuse, has its connection dropped
without receiving an HTTP error response. This results in a transport-level
error (`EOF` or `connection reset`) rather than a structured HTTP error (502
or 503). Most HTTP clients will retry on connection reset, but some will surface
the error directly to the application. Fix: write a 502 error response to
`tlsConn` before returning, consistent with the upstream failure path.

### [Medium] `json.Unmarshal` error silently passes through response unchanged — `credential.go:183–187`

When the token endpoint returns non-JSON (e.g., an HTML error page from a WAF),
the body is passed through to the container with a corrected `ContentLength`.
No warning is logged. The container will attempt to parse what it receives as
JSON and fail with a confusing error. Fix: add a `slog.Warn` log entry on the
unmarshal-failure path to alert operators that the token endpoint returned
unexpected content.

---

## 6. Test Coverage Gaps

### Missing: token endpoint returns HTTP 4xx/5xx

No test verifies behaviour when the upstream token endpoint returns a 400
`invalid_grant` or 500 error. The current code passes the error response body
through (re-encoded as JSON if parseable), but this is not tested. In particular:
does `resp.ContentLength` get correctly set for the re-encoded error body? Does
the container receive a well-formed HTTP response?

### Missing: token endpoint response with Content-Encoding: gzip

No test for a compressed token response. Per finding C1 above, this silently
bypasses credential stripping. A test with a gzip-encoded body would expose the
bug.

### Missing: expires_in: 0 or negative

No test for `"expires_in": 0`. Per finding S4 above, this creates an
immediately-expired cache entry. A test would verify the behaviour and prompt
a fix.

### Missing: rotated refresh token (Google token rotation)

`TestOAuthRefreshMutator_MutateResponse_MasksRotatedRefreshToken` verifies that
the rotated token is replaced with a dummy in the response body. But there is
no test that a second call to `MutateRequest` (simulating the next refresh
cycle) uses the **updated** real refresh token. Since `m.realRefreshToken` is
never updated, this test would catch finding S2 (Rotated refresh token silently
discarded).

### Missing: concurrent MutateRequest and MutateResponse

No test exercises concurrent access to `OAuthRefreshMutator` — concurrent
`AccessToken()` reads while a `MutateResponse` write is in progress. A race
detector (`go test -race`) run over a concurrency test would validate the mutex
usage.

### Missing: MutateRequest error surfaces as HTTP error (not EOF) to client

No test verifies that when `OAuthBearerMutator.MutateRequest` errors on a cold
cache, the container receives a proper HTTP 502 rather than a connection reset.
Per finding E1 above, the current code tears down the connection without sending
an HTTP response.

### Missing: OAuthRefreshMutator on non-POST to token path

`TestOAuthRefreshMutator_MutateRequest_GetMethod` tests a GET to `/token`.
There is no test for a DELETE or PUT — not a real-world concern, but the
`isTokenEndpoint` method-check code path is only partially exercised.

### Missing: empty body POST to token endpoint

No test for `POST /token` with an empty body (`req.Body == nil`). The code
correctly returns `nil` at line 132, but this is not tested.

### Missing: OAuthRefreshMutator with non-form-encoded body

`TestOAuthRefreshMutator_MutateRequest_NonRefreshGrant` tests a different
`grant_type`. There is no test for a JSON body (Content-Type: application/json).
`url.ParseQuery` on a JSON string produces a non-nil `url.Values` with one key
equal to the entire JSON string, which will not match `grant_type == refresh_token`,
so the body is restored unchanged. But the test for this path is absent.

---

## 7. Design Issues

### [Medium] `OAuthRefreshMutator` is both a `CredentialMutator` and a `TokenProvider` — coupling concern

`OAuthRefreshMutator` serves dual roles: it mutates requests/responses for the
token endpoint, and it provides tokens to `OAuthBearerMutator` via the
`TokenProvider` interface. This coupling means:

1. The `OAuthRefreshMutator` must be instantiated before the
   `OAuthBearerMutator`, and the same instance must be passed to both. A
   refactoring that creates the bearer mutator from a different token source
   will silently break the flow.
2. The `realRefreshToken` is a constructor argument, making it impossible to
   rotate without restarting the process (independent of the token-rotation
   bug above).
3. If `OAuthRefreshMutator` is ever used on multiple token endpoints for
   different accounts, the shared `cachedToken` will hold whichever was cached
   last, and `OAuthBearerMutator` will inject it for all API hosts regardless
   of which account they belong to.

This is acceptable for the current single-account prototype. It should be
refactored before supporting multiple accounts.

### [Low] `DummyAccessToken` and `DummyRefreshToken` are constants, not validated on use

The sentinels are defined as constants but `MutateRequest` does not check
whether the incoming refresh token matches `DummyRefreshToken`. If the container
sends the real refresh token directly (e.g., a misconfigured client that
somehow obtained it), the proxy will replace it silently — the security model
holds (real token never forwarded) but the operator has no visibility into the
violation. See also S5 above.

---

## Summary Table

| ID | Severity | File:Line | Finding |
|----|----------|-----------|---------|
| S1 | Critical | credential.go:196–212 | Real token cached before body serialisation; marshal failure leaves cache populated but client gets 502 |
| S2 | High | credential.go:205–208 | Rotated refresh token masked in response but `m.realRefreshToken` never updated; next refresh uses invalidated token |
| S3 | High | credential.go:190 | HTTP status not checked before caching access_token; non-200 responses with token field are cached |
| S4 | High | credential.go:191–195 | `expires_in: 0` produces negative expiry; every subsequent API call fails |
| S5 | High | credential.go:148–165 | Any refresh_token value swapped, not just sentinel; no validation against DummyRefreshToken |
| S6 | Medium | credential.go:85 | Real refresh token stored as plain string; no zeroing on close |
| S7 | Medium | credential.go:117–123 | `isTokenEndpoint` checks path only, not host; misrouted rule injects Google token into wrong endpoint |
| S8 | Medium | credential.go:210 | JSON round-trip via `map[string]any` changes field order and numeric representation |
| C1 | High | credential.go:175 | gzip-encoded token response: `json.Unmarshal` fails, real access_token passes through to container unmasked |
| C2 | High | credential.go:135–138 | `req.Body` consumed and not restored on `io.ReadAll` error |
| C3 | Medium | credential.go:183–187 | Non-200 error bodies re-encoded unnecessarily; `Transfer-Encoding` stripped from error responses |
| C4 | Medium | credential.go:216 | `resp.ContentLength` struct field updated but `resp.Header["Content-Length"]` not updated |
| C5 | Low | credential.go:238–245 | Cold-cache OAuthBearerMutator error not documented; ordering constraint implicit |
| R1 | High | main.go:290 | `resp.Body` closed twice on MutateResponse error (safe with NopCloser, fragile if body type changes) |
| R2 | Medium | credential.go:175–179 | `resp.Body` not replaced on `io.ReadAll` error; latent truncation risk if error path changes |
| E1 | High | main.go:243–246 | `MutateRequest` error closes connection without sending HTTP error response; container sees EOF not 502 |
| E2 | Medium | credential.go:183 | `json.Unmarshal` failure not logged; operator has no visibility when token endpoint returns non-JSON |
| T1 | — | credential_test.go | Missing: token endpoint returns 4xx/5xx |
| T2 | — | credential_test.go | Missing: gzip-encoded token response (critical path for C1) |
| T3 | — | credential_test.go | Missing: `expires_in: 0` |
| T4 | — | main_test.go | Missing: rotated refresh token with second refresh cycle (would catch S2) |
| T5 | — | credential_test.go | Missing: concurrent MutateRequest/MutateResponse under race detector |
| T6 | — | main_test.go | Missing: MutateRequest error returns HTTP 502, not connection reset |
| T7 | — | credential_test.go | Missing: non-form-encoded (JSON) body in token POST |
