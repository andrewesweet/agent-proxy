# Phase 3c: OAuth Token Exchange Interception

**Date:** 2026-04-07
**Status:** Approved
**Scope:** CredentialMutator interface upgrade + OAuth authorized_user ADC flow

---

## Goal

Intercept google-auth's OAuth refresh token exchange so that neither the
refresh token (long-lived) nor the access token (short-lived) ever enters
the container. The container holds only dummy/sentinel tokens. The proxy
performs all real credential operations on the host side.

## Security Model

The proxy keeps **all** credentials out of the container:

1. Container has a fake ADC file with a dummy `refresh_token`
2. Container's google-auth POSTs to `oauth2.googleapis.com/token` with the
   dummy refresh_token
3. Proxy swaps dummy refresh_token for the real one, forwards to Google
4. Google returns a real access_token (and possibly a rotated refresh_token)
5. Proxy caches the real access_token with its expiry, replaces both
   `access_token` and any `refresh_token` in the response with dummy values,
   returns the modified response to the container
6. Container uses the dummy access_token on subsequent API calls
7. Proxy replaces the dummy access_token with the cached real one on outbound

The container never sees a real token of any kind.

## Interface

```go
type CredentialMutator interface {
    MutateRequest(ctx context.Context, req *http.Request) error
    MutateResponse(ctx context.Context, req *http.Request, resp *http.Response) error
}
```

- `MutateRequest` is called after the inner HTTP request is read from the
  client and before `RoundTrip` to upstream.
- `MutateResponse` is called after a successful `RoundTrip` and before
  `resp.Write` to the client. It is NOT called when `RoundTrip` returns
  an error.

### staticTokenMutator

Wraps the existing static header injection logic. Implements the interface:

- `MutateRequest`: sets the header (same as current `StaticTokenMutator` func)
- `MutateResponse`: no-op (returns nil)

Constructor functions `StaticTokenMutator()`, `StaticBearerMutator()`,
`StaticGitHubTokenMutator()` return `CredentialMutator` (the interface).

### TokenProvider

Narrow interface for token provision, decoupling the bearer mutator from
the refresh mutator:

```go
type TokenProvider interface {
    AccessToken() (token string, err error)
}
```

Returns an error when no token is cached (cold start or expiry). The caller
decides how to handle the error.

## OAuthRefreshMutator

Handles `oauth2.googleapis.com`. Implements `CredentialMutator` and
`TokenProvider`.

### State

```go
type OAuthRefreshMutator struct {
    realRefreshToken string        // host-side real refresh token
    dummyAccessToken string        // sentinel returned to container

    mu               sync.RWMutex
    cachedToken      string        // real access token from Google
    cachedExpiry     time.Time     // expiry from Google's expires_in
}
```

### MutateRequest

Activation conditions (all must be true):
- `req.Method == "POST"`
- Path is `/token` or `/oauth2/v4/token`
- Parsed form body contains `grant_type=refresh_token`

If not activated: no-op (return nil).

If activated:
1. `io.ReadAll(req.Body)`, close original body
2. Parse as `application/x-www-form-urlencoded`
3. Replace `refresh_token` value with `realRefreshToken`
4. Re-encode form body
5. Set `req.Body = io.NopCloser(bytes.NewReader(encoded))`
6. Set `req.ContentLength = int64(len(encoded))`
7. Set `req.GetBody` to return the new body
8. Return nil

### MutateResponse

Activation conditions: `req.Method == "POST"` and path is `/token` or
`/oauth2/v4/token`. We cannot re-check `grant_type` from the request body
because `MutateRequest` already consumed and replaced it. Use method + path
only. If the upstream response does not contain `access_token`, the
replacement logic is a no-op anyway (step 4 below skips if the key is
absent).

If not activated: no-op.

If activated:
1. `io.ReadAll(resp.Body)`, close original body
2. `json.Unmarshal` into a `map[string]any`
3. Cache `access_token` value and compute expiry from `expires_in`
   (with 60-second skew subtracted) — acquire write lock only for
   the cache update, not for JSON parsing
4. Replace `access_token` with `dummyAccessToken`
5. If `refresh_token` is present in the response (token rotation),
   replace it with a dummy value (e.g., `1//proxy-sentinel-refresh`)
6. `json.Marshal` the modified map
7. Set `resp.Body = io.NopCloser(bytes.NewReader(modified))`
8. Set `resp.ContentLength = int64(len(modified))`
9. Delete `resp.Header["Transfer-Encoding"]`
10. Set `resp.TransferEncoding = nil`
11. Return nil

### AccessToken (TokenProvider)

Acquires read lock. If `cachedToken != ""` and `time.Now().Before(cachedExpiry)`,
returns `(cachedToken, nil)`. Otherwise returns `("", error)` indicating
no valid token is cached.

## OAuthBearerMutator

Handles API hosts (e.g., `cloudresourcemanager.googleapis.com`,
`aiplatform.googleapis.com`). Constructed with a `TokenProvider`.

### MutateRequest

**Unconditional overwrite** — does not check the incoming Authorization
header value. Calls `tokenProvider.AccessToken()`. If it returns a token,
sets `Authorization: Bearer <real-token>`. If it returns an error (cold
start), returns the error — the proxy writes a 502 and continues the
keep-alive loop.

### MutateResponse

No-op.

## Rule Wiring

```go
refreshMutator := NewOAuthRefreshMutator(realRefreshToken)

rules := NewRuleSet(
    Rule{Host: "oauth2.googleapis.com", Mutator: refreshMutator},
    Rule{Host: "cloudresourcemanager.googleapis.com", Mutator: NewOAuthBearerMutator(refreshMutator)},
    Rule{Host: "aiplatform.googleapis.com", Mutator: NewOAuthBearerMutator(refreshMutator)},
)
```

For Phase 3c, the API hosts and refresh token are specified via CLI flags.
Wildcard host matching is Phase 3d.

## Dummy Token Format

- Access token sentinel: `ya29.proxy-sentinel` (fixed string)
- Refresh token sentinel in responses: `1//proxy-sentinel-refresh` (fixed)

These are not secrets. Their purpose is to keep real tokens out of container
memory and logs, not to be unguessable. Network egress enforcement (nftables,
Phase 3d+) prevents the container from using them against real endpoints
directly.

## main.go Changes

1. Change `mutator(req)` to `mutator.MutateRequest(ctx, req)` where `ctx`
   is `context.Background()` (per-connection context deferred)
2. After successful `RoundTrip`, before `resp.Write`, call
   `mutator.MutateResponse(ctx, req, resp)`
3. If `MutateResponse` returns an error, log it and write a 502
4. `MutateResponse` is NOT called on the `RoundTrip` error path

## Files Changed

- `credential.go` — interface definition, `staticTokenMutator`,
  `TokenProvider`, `OAuthRefreshMutator`, `OAuthBearerMutator`
- `main.go` — call site updates for the interface, `MutateResponse` in
  the MITM loop
- `credential_test.go` — update existing tests for interface, add unit
  tests for both OAuth mutators
- `main_test.go` — end-to-end test with mock token endpoint + mock API
  endpoint

## Tests

### Unit tests (credential_test.go)

- `TestOAuthRefreshMutator_MutateRequest_SwapsToken` — verifies form body
  has real refresh_token after mutation
- `TestOAuthRefreshMutator_MutateRequest_NonRefreshGrant` — `grant_type=client_credentials`
  is a no-op
- `TestOAuthRefreshMutator_MutateRequest_WrongPath` — `POST /revoke` is
  a no-op
- `TestOAuthRefreshMutator_MutateRequest_GetMethod` — `GET /token` is
  a no-op
- `TestOAuthRefreshMutator_MutateResponse_CachesAndReplaces` — real token
  cached, dummy returned in body, `Content-Length` correct
- `TestOAuthRefreshMutator_MutateResponse_MasksRotatedRefreshToken` —
  rotated `refresh_token` in response is replaced
- `TestOAuthRefreshMutator_AccessToken_Expiry` — expired cache returns error
- `TestOAuthRefreshMutator_AccessToken_ColdStart` — empty cache returns error
- `TestOAuthBearerMutator_OverwritesUnconditionally` — always replaces
  Authorization header regardless of incoming value
- `TestOAuthBearerMutator_ErrorOnEmptyCache` — returns error when
  TokenProvider has no token
- Existing `TestStaticTokenMutator`, `TestStaticBearerMutator`,
  `TestStaticGitHubTokenMutator`, `TestRuleSetMatch` updated for interface
- All tests run with `-race`

### End-to-end test (main_test.go)

`TestOAuthRefreshFlow`:
1. Start a mock token endpoint that expects real refresh_token, returns
   `{"access_token":"ya29.real-token","expires_in":3600,"token_type":"Bearer"}`
2. Start a mock API endpoint that expects `Authorization: Bearer ya29.real-token`
3. Wire proxy with `OAuthRefreshMutator` for mock token host,
   `OAuthBearerMutator` for mock API host
4. Client sends `POST /token` with dummy refresh_token through proxy
5. Assert: mock token endpoint received real refresh_token
6. Assert: client received `ya29.proxy-sentinel` (not real token)
7. Assert: response `Content-Length` matches body
8. Client sends `GET /api` with `Authorization: Bearer ya29.proxy-sentinel`
   through proxy
9. Assert: mock API endpoint received `Authorization: Bearer ya29.real-token`
10. Assert: client received 200 from API

## Out of Scope

- Singleflight deduplication
- Wildcard host matching (Phase 3d)
- Per-container identity (Phase 3d)
- Config files / YAML (Phase 3d)
- Per-connection context threading
- 401-retry logic (container drives refresh lifecycle)
- Service account ADC flow (separate mutator, future phase)
