# Adversarial Code Review — Phase 3b

**Date:** 2026-04-06
**Reviewer:** Senior Go Engineer (adversarial)
**Scope:** `main.go`, `credential.go`, `main_test.go`, `credential_test.go`
**Phase:** 3b prototype

---

## 1. Security Issues

### [Critical] Token value logged indirectly via `RuleSet.String()` — `main.go:73`

`slog.Info("rules loaded", "rules", rules.String())` calls `rs.Hosts()` which only
prints host names, so the token is safe here. However, `StaticTokenMutator`
closes over `headerValue` — if any future logging of the `Rule` struct or the
mutator closure is added (e.g., `%+v` on a request), the token will appear in
structured logs. The credential is stored as a plain string in the closure with
no zeroisation. **No scrubbing or wrapping type exists.** Rate: Medium.

### [High] Host comparison is case-sensitive but HTTP Host header is case-insensitive — `main.go:197`

`reqHost != destHost` compares raw strings. RFC 7230 §5.4 requires host
comparison to be case-insensitive for the hostname portion. A client sending
`Host: TEST.EXAMPLE.COM` when `destHost` is `test.example.com` gets a 400 and
the request is dropped — correct behavior for security. But if the CONNECT
authority is `TEST.EXAMPLE.COM`, the rule lookup at `main.go:143` calls
`rules.Match(host)` after `SplitHostPort`; `Match` uses `==` (`credential.go:58`).
So `CONNECT TEST.EXAMPLE.COM:443` will not match a rule for `test.example.com`
and falls to passthrough — silently **not injecting credentials** instead of
rejecting. This is a correctness failure, not a bypass of the mismatch check.

### [High] SNI not checked against CONNECT host — `main.go:165–172`

The design document (U1 resolution) requires all three to agree: CONNECT
authority, Host header, and SNI. The code checks CONNECT vs. Host header
(`main.go:197`) but never reads `tlsConn.ConnectionState().ServerName` and
never compares it to `destHost`. A client can send:

```
CONNECT api.github.com:443
SNI: evil.internal
```

The proxy generates a cert for `api.github.com`, injects the GitHub token, but
the upstream TLS dial (via `http.DefaultTransport`) uses `req.URL.Host =
destHost` so SNI to upstream is correct. The attack vector is limited, but the
design promise is broken and a future wildcard rule could be exploitable.

### [High] Header injection via newline in `headerValue` — `credential.go:17`

`StaticTokenMutator` calls `req.Header.Set(headerName, headerValue)`. Go's
`http.Header.Set` does **not** reject CRLF in header values in all Go versions
prior to the fix in Go 1.19. Go 1.25 (`net/http` does now sanitise); however,
`headerName` is also unsanitised. If `-header` is supplied as
`"Authorization\r\nX-Evil: injected"`, the flag value enters `headerName`
unvalidated. Validate both at startup with `http.ValidHeaderFieldName` and
`http.ValidHeaderFieldValue` (`net/textproto`). Rate: Medium in Go 1.25 due to
stdlib sanitisation, but the absence of input validation is a design smell.

### [Medium] Passthrough leaks destination addresses to arbitrary callers — `main.go:269–296`

Any TCP client that reaches the proxy can issue `CONNECT evil.internal:22` and
get a blind TCP tunnel to any host the proxy machine can reach. There is no
allowlist for passthrough destinations. In a containerised deployment this
enables SSRF against the host network. The design intends to use nftables
redirect (N7), which constrains which containers reach the proxy, but **the
code itself has no enforcement.**

### [Medium] Ephemeral CA key written to disk world-readable — `main.go:452–453`

`ca.crt` is written with mode `0644` (readable by all), `ca.key` with `0600`.
The CA cert being world-readable is expected (must be injected into the container
trust store). The key file is correct. However the `tmpDir` path is logged at
`main.go:454` (`slog.Info("ephemeral ca written", "dir", tmpDir)`). Any process
that can read stderr learns the key path. Combined with a container escape, this
is a credential-escalation primitive.

---

## 2. Resource Leaks

### [High] Response body closed after write, but not on error paths — `main.go:255–259`

```go
if err := resp.Write(tlsConn); err != nil {
    slog.Debug("write response to client", "error", err)
    return  // resp.Body never closed
}
resp.Body.Close()
```

When `resp.Write` returns an error, `resp.Body` is leaked. The upstream
connection held by `http.DefaultTransport` is never returned to the pool.
Under load this exhausts the connection pool and causes all upstream requests
to hang. Fix: `defer resp.Body.Close()` immediately after the successful
`RoundTrip` call (`main.go:232`).

### [Medium] `bufio.Reader` wrapping the raw `clientConn` is discarded — `main.go:123`, `main.go:269`

`handleConn` creates `br` from `clientConn` and passes it to `handleMITM` where
it is unused (the function creates `clientBuf` from `tlsConn` instead). In
`handlePassthrough` the parameter is `_`. The buffered reader over the raw TCP
connection may have read-ahead bytes that are silently discarded. For MITM this
is harmless (the buffer is before CONNECT parsing). For passthrough it is
harmless because nothing was read past the CONNECT request. But the pattern is
fragile — if CONNECT parsing is ever moved to buffer-consuming code, bytes will
be lost.

### [Low] Goroutine leak on `io.Copy` errors in passthrough — `main.go:287–295`

The two `io.Copy` goroutines block until both connections are closed. When one
direction EOF's, the `io.Copy` returns, `wg.Done()` is called, but the other
goroutine is still blocked on read. Only when the second direction closes does
`wg.Wait()` unblock. This is **correct**: the OS will close both ends when
`upstreamConn` and `clientConn` are deferred-closed. However, if one side
hangs (no read deadline), both goroutines and both connections are held
indefinitely. No read/write deadline is set on the passthrough connections.

---

## 3. Race Conditions

### [Low] Double-check locking in `certCache.getCert` is correct but fragile — `main.go:317–339`

The RLock / RUnlock / Lock pattern is the standard double-check pattern and is
correct in Go. However, if `generateCert` panics under the write lock (e.g.,
`rand.Reader` returns an error after generating the key but before returning),
`defer c.mu.Unlock()` will still fire — correct. The cache entry is never
written, so the next caller retries generation. No issue here, but the pattern
should be documented; it is easy to break by moving the `defer` above the
double-check.

### [Low] `RuleSet` has no mutex but is read-only after construction — `credential.go:45–63`

Safe as long as no future code mutates `rules.rules` after `NewRuleSet`. The
type does not enforce immutability. A future "reload rules on SIGHUP" feature
will introduce a race without an obvious guard. Consider making `rules []Rule`
unexported and adding a note.

---

## 4. Correctness

### [High] Keep-alive loop breaks on any upstream error — `main.go:233–245`

When `RoundTrip` fails, the proxy writes a `502` to the client and then
`return`s, ending the keep-alive loop and closing the TLS connection. This is
overly conservative: a single failed request kills all pipelined requests.
HTTP/1.1 clients that send multiple requests over one connection will be
disconnected on the first upstream timeout.

### [Medium] `resp.Write` does not close or flush chunked responses correctly for keep-alive

`http.Response.Write` on a keep-alive connection must emit `Content-Length` or
chunked `Transfer-Encoding` so the client can delimit the response body.
`resp.Write` delegates this to the stdlib, which handles it for well-formed
upstream responses. However, if the upstream response has neither
`Content-Length` nor `Transfer-Encoding: chunked` (a legal HTTP/1.1 response
using connection-close semantics), `resp.Write` will write the body and the
client will not know where it ends — it will hang reading until the proxy
closes the connection. The loop at `main.go:262` checks `resp.Close`, which
may not be set for such responses.

### [Medium] HEAD request body handling — `main.go:254`

`resp.Write` for a HEAD response should write headers only. `http.Response`
has no method to set `Request` for the write path when using raw writes;
`resp.Write` inspects `resp.Request` (nil here) to determine if it's a HEAD.
With a nil `resp.Request`, it may write a body when none should be present,
corrupting the keep-alive stream.

### [Low] `100-continue` not handled

`http.ReadRequest` parses `Expect: 100-continue` headers but the proxy never
sends `100 Continue`. Clients that send `Expect: 100-continue` will block
waiting for the interim response before sending the body. `RoundTrip` with
`http.DefaultTransport` handles `100-continue` internally for the upstream
leg, but the client-facing leg receives no `100` and will timeout.

---

## 5. Error Handling

### [Medium] Panic in goroutine crashes the process — `main.go:96`, `main.go:288–294`

`go p.handleConn(conn)` has no `recover`. A panic in `handleMITM` or
`handlePassthrough` (e.g., nil pointer from a malformed TLS record) crashes
the entire proxy, dropping all active connections. Add a deferred recover at
the top of `handleConn`.

### [Low] `fmt.Fprintf` write errors silently discarded — `main.go:132`, `main.go:156`, etc.

`fmt.Fprintf(clientConn, "HTTP/1.1 405 ...")` ignores the error. If the client
disconnected, the write fails silently and execution continues. Harmless in most
cases but masks connection errors.

---

## 6. Test Coverage Gaps

- **No test for keep-alive with multiple requests** over a single tunnel.
- **No test for upstream connection failure** (502 path) — verifies the `return`
  behaviour and body leak.
- **No test for SNI mismatch** (the U1 third leg not yet implemented).
- **No test for case-insensitive host matching** (uppercase CONNECT authority).
- **No test for a mutator that returns an error** — what response does the
  client see?
- **No test for HEAD requests** through the MITM path.
- **No test for passthrough with no port in CONNECT** (the `+":443"` fallback).
- **No test for concurrent MITM to the same host** — verifies the cert cache
  double-check under load.

---

## 7. Go Idiom Violations

### [Low] `context.Background()` for TLS handshake — `main.go:169`

No timeout on the client TLS handshake. A slow client can hold an accept slot
indefinitely. Use `context.WithTimeout(context.Background(), 30*time.Second)`.

### [Low] Constructing `http.Response` by value literal — `main.go:202–211`, `235–244`

Error responses constructed as `&http.Response{...}` with a manually set
`Body: io.NopCloser(strings.NewReader("..."))` and no `ContentLength` field.
This means `resp.Write` will produce a response with no `Content-Length` and
no `Transfer-Encoding`, relying on connection-close semantics in a keep-alive
context. Use `http.Error`-equivalent patterns or set `ContentLength` explicitly.

### [Low] `x509.ParseECPrivateKey` rejects PKCS8 keys — `main.go:405`

`loadCA` uses `x509.ParseECPrivateKey` (SEC 1 DER), which fails silently for
PKCS8-encoded keys (`-----BEGIN PRIVATE KEY-----`). Tools like `openssl genpkey`
produce PKCS8 by default. The error message (`parse ca key: asn1: ...`) is
opaque. Should try `x509.ParsePKCS8PrivateKey` as a fallback.

---

## 8. CredentialMutator Design

### [Medium] Signature `func(*http.Request) error` cannot modify the response

The current signature handles request-side injection well. It cannot:

1. **Inspect the response** — OAuth refresh-on-401 requires reading the response
   status, refreshing the token, and retrying. The mutator has no response hook.
2. **Read the request body** — `req.Body` is an `io.ReadCloser`; reading it in
   the mutator consumes it. A mutator that hashes the body for AWS SigV4 must
   restore `req.Body` with `io.NopCloser(bytes.NewReader(body))` — easy to
   get wrong.
3. **Access per-request context** — no `context.Context` parameter. A mutator
   that needs to call a token refresh endpoint has no cancellation handle.

**Recommended future signature:**

```go
type CredentialMutator interface {
    MutateRequest(ctx context.Context, req *http.Request) error
    MutateResponse(ctx context.Context, req *http.Request, resp *http.Response) (*http.Request, error)
    // MutateResponse returns non-nil *Request to signal a retry with modified req.
}
```

The function type `func(*http.Request) error` is convenient for static tokens
but is a dead end for Phase 3c (OAuth sentinels) and Phase 3d (SigV4).

---

## Summary Table

| ID | Severity | File:Line | Finding |
|----|----------|-----------|---------|
| S1 | High | main.go:165 | SNI not checked against CONNECT host (U1 partial) |
| S2 | High | main.go:197 | Case-sensitive host compare; CONNECT authority case mismatch goes to passthrough |
| S3 | High | main.go:269 | Passthrough SSRF: no destination allowlist |
| S4 | Medium | credential.go:17 | No validation of headerName/headerValue at construction |
| S5 | Medium | main.go:454 | Ephemeral CA key path logged to stderr |
| R1 | High | main.go:255 | Response body leaked on write error |
| R2 | Low | main.go:275 | No read deadline on passthrough connections |
| C1 | High | main.go:233 | Keep-alive loop aborted on first upstream error |
| C2 | Medium | main.go:254 | HEAD response may write body, corrupting keep-alive stream |
| C3 | Medium | (loop) | `100-continue` not handled; body-sending clients block |
| E1 | Medium | main.go:96 | No panic recovery in per-connection goroutines |
| D1 | Medium | credential.go:12 | Mutator signature lacks context, response hook, and body-restore pattern |
| G1 | Low | main.go:169 | No timeout on client TLS handshake |
| G2 | Low | main.go:405 | PKCS8 CA keys rejected with opaque error |
