# CLAUDE.md

## Project

agent-proxy is a MITM credential injection proxy for containerized AI coding
agents. It performs TLS inspection on allowlisted destinations, injects
authentication headers, and forwards to real upstream servers — so credentials
never enter the container.

This project originated as a research spike in
[spnego-proxy](https://github.com/andrewesweet/spnego-proxy) and shares the
design philosophy of transparent, network-layer credential injection.

## Status

Research prototype (Phase 3a). Not production-ready.

## Go Version

Go 1.25. Use modern Go idioms.

## Testing

    go test -v -count=1 ./...

## Commit Convention

Same as spnego-proxy: [Conventional Commits v1.0.0](https://www.conventionalcommits.org/en/v1.0.0/).

    <type>[optional scope]: <description>

Allowed types: feat, fix, docs, refactor, test, perf, ci, build, chore.

## Architecture

- `main.go` — proxy core: CONNECT handling, TLS interception, header
  injection, passthrough tunneling, certificate generation and caching
- `main_test.go` — integration tests: MITM injection, host mismatch
  rejection, transparent passthrough
- `docs/` — research plan, adversarial reviews, empirical findings

## Key Design Decisions

See `docs/research-plan.md` for the full research trail. Summary:

- **Separate binary** from spnego-proxy (different users, threat model, release cadence)
- **Credential helpers don't help** for bearer-token APIs — the HTTP protocol
  requires the token in the calling process's memory. Network-layer injection
  is the only approach that keeps credentials out of the container.
- **No shim layer needed** — the proxy injects real credentials on outbound
  requests; real servers respond. No synthetic responses required.
- **Per-container Unix socket identity** (planned) — not SO_PEERCRED
- **nftables netns redirect** (planned) — not HTTP_PROXY env vars
- **Certificate cache** keyed by hostname with LRU eviction (planned)
- **CONNECT host == Host header == SNI** — all three must agree or reject
