# Phase 3c Continuation Prompt

Run this in a new Claude Code session from `/home/sweeand/andrewesweet/agent-proxy`.

---

## Prompt

Continue building agent-proxy. Phase 3b is complete (CredentialMutator abstraction, multi-destination rules, all code review findings addressed). Begin Phase 3c: OAuth token exchange interception for the google-auth ADC flow.

### Context

This is a MITM credential injection proxy for containerized AI coding agents. It terminates TLS on allowlisted destinations, injects credentials, and forwards to real upstream servers — so credentials never enter the container.

Read CLAUDE.md, docs/design-decisions.md, docs/phase2-empirical-findings.md, and docs/code-review-phase3b.md for full context. Check memory for project decisions (Podman, multi-container, credential order).

### Phase 3c scope

1. **Upgrade CredentialMutator from function type to interface** (D1 from code review):
   ```go
   type CredentialMutator interface {
       MutateRequest(ctx context.Context, req *http.Request) error
   }
   ```
   Keep it simple — add `MutateResponse` only if concretely needed during implementation. `StaticTokenMutator` et al become wrapper types implementing the interface.

2. **OAuthRefreshMutator** for google-auth authorized_user ADC flow:
   - Container has a fake ADC file with a dummy `refresh_token`
   - Container's google-auth POSTs to `oauth2.googleapis.com/token` with `grant_type=refresh_token`
   - Proxy intercepts this POST (it's an ordinary MITM'd request to an allowlisted host)
   - Proxy performs the REAL token refresh on the host side using the real refresh token
   - Proxy returns the real access token in the response to the container
   - Container uses the access token on subsequent API calls (proxy passes these through with no further modification since the token is already real)
   - Use `golang.org/x/sync/singleflight` to deduplicate concurrent refresh calls

3. **Important insight from Phase 2**: the proxy does NOT need sentinel tokens for google-auth. The flow is:
   - Fake ADC file → container sends dummy refresh_token → proxy intercepts at `oauth2.googleapis.com/token` → proxy uses REAL refresh_token to get REAL access_token → returns real access_token to container → container sends real access_token on API calls → proxy passes through (token is already real)
   - The access token IS in the container's memory (unavoidable — it's in the HTTP response). But the refresh_token (long-lived, high-value) never enters the container. This is the security boundary: short-lived access tokens (1h TTL) leak; long-lived refresh tokens don't.

4. **Tests**: end-to-end test with a mock token endpoint and a mock API endpoint, verifying the refresh flow works through the proxy.

### What NOT to do
- Don't add wildcard host matching yet (Phase 3d)
- Don't add per-container identity yet (Phase 3d)
- Don't add config files or YAML (Phase 3d)
- Don't change the CLI flags beyond what's needed for the OAuth flow
- Commission an adversarial code review with a Sonnet 4.6 extended thinking subagent when done, and address findings before committing
