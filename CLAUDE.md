# CLAUDE.md — WP Fleet

Hub that turns many goo1 Claude Bridge WordPress sites into **one** MCP
connector with five tools. TypeScript, Hono, SQLite (better-sqlite3) or D1.

## Layout
```
src/app.ts          Hono routes: discovery, OAuth server, /mcp, admin UI
src/config.ts       env → Config, Deps (sql, vault, cfg, fetch)
src/crypto.ts       WebCrypto: Vault (AES-GCM, HKDF from FLEET_KEK, AAD per row), PBKDF2, tokens
src/totp.ts         RFC 6238
src/auth.ts         admin, sessions, flash messages, atomic throttle `hit()`, TOTP lock
src/lock.ts         in-process withLock / Semaphore (per isolate on Workers)
src/oauth/server.ts OAuth 2.1 AS for MCP clients (DCR, PKCE S256, rotating RT + grace, revoke)
src/sites.ts        OAuth client + MCP client for Bridge sites (discovery, DCR, authorize, refresh, rpc, tool cache)
src/mcp/fleet.ts    fleet_* tools and JSON-RPC dispatch
src/ui/html.ts      escaping template helper `h`, page layout
src/store/*         Sql interface, schema, sqlite + d1 implementations
src/node.ts         Docker entry; src/cli.ts admin CLI; src/worker.ts Cloudflare entry
test/e2e.py         end-to-end test against a local WordPress + Bridge
test/browser.cjs    Playwright smoke test of login/TOTP/admin forms in a real browser
```

## Rules
- Only Web-standard APIs in everything except `node.ts`, `cli.ts`, `store/sqlite.ts` (keeps the Worker build working). Run `npm run typecheck` (checks both configs).
- Every secret at rest goes through `Vault.seal(value, aad)` with an AAD naming the row and column (`site:<id>:refresh` …). Never log tokens.
- HTML: always build with the `h` template tag (auto-escapes); `raw()` only for trusted markup (QR SVG).
- Admin POST routes go through `adminForm()` (session + TOTP + CSRF + Origin).
- Outbound requests to sites: only URLs on the site's own origin (`sameOrigin`, https unless FLEET_ALLOW_HTTP_SITES), `redirect: 'manual'`/`'error'`, timeouts, 4 MB cap enforced while streaming (`readText`).
- Read/write split: `toolAccess()` = `annotations.readOnlyHint === true`. `fleet_call_write` needs connection scope `write` and exactly one site.
- Site refresh tokens rotate: `storeTokens()` persists the new RT before the AT is used; one refresh per site at a time (`refreshing` map). After a 401, `accessToken(site, rejected)` never returns the rejected token again.
- Discovery + DCR return a `Registration`; it is kept sealed in `site_auth.reg_enc` and written to `sites` only after a successful callback.
- Throttles: always `hit()` (count first, then decide) — never read-then-write.
- OAuth server: refresh grant runs under `withLock('rt:'+hash)`; the winner's response is sealed in `oauth_rt_used.response_enc` and replayed once within the grace window. A reused code revokes its family.
- Admin feedback goes through `setFlash()`/`takeFlash()`, never as text in the URL.
- Run `test/e2e.py` after changes (see README); after changes to headers, cookies or forms also `test/browser.cjs` (a real browser sends Origin according to the Referrer-Policy).
- Keep `Referrer-Policy: same-origin`: with `no-referrer` browsers send `Origin: null` on form posts and every login fails.
