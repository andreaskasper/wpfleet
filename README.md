# WP Fleet

One MCP connector for many WordPress sites running the
[goo1 Claude Bridge](https://github.com/andreaskasper/wordpress-plugins/tree/main/src/goo1-mcp) (1.6 or newer).

Every Bridge site offers ~100 tools. With ten sites connected separately, the
tool definitions alone fill a large part of Claude's context window. WP Fleet
connects to all sites itself and offers Claude **five** tools (~3 KB):

| Tool | What it does |
|---|---|
| `fleet_sites` | the sites this connection may use (id, name, status, Bridge version, access) |
| `fleet_find_tools` | keyword search over all tools of all sites (`"elementor widget"`, `"plugin update"`) |
| `fleet_describe_tool` | full description + input schema of a tool |
| `fleet_call_read` | run a read-only tool on one site, several (`a,b`) or all (`*`) in parallel |
| `fleet_call_write` | run a tool that changes data on exactly one site |

Read vs. write follows the tool's `readOnlyHint` as reported by each site, so
in Claude you can "always allow" `fleet_call_read` and still approve every write.

## How it works

```
Claude ──OAuth──▶ WP Fleet ──OAuth (one connection per site)──▶ goo1 Claude Bridge sites
          (password + TOTP)           (tokens AES-GCM encrypted at rest)
```

* **Claude → WP Fleet:** WP Fleet is an OAuth 2.1 server (Dynamic Client
  Registration, PKCE S256, rotating refresh tokens). On the approval page you
  choose *read only* or *read + write* and optionally which sites the
  connection may use. *Read only* is preselected.
* **WP Fleet → sites:** WP Fleet registers itself on each Bridge as an OAuth
  client. "Connect" opens the site's own consent page; you log in to WordPress
  and pick the access level there. No API keys are copied anywhere.
* Every call keeps the site's own checks: scopes, rate limit, redaction of
  secrets, the site's audit log. WP Fleet logs every call in its own audit log.

## Run with Docker (Traefik)

```bash
mkdir -p /var/docker/wpfleet && cd /var/docker/wpfleet
# copy deploy/docker-compose.yml and deploy/.env.example (as .env) from this repo
openssl rand -base64 32          # → FLEET_KEK in .env
docker compose up -d
docker exec -it wpfleet node dist/cli.js admin-create --user andreas
```

Then open `https://wpfleet.goo1.de/login`, log in (the first login asks you to
set up an authenticator app), add your sites and click **Connect** for each.

Finally add the connector in Claude: **Settings → Connectors → Add custom
connector**, URL `https://wpfleet.goo1.de/mcp`. You can then switch off the
individual site connectors.

### Configuration (`.env`)

| Variable | Meaning |
|---|---|
| `FLEET_PUBLIC_URL` | public origin, e.g. `https://wpfleet.goo1.de` (required) |
| `FLEET_KEK` | 32+ random bytes, base64 — encrypts all stored tokens (required; losing it = reconnect all sites) |
| `FLEET_IP_HEADER` | header with the client IP set by your proxy (`x-real-ip` for Traefik, `cf-connecting-ip` for Cloudflare) |
| `FLEET_REDIRECT_HOSTS` | hosts MCP clients may register https redirect URIs on (default `claude.ai,claude.com`, subdomains included; loopback always allowed) |
| `FLEET_SETUP_TOKEN` | optional: allows creating the admin in the browser at `/setup` (≥ 24 chars; remove afterwards) |
| `FLEET_ACCESS_TTL` | access-token lifetime for Claude in seconds (default 3600) |
| `FLEET_REFRESH_TTL_DAYS` | days without use until Claude must reconnect (default 90) |
| `FLEET_PBKDF2_ITERATIONS` | password hashing (default 600000; Workers: 100000) |
| `FLEET_DB_PATH` | SQLite file (default `/data/wpfleet.db`) |

### CLI

```bash
docker exec -it wpfleet node dist/cli.js admin-create --user <name>
docker exec -it wpfleet node dist/cli.js admin-password   # logs out all sessions
docker exec -it wpfleet node dist/cli.js totp-reset       # lost the authenticator
docker exec -it wpfleet node dist/cli.js sites
```

## Security notes

* WP Fleet holds a connection to every site. Protect the host and `FLEET_KEK`
  like the sites' admin passwords. Back up `data/` **and** `.env` together.
* Admin login: password (PBKDF2) + TOTP. Attempts are counted atomically per
  IP (8 per 15 min) before the password is checked, at most two password
  checks run at a time, and wrong TOTP codes after a correct password are
  counted separately (10 per hour, then locked; `totp-reset` in the CLI).
  A flood across many IPs is logged (`login_flood`) instead of locking the
  admin out. Sessions are HttpOnly/Secure/SameSite cookies; forms have CSRF
  tokens and an Origin check; strict CSP; HSTS on https.
* Request bodies are limited (1 MB for `/mcp`, 64 KB elsewhere; the Traefik
  labels limit them too), responses from sites to 4 MB.
* Only Claude (claude.ai/claude.com) and loopback clients can register; the
  list is configurable.
* Tokens are only accepted while their connection exists; disconnecting a
  connection on the dashboard kills its tokens immediately. Refresh tokens
  rotate: two parallel refreshes of the same token within 120 s get the
  identical answer; any later replay revokes the connection, so does a
  reused authorization code.
* WP Fleet only follows OAuth/MCP URLs on the site's own origin (https).
  Reconnecting a site only replaces the working connection after the new
  one succeeded.
* `fleet_call_read` drops the Bridge's `unredacted` flag, so an "always
  allowed" read can never return secrets.
* Multisite or several WordPress installs on one host: each install is its
  own site in WP Fleet (the id includes the path).
* Removing a site in WP Fleet does not revoke the connection on the site:
  disconnect "WP Fleet" there under *Claude Bridge → Connector (OAuth)*.

## Other runtimes

The app (Hono) only uses Web standards, so the same code runs as a
**Cloudflare Worker** with D1 (`src/worker.ts`, `wrangler.example.toml`;
untested in production). Limits there: the in-process locks (token rotation,
parallel logins) only work within one isolate, so rare races can end in a
revoked connection (just reconnect); PBKDF2 is capped at 100 000 iterations. A hub mode inside the Bridge plugin itself is
planned.

## Development

```bash
npm ci && npm run build && npm run typecheck
FLEET_PUBLIC_URL=http://localhost:8787 FLEET_KEK=$(openssl rand -base64 32) \
  FLEET_DB_PATH=./data/dev.db FLEET_ALLOW_HTTP_SITES=1 npm start
# end-to-end test against a local WordPress with the Bridge:
FLEET_USER=… FLEET_PASS=… WP_USER=… WP_PASS=… FLEET_DB_PATH=./data/dev.db python3 test/e2e.py
```

License: GPL-2.0-or-later.
