/**
 * WP Fleet HTTP app (Hono). Runtime-agnostic: the Node entry (node.ts) and the
 * Worker entry (worker.ts) only provide the Deps (SQL store, vault, config).
 */
import { Hono, type Context } from 'hono';
import { getCookie } from 'hono/cookie';
import { bodyLimit } from 'hono/body-limit';
import QRCode from 'qrcode';
import type { Deps } from './config.js';
import { now } from './config.js';
import { audit, housekeeping } from './audit.js';
import {
  checkLogin, clearFailures, cookieAttrs, cookieName, createAdmin, createSession, destroySession, getAdmin, hit,
  loadSession, markSessionTotp, setFlash, takeFlash, type SessionRow,
} from './auth.js';
import { Semaphore } from './lock.js';
import { safeEqual } from './crypto.js';
import { newTotpSecret, otpauthUri, verifyTotp } from './totp.js';
import {
  authorizationServerMetadata, clientAllowsRedirect, getClient, issueCode, listConnections, protectedResourceMetadata,
  registerClient, revokeFamily, revokeToken, tokenEndpoint, validateAccessToken, SCOPES, type Scope,
} from './oauth/server.js';
import { handleRpc } from './mcp/fleet.js';
import {
  addSite, discoverAndRegister, finishAuthorize, getSite, listSites, refreshTools, removeSite, renameSite,
  SiteError, siteTools, startAuthorize,
} from './sites.js';
import { fmtTime, h, message, page, raw } from './ui/html.js';

type Env = { Variables: { session: SessionRow | null } };

const CSP =
  "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; frame-ancestors 'none'; " +
  "form-action 'self' https: http://localhost:* http://127.0.0.1:*";

const KB = 1024;

export function createApp(d: Deps): Hono<Env> {
  const app = new Hono<Env>();
  let lastHousekeeping = 0;
  // PBKDF2 is deliberately slow: at most two password checks at a time.
  const loginGate = new Semaphore(2);
  const tooLarge = (c: Context<Env>) => c.json({ error: 'request_too_large' }, 413);

  app.use('/mcp', bodyLimit({ maxSize: 1024 * KB, onError: tooLarge }));
  app.use('*', async (c, next) => {
    if (c.req.path === '/mcp') return next();
    return bodyLimit({ maxSize: 64 * KB, onError: tooLarge })(c, next);
  });

  app.use('*', async (c, next) => {
    if (now() - lastHousekeeping > 600) {
      lastHousekeeping = now();
      housekeeping(d).catch(() => {});
    }
    c.set('session', await loadSession(d, getCookie(c, cookieName(d))));
    await next();
    c.header('X-Content-Type-Options', 'nosniff');
    c.header('Referrer-Policy', 'no-referrer');
    if (d.cfg.publicUrl.startsWith('https://')) c.header('Strict-Transport-Security', 'max-age=31536000');
    if ((c.res.headers.get('content-type') || '').includes('text/html')) {
      c.header('Content-Security-Policy', CSP);
      c.header('Cache-Control', 'no-store');
    }
  });

  /* ---------------- helpers ---------------- */

  const html = (c: Context<Env>, body: string, status = 200) => c.html(body, status as any);

  const sameOrigin = (c: Context<Env>): boolean => {
    const o = c.req.header('origin');
    return !o || o === d.cfg.publicUrl;
  };

  /** POST guard for admin forms: logged in with TOTP, CSRF token, same origin. */
  async function adminForm(c: Context<Env>): Promise<Record<string, string> | Response> {
    const s = c.get('session');
    if (!s || !s.totp_ok) return c.redirect('/login');
    const body = (await c.req.parseBody()) as Record<string, string>;
    if (!sameOrigin(c) || typeof body.csrf !== 'string' || !safeEqual(body.csrf, s.csrf)) {
      return html(c, page('Error', message('The form has expired. Please go back and try again.')), 403);
    }
    return body;
  }

  function requireAdmin(c: Context<Env>): Response | null {
    const s = c.get('session');
    if (s && s.totp_ok) return null;
    if (s && !s.totp_ok) return c.redirect('/totp');
    const next = new URL(c.req.url);
    return c.redirect('/login?next=' + encodeURIComponent(next.pathname + next.search));
  }

  /** Client IP for throttling, from the header the trusted proxy sets (FLEET_IP_HEADER). */
  function clientIp(c: Context<Env>): string {
    if (!d.cfg.ipHeader) return 'direct';
    return (c.req.header(d.cfg.ipHeader) || 'unknown').split(',')[0].trim().slice(0, 64);
  }

  function safeNext(n: string | undefined): string {
    return n && /^\/(?!\/)[^\s\\]*$/.test(n) ? n : '/admin';
  }

  const cors = (c: Context<Env>) => {
    c.header('Access-Control-Allow-Origin', '*');
    c.header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    c.header('Access-Control-Allow-Headers', 'Authorization, Content-Type, Mcp-Protocol-Version, Mcp-Session-Id');
    c.header('Access-Control-Expose-Headers', 'WWW-Authenticate, Mcp-Session-Id');
    c.header('Access-Control-Max-Age', '86400');
  };
  for (const p of ['/mcp', '/oauth/token', '/oauth/register', '/oauth/revoke', '/.well-known/*']) {
    app.options(p, (c) => {
      cors(c);
      return c.body(null, 204);
    });
  }

  /* ---------------- discovery ---------------- */

  app.get('/healthz', (c) => c.json({ ok: true }));
  app.get('/', (c) => c.redirect('/admin'));

  const prm = (c: Context<Env>) => {
    cors(c);
    return c.json(protectedResourceMetadata(d));
  };
  app.get('/.well-known/oauth-protected-resource', prm);
  app.get('/.well-known/oauth-protected-resource/mcp', prm);
  const asm = (c: Context<Env>) => {
    cors(c);
    return c.json(authorizationServerMetadata(d));
  };
  app.get('/.well-known/oauth-authorization-server', asm);
  app.get('/.well-known/openid-configuration', asm);

  /* ---------------- OAuth server (for Claude) ---------------- */

  app.post('/oauth/register', async (c) => {
    cors(c);
    let body: any = null;
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: 'invalid_client_metadata', error_description: 'JSON body required.' }, 400);
    }
    c.header('Cache-Control', 'no-store');
    if ((await hit(d, 'dcr:' + clientIp(c), 10, 3600)) || (await hit(d, 'dcr:*', 60, 3600))) {
      return c.json({ error: 'temporarily_unavailable', error_description: 'Too many registrations.' }, 429);
    }
    const r = await registerClient(d, body);
    return c.json(r.json as any, r.status as any);
  });

  async function readTokenParams(c: Context<Env>): Promise<Record<string, string>> {
    const ct = c.req.header('content-type') || '';
    if (ct.includes('application/json')) {
      try {
        const j = await c.req.json();
        return Object.fromEntries(Object.entries(j || {}).map(([k, v]) => [k, String(v)]));
      } catch {
        return {};
      }
    }
    const b = (await c.req.parseBody()) as Record<string, unknown>;
    return Object.fromEntries(Object.entries(b).map(([k, v]) => [k, String(v)]));
  }

  app.post('/oauth/token', async (c) => {
    cors(c);
    c.header('Cache-Control', 'no-store');
    const r = await tokenEndpoint(d, await readTokenParams(c), c.req.header('authorization') || null);
    return c.json(r.json as any, r.status as any);
  });

  app.post('/oauth/revoke', async (c) => {
    cors(c);
    c.header('Cache-Control', 'no-store');
    const p = await readTokenParams(c);
    await revokeToken(d, p.token || '');
    return c.body(null, 200);
  });

  interface AuthReq {
    client_id: string;
    redirect_uri: string;
    response_type: string;
    state: string;
    code_challenge: string;
    code_challenge_method: string;
    scope: string;
  }

  function authParams(src: Record<string, string | undefined>): AuthReq {
    const g = (k: string) => (typeof src[k] === 'string' ? (src[k] as string) : '');
    return {
      client_id: g('client_id'),
      redirect_uri: g('redirect_uri'),
      response_type: g('response_type'),
      state: g('state'),
      code_challenge: g('code_challenge'),
      code_challenge_method: g('code_challenge_method') || 'plain',
      scope: g('scope'),
    };
  }

  function redirectWith(c: Context<Env>, uri: string, params: Record<string, string>) {
    const u = new URL(uri);
    for (const [k, v] of Object.entries(params)) if (v) u.searchParams.set(k, v);
    return c.redirect(u.toString(), 302);
  }

  /** Validate an authorization request. Errors before redirect_uri is trusted are shown, never redirected. */
  async function checkAuthReq(c: Context<Env>, a: AuthReq): Promise<Response | { clientName: string }> {
    const client = await getClient(d, a.client_id);
    if (!client) return html(c, page('Error', message('Unknown client_id.')), 400);
    if (!clientAllowsRedirect(d, client, a.redirect_uri)) return html(c, page('Error', message('Invalid or unregistered redirect_uri for this client.')), 400);
    const deny = requireAdmin(c);
    if (deny) return deny;
    if (a.response_type !== 'code') return redirectWith(c, a.redirect_uri, { error: 'unsupported_response_type', state: a.state });
    if (!a.code_challenge || a.code_challenge_method !== 'S256') {
      return redirectWith(c, a.redirect_uri, { error: 'invalid_request', error_description: 'PKCE with S256 is required.', state: a.state });
    }
    return { clientName: client.client_name };
  }

  app.get('/oauth/authorize', async (c) => {
    const a = authParams(c.req.query());
    const chk = await checkAuthReq(c, a);
    if (chk instanceof Response) return chk;
    const s = c.get('session')!;
    const sites = await listSites(d);
    // Default is read-only; write access must be chosen on purpose.
    const wantsWrite = false;
    const hidden = (Object.keys(a) as (keyof AuthReq)[]).map((k) => h`<input type="hidden" name="${k}" value="${a[k]}">`);
    return html(
      c,
      page(
        'Authorize',
        h`<div class="card narrow" style="max-width:520px">
          <h1>Connect ${chk.clientName}?</h1>
          <p class="muted">The client will use WP Fleet with the rights you choose. Afterwards it is listed under Connections and can be disconnected at any time.</p>
          <p class="muted">Redirect: <code>${a.redirect_uri}</code></p>
          <form method="post" action="/oauth/authorize">
            ${hidden}<input type="hidden" name="csrf" value="${s.csrf}">
            <fieldset><legend>Access</legend>
              <label class="opt"><input type="radio" name="grant_scope" value="read" ${wantsWrite ? '' : raw('checked')}> <span>Read only — only <code>fleet_call_read</code></span></label>
              <label class="opt"><input type="radio" name="grant_scope" value="write" ${wantsWrite ? raw('checked') : ''}> <span>Read + write — also <code>fleet_call_write</code> (Claude still asks before each write)</span></label>
            </fieldset>
            <fieldset><legend>Sites</legend>
              <label class="opt"><input type="checkbox" name="all_sites" value="1" checked> <span>All sites, including ones added later</span></label>
              <p class="muted">Or untick that and choose:</p>
              ${sites.map((x) => h`<label class="opt"><input type="checkbox" name="site_${x.id}" value="1"> <span>${x.name} <span class="muted">${x.id}</span></span></label>`)}
            </fieldset>
            <div class="row"><button type="submit" name="decision" value="approve">Approve</button> <button class="sec" type="submit" name="decision" value="deny">Deny</button></div>
          </form></div>`,
        { user: 'admin', csrf: s.csrf },
      ),
    );
  });

  app.post('/oauth/authorize', async (c) => {
    const body = (await c.req.parseBody()) as Record<string, string>;
    const a = authParams(body);
    const chk = await checkAuthReq(c, a);
    if (chk instanceof Response) return chk;
    const s = c.get('session')!;
    if (!sameOrigin(c) || !safeEqual(String(body.csrf || ''), s.csrf)) return html(c, page('Error', message('The form has expired. Start the connection again.')), 403);
    if (body.decision !== 'approve') return redirectWith(c, a.redirect_uri, { error: 'access_denied', state: a.state });
    const scope: Scope = (SCOPES as readonly string[]).includes(body.grant_scope) ? (body.grant_scope as Scope) : 'read';
    let sites: string[] | null = null;
    if (body.all_sites !== '1') {
      const known = (await listSites(d)).map((x) => x.id);
      sites = known.filter((id) => body['site_' + id] === '1');
    }
    const code = await issueCode(d, { clientId: a.client_id, redirectUri: a.redirect_uri, challenge: a.code_challenge, scope, sites });
    await audit(d, { actor: 'admin', action: 'connection_approved', detail: chk.clientName + ' scope=' + scope + ' sites=' + (sites ? sites.join(',') : 'all') });
    return redirectWith(c, a.redirect_uri, { code, state: a.state, iss: d.cfg.publicUrl });
  });

  /* ---------------- MCP endpoint ---------------- */

  const unauthorized = (c: Context<Env>) => {
    cors(c);
    c.header('WWW-Authenticate', `Bearer resource_metadata="${d.cfg.publicUrl}/.well-known/oauth-protected-resource/mcp"`);
    return c.json({ jsonrpc: '2.0', id: null, error: { code: -32001, message: 'Unauthorized' } }, 401);
  };

  app.on(['GET', 'POST', 'DELETE'], '/mcp', async (c) => {
    cors(c);
    const authz = c.req.header('authorization') || '';
    const token = authz.replace(/^Bearer\s+/i, '');
    const acc = token && token !== authz ? await validateAccessToken(d, token) : null;
    if (!acc) return unauthorized(c);
    if (c.req.method === 'GET') return c.body(null, 405);
    if (c.req.method === 'DELETE') return c.body(null, 204);
    let body: any;
    try {
      body = await c.req.json();
    } catch {
      return c.json({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }, 400);
    }
    const batch = Array.isArray(body);
    const msgs = batch ? body : [body];
    const out = [];
    for (const m of msgs.slice(0, 20)) {
      const r = await handleRpc(d, acc, m);
      if (r) out.push(r);
    }
    if (!out.length) return c.body(null, 202);
    return c.json((batch ? out : out[0]) as any);
  });

  /* ---------------- setup / login / TOTP ---------------- */

  app.get('/setup', async (c) => {
    if (await getAdmin(d)) return c.redirect('/login');
    if (!d.cfg.setupToken) {
      return html(c, page('Setup', h`<div class="card narrow"><h1>Set up WP Fleet</h1><p>Create the admin on the server:</p><p><code>docker exec -it wpfleet node dist/cli.js admin-create --user &lt;name&gt;</code></p><p class="muted">Or set FLEET_SETUP_TOKEN (at least 24 characters) and open /setup again.</p></div>`));
    }
    return html(c, page('Setup', h`<div class="card narrow"><h1>Set up WP Fleet</h1><form method="post">
      <label><span>Setup token (FLEET_SETUP_TOKEN)</span><input type="password" name="token" required autocomplete="off"></label>
      <label><span>Username</span><input type="text" name="username" required autocomplete="username"></label>
      <label><span>Password (min. 12 characters)</span><input type="password" name="password" required autocomplete="new-password" minlength="12"></label>
      <button type="submit">Create admin</button></form></div>`));
  });

  app.post('/setup', async (c) => {
    if ((await getAdmin(d)) || !d.cfg.setupToken) return c.redirect('/login');
    if (await hit(d, 'setup', 10, 3600)) return html(c, page('Setup', message('Too many attempts. Try again later.')), 429);
    const b = (await c.req.parseBody()) as Record<string, string>;
    if (!sameOrigin(c) || !safeEqual(String(b.token || ''), d.cfg.setupToken)) {
      return html(c, page('Setup', message('Wrong setup token.')), 403);
    }
    try {
      await createAdmin(d, String(b.username || ''), String(b.password || ''));
    } catch (e) {
      return html(c, page('Setup', message((e as Error).message)), 400);
    }
    await audit(d, { actor: 'setup', action: 'admin_created' });
    return c.redirect('/login?created=1');
  });

  const loginForm = (msg: string | null, next: string, info: string | null = null) =>
    page('Log in', h`<div class="card narrow"><h1>Log in</h1>${message(msg)}${message(info, 'okm')}<form method="post" action="/login">
      <input type="hidden" name="next" value="${next}">
      <label><span>Username</span><input type="text" name="username" required autocomplete="username" autofocus></label>
      <label><span>Password</span><input type="password" name="password" required autocomplete="current-password"></label>
      <label><span>Authenticator code (leave empty on the very first login)</span><input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{0,8}"></label>
      <button type="submit">Log in</button></form></div>`);

  app.get('/login', async (c) => {
    if (!(await getAdmin(d))) return c.redirect('/setup');
    const s = c.get('session');
    if (s?.totp_ok) return c.redirect(safeNext(c.req.query('next')));
    return html(c, loginForm(null, safeNext(c.req.query('next')), c.req.query('created') ? 'Admin created. Log in and set up the authenticator.' : null));
  });

  app.post('/login', async (c) => {
    const b = (await c.req.parseBody()) as Record<string, string>;
    const next = safeNext(b.next);
    if (!sameOrigin(c)) return html(c, loginForm('Invalid request origin.', next), 403);
    const ip = clientIp(c);
    const key = 'login:' + ip;
    // Count first, check afterwards: parallel requests cannot slip past the limit.
    if (await hit(d, key, 8, 900)) return html(c, loginForm('Too many failed attempts. Wait 15 minutes.', next), 429);
    if (await hit(d, 'login:*', 200, 900)) {
      // No global lockout (it would lock out the admin too); log it once per window instead.
      if (!(await hit(d, 'login:*:alerted', 1, 900))) await audit(d, { actor: 'login', action: 'login_flood', detail: 'more than 200 login attempts in 15 minutes' });
    }
    const r = await loginGate.run(() => checkLogin(d, String(b.username || ''), String(b.password || ''), String(b.code || '')));
    if (r === 'totp_locked') {
      await audit(d, { actor: 'login', action: 'totp_locked', detail: ip });
      return html(c, loginForm('Too many wrong authenticator codes. Wait an hour or reset TOTP with the CLI.', next), 429);
    }
    if (r !== 'ok' && r !== 'enroll') {
      await audit(d, { actor: 'login', action: 'login_failed', detail: ip });
      return html(c, loginForm(r, next), 401);
    }
    await clearFailures(d, key);
    const old = c.get('session');
    if (old) await destroySession(d, old.id_hash);
    const raw_ = await createSession(d, r === 'ok');
    c.header('Set-Cookie', cookieName(d) + '=' + raw_ + cookieAttrs(d, 12 * 3600));
    await audit(d, { actor: 'admin', action: 'login' });
    return c.redirect(r === 'ok' ? next : '/totp?next=' + encodeURIComponent(next));
  });

  app.post('/logout', async (c) => {
    const s = c.get('session');
    const b = (await c.req.parseBody()) as Record<string, string>;
    if (s && safeEqual(String(b.csrf || ''), s.csrf)) await destroySession(d, s.id_hash);
    c.header('Set-Cookie', cookieName(d) + '=' + cookieAttrs(d, 0));
    return c.redirect('/login');
  });

  /** TOTP already set up: a session without TOTP must log in again (otherwise /admin ↔ /totp loops). */
  async function totpDone(c: Context<Env>, s: SessionRow) {
    if (s.totp_ok) return c.redirect('/admin');
    await destroySession(d, s.id_hash);
    c.header('Set-Cookie', cookieName(d) + '=' + cookieAttrs(d, 0));
    return c.redirect('/login');
  }

  // TOTP enrollment: only right after a password login while no TOTP exists.
  app.get('/totp', async (c) => {
    const s = c.get('session');
    const admin = await getAdmin(d);
    if (!s || !admin) return c.redirect('/login');
    if (admin.totp_enabled) return totpDone(c, s);
    let secret = await d.vault.open(admin.totp_secret_enc, 'admin:totp');
    if (!secret) {
      secret = newTotpSecret();
      await d.sql.run('UPDATE admin SET totp_secret_enc = ? WHERE id = 1', [await d.vault.seal(secret, 'admin:totp')]);
    }
    const uri = otpauthUri(secret, admin.username + '@' + new URL(d.cfg.publicUrl).host);
    const svg = await QRCode.toString(uri, { type: 'svg', margin: 1, errorCorrectionLevel: 'M' });
    return html(c, page('Authenticator', h`<div class="card narrow"><h1>Set up the authenticator</h1>
      ${c.req.query('error') ? message('Wrong code. Check the time on your phone and try again.') : ''}
      <p>Scan the code with your authenticator app (or enter the key by hand), then confirm with the current 6-digit code. From now on every login needs it.</p>
      <div class="qr">${raw(svg)}</div><p class="muted">Key: <code>${secret.replace(/(.{4})/g, '$1 ').trim()}</code></p>
      <form method="post" action="/totp"><input type="hidden" name="csrf" value="${s.csrf}"><input type="hidden" name="next" value="${safeNext(c.req.query('next'))}">
      <label><span>Code</span><input type="text" name="code" required inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,8}"></label>
      <button type="submit">Activate</button></form></div>`));
  });

  app.post('/totp', async (c) => {
    const s = c.get('session');
    const admin = await getAdmin(d);
    const b = (await c.req.parseBody()) as Record<string, string>;
    if (!s || !admin || !sameOrigin(c) || !safeEqual(String(b.csrf || ''), s.csrf)) return c.redirect('/login');
    if (admin.totp_enabled) return totpDone(c, s);
    if (await hit(d, 'totp-enroll', 8, 900)) return html(c, page('Authenticator', message('Too many attempts. Wait 15 minutes.')), 429);
    const secret = await d.vault.open(admin.totp_secret_enc, 'admin:totp');
    const counter = secret ? await verifyTotp(secret, String(b.code || '')) : null;
    if (counter === null) return c.redirect('/totp?error=1');
    await d.sql.run('UPDATE admin SET totp_enabled = 1, totp_last_counter = ? WHERE id = 1', [counter]);
    await markSessionTotp(d, s.id_hash);
    await audit(d, { actor: 'admin', action: 'totp_enabled' });
    return c.redirect(safeNext(b.next));
  });

  /* ---------------- admin ---------------- */

  app.get('/admin', async (c) => {
    const deny = requireAdmin(c);
    if (deny) return deny;
    const s = c.get('session')!;
    const sites = await listSites(d);
    const conns = await listConnections(d);
    const f = await takeFlash(d, s);
    const flash = f && f.kind === 'ok' ? f.text : null;
    const ferr = f && f.kind === 'err' ? f.text : null;
    const status = (st: string) =>
      h`<span class="pill ${st === 'connected' ? 'ok' : st === 'needs_reconnect' || st === 'error' ? 'bad' : 'warn'}">${st.replace('_', ' ')}</span>`;
    const csrf = h`<input type="hidden" name="csrf" value="${s.csrf}">`;
    const body = h`
      ${message(ferr)}${message(flash, 'okm')}
      <div class="card"><h1>Sites</h1>
        <table><tr><th>Site</th><th>Status</th><th>Access</th><th>Bridge</th><th>Tools</th><th></th></tr>
        ${sites.map(
          (x) => h`<tr><td><b>${x.name}</b><br><span class="muted">${x.id}</span><br><code>${x.base_url}</code>${x.last_error ? h`<br><span class="bad muted">${x.last_error}</span>` : ''}</td>
            <td>${status(x.status)}</td><td>${x.scope || '—'}</td><td>${x.bridge_version || '—'}</td><td>${siteTools(x).length || '—'}<br><span class="muted">${fmtTime(x.tools_at)}</span></td>
            <td style="white-space:nowrap">
              <form class="inline" method="post" action="/admin/sites/${x.id}/connect">${csrf}<button type="submit">${x.status === 'connected' ? 'Reconnect' : 'Connect'}</button></form>
              <form class="inline" method="post" action="/admin/sites/${x.id}/refresh">${csrf}<button class="sec" type="submit">Refresh tools</button></form>
              <form class="inline" method="post" action="/admin/sites/${x.id}/remove">${csrf}<button class="danger" type="submit">Remove</button></form></td></tr>`,
        )}
        </table>
        ${sites.length ? '' : h`<p class="muted">No sites yet.</p>`}
        <h2 style="margin-top:18px">Add a site</h2>
        <form method="post" action="/admin/sites" class="row">${csrf}
          <label><span>Site URL (goo1 Claude Bridge 1.6 or newer)</span><input type="url" name="url" placeholder="https://example.com" required></label>
          <label><span>Name (optional)</span><input type="text" name="name" maxlength="100"></label>
          <button type="submit">Add and connect</button></form>
        <p class="muted">“Connect” opens the site's own approval page (log in to WordPress as an administrator and choose the access level). Removing a site here does not delete the connection on the site — disconnect “WP Fleet” there under Claude Bridge → Connector (OAuth).</p>
      </div>
      <div class="card"><h1>Connections</h1>
        <p class="muted">MCP clients connected to WP Fleet. Connector URL for Claude: <code>${d.cfg.publicUrl}/mcp</code></p>
        <table><tr><th>Client</th><th>Access</th><th>Sites</th><th>Connected</th><th></th></tr>
        ${conns.map(
          (x) => h`<tr><td>${x.client_name}</td><td>${x.scope}</td><td>${x.sites ? x.sites.join(', ') || 'none' : 'all'}</td><td>${fmtTime(x.connected_at)}</td>
          <td><form class="inline" method="post" action="/admin/connections/${x.family}/revoke">${csrf}<button class="danger" type="submit">Disconnect</button></form></td></tr>`,
        )}
        </table>${conns.length ? '' : h`<p class="muted">No connections yet.</p>`}
      </div>
      <div class="card"><h2>Audit log</h2><p><a class="btn sec" href="/admin/audit">Show the last 200 entries</a></p></div>`;
    return html(c, page('Admin', body, { user: 'admin', csrf: s.csrf }));
  });

  const back = async (c: Context<Env>, msg: string, isErr = false) => {
    const s = c.get('session');
    if (s) await setFlash(d, s.id_hash, isErr ? 'err' : 'ok', msg);
    return c.redirect('/admin');
  };

  app.post('/admin/sites', async (c) => {
    const b = await adminForm(c);
    if (b instanceof Response) return b;
    try {
      const site = await addSite(d, String(b.url || ''), String(b.name || ''));
      await audit(d, { actor: 'admin', action: 'site_added', site: site.id });
      let reg;
      try {
        reg = await discoverAndRegister(d, site);
      } catch (e) {
        await d.sql.run("UPDATE sites SET status = 'error', last_error = ? WHERE id = ?", [(e as Error).message, site.id]);
        return back(c, (e as Error).message, true);
      }
      return c.redirect(await startAuthorize(d, site, reg, c.get('session')!.id_hash));
    } catch (e) {
      return back(c, e instanceof SiteError ? e.message : 'Could not add the site.', true);
    }
  });

  app.post('/admin/sites/:id/connect', async (c) => {
    const b = await adminForm(c);
    if (b instanceof Response) return b;
    const site = await getSite(d, c.req.param('id'));
    if (!site) return back(c, 'Unknown site.', true);
    try {
      // Register again every time: cheap, and repairs a client the site has deleted.
      // The new client only replaces the old one after a successful callback.
      const reg = await discoverAndRegister(d, site);
      return c.redirect(await startAuthorize(d, site, reg, c.get('session')!.id_hash));
    } catch (e) {
      await d.sql.run("UPDATE sites SET last_error = ? WHERE id = ?", [(e as Error).message, site.id]);
      return back(c, e instanceof SiteError ? e.message : 'Could not start the connection.', true);
    }
  });

  app.get('/sites/callback', async (c) => {
    const deny = requireAdmin(c);
    if (deny) return deny;
    const q = c.req.query();
    if (q.error) return back(c, 'The site answered: ' + (q.error_description || q.error), true);
    try {
      const site = await finishAuthorize(d, String(q.state || ''), String(q.code || ''), q.iss ? String(q.iss) : null, c.get('session')!.id_hash);
      await audit(d, { actor: 'admin', action: 'site_connected', site: site.id, detail: 'scope=' + site.scope });
      return back(c, site.name + ' is connected (' + (site.scope || '?') + ', ' + siteTools(site).length + ' tools).');
    } catch (e) {
      return back(c, e instanceof SiteError ? e.message : 'Connecting failed.', true);
    }
  });

  app.post('/admin/sites/:id/refresh', async (c) => {
    const b = await adminForm(c);
    if (b instanceof Response) return b;
    const site = await getSite(d, c.req.param('id'));
    if (!site) return back(c, 'Unknown site.', true);
    try {
      const t = await refreshTools(d, site);
      return back(c, site.name + ': ' + t.length + ' tools.');
    } catch (e) {
      return back(c, e instanceof SiteError ? e.message : 'Refresh failed.', true);
    }
  });

  app.post('/admin/sites/:id/rename', async (c) => {
    const b = await adminForm(c);
    if (b instanceof Response) return b;
    await renameSite(d, c.req.param('id'), String(b.name || ''));
    return back(c, 'Renamed.');
  });

  app.post('/admin/sites/:id/remove', async (c) => {
    const b = await adminForm(c);
    if (b instanceof Response) return b;
    const id = c.req.param('id');
    await removeSite(d, id);
    await audit(d, { actor: 'admin', action: 'site_removed', site: id });
    return back(c, 'Removed ' + id + '. Also disconnect “WP Fleet” on the site itself.');
  });

  app.post('/admin/connections/:family/revoke', async (c) => {
    const b = await adminForm(c);
    if (b instanceof Response) return b;
    await revokeFamily(d, c.req.param('family'));
    await audit(d, { actor: 'admin', action: 'connection_revoked' });
    return back(c, 'Connection removed.');
  });

  app.get('/admin/audit', async (c) => {
    const deny = requireAdmin(c);
    if (deny) return deny;
    const s = c.get('session')!;
    const rows = await d.sql.all<{ at: number; actor: string; action: string; site: string | null; tool: string | null; status: string | null; ms: number | null; detail: string | null }>(
      'SELECT at, actor, action, site, tool, status, ms, detail FROM audit ORDER BY id DESC LIMIT 200',
    );
    return html(
      c,
      page(
        'Audit log',
        h`<div class="card"><h1>Audit log</h1><p><a href="/admin">← back</a></p><table><tr><th>Time</th><th>Who</th><th>Action</th><th>Site</th><th>Tool</th><th>Result</th></tr>
        ${rows.map((r) => h`<tr><td>${fmtTime(r.at)}</td><td><code>${r.actor}</code></td><td>${r.action}</td><td>${r.site || ''}</td><td>${r.tool || ''}</td><td>${r.status || ''}${r.ms ? ' · ' + r.ms + ' ms' : ''}${r.detail ? h`<br><span class="muted">${r.detail}</span>` : ''}</td></tr>`)}
        </table></div>`,
        { user: 'admin', csrf: s.csrf },
      ),
    );
  });

  app.notFound((c) => c.json({ error: 'not_found' }, 404));
  app.onError((e, c) => {
    console.error('[wpfleet]', e instanceof Error ? e.message : e);
    return c.json({ error: 'server_error' }, 500);
  });

  return app;
}

