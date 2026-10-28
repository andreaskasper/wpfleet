/**
 * OAuth 2.1 authorization server for MCP clients (claude.ai, Claude Desktop,
 * Claude Code): DCR (RFC 7591), authorization code + PKCE S256, refresh
 * tokens that rotate on every use (one grace redemption within 120 s, a later
 * replay revokes the whole connection), opaque access tokens stored hashed.
 *
 * A connection carries a scope ("read" = only fleet_call_read, "write" =
 * both) and optionally a list of sites it may use (null = all sites).
 */
import type { Deps } from '../config.js';
import { now } from '../config.js';
import { pkceChallenge, randomToken, safeEqual, sha256hex } from '../crypto.js';
import { withLock } from '../lock.js';

export const SCOPES = ['read', 'write'] as const;
export type Scope = (typeof SCOPES)[number];
const CODE_TTL = 600;
const GRACE = 120;

export interface ClientRow {
  client_id: string;
  client_name: string;
  redirect_uris: string;
  secret_hash: string | null;
}

export interface AccessInfo {
  family: string;
  client_id: string;
  scope: Scope;
  sites: string[] | null;
}

export function issuer(d: Deps): string {
  return d.cfg.publicUrl;
}

export function mcpUrl(d: Deps): string {
  return d.cfg.publicUrl + '/mcp';
}

export function protectedResourceMetadata(d: Deps) {
  return {
    resource: mcpUrl(d),
    authorization_servers: [issuer(d)],
    scopes_supported: [...SCOPES],
    bearer_methods_supported: ['header'],
    resource_name: 'WP Fleet',
  };
}

export function authorizationServerMetadata(d: Deps) {
  return {
    issuer: issuer(d),
    authorization_endpoint: d.cfg.publicUrl + '/oauth/authorize',
    token_endpoint: d.cfg.publicUrl + '/oauth/token',
    registration_endpoint: d.cfg.publicUrl + '/oauth/register',
    revocation_endpoint: d.cfg.publicUrl + '/oauth/revoke',
    scopes_supported: [...SCOPES],
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none'],
    code_challenge_methods_supported: ['S256'],
  };
}

function isLoopback(u: URL): boolean {
  return ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
}

/**
 * Redirect URIs a client may register: http(s) on a loopback host (native
 * apps, Claude Code) or https on one of FLEET_REDIRECT_HOSTS (default
 * claude.ai, claude.com and their subdomains).
 */
export function acceptableRedirect(d: Deps, uri: string): boolean {
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return false;
  }
  if (u.hash || u.username || u.password) return false;
  if (isLoopback(u)) return u.protocol === 'http:' || u.protocol === 'https:';
  if (u.protocol !== 'https:') return false;
  const host = u.hostname.toLowerCase();
  return d.cfg.redirectHosts.some((h) => host === h || host.endsWith('.' + h));
}

/* ---------------- clients ---------------- */

export async function registerClient(d: Deps, body: any): Promise<{ status: number; json: unknown }> {
  const uris: string[] = Array.isArray(body?.redirect_uris) ? body.redirect_uris.map((x: unknown) => String(x).trim()) : [];
  if (!uris.length || uris.length > 10 || !uris.every((u) => acceptableRedirect(d, u))) {
    return {
      status: 400,
      json: { error: 'invalid_redirect_uri', error_description: 'One to ten redirect_uris, each on a loopback host or https on an allowed host (' + d.cfg.redirectHosts.join(', ') + ').' },
    };
  }
  const method = ['client_secret_post', 'client_secret_basic', 'none'].includes(body?.token_endpoint_auth_method)
    ? String(body.token_endpoint_auth_method)
    : 'client_secret_post';
  const name = String(body?.client_name || 'MCP client').replace(/[\u0000-\u001f<>]/g, '').slice(0, 100);
  const clientId = randomToken('wpf_client_', 12);
  const secret = method === 'none' ? null : randomToken('wpf_secret_', 32);
  await d.sql.run('INSERT INTO oauth_clients (client_id, client_name, redirect_uris, secret_hash, created_at) VALUES (?,?,?,?,?)', [
    clientId,
    name,
    JSON.stringify(uris),
    secret ? await sha256hex(secret) : null,
    now(),
  ]);
  const out: Record<string, unknown> = {
    client_id: clientId,
    client_id_issued_at: now(),
    client_name: name,
    redirect_uris: uris,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: method,
  };
  if (secret) {
    out.client_secret = secret;
    out.client_secret_expires_at = 0;
  }
  return { status: 201, json: out };
}

export async function getClient(d: Deps, id: string): Promise<ClientRow | undefined> {
  if (!id || id.length > 100) return undefined;
  return d.sql.get<ClientRow>('SELECT client_id, client_name, redirect_uris, secret_hash FROM oauth_clients WHERE client_id = ?', [id]);
}

export function clientAllowsRedirect(d: Deps, c: ClientRow, uri: string): boolean {
  if (!acceptableRedirect(d, uri)) return false;
  let list: string[] = [];
  try {
    list = JSON.parse(c.redirect_uris);
  } catch {
    return false;
  }
  return list.some((r) => {
    if (r === uri) return true;
    // Native apps may come back on any loopback port (RFC 8252 §7.3).
    try {
      const a = new URL(r), b = new URL(uri);
      return isLoopback(a) && isLoopback(b) && a.protocol === b.protocol && a.hostname === b.hostname && a.pathname === b.pathname && a.search === b.search;
    } catch {
      return false;
    }
  });
}

/* ---------------- codes ---------------- */

export async function issueCode(
  d: Deps,
  p: { clientId: string; redirectUri: string; challenge: string; scope: Scope; sites: string[] | null },
): Promise<string> {
  const code = randomToken('wpf_code_', 32);
  await d.sql.run('INSERT INTO oauth_codes (code_hash, client_id, redirect_uri, challenge, scope, sites, expires_at) VALUES (?,?,?,?,?,?,?)', [
    await sha256hex(code),
    p.clientId,
    p.redirectUri,
    p.challenge,
    p.scope,
    p.sites ? JSON.stringify(p.sites) : null,
    now() + CODE_TTL,
  ]);
  return code;
}

/* ---------------- token endpoint ---------------- */

type TokenResult = { status: number; json: Record<string, unknown> };
const err = (status: number, error: string, description?: string): TokenResult => ({
  status,
  json: description ? { error, error_description: description } : { error },
});

function clientCredentials(params: Record<string, string>, authHeader: string | null): { id: string; secret: string } {
  let id = params.client_id || '';
  let secret = params.client_secret || '';
  if (authHeader && /^Basic\s+/i.test(authHeader)) {
    try {
      const dec = atob(authHeader.replace(/^Basic\s+/i, ''));
      const i = dec.indexOf(':');
      if (i > 0) {
        id = decodeURIComponent(dec.slice(0, i));
        secret = decodeURIComponent(dec.slice(i + 1));
      }
    } catch {
      /* ignore malformed header */
    }
  }
  return { id, secret };
}

export async function tokenEndpoint(d: Deps, params: Record<string, string>, authHeader: string | null): Promise<TokenResult> {
  const cred = clientCredentials(params, authHeader);
  const client = await getClient(d, cred.id);
  if (!client) return err(401, 'invalid_client', 'Unknown client.');
  if (client.secret_hash && !safeEqual(client.secret_hash, await sha256hex(cred.secret))) {
    return err(401, 'invalid_client', 'Client authentication failed.');
  }
  if (params.grant_type === 'authorization_code') return codeGrant(d, client, params);
  if (params.grant_type === 'refresh_token') return refreshGrant(d, client, params);
  return err(400, 'unsupported_grant_type');
}

async function codeGrant(d: Deps, client: ClientRow, p: Record<string, string>): Promise<TokenResult> {
  const h = await sha256hex(p.code || '');
  const row = await d.sql.get<{ client_id: string; redirect_uri: string; challenge: string; scope: Scope; sites: string | null; used: number; family: string | null; expires_at: number }>(
    'SELECT client_id, redirect_uri, challenge, scope, sites, used, family, expires_at FROM oauth_codes WHERE code_hash = ?',
    [h],
  );
  if (!row || row.expires_at < now()) return err(400, 'invalid_grant', 'Authorization code is invalid or expired.');
  if (row.used) {
    // RFC 6749 §4.1.2: a reused code revokes what was issued with it.
    if (row.family) await revokeFamily(d, row.family);
    return err(400, 'invalid_grant', 'Authorization code was already used; the tokens issued with it have been revoked.');
  }
  if (row.client_id !== client.client_id) return err(400, 'invalid_grant', 'Code was issued to another client.');
  if ((p.redirect_uri || '') !== row.redirect_uri) return err(400, 'invalid_grant', 'redirect_uri mismatch.');
  const v = p.code_verifier || '';
  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(v) || !safeEqual(await pkceChallenge(v), row.challenge)) return err(400, 'invalid_grant', 'PKCE verification failed.');
  const family = randomToken('', 12);
  // Single use: whoever flips "used" first wins.
  const upd = await d.sql.run('UPDATE oauth_codes SET used = 1, family = ? WHERE code_hash = ? AND used = 0', [family, h]);
  if (!upd.changes) return err(400, 'invalid_grant', 'Authorization code was already used.');
  return { status: 200, json: await issueTokens(d, client.client_id, row.scope, row.sites, family, now()) };
}

/**
 * Refresh with rotation. Serialised per token. The response of the winning
 * redemption is kept (encrypted); a second redemption of the same token
 * within GRACE seconds (two parallel requests of the same client) gets that
 * identical response, so there is never more than one live token chain. Any
 * later replay revokes the connection.
 */
async function refreshGrant(d: Deps, client: ClientRow, p: Record<string, string>): Promise<TokenResult> {
  const h = await sha256hex(p.refresh_token || '');
  return withLock('rt:' + h, async () => {
    const rec = await d.sql.get<{ family: string; client_id: string; scope: Scope; sites: string | null; connected_at: number; expires_at: number }>(
      'SELECT family, client_id, scope, sites, connected_at, expires_at FROM oauth_refresh WHERE rt_hash = ?',
      [h],
    );
    if (!rec) {
      const used = await d.sql.get<{ family: string; record: string; at: number; grace_used: number; response_enc: string | null }>(
        'SELECT family, record, at, grace_used, response_enc FROM oauth_rt_used WHERE rt_hash = ?',
        [h],
      );
      if (!used) return err(400, 'invalid_grant', 'Unknown refresh token.');
      const r = JSON.parse(used.record);
      const alive = await d.sql.get('SELECT 1 AS x FROM oauth_refresh WHERE family = ?', [used.family]);
      if (!used.grace_used && now() - used.at <= GRACE && r.client_id === client.client_id && alive && used.response_enc) {
        const g = await d.sql.run('UPDATE oauth_rt_used SET grace_used = 1 WHERE rt_hash = ? AND grace_used = 0', [h]);
        const resp = g.changes ? await d.vault.open(used.response_enc, 'rt_used:' + h) : null;
        if (resp) return { status: 200, json: JSON.parse(resp) };
      }
      await revokeFamily(d, used.family);
      return err(400, 'invalid_grant', 'Refresh token was already used; the connection has been revoked. Please reconnect.');
    }
    if (rec.client_id !== client.client_id) return err(400, 'invalid_grant', 'Refresh token belongs to another client.');
    const del = await d.sql.run('DELETE FROM oauth_refresh WHERE rt_hash = ?', [h]);
    if (!del.changes) return err(400, 'invalid_grant', 'Refresh token was just used.');
    if (rec.expires_at < now()) return err(400, 'invalid_grant', 'Refresh token expired. Please reconnect.');
    const json = await issueTokens(d, client.client_id, rec.scope, rec.sites, rec.family, rec.connected_at);
    await d.sql.run('INSERT OR REPLACE INTO oauth_rt_used (rt_hash, family, record, at, grace_used, response_enc) VALUES (?,?,?,?,0,?)', [
      h,
      rec.family,
      JSON.stringify({ client_id: rec.client_id, scope: rec.scope, sites: rec.sites, connected_at: rec.connected_at }),
      now(),
      await d.vault.seal(JSON.stringify(json), 'rt_used:' + h),
    ]);
    return { status: 200, json };
  });
}

async function issueTokens(d: Deps, clientId: string, scope: Scope, sites: string | null, family: string, connectedAt: number) {
  const at = randomToken('wpf_at_', 32);
  const rt = randomToken('wpf_rt_', 32);
  await d.sql.run('INSERT INTO oauth_access (at_hash, family, client_id, scope, sites, expires_at) VALUES (?,?,?,?,?,?)', [
    await sha256hex(at),
    family,
    clientId,
    scope,
    sites,
    now() + d.cfg.accessTtl,
  ]);
  await d.sql.run('INSERT INTO oauth_refresh (rt_hash, family, client_id, scope, sites, connected_at, expires_at) VALUES (?,?,?,?,?,?,?)', [
    await sha256hex(rt),
    family,
    clientId,
    scope,
    sites,
    connectedAt,
    now() + d.cfg.refreshTtlDays * 86400,
  ]);
  return { access_token: at, token_type: 'Bearer', expires_in: d.cfg.accessTtl, scope, refresh_token: rt };
}

export async function revokeFamily(d: Deps, family: string): Promise<void> {
  await d.sql.run('DELETE FROM oauth_refresh WHERE family = ?', [family]);
  await d.sql.run('DELETE FROM oauth_access WHERE family = ?', [family]);
}

/** RFC 7009: revoke an access or refresh token (always 200). */
export async function revokeToken(d: Deps, token: string): Promise<void> {
  const h = await sha256hex(token || '');
  const a = await d.sql.get<{ family: string }>('SELECT family FROM oauth_access WHERE at_hash = ?', [h]);
  const r = await d.sql.get<{ family: string }>('SELECT family FROM oauth_refresh WHERE rt_hash = ?', [h]);
  const fam = a?.family || r?.family;
  if (fam) await revokeFamily(d, fam);
}

export async function validateAccessToken(d: Deps, token: string): Promise<AccessInfo | null> {
  if (!token || token.length > 200) return null;
  const row = await d.sql.get<{ family: string; client_id: string; scope: Scope; sites: string | null; expires_at: number }>(
    'SELECT family, client_id, scope, sites, expires_at FROM oauth_access WHERE at_hash = ?',
    [await sha256hex(token)],
  );
  if (!row || row.expires_at < now()) return null;
  // The connection must still exist (revocation deletes the refresh family).
  const alive = await d.sql.get('SELECT 1 AS x FROM oauth_refresh WHERE family = ? LIMIT 1', [row.family]);
  const grace = alive ? true : await d.sql.get('SELECT 1 AS x FROM oauth_rt_used WHERE family = ? AND at > ? LIMIT 1', [row.family, now() - GRACE]);
  if (!grace) return null;
  let sites: string[] | null = null;
  if (row.sites) {
    try {
      sites = JSON.parse(row.sites);
    } catch {
      sites = [];
    }
  }
  return { family: row.family, client_id: row.client_id, scope: row.scope, sites };
}

export interface ConnectionInfo {
  family: string;
  client_id: string;
  client_name: string;
  scope: Scope;
  sites: string[] | null;
  connected_at: number;
  expires_at: number;
}

export async function listConnections(d: Deps): Promise<ConnectionInfo[]> {
  const rows = await d.sql.all<{ family: string; client_id: string; client_name: string | null; scope: Scope; sites: string | null; connected_at: number; expires_at: number }>(
    `SELECT r.family, r.client_id, c.client_name, r.scope, r.sites, r.connected_at, MAX(r.expires_at) AS expires_at
     FROM oauth_refresh r LEFT JOIN oauth_clients c ON c.client_id = r.client_id GROUP BY r.family ORDER BY r.connected_at DESC`,
  );
  return rows.map((r) => ({
    ...r,
    client_name: r.client_name || r.client_id,
    sites: r.sites ? JSON.parse(r.sites) : null,
  }));
}
