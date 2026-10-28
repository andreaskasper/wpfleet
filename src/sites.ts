/**
 * Talking to goo1 Claude Bridge sites as an OAuth client and MCP client.
 *
 * Connecting a site: discover its OAuth metadata, register this hub as a
 * client (DCR), then send the admin's browser to the site's consent page.
 * Tokens are stored encrypted; access tokens are refreshed on demand
 * (refresh tokens rotate on every use, so a new one is saved before the
 * access token is used). Only URLs on the site's own host are followed.
 */
import type { Deps } from './config.js';
import { now } from './config.js';
import { pkceChallenge, randomToken, sha256hex } from './crypto.js';

export interface ToolDef {
  name: string;
  description?: string;
  inputSchema?: unknown;
  annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean; [k: string]: unknown };
}

export interface SiteRow {
  id: string;
  name: string;
  base_url: string;
  mcp_url: string | null;
  issuer: string | null;
  authorization_endpoint: string | null;
  token_endpoint: string | null;
  client_id: string | null;
  client_secret_enc: string | null;
  access_token_enc: string | null;
  access_expires: number;
  refresh_token_enc: string | null;
  scope: string | null;
  status: string;
  last_error: string | null;
  bridge_version: string | null;
  tools_json: string | null;
  tools_at: number;
}

export class SiteError extends Error {}

const UA = 'wpfleet/0.1 (+https://github.com/andreaskasper/wpfleet)';
const MAX_BODY = 4 * 1024 * 1024;

export function callbackUrl(d: Deps): string {
  return d.cfg.publicUrl + '/sites/callback';
}

export function normalizeSiteUrl(d: Deps, input: string): URL {
  let u: URL;
  try {
    u = new URL(input.trim().match(/^https?:\/\//i) ? input.trim() : 'https://' + input.trim());
  } catch {
    throw new SiteError('That is not a valid URL.');
  }
  if (u.protocol !== 'https:' && !(d.cfg.allowHttpSites && u.protocol === 'http:')) {
    throw new SiteError('Sites must use https.');
  }
  if (u.username || u.password) throw new SiteError('URLs with credentials are not allowed.');
  u.hash = '';
  u.search = '';
  u.pathname = u.pathname.replace(/\/+$/, '');
  return u;
}

export function siteIdFor(u: URL): string {
  const host = u.host.toLowerCase().replace(/^www\./, '');
  const path = u.pathname.replace(/^\/+|\/+$/g, '').replace(/[^a-z0-9]+/gi, '-').toLowerCase();
  return (path ? host + '-' + path : host).replace(/:/g, '-');
}

export async function listSites(d: Deps): Promise<SiteRow[]> {
  return d.sql.all<SiteRow>('SELECT * FROM sites ORDER BY name COLLATE NOCASE');
}

export async function getSite(d: Deps, id: string): Promise<SiteRow | undefined> {
  return d.sql.get<SiteRow>('SELECT * FROM sites WHERE id = ?', [id]);
}

export function siteTools(site: SiteRow): ToolDef[] {
  if (!site.tools_json) return [];
  try {
    const t = JSON.parse(site.tools_json);
    return Array.isArray(t) ? t : [];
  } catch {
    return [];
  }
}

export function toolAccess(t: ToolDef): 'read' | 'write' {
  return t.annotations && t.annotations.readOnlyHint === true ? 'read' : 'write';
}

async function setStatus(d: Deps, id: string, status: string, error: string | null = null): Promise<void> {
  await d.sql.run('UPDATE sites SET status = ?, last_error = ?, updated_at = ? WHERE id = ?', [status, error, now(), id]);
}

/* ---------------- HTTP helpers ---------------- */

/** Read a response body with a hard byte cap (streamed; the stream is cancelled when the cap is hit). */
async function readText(r: Response): Promise<string> {
  const len = Number(r.headers.get('content-length') || 0);
  if (len > MAX_BODY) {
    await r.body?.cancel().catch(() => {});
    throw new SiteError('Response too large.');
  }
  if (!r.body) return '';
  const reader = r.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY) {
      await reader.cancel().catch(() => {});
      throw new SiteError('Response too large.');
    }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    all.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder().decode(all);
}

const discard = (r: Response) => r.body?.cancel().catch(() => {});

async function getJson(d: Deps, url: string, init: RequestInit = {}): Promise<{ status: number; headers: Headers; json: any }> {
  let r: Response;
  try {
    r = await d.fetch(url, {
      ...init,
      redirect: 'manual',
      headers: { 'User-Agent': UA, Accept: 'application/json', ...(init.headers || {}) },
      signal: AbortSignal.timeout(30000),
    });
  } catch (e) {
    throw new SiteError('Could not reach ' + new URL(url).host + '.');
  }
  const text = await readText(r);
  let json: any = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: r.status, headers: r.headers, json };
}

/** Same scheme, host and port as the site (https unless FLEET_ALLOW_HTTP_SITES). */
function sameOrigin(d: Deps, a: string, base: URL): boolean {
  try {
    const u = new URL(a);
    if (u.protocol !== 'https:' && !(d.cfg.allowHttpSites && u.protocol === 'http:')) return false;
    return u.origin === base.origin && !u.username && !u.password;
  } catch {
    return false;
  }
}

function form(params: Record<string, string>): string {
  return new URLSearchParams(params).toString();
}

/* ---------------- add / discover / register ---------------- */

export async function addSite(d: Deps, url: string, name: string): Promise<SiteRow> {
  const u = normalizeSiteUrl(d, url);
  const id = siteIdFor(u);
  if (await getSite(d, id)) throw new SiteError('This site is already in the fleet.');
  const t = now();
  await d.sql.run('INSERT INTO sites (id, name, base_url, status, created_at, updated_at) VALUES (?,?,?,?,?,?)', [
    id,
    (name || u.host).slice(0, 100),
    u.toString().replace(/\/+$/, ''),
    'new',
    t,
    t,
  ]);
  return (await getSite(d, id))!;
}

/** Result of discovery + DCR. Kept with the pending authorization; written to the site only after a successful callback. */
export interface Registration {
  mcp_url: string;
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  client_id: string;
  client_secret: string | null;
}

/**
 * Find the site's MCP endpoint and authorization server, then register this
 * hub as an OAuth client. Every URL must stay on the site's own origin.
 * Nothing is stored here, so a failed reconnect leaves a working connection intact.
 */
export async function discoverAndRegister(d: Deps, site: SiteRow): Promise<Registration> {
  const base = new URL(site.base_url);
  const candidates = [site.base_url + '/wp-json/goo1-mcp/v1/mcp', site.base_url + '/?rest_route=/goo1-mcp/v1/mcp'];
  let metaUrl: string | null = null;
  for (const mcp of candidates) {
    const r = await getJson(d, mcp, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
    });
    const wa = r.headers.get('www-authenticate') || '';
    const m = wa.match(/resource_metadata="([^"]+)"/);
    if (r.status === 401 && m) {
      metaUrl = m[1];
      break;
    }
  }
  if (!metaUrl) metaUrl = site.base_url + '/goo1-mcp-oauth/.well-known/oauth-protected-resource';
  if (!sameOrigin(d, metaUrl, base)) throw new SiteError('The site points to OAuth metadata on another origin.');

  const prm = await getJson(d, metaUrl);
  if (prm.status !== 200 || !prm.json?.resource || !Array.isArray(prm.json.authorization_servers)) {
    throw new SiteError('No goo1 Claude Bridge found (OAuth metadata missing). Is the plugin active and OAuth enabled?');
  }
  const resource = String(prm.json.resource);
  const issuer = String(prm.json.authorization_servers[0] || '');
  if (!sameOrigin(d, resource, base) || !sameOrigin(d, issuer, base)) throw new SiteError('The site names an MCP endpoint or issuer on another origin.');

  const asm = await getJson(d, issuer.replace(/\/+$/, '') + '/.well-known/oauth-authorization-server');
  const a = asm.json || {};
  if (asm.status !== 200 || !a.authorization_endpoint || !a.token_endpoint) throw new SiteError('The site has no usable authorization server metadata.');
  for (const k of ['authorization_endpoint', 'token_endpoint', 'registration_endpoint']) {
    if (a[k] && !sameOrigin(d, String(a[k]), base)) throw new SiteError('The site names an OAuth endpoint on another origin.');
  }
  if (!Array.isArray(a.code_challenge_methods_supported) || !a.code_challenge_methods_supported.includes('S256')) {
    throw new SiteError('The site does not support PKCE S256 (Bridge older than 1.6?).');
  }
  if (!a.registration_endpoint) throw new SiteError('Dynamic Client Registration is disabled on the site (Claude Bridge → Settings).');

  const reg = await getJson(d, a.registration_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_name: 'WP Fleet (' + new URL(d.cfg.publicUrl).host + ')',
      redirect_uris: [callbackUrl(d)],
      grant_types: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_method: 'client_secret_post',
    }),
  });
  if (reg.status !== 201 || !reg.json?.client_id) {
    throw new SiteError('Client registration failed (' + (reg.json?.error_description || reg.status) + ').');
  }
  return {
    mcp_url: resource,
    issuer,
    authorization_endpoint: String(a.authorization_endpoint),
    token_endpoint: String(a.token_endpoint),
    client_id: String(reg.json.client_id),
    client_secret: reg.json.client_secret ? String(reg.json.client_secret) : null,
  };
}

/* ---------------- authorize ---------------- */

export async function startAuthorize(d: Deps, site: SiteRow, reg: Registration, sessionHash: string): Promise<string> {
  const state = randomToken('st_', 24);
  const verifier = randomToken('', 48);
  await d.sql.run('INSERT INTO site_auth (state_hash, site_id, verifier_enc, reg_enc, session_hash, expires_at) VALUES (?,?,?,?,?,?)', [
    await sha256hex(state),
    site.id,
    await d.vault.seal(verifier, 'site_auth:' + site.id),
    await d.vault.seal(JSON.stringify(reg), 'site_auth:' + site.id + ':reg'),
    sessionHash,
    now() + 900,
  ]);
  const u = new URL(reg.authorization_endpoint);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('client_id', reg.client_id);
  u.searchParams.set('redirect_uri', callbackUrl(d));
  u.searchParams.set('code_challenge', await pkceChallenge(verifier));
  u.searchParams.set('code_challenge_method', 'S256');
  u.searchParams.set('state', state);
  u.searchParams.set('resource', reg.mcp_url);
  return u.toString();
}

export async function finishAuthorize(d: Deps, state: string, code: string, iss: string | null, sessionHash: string): Promise<SiteRow> {
  const sh = await sha256hex(state);
  const row = await d.sql.get<{ site_id: string; verifier_enc: string; reg_enc: string | null; session_hash: string; expires_at: number }>(
    'SELECT site_id, verifier_enc, reg_enc, session_hash, expires_at FROM site_auth WHERE state_hash = ?',
    [sh],
  );
  if (!row || row.expires_at < now() || row.session_hash !== sessionHash) throw new SiteError('This authorization link has expired. Start again.');
  const del = await d.sql.run('DELETE FROM site_auth WHERE state_hash = ?', [sh]);
  if (!del.changes) throw new SiteError('This authorization link was already used.');
  const site = await getSite(d, row.site_id);
  if (!site) throw new SiteError('Unknown site.');
  const verifier = await d.vault.open(row.verifier_enc, 'site_auth:' + site.id);
  const regJson = await d.vault.open(row.reg_enc, 'site_auth:' + site.id + ':reg');
  if (!verifier || !regJson) throw new SiteError('Authorization state could not be decrypted.');
  const reg = JSON.parse(regJson) as Registration;
  // RFC 9207: if the site names its issuer on the callback, it must be the one we started with.
  if (iss && iss.replace(/\/+$/, '') !== reg.issuer.replace(/\/+$/, '')) throw new SiteError('The callback came from an unexpected issuer.');
  const params: Record<string, string> = {
    grant_type: 'authorization_code',
    code,
    redirect_uri: callbackUrl(d),
    client_id: reg.client_id,
    code_verifier: verifier,
  };
  if (reg.client_secret) params.client_secret = reg.client_secret;
  const r = await getJson(d, reg.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form(params),
  });
  if (r.status !== 200 || !r.json?.access_token) {
    await d.sql.run('UPDATE sites SET last_error = ?, updated_at = ? WHERE id = ?', ['Token exchange failed: ' + (r.json?.error_description || r.status), now(), site.id]);
    throw new SiteError('Token exchange failed (' + (r.json?.error_description || r.status) + ').');
  }
  // Promote the new registration together with its tokens.
  await d.sql.run(
    `UPDATE sites SET mcp_url = ?, issuer = ?, authorization_endpoint = ?, token_endpoint = ?, client_id = ?, client_secret_enc = ?,
     refresh_token_enc = NULL, status = 'connected', last_error = NULL, updated_at = ? WHERE id = ?`,
    [
      reg.mcp_url,
      reg.issuer,
      reg.authorization_endpoint,
      reg.token_endpoint,
      reg.client_id,
      reg.client_secret ? await d.vault.seal(reg.client_secret, 'site:' + site.id + ':client_secret') : null,
      now(),
      site.id,
    ],
  );
  await storeTokens(d, site.id, r.json);
  const fresh = (await getSite(d, site.id))!;
  try {
    await refreshTools(d, fresh);
  } catch {
    /* shown as last_error */
  }
  return (await getSite(d, site.id))!;
}

async function storeTokens(d: Deps, id: string, tok: any): Promise<void> {
  await d.sql.run(
    'UPDATE sites SET access_token_enc = ?, access_expires = ?, refresh_token_enc = COALESCE(?, refresh_token_enc), scope = COALESCE(?, scope), updated_at = ? WHERE id = ?',
    [
      await d.vault.seal(String(tok.access_token), 'site:' + id + ':access'),
      now() + Math.max(60, Number(tok.expires_in) || 3600),
      tok.refresh_token ? await d.vault.seal(String(tok.refresh_token), 'site:' + id + ':refresh') : null,
      tok.scope ? String(tok.scope) : null,
      now(),
      id,
    ],
  );
}

/* ---------------- tokens ---------------- */

const refreshing = new Map<string, Promise<string>>();

/** A valid access token for the site (refreshes when needed, one refresh per site at a time). */
export async function accessToken(d: Deps, site: SiteRow, rejected: string | null = null): Promise<string> {
  if (!rejected && site.access_expires > now() + 60) {
    const at = await d.vault.open(site.access_token_enc, 'site:' + site.id + ':access');
    if (at) return at;
  }
  const running = refreshing.get(site.id);
  if (running) return running;
  const p = doRefresh(d, site.id, rejected).finally(() => refreshing.delete(site.id));
  refreshing.set(site.id, p);
  return p;
}

/** Refresh the site's tokens. `rejected` = the access token the site just refused (never hand that one out again). */
async function doRefresh(d: Deps, id: string, rejected: string | null): Promise<string> {
  const site = await getSite(d, id);
  if (!site || !site.token_endpoint || !site.client_id) throw new SiteError('Site not connected.');
  // Another request may have refreshed in the meantime.
  if (site.access_expires > now() + 60) {
    const at = await d.vault.open(site.access_token_enc, 'site:' + id + ':access');
    if (at && at !== rejected) return at;
  }
  const rt = await d.vault.open(site.refresh_token_enc, 'site:' + id + ':refresh');
  if (!rt) {
    await setStatus(d, id, 'needs_reconnect', 'No refresh token stored.');
    throw new SiteError('Site ' + id + ' must be reconnected in WP Fleet.');
  }
  const params: Record<string, string> = { grant_type: 'refresh_token', refresh_token: rt, client_id: site.client_id };
  const secret = await d.vault.open(site.client_secret_enc, 'site:' + id + ':client_secret');
  if (secret) params.client_secret = secret;
  const r = await getJson(d, site.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form(params),
  });
  if (r.status === 200 && r.json?.access_token) {
    await storeTokens(d, id, r.json);
    if (site.status !== 'connected') await setStatus(d, id, 'connected');
    return String(r.json.access_token);
  }
  if (r.status === 400 || r.status === 401) {
    await d.sql.run('UPDATE sites SET access_token_enc = NULL, refresh_token_enc = NULL, access_expires = 0 WHERE id = ?', [id]);
    await setStatus(d, id, 'needs_reconnect', 'Refresh refused: ' + (r.json?.error_description || r.json?.error || r.status));
    throw new SiteError('Site ' + id + ' refused the refresh token and must be reconnected in WP Fleet.');
  }
  await setStatus(d, id, site.status, 'Refresh failed: HTTP ' + r.status);
  throw new SiteError('Site ' + id + ' token endpoint answered HTTP ' + r.status + '.');
}

/* ---------------- MCP calls ---------------- */

let rpcId = 1;

/** One JSON-RPC call to the site's MCP endpoint (retries once after a 401). */
export async function siteRpc(d: Deps, site: SiteRow, method: string, params: unknown, timeoutMs = 120000): Promise<any> {
  const url = site.mcp_url;
  if (!url) throw new SiteError('Site ' + site.id + ' is not connected.');
  let rejected: string | null = null;
  for (let attempt = 0; attempt < 2; attempt++) {
    const token = await accessToken(d, site, rejected);
    let r: Response;
    try {
      r = await d.fetch(url, {
        method: 'POST',
        redirect: 'error',
        headers: {
          'User-Agent': UA,
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
          'MCP-Protocol-Version': '2025-06-18',
          Authorization: 'Bearer ' + token,
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: rpcId++, method, params }),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (e) {
      throw new SiteError('Site ' + site.id + ' did not answer (' + ((e as Error).name === 'TimeoutError' ? 'timeout' : 'network error') + ').');
    }
    if (r.status === 401 && attempt === 0) {
      await discard(r);
      rejected = token;
      site = (await getSite(d, site.id)) || site;
      continue;
    }
    const text = await readText(r);
    let json: any = null;
    try {
      json = JSON.parse(text);
    } catch {
      /* handled below */
    }
    if (json?.error) throw new SiteError('Site ' + site.id + ': ' + String(json.error.message || 'error').slice(0, 300));
    if (!r.ok) throw new SiteError('Site ' + site.id + ' answered HTTP ' + r.status + '.');
    if (!json || typeof json !== 'object') throw new SiteError('Site ' + site.id + ' answered without JSON.');
    return json.result;
  }
  throw new SiteError('Site ' + site.id + ' rejected the token.');
}

export async function refreshTools(d: Deps, site: SiteRow): Promise<ToolDef[]> {
  try {
    const init = await siteRpc(d, site, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'wpfleet', version: '0.1' } });
    const list = await siteRpc(d, site, 'tools/list', {});
    const tools: ToolDef[] = Array.isArray(list?.tools)
      ? list.tools
          .filter((t: any) => t && typeof t.name === 'string')
          .map((t: any) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema, annotations: t.annotations }))
      : [];
    await d.sql.run('UPDATE sites SET tools_json = ?, tools_at = ?, bridge_version = ?, last_error = NULL, updated_at = ? WHERE id = ?', [
      JSON.stringify(tools),
      now(),
      init?.serverInfo?.version ? String(init.serverInfo.version) : null,
      now(),
      site.id,
    ]);
    return tools;
  } catch (e) {
    await d.sql.run('UPDATE sites SET last_error = ?, updated_at = ? WHERE id = ?', [(e as Error).message.slice(0, 300), now(), site.id]);
    throw e;
  }
}

/** Cached tools, refreshed when older than 6 hours. */
export async function toolsFor(d: Deps, site: SiteRow): Promise<ToolDef[]> {
  if (site.tools_json && site.tools_at > now() - 6 * 3600) return siteTools(site);
  try {
    return await refreshTools(d, site);
  } catch {
    return siteTools(site); // stale is better than nothing
  }
}

export async function removeSite(d: Deps, id: string): Promise<void> {
  await d.sql.run('DELETE FROM site_auth WHERE site_id = ?', [id]);
  await d.sql.run('DELETE FROM sites WHERE id = ?', [id]);
}

export async function renameSite(d: Deps, id: string, name: string): Promise<void> {
  await d.sql.run('UPDATE sites SET name = ?, updated_at = ? WHERE id = ?', [name.slice(0, 100), now(), id]);
}
