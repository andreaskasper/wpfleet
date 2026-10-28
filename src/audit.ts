import type { Deps } from './config.js';
import { now } from './config.js';

export interface AuditEntry {
  actor: string;
  action: string;
  site?: string | null;
  tool?: string | null;
  status?: string | null;
  ms?: number | null;
  detail?: string | null;
}

export async function audit(d: Deps, e: AuditEntry): Promise<void> {
  try {
    await d.sql.run(
      'INSERT INTO audit (at, actor, action, site, tool, status, ms, detail) VALUES (?,?,?,?,?,?,?,?)',
      [now(), e.actor, e.action, e.site ?? null, e.tool ?? null, e.status ?? null, e.ms ?? null, e.detail ? e.detail.slice(0, 500) : null],
    );
  } catch {
    /* auditing must never break a request */
  }
}

/** Drop old audit rows and expired OAuth/session rows (cheap, run opportunistically). */
export async function housekeeping(d: Deps): Promise<void> {
  const t = now();
  await d.sql.run('DELETE FROM audit WHERE at < ?', [t - 90 * 86400]);
  await d.sql.run('DELETE FROM sessions WHERE expires_at < ?', [t]);
  await d.sql.run('DELETE FROM oauth_codes WHERE expires_at < ?', [t]);
  await d.sql.run('DELETE FROM oauth_access WHERE expires_at < ?', [t]);
  await d.sql.run('DELETE FROM oauth_refresh WHERE expires_at < ?', [t]);
  await d.sql.run('DELETE FROM oauth_rt_used WHERE at < ?', [t - d.cfg.refreshTtlDays * 86400]);
  await d.sql.run('DELETE FROM site_auth WHERE expires_at < ?', [t]);
  await d.sql.run('DELETE FROM throttle WHERE first_at < ?', [t - 2 * 86400]);
  // The kept grace response is only needed for GRACE seconds.
  await d.sql.run('UPDATE oauth_rt_used SET response_enc = NULL WHERE response_enc IS NOT NULL AND at < ?', [t - 600]);
  // Registered clients that never connected (or whose connections are all gone).
  await d.sql.run(
    `DELETE FROM oauth_clients WHERE created_at < ?
       AND client_id NOT IN (SELECT client_id FROM oauth_refresh)
       AND client_id NOT IN (SELECT client_id FROM oauth_codes)`,
    [t - 86400],
  );
}
