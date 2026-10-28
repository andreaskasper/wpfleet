/** Admin account, sessions, CSRF and login throttling. */
import type { Deps } from './config.js';
import { now } from './config.js';
import { hashPassword, randomToken, sha256hex, verifyPassword } from './crypto.js';
import { verifyTotp } from './totp.js';

export interface AdminRow {
  username: string;
  pw_hash: string;
  totp_secret_enc: string | null;
  totp_enabled: number;
  totp_last_counter: number;
}

export interface SessionRow {
  id_hash: string;
  csrf: string;
  totp_ok: number;
  flash: string | null;
  expires_at: number;
}

const SESSION_TTL = 12 * 3600;

export function cookieName(d: Deps): string {
  // __Host- requires Secure, which browsers refuse on plain http (local dev).
  return d.cfg.publicUrl.startsWith('https://') ? '__Host-wpfleet' : 'wpfleet';
}

export function cookieAttrs(d: Deps, maxAge: number): string {
  const secure = d.cfg.publicUrl.startsWith('https://') ? '; Secure' : '';
  return `; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}

export async function getAdmin(d: Deps): Promise<AdminRow | undefined> {
  return d.sql.get<AdminRow>('SELECT username, pw_hash, totp_secret_enc, totp_enabled, totp_last_counter FROM admin WHERE id = 1');
}

export function validatePassword(pw: string): string | null {
  if (pw.length < 12) return 'The password needs at least 12 characters.';
  if (pw.length > 200) return 'The password is too long.';
  return null;
}

export async function createAdmin(d: Deps, username: string, password: string): Promise<void> {
  if (await getAdmin(d)) throw new Error('An admin already exists.');
  const err = validatePassword(password);
  if (err) throw new Error(err);
  if (!/^[a-zA-Z0-9._@-]{2,64}$/.test(username)) throw new Error('Invalid username.');
  await d.sql.run('INSERT INTO admin (id, username, pw_hash, created_at) VALUES (1, ?, ?, ?)', [
    username,
    await hashPassword(password, d.cfg.pbkdf2Iterations),
    now(),
  ]);
}

export async function setPassword(d: Deps, password: string): Promise<void> {
  const err = validatePassword(password);
  if (err) throw new Error(err);
  await d.sql.run('UPDATE admin SET pw_hash = ? WHERE id = 1', [await hashPassword(password, d.cfg.pbkdf2Iterations)]);
  await d.sql.run('DELETE FROM sessions');
}

export async function resetTotp(d: Deps): Promise<void> {
  await d.sql.run('UPDATE admin SET totp_secret_enc = NULL, totp_enabled = 0, totp_last_counter = 0 WHERE id = 1');
  await d.sql.run('DELETE FROM sessions');
}

/* ---------------- throttle ---------------- */

/**
 * Count one attempt atomically (before doing any expensive work) and report
 * whether the key is over its limit. The window restarts after windowSec.
 */
export async function hit(d: Deps, key: string, max: number, windowSec: number): Promise<boolean> {
  const t = now();
  const r = await d.sql.get<{ n: number }>(
    `INSERT INTO throttle (k, n, first_at) VALUES (?, 1, ?)
     ON CONFLICT(k) DO UPDATE SET
       n = CASE WHEN throttle.first_at < ? THEN 1 ELSE throttle.n + 1 END,
       first_at = CASE WHEN throttle.first_at < ? THEN ? ELSE throttle.first_at END
     RETURNING n`,
    [key, t, t - windowSec, t - windowSec, t],
  );
  return (r?.n ?? 1) > max;
}

/** Read-only check (no increment). */
export async function throttled(d: Deps, key: string, max: number, windowSec: number): Promise<boolean> {
  const r = await d.sql.get<{ n: number; first_at: number }>('SELECT n, first_at FROM throttle WHERE k = ?', [key]);
  return !!r && r.first_at >= now() - windowSec && r.n >= max;
}

export async function clearFailures(d: Deps, key: string): Promise<void> {
  await d.sql.run('DELETE FROM throttle WHERE k = ?', [key]);
}

/* ---------------- login ---------------- */

/** TOTP failures after a correct password; NOT reset by a correct password. */
export const TOTP_FAIL_KEY = 'totp-fail:admin';
const TOTP_FAIL_MAX = 10;

let dummyHash: Promise<string> | null = null;

/**
 * Check username + password (+ TOTP code when enrolled). Returns
 * 'ok' | 'enroll' (password fine, TOTP still to be set up) | 'totp_locked' | an error text.
 */
export async function checkLogin(d: Deps, username: string, password: string, code: string): Promise<'ok' | 'enroll' | 'totp_locked' | string> {
  const admin = await getAdmin(d);
  if (!dummyHash) dummyHash = hashPassword('dummy-password-for-timing', d.cfg.pbkdf2Iterations);
  // Always run one PBKDF2 with the real cost so timing does not reveal whether the user exists.
  const passOk = admin
    ? (await verifyPassword(password, admin.pw_hash)) && username === admin.username
    : (await verifyPassword(password, await dummyHash), false);
  if (!admin || !passOk) return 'Wrong username, password or code.';
  if (!admin.totp_enabled) return 'enroll';
  if (await throttled(d, TOTP_FAIL_KEY, TOTP_FAIL_MAX, 3600)) return 'totp_locked';
  const secret = await d.vault.open(admin.totp_secret_enc, 'admin:totp');
  if (!secret) return 'The TOTP secret cannot be decrypted (was FLEET_KEK changed?). Reset it with the CLI.';
  const counter = await verifyTotp(secret, code);
  // Atomic: a code (counter) can be used only once, also under parallel logins.
  const used = counter === null ? { changes: 0 } : await d.sql.run('UPDATE admin SET totp_last_counter = ? WHERE id = 1 AND totp_last_counter < ?', [counter, counter]);
  if (counter === null || !used.changes) {
    await hit(d, TOTP_FAIL_KEY, TOTP_FAIL_MAX, 3600);
    return 'Wrong username, password or code.';
  }
  return 'ok';
}

/* ---------------- sessions ---------------- */

export async function createSession(d: Deps, totpOk: boolean): Promise<string> {
  const raw = randomToken('s_');
  await d.sql.run('INSERT INTO sessions (id_hash, csrf, totp_ok, created_at, expires_at) VALUES (?,?,?,?,?)', [
    await sha256hex(raw),
    randomToken('', 24),
    totpOk ? 1 : 0,
    now(),
    now() + SESSION_TTL,
  ]);
  return raw;
}

export async function loadSession(d: Deps, raw: string | undefined): Promise<SessionRow | null> {
  if (!raw || raw.length > 100) return null;
  const s = await d.sql.get<SessionRow>('SELECT id_hash, csrf, totp_ok, flash, expires_at FROM sessions WHERE id_hash = ?', [await sha256hex(raw)]);
  if (!s || s.expires_at < now()) return null;
  return s;
}

export async function markSessionTotp(d: Deps, idHash: string): Promise<void> {
  await d.sql.run('UPDATE sessions SET totp_ok = 1 WHERE id_hash = ?', [idHash]);
}

export async function destroySession(d: Deps, idHash: string): Promise<void> {
  await d.sql.run('DELETE FROM sessions WHERE id_hash = ?', [idHash]);
}

/** One-shot message for the next page view (instead of text in the URL). */
export async function setFlash(d: Deps, idHash: string, kind: 'ok' | 'err', text: string): Promise<void> {
  await d.sql.run('UPDATE sessions SET flash = ? WHERE id_hash = ?', [JSON.stringify({ kind, text: text.slice(0, 400) }), idHash]);
}

export async function takeFlash(d: Deps, s: SessionRow): Promise<{ kind: 'ok' | 'err'; text: string } | null> {
  if (!s.flash) return null;
  await d.sql.run('UPDATE sessions SET flash = NULL WHERE id_hash = ?', [s.id_hash]);
  try {
    return JSON.parse(s.flash);
  } catch {
    return null;
  }
}
