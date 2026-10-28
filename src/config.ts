import type { Sql } from './store/types.js';
import type { Vault } from './crypto.js';

export interface Config {
  /** Public origin of this hub, e.g. https://wpfleet.goo1.de (no trailing slash). */
  publicUrl: string;
  /** Allow http:// site URLs (local testing only). */
  allowHttpSites: boolean;
  /** PBKDF2 iterations for new password hashes (Workers allow at most 100000). */
  pbkdf2Iterations: number;
  /** One-time token that unlocks /setup while no admin exists (optional). */
  setupToken: string | null;
  /** Access-token lifetime for MCP clients (seconds). */
  accessTtl: number;
  /** Refresh-token lifetime without use (days). */
  refreshTtlDays: number;
  /** Request header that carries the client IP, set by a trusted proxy (x-real-ip behind Traefik, cf-connecting-ip on Cloudflare). */
  ipHeader: string | null;
  /** Hosts MCP clients may register https redirect URIs on (loopback is always allowed). */
  redirectHosts: string[];
}

export interface Deps {
  sql: Sql;
  vault: Vault;
  cfg: Config;
  fetch: typeof fetch;
}

export function configFromEnv(env: Record<string, string | undefined>): Config {
  const publicUrl = (env.FLEET_PUBLIC_URL || '').replace(/\/+$/, '');
  if (!/^https?:\/\/[^/]+$/.test(publicUrl)) {
    throw new Error('FLEET_PUBLIC_URL must be an origin like https://wpfleet.goo1.de');
  }
  if (publicUrl.startsWith('http://') && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(publicUrl)) {
    throw new Error('FLEET_PUBLIC_URL must use https (http only for localhost)');
  }
  const int = (name: string, def: number, min: number, max: number): number => {
    const raw = env[name];
    if (raw === undefined || raw === '') return def;
    const n = Number(raw);
    if (!Number.isInteger(n) || n < min || n > max) throw new Error(`${name} must be an integer between ${min} and ${max}`);
    return n;
  };
  if (env.FLEET_SETUP_TOKEN && env.FLEET_SETUP_TOKEN.length < 24) throw new Error('FLEET_SETUP_TOKEN must have at least 24 characters');
  const redirectHosts = (env.FLEET_REDIRECT_HOSTS ?? 'claude.ai,claude.com')
    .split(',')
    .map((x) => x.trim().toLowerCase())
    .filter(Boolean);
  return {
    publicUrl,
    allowHttpSites: env.FLEET_ALLOW_HTTP_SITES === '1',
    pbkdf2Iterations: int('FLEET_PBKDF2_ITERATIONS', 600000, 100000, 5000000),
    setupToken: env.FLEET_SETUP_TOKEN || null,
    accessTtl: int('FLEET_ACCESS_TTL', 3600, 60, 86400),
    refreshTtlDays: int('FLEET_REFRESH_TTL_DAYS', 90, 1, 365),
    ipHeader: env.FLEET_IP_HEADER ? env.FLEET_IP_HEADER.toLowerCase() : null,
    redirectHosts,
  };
}

export const now = () => Math.floor(Date.now() / 1000);
