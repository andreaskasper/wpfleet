/**
 * Cloudflare Worker entry point (D1 as store). Untested in production —
 * see README "Cloudflare Worker". Bindings: DB (D1), secrets FLEET_KEK,
 * FLEET_PUBLIC_URL, optional FLEET_SETUP_TOKEN; set FLEET_PBKDF2_ITERATIONS=100000
 * (Workers cap PBKDF2 there).
 */
import { createApp } from './app.js';
import { configFromEnv, type Deps } from './config.js';
import { Vault } from './crypto.js';
import { SCHEMA } from './store/schema.js';
import { openD1 } from './store/d1.js';

interface Env {
  DB: D1Database;
  FLEET_KEK: string;
  FLEET_PUBLIC_URL: string;
  [k: string]: unknown;
}

let app: ReturnType<typeof createApp> | null = null;

async function init(env: Env) {
  const strings = Object.fromEntries(Object.entries(env).filter(([, v]) => typeof v === 'string')) as Record<string, string>;
  const sql = openD1(env.DB);
  await sql.exec(SCHEMA);
  const d: Deps = { sql, vault: await Vault.create(env.FLEET_KEK), cfg: configFromEnv(strings), fetch: fetch.bind(globalThis) };
  return createApp(d);
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (!app) app = await init(env);
    return app.fetch(request, env, ctx);
  },
};
