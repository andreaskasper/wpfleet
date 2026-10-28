/** Node / Docker entry point. */
import { serve } from '@hono/node-server';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { createApp } from './app.js';
import { configFromEnv, type Deps } from './config.js';
import { Vault } from './crypto.js';
import { SCHEMA } from './store/schema.js';
import { openSqlite } from './store/sqlite.js';

export async function nodeDeps(): Promise<Deps> {
  const cfg = configFromEnv(process.env);
  if (!process.env.FLEET_KEK) throw new Error('FLEET_KEK is required (32 random bytes, base64): openssl rand -base64 32');
  const vault = await Vault.create(process.env.FLEET_KEK);
  const path = process.env.FLEET_DB_PATH || '/data/wpfleet.db';
  mkdirSync(dirname(path), { recursive: true });
  const sql = openSqlite(path);
  await sql.exec(SCHEMA);
  return { sql, vault, cfg, fetch: globalThis.fetch.bind(globalThis) };
}

async function main() {
  const d = await nodeDeps();
  const app = createApp(d);
  const port = parseInt(process.env.PORT || '8787', 10);
  serve({ fetch: app.fetch, port, hostname: process.env.HOST || '0.0.0.0' }, () => {
    console.log(`[wpfleet] listening on :${port} as ${d.cfg.publicUrl}`);
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error('[wpfleet] ' + (e instanceof Error ? e.message : e));
    process.exit(1);
  });
}
