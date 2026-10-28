/** Cloudflare D1 implementation of Sql (Worker). */
import type { Sql, SqlValue } from './types.js';

export function openD1(db: D1Database): Sql {
  return {
    async get<T>(sql: string, params: SqlValue[] = []) {
      return ((await db.prepare(sql).bind(...params).first()) ?? undefined) as T | undefined;
    },
    async all<T>(sql: string, params: SqlValue[] = []) {
      return (await db.prepare(sql).bind(...params).all()).results as T[];
    },
    async run(sql: string, params: SqlValue[] = []) {
      const r = await db.prepare(sql).bind(...params).run();
      return { changes: r.meta.changes ?? 0 };
    },
    async exec(sql: string) {
      // D1's exec() wants one statement per line; run them one by one.
      for (const stmt of sql.split(';').map((s) => s.trim()).filter(Boolean)) {
        await db.prepare(stmt).run();
      }
    },
  };
}
