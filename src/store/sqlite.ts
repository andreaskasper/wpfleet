/** better-sqlite3 implementation of Sql (Docker / Node). */
import Database from 'better-sqlite3';
import type { Sql, SqlValue } from './types.js';

export function openSqlite(path: string): Sql {
  const db = new Database(path);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');
  return {
    async get<T>(sql: string, params: SqlValue[] = []) {
      return db.prepare(sql).get(...params) as T | undefined;
    },
    async all<T>(sql: string, params: SqlValue[] = []) {
      return db.prepare(sql).all(...params) as T[];
    },
    async run(sql: string, params: SqlValue[] = []) {
      const r = db.prepare(sql).run(...params);
      return { changes: r.changes };
    },
    async exec(sql: string) {
      db.exec(sql);
    },
  };
}
