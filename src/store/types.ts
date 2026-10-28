/**
 * Minimal async SQL interface. Implemented by better-sqlite3 (Docker/Node)
 * and Cloudflare D1 (Worker); both speak SQLite with `?` placeholders.
 */
export type SqlValue = string | number | null;

export interface Sql {
  get<T = Record<string, unknown>>(sql: string, params?: SqlValue[]): Promise<T | undefined>;
  all<T = Record<string, unknown>>(sql: string, params?: SqlValue[]): Promise<T[]>;
  run(sql: string, params?: SqlValue[]): Promise<{ changes: number }>;
  exec(sql: string): Promise<void>;
}
