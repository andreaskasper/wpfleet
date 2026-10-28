/** SQLite schema (also valid for Cloudflare D1). Idempotent. */
export const SCHEMA = `
CREATE TABLE IF NOT EXISTS admin (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  username TEXT NOT NULL,
  pw_hash TEXT NOT NULL,
  totp_secret_enc TEXT,
  totp_enabled INTEGER NOT NULL DEFAULT 0,
  totp_last_counter INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id_hash TEXT PRIMARY KEY,
  csrf TEXT NOT NULL,
  totp_ok INTEGER NOT NULL DEFAULT 0,
  flash TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS throttle (
  k TEXT PRIMARY KEY,
  n INTEGER NOT NULL,
  first_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sites (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  base_url TEXT NOT NULL,
  mcp_url TEXT,
  issuer TEXT,
  authorization_endpoint TEXT,
  token_endpoint TEXT,
  client_id TEXT,
  client_secret_enc TEXT,
  access_token_enc TEXT,
  access_expires INTEGER NOT NULL DEFAULT 0,
  refresh_token_enc TEXT,
  scope TEXT,
  status TEXT NOT NULL DEFAULT 'new',
  last_error TEXT,
  bridge_version TEXT,
  tools_json TEXT,
  tools_at INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS site_auth (
  state_hash TEXT PRIMARY KEY,
  site_id TEXT NOT NULL,
  verifier_enc TEXT NOT NULL,
  reg_enc TEXT,
  session_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id TEXT PRIMARY KEY,
  client_name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,
  secret_hash TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  challenge TEXT NOT NULL,
  scope TEXT NOT NULL,
  sites TEXT,
  used INTEGER NOT NULL DEFAULT 0,
  family TEXT,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_refresh (
  rt_hash TEXT PRIMARY KEY,
  family TEXT NOT NULL,
  client_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  sites TEXT,
  connected_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_rt_used (
  rt_hash TEXT PRIMARY KEY,
  family TEXT NOT NULL,
  record TEXT NOT NULL,
  at INTEGER NOT NULL,
  grace_used INTEGER NOT NULL DEFAULT 0,
  response_enc TEXT
);
CREATE TABLE IF NOT EXISTS oauth_access (
  at_hash TEXT PRIMARY KEY,
  family TEXT NOT NULL,
  client_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  sites TEXT,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS oauth_access_family ON oauth_access(family);
CREATE INDEX IF NOT EXISTS oauth_refresh_family ON oauth_refresh(family);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  site TEXT,
  tool TEXT,
  status TEXT,
  ms INTEGER,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS audit_at ON audit(at);
`;
