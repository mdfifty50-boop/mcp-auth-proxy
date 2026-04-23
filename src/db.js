/**
 * SQLite persistence layer for mcp-auth-proxy.
 * DB file: ~/.mcp-auth-proxy/auth.db
 * WAL mode enabled for concurrent read performance.
 */

import Database from 'better-sqlite3';
import { mkdirSync, existsSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

// ─────────────────────────────────────────────
// DB initialisation
// ─────────────────────────────────────────────

const DB_DIR = process.env.MCP_AUTH_PROXY_DB_DIR || join(homedir(), '.mcp-auth-proxy');
const DB_PATH = join(DB_DIR, 'auth.db');

if (!existsSync(DB_DIR)) {
  mkdirSync(DB_DIR, { recursive: true });
}

const db = new Database(DB_PATH);

// WAL mode: much better concurrent performance
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');
db.pragma('foreign_keys = ON');

// ─────────────────────────────────────────────
// Schema
// ─────────────────────────────────────────────

db.exec(`
  CREATE TABLE IF NOT EXISTS api_keys (
    key_id       TEXT PRIMARY KEY,
    hashed_key   TEXT UNIQUE NOT NULL,
    agent_id     TEXT,
    scopes_json  TEXT NOT NULL DEFAULT '[]',
    created_at   TEXT NOT NULL,
    expires_at   INTEGER,
    last_used    TEXT,
    revoked      INTEGER NOT NULL DEFAULT 0
  );

  CREATE INDEX IF NOT EXISTS idx_api_keys_hashed_key ON api_keys(hashed_key);
  CREATE INDEX IF NOT EXISTS idx_api_keys_agent_id   ON api_keys(agent_id);

  CREATE TABLE IF NOT EXISTS sessions (
    session_id    TEXT PRIMARY KEY,
    agent_id      TEXT,
    key_id        TEXT,
    created_at    TEXT NOT NULL,
    expires_at    INTEGER,
    metadata_json TEXT NOT NULL DEFAULT '{}'
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT NOT NULL,
    agent_id   TEXT,
    action     TEXT,
    key_id     TEXT,
    detail     TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_audit_log_key_id    ON audit_log(key_id);
  CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);

  CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`);

export default db;
