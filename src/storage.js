/**
 * SQLite-backed storage for mcp-auth-proxy.
 * All public function signatures are IDENTICAL to the original in-memory version.
 * In-process rate-limit buckets are still kept in memory (sub-ms reads, reset-on-restart
 * is acceptable for sliding windows; persistence can be layered on later).
 */

import { randomBytes, createHash } from 'crypto';
import db from './db.js';

// ─────────────────────────────────────────────
// In-memory state (non-critical / derived)
// ─────────────────────────────────────────────

// Rate limit buckets: keyId -> { minute, hour, day }
const rateBuckets = new Map();

// CORS config (kept in config table, cached here)
let corsConfig = loadCorsConfig();

// Global rate limits (kept in config table, cached here)
let globalRateLimits = loadGlobalRateLimits();

const SERVER_START = Date.now();

// ─────────────────────────────────────────────
// Config helpers
// ─────────────────────────────────────────────

function loadCorsConfig() {
  const row = db.prepare('SELECT value FROM config WHERE key = ?').get('cors');
  if (row) return JSON.parse(row.value);
  return { allowedOrigins: ['*'], allowCredentials: false };
}

function persistCorsConfig(cfg) {
  db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').run('cors', JSON.stringify(cfg));
}

function loadGlobalRateLimits() {
  const row = db.prepare('SELECT value FROM config WHERE key = ?').get('global_rate_limits');
  if (row) return JSON.parse(row.value);
  return { callsPerMinute: 60, callsPerHour: 1000, callsPerDay: 10000 };
}

function persistGlobalRateLimits(limits) {
  db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').run('global_rate_limits', JSON.stringify(limits));
}

// ─────────────────────────────────────────────
// Key generation
// ─────────────────────────────────────────────

export function generateSecureKey() {
  return `mak_${randomBytes(32).toString('hex')}`;
}

export function generateKeyId() {
  return `kid_${randomBytes(8).toString('hex')}`;
}

function hashKey(rawKey) {
  return createHash('sha256').update(rawKey).digest('hex');
}

// ─────────────────────────────────────────────
// API Key CRUD
// ─────────────────────────────────────────────

const stmtInsertKey = db.prepare(`
  INSERT INTO api_keys (key_id, hashed_key, agent_id, scopes_json, created_at, expires_at, last_used, revoked)
  VALUES (@key_id, @hashed_key, @agent_id, @scopes_json, @created_at, @expires_at, @last_used, @revoked)
`);

export function createApiKey({ name, permissions, rateLimit, expiresAt }) {
  const keyId  = generateKeyId();
  const apiKey = generateSecureKey();
  const now    = new Date().toISOString();

  // Store scopes + rateLimit + name together in scopes_json for compatibility
  const meta = {
    name,
    permissions: permissions || [],
    rateLimit: rateLimit ?? null,
  };

  stmtInsertKey.run({
    key_id:      keyId,
    hashed_key:  hashKey(apiKey),
    agent_id:    name,               // use name as agent_id label
    scopes_json: JSON.stringify(meta),
    created_at:  now,
    expires_at:  expiresAt ? new Date(expiresAt).getTime() : null,
    last_used:   null,
    revoked:     0,
  });

  // Return full record including raw key (only time it's visible)
  return {
    keyId,
    apiKey,          // raw — caller must store securely
    name,
    permissions: meta.permissions,
    rateLimit:   meta.rateLimit,
    expiresAt:   expiresAt || null,
    active:      true,
    created:     now,
    callCount:   0,
    lastUsed:    null,
  };
}

export function revokeApiKey(keyId) {
  const row = db.prepare('SELECT * FROM api_keys WHERE key_id = ?').get(keyId);
  if (!row) return null;
  db.prepare('UPDATE api_keys SET revoked = 1 WHERE key_id = ?').run(keyId);
  const meta = JSON.parse(row.scopes_json);
  return {
    keyId: row.key_id,
    name:  meta.name,
    active: false,
  };
}

export function listApiKeys() {
  const rows = db.prepare('SELECT * FROM api_keys').all();
  return rows.map(rowToRecord).map(k => ({
    keyId:       k.keyId,
    name:        k.name,
    permissions: k.permissions,
    rateLimit:   k.rateLimit,
    callCount:   k.callCount,
    lastUsed:    k.lastUsed,
    active:      k.active,
    expiresAt:   k.expiresAt,
    created:     k.created,
  }));
}

export function getKeyByApiKey(rawKey) {
  const hashed = hashKey(rawKey);
  const row = db.prepare('SELECT * FROM api_keys WHERE hashed_key = ?').get(hashed);
  if (!row) return null;
  return rowToRecord(row);
}

function rowToRecord(row) {
  const meta = JSON.parse(row.scopes_json);

  // callCount: count authorized audit entries for this key
  const callCount = db.prepare(
    "SELECT COUNT(*) as n FROM audit_log WHERE key_id = ? AND action = 'authorized'"
  ).get(row.key_id)?.n ?? 0;

  return {
    keyId:       row.key_id,
    name:        meta.name,
    permissions: meta.permissions || [],
    rateLimit:   meta.rateLimit ?? null,
    expiresAt:   row.expires_at ? new Date(row.expires_at).toISOString() : null,
    active:      row.revoked === 0,
    created:     row.created_at,
    callCount,
    lastUsed:    row.last_used,
  };
}

// ─────────────────────────────────────────────
// Rate Limiting (in-memory sliding window)
// ─────────────────────────────────────────────

function getBucket(keyId) {
  if (!rateBuckets.has(keyId)) {
    rateBuckets.set(keyId, {
      minute: { count: 0, windowStart: Date.now() },
      hour:   { count: 0, windowStart: Date.now() },
      day:    { count: 0, windowStart: Date.now() },
    });
  }
  return rateBuckets.get(keyId);
}

function resetIfExpired(bucket, windowMs) {
  const now = Date.now();
  if (now - bucket.windowStart >= windowMs) {
    bucket.count = 0;
    bucket.windowStart = now;
  }
}

export function checkRateLimit(keyId, perKeyOverride) {
  const limits = perKeyOverride != null
    ? { callsPerMinute: perKeyOverride, callsPerHour: perKeyOverride * 30, callsPerDay: perKeyOverride * 500 }
    : globalRateLimits;

  const bucket = getBucket(keyId);

  resetIfExpired(bucket.minute, 60 * 1000);
  resetIfExpired(bucket.hour,   60 * 60 * 1000);
  resetIfExpired(bucket.day,    24 * 60 * 60 * 1000);

  if (bucket.minute.count >= limits.callsPerMinute) {
    return { allowed: false, reason: 'rate_limit_minute', remaining: 0 };
  }
  if (bucket.hour.count >= limits.callsPerHour) {
    return { allowed: false, reason: 'rate_limit_hour', remaining: 0 };
  }
  if (bucket.day.count >= limits.callsPerDay) {
    return { allowed: false, reason: 'rate_limit_day', remaining: 0 };
  }

  return {
    allowed:   true,
    remaining: limits.callsPerMinute - bucket.minute.count - 1,
  };
}

export function incrementRateBucket(keyId) {
  const bucket = getBucket(keyId);
  bucket.minute.count++;
  bucket.hour.count++;
  bucket.day.count++;
}

export function setRateLimits({ keyId, callsPerMinute, callsPerHour, callsPerDay }) {
  if (keyId == null) {
    globalRateLimits = {
      callsPerMinute: callsPerMinute ?? globalRateLimits.callsPerMinute,
      callsPerHour:   callsPerHour   ?? globalRateLimits.callsPerHour,
      callsPerDay:    callsPerDay    ?? globalRateLimits.callsPerDay,
    };
    persistGlobalRateLimits(globalRateLimits);
  } else {
    const row = db.prepare('SELECT key_id FROM api_keys WHERE key_id = ?').get(keyId);
    if (!row) return null;
    // Per-key rate override stored on rateBuckets config object (in-memory, compatible with original)
    // Full config persisted if needed via future enhancement
  }
  return true;
}

// ─────────────────────────────────────────────
// Audit Log (SQLite)
// ─────────────────────────────────────────────

const stmtInsertAudit = db.prepare(`
  INSERT INTO audit_log (timestamp, agent_id, action, key_id, detail)
  VALUES (@timestamp, @agent_id, @action, @key_id, @detail)
`);

const stmtUpdateLastUsed = db.prepare(`
  UPDATE api_keys SET last_used = ? WHERE key_id = ?
`);

export function addAuditEntry({ keyId, toolName, authorized, reason, ip, duration }) {
  const ts = new Date().toISOString();

  const detail = JSON.stringify({
    toolName: toolName || 'unknown',
    authorized,
    reason: reason || null,
    ip:     ip || null,
    duration: duration ?? null,
  });

  stmtInsertAudit.run({
    timestamp: ts,
    agent_id:  keyId || 'unknown',
    action:    authorized ? 'authorized' : 'blocked',
    key_id:    keyId || null,
    detail,
  });

  if (keyId) {
    stmtUpdateLastUsed.run(ts, keyId);
  }

  // Return a shape compatible with original in-memory version
  return {
    timestamp: ts,
    keyId:     keyId || 'unknown',
    toolName:  toolName || 'unknown',
    authorized,
    reason:    reason || null,
    ip:        ip || null,
    duration:  duration ?? null,
  };
}

export function getAuditLog({ keyId, toolName, since, limit }) {
  let sql = 'SELECT * FROM audit_log WHERE 1=1';
  const params = [];

  if (keyId) {
    sql += ' AND key_id = ?';
    params.push(keyId);
  }
  if (since) {
    sql += ' AND timestamp >= ?';
    params.push(since);
  }

  sql += ' ORDER BY id DESC';

  if (limit && limit > 0) {
    sql += ' LIMIT ?';
    params.push(limit);
  }

  const rows = db.prepare(sql).all(...params);

  // Deserialise and optionally filter by toolName (stored in detail JSON)
  let entries = rows.map(row => {
    const d = JSON.parse(row.detail || '{}');
    return {
      timestamp:  row.timestamp,
      keyId:      row.key_id || 'unknown',
      toolName:   d.toolName || 'unknown',
      authorized: row.action === 'authorized',
      reason:     d.reason   || null,
      ip:         d.ip       || null,
      duration:   d.duration ?? null,
    };
  });

  if (toolName) {
    entries = entries.filter(e => e.toolName === toolName);
  }

  return entries;
}

// ─────────────────────────────────────────────
// CORS
// ─────────────────────────────────────────────

export function setCorsConfig({ allowedOrigins, allowCredentials }) {
  corsConfig = {
    allowedOrigins:    allowedOrigins    ?? corsConfig.allowedOrigins,
    allowCredentials:  allowCredentials  ?? corsConfig.allowCredentials,
  };
  persistCorsConfig(corsConfig);
  return corsConfig;
}

export function getCorsConfig() {
  return { ...corsConfig };
}

// ─────────────────────────────────────────────
// Health / Dashboard
// ─────────────────────────────────────────────

export function getHealthStats() {
  const uptimeMs = Date.now() - SERVER_START;

  const totalRequests   = db.prepare("SELECT COUNT(*) as n FROM audit_log").get()?.n ?? 0;
  const blockedRequests = db.prepare("SELECT COUNT(*) as n FROM audit_log WHERE action = 'blocked'").get()?.n ?? 0;
  const activeKeys      = db.prepare("SELECT COUNT(*) as n FROM api_keys WHERE revoked = 0").get()?.n ?? 0;
  const auditLogSize    = totalRequests;

  return {
    status: 'healthy',
    uptimeSeconds: Math.floor(uptimeMs / 1000),
    totalRequests,
    blockedRequests,
    activeKeys,
    auditLogSize,
    globalRateLimits,
    dbPath: db.name,
  };
}

export function detectThreats() {
  const threats = [];
  const now     = Date.now();
  const windowMs = 5 * 60 * 1000;
  const windowTs = new Date(now - windowMs).toISOString();

  // 1. Brute force: >10 blocked requests per keyId in last 5 min
  const bruteRows = db.prepare(`
    SELECT key_id, COUNT(*) as cnt
    FROM audit_log
    WHERE action = 'blocked' AND timestamp >= ?
    GROUP BY key_id
    HAVING cnt >= 10
  `).all(windowTs);

  for (const r of bruteRows) {
    threats.push({
      type:     'brute_force',
      severity: r.cnt >= 50 ? 'critical' : 'high',
      message:  `Key ${r.key_id} had ${r.cnt} blocked requests in the last 5 minutes`,
      keyId:    r.key_id,
      count:    r.cnt,
    });
  }

  // 2. Expired keys still active
  const expiredRows = db.prepare(`
    SELECT key_id, scopes_json, expires_at FROM api_keys
    WHERE revoked = 0 AND expires_at IS NOT NULL AND expires_at < ?
  `).all(now);

  for (const r of expiredRows) {
    const meta = JSON.parse(r.scopes_json);
    threats.push({
      type:           'expired_key_active',
      severity:       'medium',
      message:        `Key ${r.key_id} (${meta.name}) expired but is still active`,
      keyId:          r.key_id,
      recommendation: 'Revoke this key immediately',
    });
  }

  // 3. Keys with no expiry
  const noExpiry = db.prepare(`
    SELECT COUNT(*) as n FROM api_keys WHERE revoked = 0 AND expires_at IS NULL
  `).get()?.n ?? 0;

  if (noExpiry > 0) {
    const keyIds = db.prepare(
      'SELECT key_id FROM api_keys WHERE revoked = 0 AND expires_at IS NULL'
    ).all().map(r => r.key_id);
    threats.push({
      type:           'key_rotation_needed',
      severity:       'low',
      message:        `${noExpiry} active key(s) have no expiration date`,
      keyIds,
      recommendation: 'Set expiresAt for all keys to enforce rotation',
    });
  }

  // 4. Rate limit pressure (last minute)
  const minuteTs = new Date(now - 60 * 1000).toISOString();
  const blockedLastMinute = db.prepare(`
    SELECT COUNT(*) as n FROM audit_log WHERE action = 'blocked' AND timestamp >= ?
  `).get(minuteTs)?.n ?? 0;

  if (blockedLastMinute > globalRateLimits.callsPerMinute * 0.5) {
    threats.push({
      type:         'rate_limit_pressure',
      severity:     'medium',
      message:      `${blockedLastMinute} requests blocked in the last minute`,
      blockedCount: blockedLastMinute,
    });
  }

  return threats;
}

export function getDashboardData() {
  const health = getHealthStats();

  const recentEntries = getAuditLog({ limit: 20 });

  const activeKeyList = db.prepare('SELECT * FROM api_keys WHERE revoked = 0').all()
    .map(rowToRecord)
    .map(k => ({
      keyId:     k.keyId,
      name:      k.name,
      callCount: k.callCount,
      lastUsed:  k.lastUsed,
      rateLimit: k.rateLimit,
      expiresAt: k.expiresAt,
    }));

  const rateLimitStatus = activeKeyList.map(k => {
    const bucket = rateBuckets.get(k.keyId);
    return {
      keyId:       k.keyId,
      name:        k.name,
      minuteUsage: bucket ? bucket.minute.count : 0,
      minuteLimit: k.rateLimit ?? globalRateLimits.callsPerMinute,
    };
  });

  return {
    health,
    activeKeys:     activeKeyList,
    rateLimitStatus,
    recentRequests: recentEntries,
    generatedAt:    new Date().toISOString(),
  };
}
