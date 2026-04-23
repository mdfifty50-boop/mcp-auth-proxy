/**
 * In-memory storage for mcp-auth-proxy.
 * All Maps are module-level singletons — hot-swappable to Redis in v2.
 */

import { randomBytes } from 'crypto';

// API keys: keyId -> ApiKeyRecord
const apiKeys = new Map();

// Rate limit buckets: keyId -> { minute: {count, windowStart}, hour: {count, windowStart}, day: {count, windowStart} }
const rateBuckets = new Map();

// Audit log: Array<AuditEntry> (bounded by MAX_AUDIT_ENTRIES)
const auditLog = [];

// Global rate limits (applied when per-key override is absent)
let globalRateLimits = {
  callsPerMinute: 60,
  callsPerHour: 1000,
  callsPerDay: 10000,
};

// CORS config
let corsConfig = {
  allowedOrigins: ['*'],
  allowCredentials: false,
};

const MAX_AUDIT_ENTRIES = 10000;
const SERVER_START = Date.now();
let totalRequests = 0;
let blockedRequests = 0;

// ─────────────────────────────────────────────
// Key generation
// ─────────────────────────────────────────────

export function generateSecureKey() {
  // Format: mak_<32 hex bytes> (mak = mcp auth key)
  return `mak_${randomBytes(32).toString('hex')}`;
}

export function generateKeyId() {
  return `kid_${randomBytes(8).toString('hex')}`;
}

// ─────────────────────────────────────────────
// API Key CRUD
// ─────────────────────────────────────────────

export function createApiKey({ name, permissions, rateLimit, expiresAt }) {
  const keyId = generateKeyId();
  const apiKey = generateSecureKey();
  const now = new Date().toISOString();

  const record = {
    keyId,
    apiKey,
    name,
    permissions: permissions || [],          // [] = all tools allowed
    rateLimit: rateLimit ?? null,            // null = use global limits
    expiresAt: expiresAt || null,
    active: true,
    created: now,
    callCount: 0,
    lastUsed: null,
  };

  apiKeys.set(keyId, record);
  return record;
}

export function revokeApiKey(keyId) {
  const record = apiKeys.get(keyId);
  if (!record) return null;
  record.active = false;
  return record;
}

export function listApiKeys() {
  return [...apiKeys.values()].map(k => ({
    keyId: k.keyId,
    name: k.name,
    permissions: k.permissions,
    rateLimit: k.rateLimit,
    callCount: k.callCount,
    lastUsed: k.lastUsed,
    active: k.active,
    expiresAt: k.expiresAt,
    created: k.created,
  }));
}

export function getKeyByApiKey(rawKey) {
  for (const record of apiKeys.values()) {
    if (record.apiKey === rawKey) return record;
  }
  return null;
}

// ─────────────────────────────────────────────
// Rate Limiting
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
    allowed: true,
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
    // Global
    globalRateLimits = {
      callsPerMinute: callsPerMinute ?? globalRateLimits.callsPerMinute,
      callsPerHour:   callsPerHour   ?? globalRateLimits.callsPerHour,
      callsPerDay:    callsPerDay    ?? globalRateLimits.callsPerDay,
    };
  } else {
    const record = apiKeys.get(keyId);
    if (!record) return null;
    // Store per-key overrides directly on the record
    record.rateLimitConfig = {
      callsPerMinute: callsPerMinute ?? 60,
      callsPerHour:   callsPerHour   ?? 1000,
      callsPerDay:    callsPerDay    ?? 10000,
    };
  }
  return true;
}

// ─────────────────────────────────────────────
// Audit Log
// ─────────────────────────────────────────────

export function addAuditEntry({ keyId, toolName, authorized, reason, ip, duration }) {
  totalRequests++;
  if (!authorized) blockedRequests++;

  const entry = {
    timestamp: new Date().toISOString(),
    keyId: keyId || 'unknown',
    toolName: toolName || 'unknown',
    authorized,
    reason: reason || null,
    ip: ip || null,
    duration: duration ?? null,
  };

  auditLog.push(entry);

  // Evict oldest if we hit the cap
  if (auditLog.length > MAX_AUDIT_ENTRIES) {
    auditLog.shift();
  }

  // Update key's callCount + lastUsed
  if (keyId) {
    const record = apiKeys.get(keyId);
    if (record) {
      record.callCount++;
      record.lastUsed = entry.timestamp;
    }
  }

  return entry;
}

export function getAuditLog({ keyId, toolName, since, limit }) {
  let results = [...auditLog];

  if (keyId) results = results.filter(e => e.keyId === keyId);
  if (toolName) results = results.filter(e => e.toolName === toolName);
  if (since) {
    const sinceTs = new Date(since).getTime();
    results = results.filter(e => new Date(e.timestamp).getTime() >= sinceTs);
  }

  // Return most-recent first
  results = results.reverse();

  if (limit && limit > 0) results = results.slice(0, limit);

  return results;
}

// ─────────────────────────────────────────────
// CORS
// ─────────────────────────────────────────────

export function setCorsConfig({ allowedOrigins, allowCredentials }) {
  corsConfig = {
    allowedOrigins: allowedOrigins ?? corsConfig.allowedOrigins,
    allowCredentials: allowCredentials ?? corsConfig.allowCredentials,
  };
  return corsConfig;
}

export function getCorsConfig() {
  return { ...corsConfig };
}

// ─────────────────────────────────────────────
// Health / Dashboard stats
// ─────────────────────────────────────────────

export function getHealthStats() {
  const uptimeMs = Date.now() - SERVER_START;
  const activeKeys = [...apiKeys.values()].filter(k => k.active).length;

  return {
    status: 'healthy',
    uptimeSeconds: Math.floor(uptimeMs / 1000),
    totalRequests,
    blockedRequests,
    activeKeys,
    auditLogSize: auditLog.length,
    globalRateLimits,
  };
}

// ─────────────────────────────────────────────
// Threat detection
// ─────────────────────────────────────────────

export function detectThreats() {
  const threats = [];
  const now = Date.now();
  const windowMs = 5 * 60 * 1000; // 5-minute window

  // 1. Brute force: >10 blocked requests from same keyId in last 5 min
  const recentBlocked = auditLog.filter(
    e => !e.authorized && (now - new Date(e.timestamp).getTime()) < windowMs
  );
  const blockedByKey = {};
  for (const e of recentBlocked) {
    blockedByKey[e.keyId] = (blockedByKey[e.keyId] || 0) + 1;
  }
  for (const [kid, count] of Object.entries(blockedByKey)) {
    if (count >= 10) {
      threats.push({
        type: 'brute_force',
        severity: count >= 50 ? 'critical' : 'high',
        message: `Key ${kid} had ${count} blocked requests in the last 5 minutes`,
        keyId: kid,
        count,
      });
    }
  }

  // 2. Expired keys still being used
  const expiredStillUsed = [...apiKeys.values()].filter(
    k => k.expiresAt && new Date(k.expiresAt) < new Date() && k.callCount > 0 && k.active
  );
  for (const k of expiredStillUsed) {
    threats.push({
      type: 'expired_key_active',
      severity: 'medium',
      message: `Key ${k.keyId} (${k.name}) expired at ${k.expiresAt} but is still active`,
      keyId: k.keyId,
      recommendation: 'Revoke this key immediately',
    });
  }

  // 3. Keys with no expiry (rotation needed)
  const noExpiry = [...apiKeys.values()].filter(k => k.active && !k.expiresAt);
  if (noExpiry.length > 0) {
    threats.push({
      type: 'key_rotation_needed',
      severity: 'low',
      message: `${noExpiry.length} active key(s) have no expiration date`,
      keyIds: noExpiry.map(k => k.keyId),
      recommendation: 'Set expiresAt for all keys to enforce rotation',
    });
  }

  // 4. Global rate limit near capacity
  const blockedLastMinute = recentBlocked.filter(
    e => (now - new Date(e.timestamp).getTime()) < 60 * 1000
  ).length;
  if (blockedLastMinute > globalRateLimits.callsPerMinute * 0.5) {
    threats.push({
      type: 'rate_limit_pressure',
      severity: 'medium',
      message: `${blockedLastMinute} requests blocked in the last minute — consider raising global rate limits`,
      blockedCount: blockedLastMinute,
    });
  }

  return threats;
}

// ─────────────────────────────────────────────
// Dashboard data
// ─────────────────────────────────────────────

export function getDashboardData() {
  const health = getHealthStats();
  const recentEntries = [...auditLog].reverse().slice(0, 20);
  const activeKeyList = [...apiKeys.values()]
    .filter(k => k.active)
    .map(k => ({
      keyId: k.keyId,
      name: k.name,
      callCount: k.callCount,
      lastUsed: k.lastUsed,
      rateLimit: k.rateLimit,
      expiresAt: k.expiresAt,
    }));

  // Rate limit status per active key
  const rateLimitStatus = activeKeyList.map(k => {
    const bucket = rateBuckets.get(k.keyId);
    return {
      keyId: k.keyId,
      name: k.name,
      minuteUsage: bucket ? bucket.minute.count : 0,
      minuteLimit: k.rateLimit ?? globalRateLimits.callsPerMinute,
    };
  });

  return {
    health,
    activeKeys: activeKeyList,
    rateLimitStatus,
    recentRequests: recentEntries,
    generatedAt: new Date().toISOString(),
  };
}
