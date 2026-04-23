/**
 * Integration tests for the SQLite-backed storage layer.
 * Uses Node.js built-in test runner (node --test).
 *
 * We set MCP_AUTH_PROXY_DB_DIR to a temp directory BEFORE any imports
 * so db.js creates the test DB there instead of ~/.mcp-auth-proxy.
 * This file is executed as its own process by `node --test`, so the
 * module cache is fresh and the env var is seen by db.js on first load.
 */

// MUST be set before any local imports that transitively import db.js
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const tmpDir = mkdtempSync(join(tmpdir(), 'mcp-auth-proxy-test-'));
process.env.MCP_AUTH_PROXY_DB_DIR = tmpDir;

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  createApiKey, revokeApiKey, listApiKeys, getKeyByApiKey,
  addAuditEntry, getAuditLog, checkRateLimit, incrementRateBucket,
  setCorsConfig, getCorsConfig, getHealthStats,
} from './storage.js';

// ─────────────────────────────────────────────
// Test 1: createApiKey + getKeyByApiKey round-trip
// ─────────────────────────────────────────────

test('createApiKey stores key and getKeyByApiKey retrieves it', () => {
  const record = createApiKey({
    name: 'test-agent',
    permissions: ['tool_a', 'tool_b'],
    rateLimit: 30,
    expiresAt: null,
  });

  assert.ok(record.apiKey.startsWith('mak_'), 'apiKey should start with mak_');
  assert.ok(record.keyId.startsWith('kid_'), 'keyId should start with kid_');
  assert.equal(record.name, 'test-agent');
  assert.deepEqual(record.permissions, ['tool_a', 'tool_b']);
  assert.equal(record.rateLimit, 30);
  assert.equal(record.active, true);

  // Look up by raw key
  const found = getKeyByApiKey(record.apiKey);
  assert.ok(found, 'should find key by raw apiKey');
  assert.equal(found.keyId, record.keyId);
  assert.equal(found.name, 'test-agent');
  assert.equal(found.active, true);

  // Invalid key returns null
  const notFound = getKeyByApiKey('mak_invalid');
  assert.equal(notFound, null);
});

// ─────────────────────────────────────────────
// Test 2: revokeApiKey + listApiKeys
// ─────────────────────────────────────────────

test('revokeApiKey marks key inactive and listApiKeys reflects it', () => {
  const r = createApiKey({ name: 'revoke-me', permissions: [], rateLimit: null, expiresAt: null });
  assert.equal(r.active, true);

  const revoked = revokeApiKey(r.keyId);
  assert.ok(revoked, 'revokeApiKey should return the record');
  assert.equal(revoked.keyId, r.keyId);

  // Lookup should show inactive
  const found = getKeyByApiKey(r.apiKey);
  assert.equal(found.active, false, 'revoked key should be inactive');

  // listApiKeys should include it with active=false
  const list = listApiKeys();
  const match = list.find(k => k.keyId === r.keyId);
  assert.ok(match, 'revoked key should appear in listApiKeys');
  assert.equal(match.active, false);

  // revoking a non-existent key returns null
  const none = revokeApiKey('kid_doesnotexist');
  assert.equal(none, null);
});

// ─────────────────────────────────────────────
// Test 3: audit log persistence and filtering
// ─────────────────────────────────────────────

test('addAuditEntry persists to SQLite and getAuditLog filters correctly', () => {
  const key = createApiKey({ name: 'audit-agent', permissions: [], rateLimit: null, expiresAt: null });

  addAuditEntry({ keyId: key.keyId, toolName: 'my_tool',    authorized: true,  reason: null,          ip: '1.2.3.4', duration: 5 });
  addAuditEntry({ keyId: key.keyId, toolName: 'other_tool', authorized: false, reason: 'key_revoked', ip: null,      duration: 2 });
  addAuditEntry({ keyId: 'kid_other', toolName: 'my_tool',  authorized: true,  reason: null,          ip: null,      duration: 1 });

  // Filter by keyId — should return only entries for this key
  const byKey = getAuditLog({ keyId: key.keyId });
  assert.ok(byKey.length >= 2, `expected >=2 entries for keyId, got ${byKey.length}`);
  assert.ok(byKey.every(e => e.keyId === key.keyId), 'all entries should match keyId filter');

  // Filter by toolName
  const byTool = getAuditLog({ toolName: 'my_tool' });
  assert.ok(byTool.length >= 2, `expected >=2 my_tool entries, got ${byTool.length}`);
  assert.ok(byTool.every(e => e.toolName === 'my_tool'), 'all entries should match toolName filter');

  // Limit
  const limited = getAuditLog({ limit: 1 });
  assert.equal(limited.length, 1, 'limit:1 should return exactly 1 entry');

  // Health stats reflect counts
  const health = getHealthStats();
  assert.ok(health.totalRequests >= 3, `expected totalRequests >= 3, got ${health.totalRequests}`);
  assert.ok(health.blockedRequests >= 1, `expected blockedRequests >= 1, got ${health.blockedRequests}`);
  assert.equal(health.status, 'healthy');
  assert.ok(health.dbPath, 'health should include dbPath');
});
