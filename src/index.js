#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import {
  createApiKey,
  revokeApiKey,
  listApiKeys,
  getKeyByApiKey,
  checkRateLimit,
  incrementRateBucket,
  setRateLimits,
  addAuditEntry,
  getAuditLog,
  setCorsConfig,
  getCorsConfig,
  getHealthStats,
  detectThreats,
  getDashboardData,
} from './storage.js';

const server = new McpServer({
  name: 'mcp-auth-proxy',
  version: '0.1.0',
  description: 'Production-ready authentication, rate limiting, and audit logging for any MCP server',
});

// ═══════════════════════════════════════════
// TOOL: create_api_key
// ═══════════════════════════════════════════

server.tool(
  'create_api_key',
  'Generate a new API key for accessing protected MCP servers. Supports per-key tool permissions, rate limits, and optional expiry.',
  {
    name: z.string().min(1).describe('Human-readable name for this API key (e.g. "production-agent", "dev-testing")'),
    permissions: z.array(z.string()).optional().describe('Tool names this key is allowed to call. Empty array = all tools permitted.'),
    rateLimit: z.number().int().positive().optional().describe('Maximum calls per minute for this key. Null = use global limit.'),
    expiresAt: z.string().optional().describe('ISO 8601 expiry datetime (e.g. "2026-12-31T23:59:59Z"). Null = no expiry.'),
  },
  async (params) => {
    const record = createApiKey({
      name: params.name,
      permissions: params.permissions || [],
      rateLimit: params.rateLimit ?? null,
      expiresAt: params.expiresAt ?? null,
    });

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          apiKey: record.apiKey,
          keyId: record.keyId,
          name: record.name,
          permissions: record.permissions,
          rateLimit: record.rateLimit,
          expiresAt: record.expiresAt,
          created: record.created,
          note: 'Store this apiKey securely — it will not be shown again',
        }, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════════
// TOOL: revoke_api_key
// ═══════════════════════════════════════════

server.tool(
  'revoke_api_key',
  'Immediately disable an existing API key. Revoked keys are permanently blocked from all further requests.',
  {
    keyId: z.string().describe('The keyId of the API key to revoke (format: kid_xxxxxxxxxxxxxxxx)'),
  },
  async ({ keyId }) => {
    const record = revokeApiKey(keyId);

    if (!record) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ error: `Key not found: ${keyId}` }, null, 2),
        }],
      };
    }

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          revoked: true,
          keyId: record.keyId,
          name: record.name,
          revokedAt: new Date().toISOString(),
        }, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════════
// TOOL: list_api_keys
// ═══════════════════════════════════════════

server.tool(
  'list_api_keys',
  'Show all API keys (active and revoked) with their usage statistics. The raw apiKey value is never returned for security.',
  {},
  async () => {
    const keys = listApiKeys();

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          total: keys.length,
          active: keys.filter(k => k.active).length,
          revoked: keys.filter(k => !k.active).length,
          keys,
        }, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════════
// TOOL: validate_request
// ═══════════════════════════════════════════

server.tool(
  'validate_request',
  'Check whether an incoming request is authorized. Called by other MCP servers to gate their tools. Returns authorized status, reason, and remaining rate limit.',
  {
    apiKey: z.string().describe('The raw API key from the incoming request header or parameter'),
    toolName: z.string().describe('The MCP tool name being requested'),
    metadata: z.record(z.any()).optional().describe('Optional request metadata for audit logging (ip, user-agent, etc.)'),
  },
  async ({ apiKey, toolName, metadata }) => {
    const startMs = Date.now();
    const ip = metadata?.ip || null;

    // 1. Look up key
    const record = getKeyByApiKey(apiKey);
    if (!record) {
      addAuditEntry({
        keyId: null,
        toolName,
        authorized: false,
        reason: 'invalid_api_key',
        ip,
        duration: Date.now() - startMs,
      });
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            authorized: false,
            reason: 'invalid_api_key',
            remainingCalls: 0,
          }, null, 2),
        }],
      };
    }

    // 2. Check key active
    if (!record.active) {
      addAuditEntry({
        keyId: record.keyId,
        toolName,
        authorized: false,
        reason: 'key_revoked',
        ip,
        duration: Date.now() - startMs,
      });
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            authorized: false,
            reason: 'key_revoked',
            remainingCalls: 0,
          }, null, 2),
        }],
      };
    }

    // 3. Check expiry
    if (record.expiresAt && new Date(record.expiresAt) < new Date()) {
      addAuditEntry({
        keyId: record.keyId,
        toolName,
        authorized: false,
        reason: 'key_expired',
        ip,
        duration: Date.now() - startMs,
      });
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            authorized: false,
            reason: 'key_expired',
            remainingCalls: 0,
          }, null, 2),
        }],
      };
    }

    // 4. Check permissions (empty array = all tools allowed)
    if (record.permissions.length > 0 && !record.permissions.includes(toolName)) {
      addAuditEntry({
        keyId: record.keyId,
        toolName,
        authorized: false,
        reason: 'permission_denied',
        ip,
        duration: Date.now() - startMs,
      });
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            authorized: false,
            reason: 'permission_denied',
            allowedTools: record.permissions,
            remainingCalls: 0,
          }, null, 2),
        }],
      };
    }

    // 5. Check rate limit
    const rlResult = checkRateLimit(record.keyId, record.rateLimit);
    if (!rlResult.allowed) {
      addAuditEntry({
        keyId: record.keyId,
        toolName,
        authorized: false,
        reason: rlResult.reason,
        ip,
        duration: Date.now() - startMs,
      });
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            authorized: false,
            reason: rlResult.reason,
            remainingCalls: 0,
          }, null, 2),
        }],
      };
    }

    // 6. Authorized — increment bucket and log
    incrementRateBucket(record.keyId);
    addAuditEntry({
      keyId: record.keyId,
      toolName,
      authorized: true,
      reason: null,
      ip,
      duration: Date.now() - startMs,
    });

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          authorized: true,
          keyId: record.keyId,
          name: record.name,
          remainingCalls: rlResult.remaining,
        }, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════════
// TOOL: get_audit_log
// ═══════════════════════════════════════════

server.tool(
  'get_audit_log',
  'Retrieve the access audit trail. Filter by key, tool name, or time range. Returns most-recent entries first.',
  {
    keyId: z.string().optional().describe('Filter entries by a specific keyId'),
    toolName: z.string().optional().describe('Filter entries by tool name'),
    since: z.string().optional().describe('ISO 8601 datetime — only return entries at or after this time'),
    limit: z.number().int().positive().optional().describe('Maximum number of entries to return (default: 100)'),
  },
  async (params) => {
    const entries = getAuditLog({
      keyId: params.keyId,
      toolName: params.toolName,
      since: params.since,
      limit: params.limit ?? 100,
    });

    const authorizedCount = entries.filter(e => e.authorized).length;
    const blockedCount = entries.filter(e => !e.authorized).length;

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          total: entries.length,
          authorized: authorizedCount,
          blocked: blockedCount,
          blockRate: entries.length > 0
            ? `${((blockedCount / entries.length) * 100).toFixed(1)}%`
            : '0%',
          entries,
        }, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════════
// TOOL: set_rate_limit
// ═══════════════════════════════════════════

server.tool(
  'set_rate_limit',
  'Configure rate limits for a specific key or globally (when keyId is omitted). Per-key limits override global limits.',
  {
    keyId: z.string().optional().describe('Key to configure. Omit or set null to configure global limits.'),
    callsPerMinute: z.number().int().positive().optional().describe('Max calls allowed per 60-second window'),
    callsPerHour: z.number().int().positive().optional().describe('Max calls allowed per 60-minute window'),
    callsPerDay: z.number().int().positive().optional().describe('Max calls allowed per 24-hour window'),
  },
  async (params) => {
    const result = setRateLimits({
      keyId: params.keyId ?? null,
      callsPerMinute: params.callsPerMinute,
      callsPerHour: params.callsPerHour,
      callsPerDay: params.callsPerDay,
    });

    if (result === null) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ error: `Key not found: ${params.keyId}` }, null, 2),
        }],
      };
    }

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          configured: true,
          scope: params.keyId ? `key:${params.keyId}` : 'global',
          callsPerMinute: params.callsPerMinute ?? '(unchanged)',
          callsPerHour: params.callsPerHour ?? '(unchanged)',
          callsPerDay: params.callsPerDay ?? '(unchanged)',
        }, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════════
// TOOL: check_health
// ═══════════════════════════════════════════

server.tool(
  'check_health',
  'Health check for the auth proxy. Returns uptime, request counters, active key count, and current global rate limit config.',
  {},
  async () => {
    const stats = getHealthStats();

    return {
      content: [{
        type: 'text',
        text: JSON.stringify(stats, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════════
// TOOL: configure_cors
// ═══════════════════════════════════════════

server.tool(
  'configure_cors',
  'Set allowed origins for HTTP-based MCP access. Use ["*"] to allow all origins (default). Supports credentials flag.',
  {
    allowedOrigins: z.array(z.string()).describe('List of allowed origins. Use ["*"] for wildcard. Example: ["https://myapp.com", "https://staging.myapp.com"]'),
    allowCredentials: z.boolean().optional().describe('Whether to allow credentials (cookies, auth headers) in cross-origin requests. Default: false.'),
  },
  async (params) => {
    const config = setCorsConfig({
      allowedOrigins: params.allowedOrigins,
      allowCredentials: params.allowCredentials ?? false,
    });

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          configured: true,
          allowedOrigins: config.allowedOrigins,
          allowCredentials: config.allowCredentials,
        }, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════════
// RESOURCES
// ═══════════════════════════════════════════

server.resource(
  'auth-dashboard',
  'auth://dashboard',
  async () => {
    const data = getDashboardData();
    return {
      contents: [{
        uri: 'auth://dashboard',
        mimeType: 'application/json',
        text: JSON.stringify(data, null, 2),
      }],
    };
  }
);

server.resource(
  'auth-threats',
  'auth://threats',
  async () => {
    const threats = detectThreats();
    const health = getHealthStats();

    return {
      contents: [{
        uri: 'auth://threats',
        mimeType: 'application/json',
        text: JSON.stringify({
          scannedAt: new Date().toISOString(),
          totalThreats: threats.length,
          critical: threats.filter(t => t.severity === 'critical').length,
          high:     threats.filter(t => t.severity === 'high').length,
          medium:   threats.filter(t => t.severity === 'medium').length,
          low:      threats.filter(t => t.severity === 'low').length,
          threats,
          stats: {
            totalRequests: health.totalRequests,
            blockedRequests: health.blockedRequests,
            blockRate: health.totalRequests > 0
              ? `${((health.blockedRequests / health.totalRequests) * 100).toFixed(1)}%`
              : '0%',
          },
        }, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('MCP Auth Proxy running on stdio');
}

main().catch(console.error);
