# mcp-auth-proxy

**Production-ready authentication, rate limiting, and audit logging for any MCP server.**

> 38.7% of MCP servers have zero authentication. Only 2.4% implement rate limiting.
> This server fixes both — in one line.

---

## Install

```bash
npx mcp-auth-proxy
```

Or add to your Claude Desktop / MCP client config:

```json
{
  "mcpServers": {
    "mcp-auth-proxy": {
      "command": "npx",
      "args": ["mcp-auth-proxy"]
    }
  }
}
```

---

## What It Does

`mcp-auth-proxy` acts as a security layer that any MCP server can call to validate
incoming requests before executing its tools. It provides:

- **API key management** — generate, revoke, and list keys with a single tool call
- **Per-key RBAC** — restrict each key to a specific subset of tool names
- **Rate limiting** — per-minute, per-hour, and per-day windows, configurable globally or per key
- **Audit logging** — every request is logged with timestamp, key, tool, authorization result, and latency
- **Threat detection** — automatic detection of brute force attempts, expired keys, rotation reminders
- **CORS configuration** — control allowed origins for HTTP-based MCP deployments
- **Health monitoring** — uptime, total requests, block rate, active key count

---

## One-Line Integration

To protect an existing MCP tool, add a single `validate_request` call at the top
of your tool handler:

```js
// Before executing your tool logic:
const auth = await mcpClient.callTool('mcp-auth-proxy', 'validate_request', {
  apiKey: incomingRequest.apiKey,
  toolName: 'your_tool_name',
  metadata: { ip: request.ip },
});

if (!auth.authorized) {
  return { error: auth.reason };
}

// ... your existing tool logic
```

That is the entire integration. No middleware, no libraries, no configuration files.

---

## Tools

### `create_api_key`

Generate a new API key with optional constraints.

```json
{
  "name": "production-agent",
  "permissions": ["read_data", "write_record"],
  "rateLimit": 30,
  "expiresAt": "2026-12-31T23:59:59Z"
}
```

Returns:
```json
{
  "apiKey": "mak_a3f8...",
  "keyId": "kid_9c2b...",
  "name": "production-agent",
  "created": "2026-04-23T10:00:00.000Z",
  "note": "Store this apiKey securely — it will not be shown again"
}
```

**Permissions**: pass an empty array `[]` to allow all tools (default). Pass specific
tool names to restrict access: `["read_data", "search"]`.

**Rate limit**: calls per minute for this key. Omit to inherit global limits.

---

### `revoke_api_key`

Immediately and permanently disable a key.

```json
{ "keyId": "kid_9c2b..." }
```

Returns:
```json
{ "revoked": true, "keyId": "kid_9c2b...", "revokedAt": "2026-04-23T..." }
```

---

### `list_api_keys`

Show all keys and their usage statistics. The raw `apiKey` value is never returned.

```json
{
  "total": 3,
  "active": 2,
  "revoked": 1,
  "keys": [
    {
      "keyId": "kid_9c2b...",
      "name": "production-agent",
      "permissions": ["read_data"],
      "rateLimit": 30,
      "callCount": 1482,
      "lastUsed": "2026-04-23T09:58:00.000Z",
      "active": true
    }
  ]
}
```

---

### `validate_request`

The core gate. Call this from any MCP server before executing sensitive tools.

```json
{
  "apiKey": "mak_a3f8...",
  "toolName": "read_customer_data",
  "metadata": { "ip": "1.2.3.4" }
}
```

Returns one of:

```json
{ "authorized": true, "keyId": "kid_9c2b...", "name": "production-agent", "remainingCalls": 28 }
```

```json
{ "authorized": false, "reason": "rate_limit_minute", "remainingCalls": 0 }
```

Possible `reason` values:
- `invalid_api_key` — key not found
- `key_revoked` — key has been revoked
- `key_expired` — key's `expiresAt` has passed
- `permission_denied` — tool not in key's `permissions` list
- `rate_limit_minute` / `rate_limit_hour` / `rate_limit_day` — rate window exceeded

---

### `get_audit_log`

Retrieve the access trail with optional filters.

```json
{
  "keyId": "kid_9c2b...",
  "since": "2026-04-23T00:00:00Z",
  "limit": 50
}
```

Returns entries sorted most-recent-first with block rate summary.

---

### `set_rate_limit`

Configure rate limits globally (omit `keyId`) or per key.

```json
{
  "callsPerMinute": 100,
  "callsPerHour": 2000,
  "callsPerDay": 20000
}
```

Per-key override:
```json
{
  "keyId": "kid_9c2b...",
  "callsPerMinute": 5
}
```

---

### `check_health`

```json
{
  "status": "healthy",
  "uptimeSeconds": 3600,
  "totalRequests": 8421,
  "blockedRequests": 34,
  "activeKeys": 5,
  "auditLogSize": 8421,
  "globalRateLimits": { "callsPerMinute": 60, "callsPerHour": 1000, "callsPerDay": 10000 }
}
```

---

### `configure_cors`

Set allowed origins for HTTP-based MCP access.

```json
{
  "allowedOrigins": ["https://myapp.com", "https://staging.myapp.com"],
  "allowCredentials": true
}
```

---

## Resources

### `auth://dashboard`

Real-time JSON view of active keys, rate limit status, and recent requests. Useful
for monitoring dashboards and status pages.

### `auth://threats`

Auto-detected security events:
- **brute_force** — key receiving 10+ blocked requests in 5 minutes
- **expired_key_active** — key past its `expiresAt` still configured as active
- **key_rotation_needed** — keys with no expiry date set
- **rate_limit_pressure** — global rate limit approaching capacity

---

## Design Principles

- **Zero external dependencies** — only `@modelcontextprotocol/sdk` and `zod`. No auth libraries.
- **Crypto-secure keys** — uses Node.js built-in `crypto.randomBytes(32)` for key generation
- **In-memory storage** — fast, zero-config, zero-infrastructure. Production upgrade to Redis requires
  changing the storage module only — the interface is identical.
- **Bounded audit log** — capped at 10,000 entries with automatic eviction of oldest records
- **Audit-first design** — every `validate_request` call writes an audit entry regardless of outcome

---

## Security Notes

1. The raw `apiKey` value (`mak_...`) is only returned once at creation. Store it immediately.
2. `list_api_keys` and `get_audit_log` should themselves be protected in production — wrap them
   with an admin-only key that has `permissions: ["list_api_keys", "get_audit_log"]`.
3. Set `expiresAt` on all keys to enforce rotation. The `auth://threats` resource flags keys
   without an expiry date.
4. Rate limit windows are rolling — the minute window resets 60 seconds after it opened,
   not at the top of the clock minute.

---

## Architecture

```
Client Request
      |
      v
validate_request (mcp-auth-proxy)
      |
      +-- Key lookup (O(n) scan, indexed in v2)
      +-- Active check
      +-- Expiry check
      +-- Permission check (RBAC)
      +-- Rate limit check (sliding window per key)
      +-- Audit log write
      |
      v
{ authorized: true/false, reason, remainingCalls }
      |
      v
Your MCP Tool (executes only if authorized: true)
```

---

## Claude Desktop Example

Protect all tools in an existing `my-data-server` with API key auth:

```json
{
  "mcpServers": {
    "mcp-auth-proxy": {
      "command": "npx",
      "args": ["mcp-auth-proxy"]
    },
    "my-data-server": {
      "command": "node",
      "args": ["my-data-server/src/index.js"]
    }
  }
}
```

Then in `my-data-server`, call `validate_request` before any sensitive tool executes.

---

## License

MIT
