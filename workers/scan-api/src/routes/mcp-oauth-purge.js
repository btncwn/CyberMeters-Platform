const USER_RE = /^[A-Za-z0-9_-]{1,128}$/;
const CONNECTION_RE = /^mcpconn_[a-f0-9-]{36}$/;

async function oauthGrantApi(env) {
  // The injected API is only used by local Node purge validators. Production
  // Wrangler has no such binding and loads the real provider on first use.
  if (env.MCP_OAUTH_PURGE_API) {
    if (typeof env.MCP_OAUTH_PURGE_API.listUserGrants !== "function" ||
        typeof env.MCP_OAUTH_PURGE_API.revokeGrant !== "function") {
      throw new Error("mcp_oauth_purge_unavailable");
    }
    return env.MCP_OAUTH_PURGE_API;
  }
  const { createMcpOAuthAuthorizationServer } = await import("./mcp-oauth-server.js");
  return createMcpOAuthAuthorizationServer(env).getOAuthApi(env);
}

async function revokeMcpOAuthGrantsForPurge(env, userId, connectionId) {
  if (!env?.cybermeters_db || typeof userId !== "string" || !USER_RE.test(userId) ||
      (connectionId !== null && !CONNECTION_RE.test(connectionId))) {
    throw new Error("mcp_oauth_purge_unavailable");
  }
  if (!env.OAUTH_KV) {
    if (connectionId !== null) throw new Error("mcp_oauth_purge_unavailable");
    const table = await env.cybermeters_db.prepare(
      `SELECT name FROM sqlite_master WHERE type = 'table'
        AND name = 'mcp_oauth_connections' LIMIT 1`,
    ).first();
    if (!table) return { revoked: 0 }; // Pre-migration legacy account purge.
    const existing = await env.cybermeters_db.prepare(
      `SELECT id FROM mcp_oauth_connections WHERE user_id = ? LIMIT 1`,
    ).bind(userId).first();
    if (existing) throw new Error("mcp_oauth_purge_unavailable");
    return { revoked: 0 };
  }
  const oauth = await oauthGrantApi(env);
  let revoked = 0;
  // Verify after deletion. Cursor exhaustion and errors stop the D1 hard purge.
  for (let sweep = 0; sweep < 3; sweep++) {
    let cursor;
    let matches = 0;
    let complete = false;
    for (let page = 0; page < 100; page++) {
      const listed = await oauth.listUserGrants(userId, { limit: 50, cursor });
      if (!Array.isArray(listed?.items)) throw new Error("mcp_oauth_purge_unavailable");
      for (const grant of listed.items) {
        if (connectionId === null || grant.metadata?.connectionId === connectionId) {
          await oauth.revokeGrant(grant.id, userId);
          matches++;
          revoked++;
        }
      }
      cursor = listed.cursor;
      if (!cursor) { complete = true; break; }
    }
    if (!complete) throw new Error("mcp_oauth_purge_incomplete");
    if (matches === 0) return { revoked };
  }
  throw new Error("mcp_oauth_purge_incomplete");
}

/** Use before account D1 hard deletion. OAUTH_KV is dedicated to MCP grants. */
export async function revokeMcpOAuthUserGrantsForPurge(env, userId) {
  return revokeMcpOAuthGrantsForPurge(env, userId, null);
}

/** Use before workspace D1 hard deletion; leaves unrelated connections live. */
export async function revokeMcpOAuthConnectionGrantsForPurge(env, userId, connectionId) {
  return revokeMcpOAuthGrantsForPurge(env, userId, connectionId);
}
