const USER_RE = /^[A-Za-z0-9_-]{1,128}$/;
const CONNECTION_RE = /^mcpconn_[a-f0-9-]{36}$/;
// A hard purge handles one MCP connection per Worker invocation. Reserve the
// rest of that invocation's subrequest budget for D1/R2 purge work.
export const MCP_OAUTH_KV_IO_BUDGET = 32;
const MAX_KV_PAGES_PER_SWEEP = 2;
const KV_GRANT_PAGE_SIZE = 25;
export const MCP_OAUTH_REFRESH_RETENTION_BATCH_SIZE = 250;
export const MCP_OAUTH_REFRESH_RETENTION_MAX_BATCHES = 20;

async function hasTable(env, name) {
  return Boolean(await env.cybermeters_db.prepare(
    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1",
  ).bind(name).first());
}

async function hasColumn(env, table, name) {
  const columns = await env.cybermeters_db.prepare(`PRAGMA table_info(${table})`).bind().all();
  return Array.isArray(columns?.results) && columns.results.some((row) => row.name === name);
}

function claimKvOperation(budget, count = 1) {
  if (!Number.isInteger(count) || count < 0 || budget.used + count > MCP_OAUTH_KV_IO_BUDGET) {
    throw new Error("mcp_oauth_purge_incomplete");
  }
  budget.used += count;
}

async function oauthGrantApi(env, budget) {
  // The injected API is only used by local Node purge validators. Production
  // Wrangler has no such binding and loads the real provider on first use.
  if (env.MCP_OAUTH_PURGE_API) {
    if (typeof env.MCP_OAUTH_PURGE_API.listUserGrants !== "function" ||
        typeof env.MCP_OAUTH_PURGE_API.revokeGrant !== "function") {
      throw new Error("mcp_oauth_purge_unavailable");
    }
    return {
      async listUserGrants(userId, options) {
        const listed = await env.MCP_OAUTH_PURGE_API.listUserGrants(userId, options);
        // The real SDK performs one KV list plus one KV get per returned grant.
        claimKvOperation(budget, 1 + (Array.isArray(listed?.items) ? listed.items.length : 0));
        return listed;
      },
      async revokeGrant(grantId, userId) {
        // The injected fixture has no KV calls to intercept. A real provider
        // revocation is measured precisely by the namespace proxy below.
        claimKvOperation(budget, 2);
        return env.MCP_OAUTH_PURGE_API.revokeGrant(grantId, userId);
      },
    };
  }
  const { createMcpOAuthAuthorizationServer } = await import("./mcp-oauth-server.js");
  const boundedKv = new Proxy(env.OAUTH_KV, {
    get(target, property) {
      const value = Reflect.get(target, property);
      if (typeof value !== "function") return value;
      return (...args) => {
        claimKvOperation(budget);
        return value.apply(target, args);
      };
    },
  });
  return createMcpOAuthAuthorizationServer(env).getOAuthApi({ ...env, OAUTH_KV: boundedKv });
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
  const budget = { used: 0 };
  const oauth = await oauthGrantApi(env, budget);
  if (connectionId !== null && await hasColumn(env, "mcp_oauth_connections", "oauth_grant_id")) {
    const row = await env.cybermeters_db.prepare(
      "SELECT oauth_grant_id FROM mcp_oauth_connections WHERE id = ? AND user_id = ? LIMIT 1",
    ).bind(connectionId, userId).first();
    if (row?.oauth_grant_id != null) {
      if (!/^[A-Za-z0-9_-]{16}$/.test(row.oauth_grant_id)) {
        throw new Error("mcp_oauth_purge_unavailable");
      }
      // A connection created by this provider owns exactly one stable grant.
      // The SDK contract confirms revokeGrant deletes its token keys first and
      // the grant key last. Any interrupted call leaves D1 revoked and retries.
      await oauth.revokeGrant(row.oauth_grant_id, userId);
      return { revoked: 1, kv_operations: budget.used };
    }
  }
  let revoked = 0;
  // Verify after deletion. Cursor exhaustion and errors stop the D1 hard purge.
  for (let sweep = 0; sweep < 3; sweep++) {
    let cursor;
    let matches = 0;
    let complete = false;
    for (let page = 0; page < MAX_KV_PAGES_PER_SWEEP; page++) {
      const listed = await oauth.listUserGrants(userId, { limit: KV_GRANT_PAGE_SIZE, cursor });
      if (!Array.isArray(listed?.items) || listed.items.length > KV_GRANT_PAGE_SIZE) {
        throw new Error("mcp_oauth_purge_unavailable");
      }
      const selected = listed.items.filter((grant) =>
        connectionId === null || grant.metadata?.connectionId === connectionId);
      for (const grant of selected) {
        await oauth.revokeGrant(grant.id, userId);
        matches++;
        revoked++;
      }
      cursor = listed.cursor;
      if (!cursor) { complete = true; break; }
    }
    if (!complete) throw new Error("mcp_oauth_purge_incomplete");
    if (matches === 0) return { revoked, kv_operations: budget.used };
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

/** Security lifecycle fence. D1 status changes first, before eventual KV
 * cleanup, so no old access token can read during a KV outage. */
export async function revokeMcpOAuthUserConnections(env, userId) {
  if (!env?.cybermeters_db || !USER_RE.test(userId ?? "")) throw new Error("mcp_oauth_revoke_unavailable");
  if (!(await hasTable(env, "mcp_oauth_connections"))) return { revoked: 0 };
  const result = await env.cybermeters_db.prepare(
    `UPDATE mcp_oauth_connections SET status = 'revoked',
      revoked_at = COALESCE(revoked_at, datetime('now'))
      WHERE user_id = ? AND status = 'active'`,
  ).bind(userId).run();
  // Migration 124's trigger queues every revoked row. One bounded cleanup is
  // attempted now; the hourly retry drains the rest without blocking account
  // security changes or leaving an active D1 grant.
  await drainRevokedMcpOAuthGrantBacklog(env).catch(() => {});
  return { revoked: Number(result?.meta?.changes ?? result?.changes ?? 0) };
}

async function revokeWorkspaceConnections(env, workspaceId, userId = null) {
  if (!env?.cybermeters_db || !USER_RE.test(workspaceId ?? "") ||
      (userId !== null && !USER_RE.test(userId))) throw new Error("mcp_oauth_revoke_unavailable");
  const statement = await prepareMcpOAuthWorkspaceRevocation(env, workspaceId, userId);
  if (!statement) return { revoked: 0 };
  const result = await statement.run();
  await drainRevokedMcpOAuthGrantBacklog(env).catch(() => {});
  return { revoked: Number(result?.meta?.changes ?? result?.changes ?? 0) };
}

// The delete-request route puts this prepared fence in the same D1 batch as
// soft deletion and the purge request. The revocation trigger queues KV cleanup;
// the caller drains it only after that batch commits.
export async function prepareMcpOAuthWorkspaceRevocation(env, workspaceId, userId = null) {
  if (!env?.cybermeters_db || !USER_RE.test(workspaceId ?? "") ||
      (userId !== null && !USER_RE.test(userId))) throw new Error("mcp_oauth_revoke_unavailable");
  if (!(await hasTable(env, "mcp_oauth_connections"))) return null;
  const selectedTable = await hasTable(env, "mcp_oauth_connection_workspaces");
  const predicate = selectedTable ? `workspace_id = ? OR EXISTS (
    SELECT 1 FROM mcp_oauth_connection_workspaces selected
     WHERE selected.connection_id = mcp_oauth_connections.id AND selected.workspace_id = ?)` : `workspace_id = ?`;
  const userFilter = userId === null ? "" : " AND user_id = ?";
  const bound = [...(selectedTable ? [workspaceId, workspaceId] : [workspaceId]),
    ...(userId === null ? [] : [userId])];
  // One D1 statement fences every affected connection, regardless of count.
  // Migration 124's trigger makes each status change a durable cleanup item.
  return env.cybermeters_db.prepare(
    `UPDATE mcp_oauth_connections SET status = 'revoked',
      revoked_at = COALESCE(revoked_at, datetime('now'))
      WHERE (${predicate})${userFilter} AND status = 'active'`,
  ).bind(...bound);
}

export async function revokeMcpOAuthUserWorkspaceConnections(env, userId, workspaceId) {
  return revokeWorkspaceConnections(env, workspaceId, userId);
}

export async function revokeMcpOAuthWorkspaceConnections(env, workspaceId) {
  return revokeWorkspaceConnections(env, workspaceId);
}

/** Process one persistent cleanup item. The D1 status is already revoked;
 * an outage or operation cap leaves the item pending for the next hourly tick.
 * Selection rotates failed items so one problematic grant cannot starve others. */
export async function drainRevokedMcpOAuthGrantBacklog(env) {
  if (!env?.cybermeters_db || !(await hasTable(env, "mcp_oauth_connections")) ||
      !(await hasColumn(env, "mcp_oauth_connections", "kv_cleanup_pending"))) {
    return { processed: 0, pending: false };
  }
  const row = await env.cybermeters_db.prepare(
    `SELECT id, user_id FROM mcp_oauth_connections
      WHERE status = 'revoked' AND kv_cleanup_pending = 1
      ORDER BY COALESCE(kv_cleanup_attempted_at, ''), id LIMIT 1`,
  ).bind().first();
  if (!row) return { processed: 0, pending: false };
  await env.cybermeters_db.prepare(
    `UPDATE mcp_oauth_connections SET kv_cleanup_attempted_at = datetime('now')
      WHERE id = ? AND status = 'revoked' AND kv_cleanup_pending = 1`,
  ).bind(row.id).run();
  await revokeMcpOAuthConnectionGrantsForPurge(env, row.user_id, row.id);
  const completed = await env.cybermeters_db.prepare(
    `UPDATE mcp_oauth_connections SET kv_cleanup_pending = 0
      WHERE id = ? AND status = 'revoked' AND kv_cleanup_pending = 1`,
  ).bind(row.id).run();
  if (Number(completed?.meta?.changes ?? completed?.changes ?? 0) !== 1) {
    throw new Error("mcp_oauth_purge_incomplete");
  }
  return { processed: 1, pending: true };
}

/** Daily bounded cleanup of refresh-use hashes after their grant lifetime.
 * A backlog is reported to cron telemetry and drained on later ticks. */
export async function purgeExpiredMcpOAuthRefreshUses(env, nowIso, options = {}) {
  const time = Date.parse(nowIso);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== nowIso ||
      !env?.cybermeters_db) throw new Error("mcp_oauth_refresh_cleanup_unavailable");
  const batchSize = options.batchSize ?? MCP_OAUTH_REFRESH_RETENTION_BATCH_SIZE;
  const maxBatches = options.maxBatches ?? MCP_OAUTH_REFRESH_RETENTION_MAX_BATCHES;
  if (!Number.isInteger(batchSize) || batchSize < 1 ||
      batchSize > MCP_OAUTH_REFRESH_RETENTION_BATCH_SIZE ||
      !Number.isInteger(maxBatches) || maxBatches < 1 ||
      maxBatches > MCP_OAUTH_REFRESH_RETENTION_MAX_BATCHES) {
    throw new Error("mcp_oauth_refresh_cleanup_unavailable");
  }
  if (!(await hasTable(env, "mcp_oauth_refresh_uses"))) return { deleted: 0, pending: false };
  let deleted = 0;
  for (let batch = 0; batch < maxBatches; batch++) {
    const result = await env.cybermeters_db.prepare(
      `DELETE FROM mcp_oauth_refresh_uses WHERE rowid IN (
         SELECT rowid FROM mcp_oauth_refresh_uses
          WHERE expires_at < ? ORDER BY expires_at, rowid LIMIT ?)`,
    ).bind(nowIso, batchSize).run();
    const changes = Number(result?.meta?.changes ?? result?.changes);
    if (!Number.isInteger(changes) || changes < 0 || changes > batchSize) {
      throw new Error("mcp_oauth_refresh_cleanup_unavailable");
    }
    deleted += changes;
    if (changes < batchSize) return { deleted, pending: false };
  }
  const pending = Boolean(await env.cybermeters_db.prepare(
    "SELECT 1 FROM mcp_oauth_refresh_uses WHERE expires_at < ? LIMIT 1",
  ).bind(nowIso).first());
  if (pending) console.warn("[mcp-oauth-refresh-cleanup-backlog]", JSON.stringify({ deleted }));
  return { deleted, pending };
}
