#!/usr/bin/env node
// Hermetic proof that spent OAuth refresh hashes expire in bounded batches.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import {
  MCP_OAUTH_REFRESH_RETENTION_BATCH_SIZE,
  MCP_OAUTH_REFRESH_RETENTION_MAX_BATCHES,
  purgeExpiredMcpOAuthRefreshUses,
} from "../workers/scan-api/src/routes/mcp-oauth-purge.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const now = "2026-10-15T02:00:00.000Z";

function wrap(db) {
  return { cybermeters_db: { prepare(sql) {
    return { bind(...args) {
      const statement = db.prepare(sql);
      return {
        first: async () => statement.get(...args) ?? null,
        run: async () => ({ meta: { changes: statement.run(...args).changes } }),
      };
    } };
  } } };
}

function fixture() {
  const db = new DatabaseSync(":memory:");
  db.exec(`CREATE TABLE users(id TEXT PRIMARY KEY);
    CREATE TABLE workspaces(id TEXT PRIMARY KEY);
    CREATE TABLE user_sessions(id TEXT PRIMARY KEY);`);
  for (const file of ["121-mcp-oauth.sql", "124-mcp-oauth-selected-workspaces.sql"]) {
    db.exec(fs.readFileSync(path.join(root, "database/migrations", file), "utf8"));
  }
  db.exec("PRAGMA foreign_keys = ON");
  db.exec(`INSERT INTO users(id) VALUES ('u1');
    INSERT INTO workspaces(id) VALUES ('w1');
    INSERT INTO mcp_oauth_connections
      (id,user_id,client_id,resource,workspace_id,portfolio_read,granted_scopes)
      VALUES ('mcpconn_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','u1','client',
        'https://mcp.cybermeters.com/mcp','w1',0,'["mcp:read"]');`);
  const insert = db.prepare(`INSERT INTO mcp_oauth_refresh_uses
    (token_hash, connection_id, expires_at) VALUES (?, ?, ?)`);
  const add = (id, expiry) => insert.run(id,
    "mcpconn_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", expiry);
  const ids = () => db.prepare("SELECT token_hash FROM mcp_oauth_refresh_uses ORDER BY token_hash")
    .all().map((row) => row.token_hash);
  return { db, env: wrap(db), add, ids };
}

{
  const { db, env, add, ids } = fixture();
  assert.ok(db.prepare(`SELECT name FROM sqlite_master WHERE type='index'
    AND name='idx_mcp_oauth_refresh_uses_expiry'`).get(),
  "Migration 124 must index refresh expiry");
  add("expired_a", "2026-10-14T23:59:59.999Z");
  add("expired_b", "2026-10-01T00:00:00.000Z");
  add("boundary", now);
  add("fresh", "2026-10-16T00:00:00.000Z");
  assert.deepEqual(await purgeExpiredMcpOAuthRefreshUses(env, now),
    { deleted: 2, pending: false });
  assert.deepEqual(ids(), ["boundary", "fresh"]);
  assert.deepEqual(await purgeExpiredMcpOAuthRefreshUses(env, now),
    { deleted: 0, pending: false });
  db.close();
}

{
  const { db, env, add, ids } = fixture();
  for (let n = 0; n < 5; n++) add(`old_${n}`, "2026-10-01T00:00:00.000Z");
  const originalWarn = console.warn;
  const warnings = [];
  console.warn = (...parts) => warnings.push(parts);
  try {
    assert.deepEqual(await purgeExpiredMcpOAuthRefreshUses(env, now,
      { batchSize: 2, maxBatches: 2 }), { deleted: 4, pending: true });
  } finally { console.warn = originalWarn; }
  assert.deepEqual(ids(), ["old_4"]);
  assert.equal(warnings[0]?.[0], "[mcp-oauth-refresh-cleanup-backlog]");
  assert.equal(JSON.stringify(warnings).includes("old_4"), false,
    "backlog telemetry must contain counts only");
  assert.deepEqual(await purgeExpiredMcpOAuthRefreshUses(env, now,
    { batchSize: 2, maxBatches: 2 }), { deleted: 1, pending: false });
  db.close();
}

{
  const db = new DatabaseSync(":memory:");
  assert.deepEqual(await purgeExpiredMcpOAuthRefreshUses(wrap(db), now),
    { deleted: 0, pending: false }, "pre-migration databases remain safe");
  db.close();
}

assert.equal(MCP_OAUTH_REFRESH_RETENTION_BATCH_SIZE *
  MCP_OAUTH_REFRESH_RETENTION_MAX_BATCHES, 5000);
await assert.rejects(purgeExpiredMcpOAuthRefreshUses({}, now),
  /mcp_oauth_refresh_cleanup_unavailable/);
await assert.rejects(purgeExpiredMcpOAuthRefreshUses({ cybermeters_db: {} }, "invalid"),
  /mcp_oauth_refresh_cleanup_unavailable/);
await assert.rejects(purgeExpiredMcpOAuthRefreshUses(wrap(new DatabaseSync(":memory:")), now,
  { batchSize: 251 }), /mcp_oauth_refresh_cleanup_unavailable/);
await assert.rejects(purgeExpiredMcpOAuthRefreshUses({ cybermeters_db: {
  prepare: () => ({ bind: () => ({ first: async () => { throw new Error("D1 down"); } }) }),
} }, now), /D1 down/);
console.log("PASS MCP refresh-use retention: migration index, strict expiry, 5000-row cap, backlog and failures");
