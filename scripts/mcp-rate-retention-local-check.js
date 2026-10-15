#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import { cleanupExpiredMcpRateLimits,
  MCP_RATE_RETENTION_BATCH_SIZE, MCP_RATE_RETENTION_MAX_BATCHES,
} from "../workers/scan-api/src/cron/mcp-rate-retention.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const now = "2026-10-15T02:00:00.000Z";

function fixture() {
  const db = new DatabaseSync(":memory:");
  db.exec(fs.readFileSync(path.join(root, "database/migrations/026-api-rate-limits.sql"), "utf8"));
  db.exec(fs.readFileSync(path.join(root, "database/migrations/123-mcp-rate-retention-index.sql"), "utf8"));
  const env = { cybermeters_db: { prepare(sql) { return { bind(...args) {
    const statement = db.prepare(sql);
    return {
      run: async () => ({ meta: { changes: statement.run(...args).changes } }),
      first: async () => statement.get(...args) ?? null,
    };
  } }; } } };
  return { db, env };
}
function seed(db, entries) {
  const insert = db.prepare(`INSERT INTO api_rate_limits
    (id, scope, scope_id, action, window_start, window_seconds)
    VALUES (?, 'test', 'test', ?, ?, ?)`);
  for (const [id, action, windowStart, windowSeconds] of entries) {
    insert.run(id, action, windowStart, windowSeconds);
  }
}
function ids(db) {
  return db.prepare("SELECT id FROM api_rate_limits ORDER BY id").all().map((row) => row.id);
}

{
  const { db, env } = fixture();
  db.exec(fs.readFileSync(path.join(root, "database/migrations/123-mcp-rate-retention-index.sql"), "utf8"));
  const plan = db.prepare(`EXPLAIN QUERY PLAN SELECT rowid FROM api_rate_limits
    WHERE action GLOB 'mcp_*' AND window_seconds BETWEEN 1 AND 86400
      AND window_start < ? ORDER BY window_start, rowid LIMIT ?`)
    .all("2026-10-13T02:00:00.000Z", 250);
  assert.ok(plan.some((row) => String(row.detail).includes("idx_api_rate_limits_mcp_retention")));
  seed(db, [
    ["expired_authorize", "mcp_authorize_start", "2026-10-12T01:00:00.000Z", 60],
    ["expired_token", "mcp_token_exchange", "2026-10-12T01:00:00.000Z", 60],
    ["expired_dcr", "mcp_dcr_register", "2026-10-12T01:00:00.000Z", 3600],
    ["fresh_mcp", "mcp_customer_read", "2026-10-14T01:00:00.000Z", 60],
    ["boundary_mcp", "mcp_read", "2026-10-13T02:00:00.000Z", 60],
    ["long_mcp", "mcp_future", "2026-10-12T01:00:00.000Z", 172800],
    ["other_action", "login", "2026-10-12T01:00:00.000Z", 60],
    ["similar_prefix", "mcpXlogin", "2026-10-12T01:00:00.000Z", 60],
  ]);
  assert.deepEqual(await cleanupExpiredMcpRateLimits(env, now), { deleted: 3, pending: false });
  assert.deepEqual(ids(db), ["boundary_mcp", "fresh_mcp", "long_mcp", "other_action", "similar_prefix"]);
  assert.deepEqual(await cleanupExpiredMcpRateLimits(env, now), { deleted: 0, pending: false });
  db.close();
}

{
  const { db, env } = fixture();
  seed(db, Array.from({ length: 5 }, (_, n) =>
    [`old_${n}`, "mcp_token_exchange", "2026-10-01T00:00:00.000Z", 60]));
  const originalWarn = console.warn;
  const warnings = [];
  console.warn = (...parts) => warnings.push(parts);
  try {
    assert.deepEqual(await cleanupExpiredMcpRateLimits(env, now,
      { batchSize: 2, maxBatches: 2 }), { deleted: 4, pending: true });
  } finally { console.warn = originalWarn; }
  assert.deepEqual(ids(db), ["old_4"]);
  assert.equal(warnings[0]?.[0], "[mcp-rate-retention-backlog]");
  assert.deepEqual(await cleanupExpiredMcpRateLimits(env, now,
    { batchSize: 2, maxBatches: 2 }), { deleted: 1, pending: false });
  db.close();
}

{
  const { db, env } = fixture();
  assert.equal(MCP_RATE_RETENTION_BATCH_SIZE * MCP_RATE_RETENTION_MAX_BATCHES, 5000);
  await assert.rejects(cleanupExpiredMcpRateLimits(env, "invalid"), /Invalid MCP rate retention time/);
  await assert.rejects(cleanupExpiredMcpRateLimits(env, now, { batchSize: 251 }),
    /Invalid MCP rate retention batch bound/);
  await assert.rejects(cleanupExpiredMcpRateLimits({}, now), /MCP rate database unavailable/);
  await assert.rejects(cleanupExpiredMcpRateLimits({ cybermeters_db: {
    prepare: () => ({ bind: () => ({ run: async () => { throw new Error("D1 down"); } }) }),
  } }, now), /D1 down/);
  db.close();
}
console.log("PASS MCP rate retention: only expired mcp_ actions, bounded deletion, indexed query and failures");
