#!/usr/bin/env node
// Launch reliability fixtures: failed deletion enqueue, scheduled-query errors,
// purge head-of-line blocking, and global rate-limit storage failure.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const source = (...parts) => pathToFileURL(path.join(root, "workers/scan-api/src", ...parts)).href;
const { workspacesCoreRoutes } = await import(source("routes/workspaces-core.js"));
const { runScheduled, HOURLY_CRON } = await import(source("cron/scheduled.js"));
const { computeOpsHealth } = await import(source("lib/ops-health.js"));
const { consumeApiRateLimit } = await import(source("lib/rate-limit.js"));
const worker = await import(source("index.js"));

let passed = 0, failed = 0;
function ok(name, condition) {
  if (condition) passed++;
  else { failed++; console.error(`FAIL ${name}`); }
}
function dbFixture() {
  const db = new DatabaseSync(":memory:");
  const apply = (file) => { try { db.exec(fs.readFileSync(file, "utf8")); } catch { /* existing migration convergence */ } };
  apply(path.join(root, "database/schema.sql"));
  for (const file of fs.readdirSync(path.join(root, "database/migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database/migrations", file));
  }
  db.exec("PRAGMA foreign_keys = ON");
  return db;
}
function d1(db, fault = () => null) {
  const statement = (sql, args = []) => {
    const check = () => { const error = fault(sql, args); if (error) throw error; };
    return {
      sql, args,
      bind: (...values) => statement(sql, values),
      first: async () => { check(); return db.prepare(sql).get(...args) ?? null; },
      all: async () => { check(); return { results: db.prepare(sql).all(...args) }; },
      run: async () => { check(); const result = db.prepare(sql).run(...args); return { success: true, meta: { changes: result.changes } }; },
    };
  };
  return {
    prepare: (sql) => statement(sql),
    async batch(statements) {
      db.exec("BEGIN");
      try {
        const results = [];
        for (const stmt of statements) results.push(await stmt.run());
        db.exec("COMMIT");
        return results;
      } catch (error) { db.exec("ROLLBACK"); throw error; }
    },
  };
}
const seedUser = (db, id) => db.prepare("INSERT INTO users(id,email,name,plan,status,email_verified) VALUES (?,?,?,?,?,1)")
  .run(id, `${id}@example.test`, id, "free", "active");
const seedWorkspace = (db, id, userId, deletedAt = null) => db.prepare("INSERT INTO workspaces(id,name,owner_user_id,deleted_at) VALUES (?,?,?,?)")
  .run(id, id, userId, deletedAt);

// CM-P1-002: a D1 insert failure must roll back the already prepared soft
// delete, schedule disable and asset archive, and the customer can retry.
{
  const db = dbFixture();
  seedUser(db, "owner"); seedWorkspace(db, "ws_delete", "owner");
  db.prepare("INSERT INTO domains(id,user_id,domain) VALUES ('domain_delete','owner','example.test')").run();
  db.prepare("INSERT INTO scheduled_scans(id,domain,frequency,enabled,workspace_id) VALUES ('schedule_delete','example.test','daily',1,'ws_delete')").run();
  db.prepare("INSERT INTO workspace_assets(id,workspace_id,domain_id,hostname,status,first_seen,last_seen,created_at,updated_at) VALUES ('asset_delete','ws_delete','domain_delete','example.test','active',datetime('now'),datetime('now'),datetime('now'),datetime('now'))").run();
  const connectionId = "mcpconn_11111111-1111-4111-8111-111111111111";
  db.prepare("INSERT INTO mcp_oauth_connections(id,user_id,client_id,resource,workspace_id,portfolio_read,granted_scopes) VALUES (?,?,?,?,?,0,?)")
    .run(connectionId, "owner", "fixture-client", "https://api.example/mcp", "ws_delete", '["mcp:read"]');
  let failInsert = true;
  let kvDeletes = 0;
  let grantPresent = true;
  const env = {
    cybermeters_db: d1(db, (sql) => failInsert && /INSERT INTO deletion_requests/i.test(sql) ? new Error("queue unavailable") : null),
    OAUTH_KV: { async delete() { kvDeletes++; } },
    MCP_OAUTH_PURGE_API: {
      async listUserGrants() {
        return { items: grantPresent ? [{ id: "grant-fixture", userId: "owner", metadata: { connectionId } }] : [] };
      },
      async revokeGrant() { kvDeletes++; grantPresent = false; },
    },
  };
  const request = new Request("https://api.example/api/workspaces/ws_delete/delete-request", { method: "POST" });
  const route = () => workspacesCoreRoutes({
    request, url: new URL(request.url), env, ctx: { waitUntil() {} },
    json: (body, status = 200) => Response.json(body, { status }),
    requireAuth: async () => ({ id: "owner" }),
    requireWorkspaceRole: async () => ({ role: "owner" }),
    DELETION_PURGE_WINDOW_DAYS: 30,
  });
  const failedResponse = await route();
  ok("CM-P1-002 failed enqueue returns retryable error", failedResponse.status === 503);
  ok("CM-P1-002 failed enqueue leaves workspace visible", db.prepare("SELECT deleted_at FROM workspaces WHERE id='ws_delete'").get().deleted_at === null);
  ok("CM-P1-002 failed enqueue leaves monitoring and assets active",
    db.prepare("SELECT enabled FROM scheduled_scans WHERE id='schedule_delete'").get().enabled === 1 &&
    db.prepare("SELECT status FROM workspace_assets WHERE id='asset_delete'").get().status === "active");
  ok("CM-P1-002 failed enqueue leaves no pending request", db.prepare("SELECT COUNT(*) c FROM deletion_requests WHERE workspace_id='ws_delete'").get().c === 0);
  ok("CM-P1-002 failed enqueue leaves OAuth access and grant untouched",
    db.prepare("SELECT status,kv_cleanup_pending FROM mcp_oauth_connections WHERE id=?").get(connectionId).status === "active" &&
    db.prepare("SELECT kv_cleanup_pending FROM mcp_oauth_connections WHERE id=?").get(connectionId).kv_cleanup_pending === 0 && kvDeletes === 0 && grantPresent);
  failInsert = false;
  const retry = await route();
  ok("CM-P1-002 retry succeeds with both states committed", retry.status === 200 &&
    db.prepare("SELECT deleted_at FROM workspaces WHERE id='ws_delete'").get().deleted_at !== null &&
    db.prepare("SELECT COUNT(*) c FROM deletion_requests WHERE workspace_id='ws_delete' AND status='pending'").get().c === 1);
  ok("CM-P1-002 successful delete revokes OAuth access and drains grant",
    db.prepare("SELECT status,kv_cleanup_pending FROM mcp_oauth_connections WHERE id=?").get(connectionId).status === "revoked" &&
    db.prepare("SELECT kv_cleanup_pending FROM mcp_oauth_connections WHERE id=?").get(connectionId).kv_cleanup_pending === 0 &&
    kvDeletes === 1 && !grantPresent);
}

// CM-P1-001: classify only the absent scheduled_scans table as missing;
// other failures must reach cron telemetry and durable ops health.
for (const [kind, message, expectedStatus, expectCronError] of [
  ["query", "D1 query unavailable", "error", true],
  ["missing", "no such table: scheduled_scans", "table_missing", false],
]) {
  const db = dbFixture();
  const env = { cybermeters_db: d1(db, (sql) => /ROW_NUMBER\(\) OVER/.test(sql) ? new Error(message) : null) };
  const errors = [], originalError = console.error;
  console.error = (...args) => errors.push(args.join(" "));
  const pending = [];
  let otherTasks = 0;
  const tasks = new Proxy({}, { get: () => async () => { otherTasks++; } });
  try {
    await runScheduled({ cron: HOURLY_CRON }, env, { waitUntil: (promise) => pending.push(promise) }, tasks);
    await Promise.all(pending);
  } finally { console.error = originalError; }
  const event = db.prepare("SELECT status FROM operational_events WHERE event_type='scheduled_scan_query' ORDER BY created_at DESC LIMIT 1").get();
  const health = await computeOpsHealth(env);
  ok(`CM-P1-001 ${kind} has distinct durable outcome`, event?.status === expectedStatus);
  ok(`CM-P1-001 ${kind} reaches ops health`, health.signals.find((s) => s.key === "scheduled_scan_query")?.breached === true && health.healthy === false);
  ok(`CM-P1-001 ${kind} cron error classification`, errors.some((line) => line.includes('"task":"scheduled_scan_dispatch"')) === expectCronError);
  ok(`CM-P1-001 ${kind} does not stop other jobs`, otherTasks > 0);
}

{
  const db = dbFixture();
  let queryFailure = false;
  const env = { cybermeters_db: d1(db, (sql) => queryFailure && /ROW_NUMBER\(\) OVER/.test(sql) ? new Error("query interrupted") : null) };
  const tasks = new Proxy({}, { get: () => async () => {} });
  const RealDate = Date;
  class FixedDate extends RealDate {
    constructor(...args) { super(...(args.length ? args : ["2026-10-16T13:00:00.000Z"])); }
    static now() { return Date.parse("2026-10-16T13:00:00.000Z"); }
  }
  const originalError = console.error;
  console.error = () => {};
  globalThis.Date = FixedDate;
  try {
    for (const fails of [false, true, false]) {
      queryFailure = fails;
      const pending = [];
      await runScheduled({ cron: HOURLY_CRON }, env, { waitUntil: (promise) => pending.push(promise) }, tasks);
      await Promise.all(pending);
    }
  } finally { globalThis.Date = RealDate; console.error = originalError; }
  const rows = db.prepare("SELECT status FROM operational_events WHERE event_type='scheduled_scan_query' ORDER BY rowid").all();
  const health = await computeOpsHealth(env);
  ok("CM-P1-001 same-minute retries record each outcome", rows.length === 3 && rows.map((r) => r.status).join(",") === "ok,error,ok");
  ok("CM-P1-001 later success does not erase recent failure from ops health",
    health.signals.find((s) => s.key === "scheduled_scan_query")?.count === 1 && health.healthy === false);
}

// CM-P1-005: ten old bad requests are deferred, then the healthy eleventh
// request is reached. The first bad request grows its wait on its next attempt.
{
  const db = dbFixture();
  const reports = { async delete(key) { if (key === "reports/failing.pdf") throw new Error("R2 unavailable"); },
    async head() { return null; }, async get() { return null; }, async list() { return { objects: [] }; } };
  const env = { cybermeters_db: d1(db), cybermeters_reports: reports };
  for (let i = 0; i < 11; i++) {
    const user = `purge_user_${i}`, ws = `purge_ws_${i}`, req = `purge_req_${i}`;
    seedUser(db, user); seedWorkspace(db, ws, user, "2026-01-01T00:00:00.000Z");
    db.prepare("INSERT INTO deletion_requests(id,request_type,user_id,workspace_id,requested_by,status,created_at) VALUES (?,?,?,?,?,'pending',?)")
      .run(req, "workspace", user, ws, user, new Date(Date.now() - (80 - i) * 86400000).toISOString());
    if (i < 10) db.prepare("INSERT INTO workspace_reports(id,workspace_id,report_type,status,report_key) VALUES (?,?,?,?,?)")
      .run(`report_${i}`, ws, "manual", "completed", "reports/failing.pdf");
  }
  const originalError = console.error; console.error = () => {};
  try { for (let tick = 0; tick < 6; tick++) await worker.processDeletionRequests(env); }
  finally { console.error = originalError; }
  const bad = db.prepare("SELECT attempt_count,next_attempt_at,status FROM deletion_requests WHERE id='purge_req_0'").get();
  const good = db.prepare("SELECT status FROM deletion_requests WHERE id='purge_req_10'").get();
  ok("CM-P1-005 failed request is retryable with a future attempt", bad?.status === "purging" && bad?.attempt_count === 1 && Date.parse(bad?.next_attempt_at) > Date.now());
  ok("CM-P1-005 healthy request behind ten failures completes", good?.status === "completed");
  seedUser(db, "purge_user_11"); seedWorkspace(db, "purge_ws_11", "purge_user_11", "2026-01-01T00:00:00.000Z");
  db.prepare("INSERT INTO deletion_requests(id,request_type,user_id,workspace_id,requested_by,status,created_at) VALUES (?,?,?,?,?,'pending',?)")
    .run("purge_req_11", "workspace", "purge_user_11", "purge_ws_11", "purge_user_11", new Date(Date.now() - 60 * 86400000).toISOString());
  db.prepare("UPDATE deletion_requests SET updated_at = datetime('now','-2 hours') WHERE id LIKE 'purge_req_%' AND status='purging'").run();
  const quietError = console.error; console.error = () => {};
  try { await worker.processDeletionRequests(env); } finally { console.error = quietError; }
  ok("CM-P1-005 retry delay excludes lease-expired failures from the next healthy turn",
    db.prepare("SELECT status FROM deletion_requests WHERE id='purge_req_11'").get()?.status === "completed");
  const firstWait = Date.parse(bad?.next_attempt_at) - Date.now();
  db.prepare("UPDATE deletion_requests SET next_attempt_at = datetime('now','-1 minute'), updated_at = datetime('now','-2 hours') WHERE id='purge_req_0'").run();
  const originalError2 = console.error; console.error = () => {};
  try { await worker.processDeletionRequests(env); } finally { console.error = originalError2; }
  const retried = db.prepare("SELECT attempt_count,next_attempt_at FROM deletion_requests WHERE id='purge_req_0'").get();
  ok("CM-P1-005 repeated failure increases wait", retried?.attempt_count === 2 && Date.parse(retried?.next_attempt_at) - Date.now() > firstWait + 30 * 60000);
}

// CM-P1-007: the coarse guard closes on D1 failure; callers that did not ask
// for failClosed retain their previous login and scan limiter behaviour.
{
  const db = dbFixture();
  const unavailable = d1(db, (sql) => /api_rate_limits/i.test(sql) ? new Error("D1 unavailable") : null);
  const env = { cybermeters_db: unavailable };
  const response = await worker.default.fetch(new Request("https://api.example/api/unknown", {
    headers: { "CF-Connecting-IP": "192.0.2.1" },
  }), env, { waitUntil() {} });
  const body = await response.json();
  ok("CM-P1-007 global guard closes on storage failure", response.status === 503 && body.code === "rate_limit_unavailable");
  const scopes = [{ scope: "ip", scope_id: "fixture" }];
  const login = await consumeApiRateLimit(env, scopes, "login", 5, 300);
  const scan = await consumeApiRateLimit(env, scopes, "scan_start", 5, 300);
  ok("CM-P1-007 existing login and scan limiter fallback stays unchanged", login === null && scan === null);
}

console.log(`Launch reliability fixtures: ${passed}/${passed + failed} passed`);
if (failed) process.exit(1);
