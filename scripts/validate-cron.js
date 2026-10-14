#!/usr/bin/env node
//
// Cron orchestration regression: runScheduled must dispatch every due scheduled
// scan, run the always-on maintenance tasks every hour, fire the daily-gated
// tasks ONLY at their UTC hour (report_retention @02:00, ops_health @08:00), and
// isolate failures so one throwing task never aborts the others. Drives the real
// runScheduled with an injected task registry + a real in-memory SQLite. The UTC
// hour is controlled by stubbing Date. Requires Node 24+ (node:sqlite). CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const {
  runScheduled, runBoundedPool, SCHEDULED_SCAN_CONCURRENCY, SCHEDULED_SCAN_MAX_PER_TICK,
  HOURLY_CRON, DISPATCH_CRON, DISPATCH_TICK_MS, nextDispatchTickIso, retryAtFor, LONG_FAILING_RETRY_MS,
} = await import(
  pathToFileURL(path.join(root, "workers", "scan-api", "src", "cron", "scheduled.js")).href
);

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

// ── Real schema + one DUE scheduled scan (enabled, next_run_at NULL) ─────────
function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  try { db.prepare("INSERT INTO scheduled_scans (id, domain, enabled, next_run_at) VALUES ('sched_test','example.com',1,NULL)").run(); } catch { /* */ }
  return db;
}
function makeD1(db) {
  const wrap = (sql, args) => ({
    first: async () => db.prepare(sql).get(...args) ?? null,
    all: async () => ({ results: db.prepare(sql).all(...args) }),
    run: async () => { const r = db.prepare(sql).run(...args); return { meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
}

// Task registry: every task records that it was called; `throwers` names those
// that should reject (to prove isolation).
function makeTasks(calls, throwers = new Set()) {
  const rec = (name, fn) => async (...args) => {
    calls[name] = (calls[name] || 0) + 1;
    if (throwers.has(name)) throw new Error(`${name} boom`);
    return fn ? fn(...args) : undefined;
  };
  return {
    triggerScheduledScan: rec("triggerScheduledScan", (s) => { calls.lastSchedule = s; }),
    generateScheduledReports: rec("generateScheduledReports"),
    processScheduledReports: rec("processScheduledReports"),
    runHostedDnsVerificationSweep: rec("runHostedDnsVerificationSweep"),
    runBrandTakedownFollowupSweep: rec("runBrandTakedownFollowupSweep"),
    cleanupExpiredReports: rec("cleanupExpiredReports"),
    opsHealthHeartbeat: rec("opsHealthHeartbeat"),
    processDeletionRequests: rec("processDeletionRequests"),
    retryFailedLifecycleEmails: rec("retryFailedLifecycleEmails"),
    retryFailedAssetAlerts: rec("retryFailedAssetAlerts"),
    retryPendingDomainVerifications: rec("retryPendingDomainVerifications"),
  };
}

// Run runScheduled at a fixed UTC hour, awaiting all ctx.waitUntil promises so
// the call flags are settled before we assert.
async function runAtHour(hourUTC, { throwers } = {}) {
  const db = buildDb();
  const env = { cybermeters_db: makeD1(db) };
  const calls = {};
  const tasks = makeTasks(calls, throwers);
  const promises = [];
  const ctx = { waitUntil: (p) => promises.push(Promise.resolve(p).catch(() => {})) };

  const RealDate = Date;
  const fixed = new RealDate(RealDate.UTC(2026, 0, 5, hourUTC, 30, 0)); // Mon Jan 5 2026, hh:30
  const freeCutoff = new RealDate(fixed.getTime() - 25 * 60 * 60 * 1000).toISOString();
  const globalCutoff = new RealDate(fixed.getTime() - (24 * 60 * 60 + 300) * 1000).toISOString();
  const rows = [
    ["old_ip", "free_scan", 3600, new RealDate(fixed.getTime() - 26 * 60 * 60 * 1000).toISOString()],
    ["old_domain", "free_scan_domain", 3600, new RealDate(fixed.getTime() - 26 * 60 * 60 * 1000).toISOString()],
    ["old_global", "free_scan_global", 3600, new RealDate(fixed.getTime() - 26 * 60 * 60 * 1000).toISOString()],
    ["old_global_read", "global_read", 300, new RealDate(fixed.getTime() - 25 * 60 * 60 * 1000).toISOString()],
    ["old_global_write", "global_write", 300, new RealDate(fixed.getTime() - 25 * 60 * 60 * 1000).toISOString()],
    ["fresh_free", "free_scan", 3600, new RealDate(fixed.getTime() - 60 * 60 * 1000).toISOString()],
    ["fresh_global_write", "global_write", 300, new RealDate(fixed.getTime() - 60 * 60 * 1000).toISOString()],
    ["boundary_free", "free_scan", 3600, freeCutoff],
    ["boundary_global_write", "global_write", 300, globalCutoff],
    ["old_account", "login", 3600, new RealDate(fixed.getTime() - 25 * 60 * 60 * 1000).toISOString()],
    ["old_long_window", "free_scan", 86400, new RealDate(fixed.getTime() - 25 * 60 * 60 * 1000).toISOString()],
  ];
  const insertLimit = db.prepare("INSERT INTO api_rate_limits (id, scope, scope_id, action, window_start, window_seconds, request_count) VALUES (?, 'ip', 'test', ?, ?, ?, 1)");
  for (const [id, action, seconds, start] of rows) insertLimit.run(id, action, start, seconds);
  class FakeDate extends RealDate {
    constructor(...args) { if (args.length === 0) super(fixed.getTime()); else super(...args); }
    static now() { return fixed.getTime(); }
  }
  globalThis.Date = FakeDate;
  try {
    await runScheduled({}, env, ctx, tasks);
    await Promise.all(promises);
  } finally {
    globalThis.Date = RealDate;
  }
  calls.rateLimitIds = db.prepare("SELECT id FROM api_rate_limits ORDER BY id").all().map((row) => row.id);
  return calls;
}

// ── Always-on tasks fire every hour + the due scan dispatches ────────────────
const ALWAYS = ["generateScheduledReports", "processScheduledReports", "runHostedDnsVerificationSweep",
  "runBrandTakedownFollowupSweep",
  "processDeletionRequests", "retryFailedLifecycleEmails", "retryFailedAssetAlerts", "retryPendingDomainVerifications"];

const mid = await runAtHour(13); // 13:00 UTC — no daily gate active
for (const t of ALWAYS) ok(`13:00 runs always-on task: ${t}`, mid[t] === 1);
ok("13:00 dispatches the due scheduled scan", mid.triggerScheduledScan === 1);
ok("13:00 passes the seeded schedule to triggerScheduledScan", mid.lastSchedule?.id === "sched_test");
ok("13:00 does NOT run report_retention (hour!=2)", !mid.cleanupExpiredReports);
ok("13:00 leaves old free-check counters for daily cleanup", mid.rateLimitIds.includes("old_ip"));
ok("13:00 does NOT run ops_health (hour!=8)", !mid.opsHealthHeartbeat);

// ── Daily-gated tasks fire only at their hour ────────────────────────────────
const h2 = await runAtHour(2);
ok("02:00 runs report_retention", h2.cleanupExpiredReports === 1);
ok("02:00 removes expired free-check and API-wide counters", ["old_ip", "old_domain", "old_global", "old_global_read", "old_global_write"].every((id) => !h2.rateLimitIds.includes(id)));
ok("02:00 retains current, boundary, account and long-window counters", ["fresh_free", "fresh_global_write", "boundary_free", "boundary_global_write", "old_account", "old_long_window"].every((id) => h2.rateLimitIds.includes(id)));
ok("02:00 does NOT run ops_health", !h2.opsHealthHeartbeat);

const h8 = await runAtHour(8);
ok("08:00 runs ops_health heartbeat", h8.opsHealthHeartbeat === 1);
ok("08:00 does NOT run report_retention", !h8.cleanupExpiredReports);

// ── Isolation: a throwing task never aborts the others ───────────────────────
const iso = await runAtHour(13, { throwers: new Set(["processDeletionRequests"]) });
ok("isolation: the throwing task was still invoked", iso.processDeletionRequests === 1);
for (const t of ALWAYS.filter((t) => t !== "processDeletionRequests")) {
  ok(`isolation: ${t} still runs despite deletion_purge throwing`, iso[t] === 1);
}
ok("isolation: scheduled scan still dispatched", iso.triggerScheduledScan === 1);

// ── Scheduled-scan burst cap: runBoundedPool never exceeds the concurrency bound ─
{
  ok("per-tick cap is a sane bound", SCHEDULED_SCAN_MAX_PER_TICK >= SCHEDULED_SCAN_CONCURRENCY && SCHEDULED_SCAN_MAX_PER_TICK <= 50);
  let inFlight = 0, peak = 0, done = 0;
  const items = Array.from({ length: 10 }, (_, i) => i); // 10 due scans > concurrency
  let release;
  const gate = new Promise((r) => { release = r; });
  const run = runBoundedPool(items, SCHEDULED_SCAN_CONCURRENCY, async () => {
    inFlight++; peak = Math.max(peak, inFlight);
    await gate;            // hold every started worker so peak reflects true concurrency
    inFlight--; done++;
  });
  await Promise.resolve(); await Promise.resolve(); // let workers start & saturate the pool
  ok("bounded pool never exceeds the concurrency cap", peak <= SCHEDULED_SCAN_CONCURRENCY && peak > 0);
  release();
  await run;
  ok("bounded pool processes every item", done === items.length);
}

// A per-item failure never aborts the rest of the pool (isolation preserved).
{
  let completed = 0;
  await runBoundedPool([1, 2, 3, 4], 2, async (n) => { if (n === 2) throw new Error("boom"); completed++; });
  ok("bounded pool isolates a failing item (others still run)", completed === 3);
}

// ── Fair, unblockable scheduling ─────────────────────────────────────────────
// Runs the real runScheduled against the real schema with a trigger that does
// what the real one does to the schedule row: a schedule it starts gets its
// next run stamped; one it skips (not eligible, already scanning) is left alone.
async function tickAt(db, atMs, { cron = HOURLY_CRON, skip = () => false, calls = {}, env: extra = { SCHEDULED_DISPATCH_MODE: "queue" } } = {}) {
  const env = { cybermeters_db: makeD1(db), ...extra };
  const started = [];
  const tasks = {
    ...makeTasks(calls),
    triggerScheduledScan: async (schedule) => {
      calls.triggerScheduledScan = (calls.triggerScheduledScan || 0) + 1;
      if (skip(schedule)) return;
      started.push(schedule.id);
      db.prepare("UPDATE scheduled_scans SET last_run_at = ?, next_run_at = ? WHERE id = ?")
        .run(new Date(atMs).toISOString(), new Date(atMs + 864e5).toISOString(), schedule.id);
    },
  };
  const promises = [];
  const ctx = { waitUntil: (p) => promises.push(Promise.resolve(p).catch(() => {})) };
  const RealDate = Date;
  class FakeDate extends RealDate {
    constructor(...args) { if (args.length === 0) super(atMs); else super(...args); }
    static now() { return atMs; }
  }
  globalThis.Date = FakeDate;
  try { await runScheduled({ cron }, env, ctx, tasks); await Promise.all(promises); } finally { globalThis.Date = RealDate; }
  return started;
}
function scheduleDb() {
  const db = buildDb();
  db.exec("DELETE FROM scheduled_scans");
  return db;
}
const T0 = Date.UTC(2026, 0, 6, 2, 0, 0);
// A daily schedule that last started a day before it fell due, unless told otherwise.
const seedSchedule = (db, id, owner, dueMs, { lastRunMs = dueMs - 864e5 } = {}) => {
  db.prepare("INSERT OR IGNORE INTO workspaces (id, name, owner_user_id) VALUES (?, ?, ?)").run(`ws_${owner}`, owner, owner);
  db.prepare("INSERT INTO scheduled_scans (id, domain, enabled, next_run_at, last_run_at, workspace_id, frequency, created_at) VALUES (?, ?, 1, ?, ?, ?, 'daily', ?)")
    .run(id, `${id}.example.com`, new Date(dueMs).toISOString(), lastRunMs == null ? null : new Date(lastRunMs).toISOString(), `ws_${owner}`, new Date(T0 - 30 * 864e5).toISOString());
};

// One customer with many schedules due first never takes every place.
{
  const db = scheduleDb();
  for (let i = 0; i < 30; i++) seedSchedule(db, `big_${i}`, "u_big", T0 - 3_600_000 + i);
  for (let i = 0; i < 5; i++) seedSchedule(db, `small_${i}`, `u_small_${i}`, T0 - 60_000 + i);
  const started = await tickAt(db, T0);
  ok("fair: a tick starts no more than its cap", started.length === SCHEDULED_SCAN_MAX_PER_TICK);
  ok("fair: every customer with a due schedule gets a turn in the same tick, behind one big customer's older backlog",
    [0, 1, 2, 3, 4].every((i) => started.includes(`small_${i}`)));
  ok("fair: the big customer's remaining turns go oldest first",
    started.filter((id) => id.startsWith("big_")).join() === Array.from({ length: SCHEDULED_SCAN_MAX_PER_TICK - 5 }, (_, i) => `big_${i}`).join());
}

// Schedules that can no longer start (verification removed, trial ended) never
// hold the places of schedules that can.
{
  const db = scheduleDb();
  const stuck = Array.from({ length: SCHEDULED_SCAN_MAX_PER_TICK + 3 }, (_, i) => `stuck_${i}`);
  // Last started four days ago: waiting on their customers.
  stuck.forEach((id, i) => seedSchedule(db, id, `u_stuck_${i}`, T0 - 3 * 864e5 + i, { lastRunMs: T0 - 4 * 864e5 }));
  seedSchedule(db, "runnable", "u_runnable", T0 - 60_000);
  seedSchedule(db, "busy", "u_busy", T0 - 120_000);
  const skip = (schedule) => schedule.id.startsWith("stuck_") || schedule.id === "busy";
  const first = await tickAt(db, T0, { skip });
  const firstStuck = db.prepare("SELECT next_run_at FROM scheduled_scans WHERE id = 'stuck_0'").get().next_run_at;
  const second = await tickAt(db, T0 + DISPATCH_TICK_MS, { cron: DISPATCH_CRON, skip });
  const busyRetry = db.prepare("SELECT next_run_at FROM scheduled_scans WHERE id = 'busy'").get().next_run_at;
  ok("unblockable: a schedule that has not started for two days is moved back an hour, not left first in line",
    Date.parse(firstStuck) === T0 + LONG_FAILING_RETRY_MS && firstStuck === retryAtFor({ frequency: "daily", last_run_at: new Date(T0 - 4 * 864e5).toISOString() }, T0), firstStuck);
  ok("unblockable: a schedule that ran yesterday and could not start now (its domain already scanning) is retried on the next dispatch tick",
    busyRetry === nextDispatchTickIso(T0 + DISPATCH_TICK_MS) && Date.parse(busyRetry) === T0 + 2 * DISPATCH_TICK_MS, busyRetry);
  ok("unblockable: a runnable schedule behind a full tick of stuck ones starts on the next tick",
    first.length === 0 && second.includes("runnable"), JSON.stringify({ first, second }));
  ok("unblockable: a stuck schedule stays enabled and due — it is retried, never dropped",
    db.prepare("SELECT COUNT(*) AS n FROM scheduled_scans WHERE id LIKE 'stuck_%' AND enabled = 1").get().n === stuck.length);
  const stamped = db.prepare("SELECT next_run_at FROM scheduled_scans WHERE id = 'runnable'").get().next_run_at;
  ok("unblockable: a schedule the trigger started keeps the next run it was stamped with",
    stamped === new Date(T0 + DISPATCH_TICK_MS + 864e5).toISOString(), stamped);
}

// The dispatch ticks between the hours dispatch scheduled scans and nothing else.
{
  const db = scheduleDb();
  seedSchedule(db, "due", "u_due", T0 - 60_000);
  const calls = {};
  const started = await tickAt(db, T0 + DISPATCH_TICK_MS, { cron: DISPATCH_CRON, calls });
  ok("dispatch tick: dispatches the due schedule", calls.triggerScheduledScan === 1 && started.includes("due"));
  ok("dispatch tick: runs no other cron task", ALWAYS.every((t) => !calls[t]) && !calls.cleanupExpiredReports && !calls.opsHealthHeartbeat);
  // Outside queue mode a pick runs the scan inline for minutes; a dispatch tick
  // could pick a schedule the previous tick has not stamped yet.
  const legacyCalls = {};
  const legacyDb = scheduleDb();
  seedSchedule(legacyDb, "due", "u_due", T0 - 60_000);
  await tickAt(legacyDb, T0 + DISPATCH_TICK_MS, { cron: DISPATCH_CRON, calls: legacyCalls, env: {} });
  const hourly = await tickAt(legacyDb, T0 + 6 * DISPATCH_TICK_MS, { calls: {}, env: {} });
  ok("dispatch tick: outside queue mode it dispatches nothing; the hourly tick still does",
    !legacyCalls.triggerScheduledScan && hourly.includes("due"), JSON.stringify({ legacyCalls, hourly }));
  ok("next dispatch tick is the next ten-minute boundary",
    nextDispatchTickIso(Date.UTC(2026, 0, 6, 10, 7, 30)) === "2026-01-06T10:10:00.000Z" &&
      nextDispatchTickIso(Date.UTC(2026, 0, 6, 10, 50, 0)) === "2026-01-06T11:00:00.000Z");
  const toml = fs.readFileSync(path.join(root, "workers", "scan-api", "wrangler.toml"), "utf8");
  ok("the Worker's cron triggers are exactly the hourly tick and the dispatch ticks the code expects",
    toml.includes(`crons = ["${HOURLY_CRON}", "${DISPATCH_CRON}"]`) &&
      DISPATCH_CRON.split(" ")[0].split(",").map(Number).every((m) => m % (DISPATCH_TICK_MS / 60_000) === 0));
}

console.log(`\nCron orchestration: ${pass}/${pass + fail} passed`);
if (fail) { console.error("cron validation FAILED"); process.exit(1); }
console.log("cron validation passed");
