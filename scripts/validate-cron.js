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
const { runScheduled } = await import(
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
    runDmarcAlertsSweep: rec("runDmarcAlertsSweep"),
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
  return calls;
}

// ── Always-on tasks fire every hour + the due scan dispatches ────────────────
const ALWAYS = ["generateScheduledReports", "processScheduledReports", "runHostedDnsVerificationSweep",
  "runDmarcAlertsSweep",
  "processDeletionRequests", "retryFailedLifecycleEmails", "retryFailedAssetAlerts", "retryPendingDomainVerifications"];

const mid = await runAtHour(13); // 13:00 UTC — no daily gate active
for (const t of ALWAYS) ok(`13:00 runs always-on task: ${t}`, mid[t] === 1);
ok("13:00 dispatches the due scheduled scan", mid.triggerScheduledScan === 1);
ok("13:00 passes the seeded schedule to triggerScheduledScan", mid.lastSchedule?.id === "sched_test");
ok("13:00 does NOT run report_retention (hour!=2)", !mid.cleanupExpiredReports);
ok("13:00 does NOT run ops_health (hour!=8)", !mid.opsHealthHeartbeat);

// ── Daily-gated tasks fire only at their hour ────────────────────────────────
const h2 = await runAtHour(2);
ok("02:00 runs report_retention", h2.cleanupExpiredReports === 1);
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

console.log(`\nCron orchestration: ${pass}/${pass + fail} passed`);
if (fail) { console.error("cron validation FAILED"); process.exit(1); }
console.log("cron validation passed");
