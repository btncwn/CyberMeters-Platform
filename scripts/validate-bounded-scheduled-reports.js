#!/usr/bin/env node
//
// Bounded scheduled-report generation — behavioural proof that the hourly executive
// report cron is bounded, deterministic, idempotent, retry-safe, fair, entitlement-
// aware and observable. Drives the real exported runBoundedScheduledReports /
// selectDueReportJobs / checkScheduledReportEligibility (engines/scheduled-reports.js)
// against a node:sqlite DB, with the PDF/R2 generator injected so no artifacts are
// built. Node 24+. CI-blocking.
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const mod = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "scheduled-reports.js")).href);
const {
  runBoundedScheduledReports, selectDueReportJobs, getDueReportTypes,
  resolveScheduledReportBatchLimit, checkScheduledReportEligibility,
  SCHEDULED_REPORT_BATCH_DEFAULT, SCHEDULED_REPORT_BATCH_MAX,
} = mod;

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };

const MONDAY   = "2026-07-06T10:00:00.000Z"; // Monday, not the 1st → weekly only
const TUESDAY  = "2026-07-07T10:00:00.000Z"; // not Monday, not 1st → no due jobs
const WEEKLY   = getDueReportTypes(MONDAY)[0]; // { report_type:'weekly_executive', report_period }
const nowMonth = new Date().toISOString();     // for quota rows counted "this month"

function makeD1(db) {
  const wrap = (sql, args) => ({
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all:   async () => ({ results: db.prepare(sql).all(...args) }),
    run:   async () => { const r = db.prepare(sql).run(...args); return { meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
}
function freshDb() {
  const db = new DatabaseSync(":memory:");
  db.exec(`
    CREATE TABLE workspaces (id TEXT PRIMARY KEY, owner_user_id TEXT, deleted_at TEXT);
    CREATE TABLE workspace_reports (id TEXT PRIMARY KEY, workspace_id TEXT, report_type TEXT, report_period TEXT, status TEXT, created_at TEXT, deleted_at TEXT);
    CREATE TABLE subscriptions (id TEXT, owner_user_id TEXT, workspace_id TEXT, plan TEXT, status TEXT, subscription_status TEXT, trial_end TEXT, expires_at TEXT, current_period_end TEXT, payment_failed_at TEXT, stripe_subscription_id TEXT, created_at TEXT, updated_at TEXT);
  `);
  return db;
}
const addWs = (db, id, { owner = id + "_owner", deleted = false } = {}) =>
  db.prepare("INSERT INTO workspaces VALUES (?,?,?)").run(id, owner, deleted ? nowMonth : null);
const addSub = (db, owner, plan, status = "active") =>
  db.prepare("INSERT INTO subscriptions (owner_user_id, plan, subscription_status, current_period_end, created_at) VALUES (?,?,?,?,?)")
    .run(owner, plan, status, new Date(Date.now() + 30 * 864e5).toISOString(), nowMonth);
const addReport = (db, wsId, type, period, status) =>
  db.prepare("INSERT INTO workspace_reports (id, workspace_id, report_type, report_period, status, created_at, deleted_at) VALUES (?,?,?,?,?,?,NULL)")
    .run(`rpt_${wsId}_${period}_${status}_${Math.floor(Math.random()*1e9)}`, wsId, type, period, status, nowMonth);

// generator stub: records calls; writes a completed row (mirrors the real generator's
// completed-row claim) so idempotency/next-invocation behaviour is exercised.
function makeGen(db, { throwFor = new Set() } = {}) {
  const calls = [];
  const generate = async (wsId, env, opts) => {
    calls.push({ wsId, ...opts });
    if (throwFor.has(wsId)) throw new Error("simulated generation/R2 failure");
    db.prepare("INSERT INTO workspace_reports (id, workspace_id, report_type, report_period, status, created_at, deleted_at) VALUES (?,?,?,?,?,?,NULL)")
      .run(`rpt_${wsId}_${opts.report_period}_${Math.floor(Math.random()*1e9)}`, wsId, opts.report_type, opts.report_period, "completed", nowMonth);
    return { id: "ok" };
  };
  return { calls, generate };
}
const okElig = async () => ({ ok: true });
const silent = () => {};

// ── batch-limit resolution ───────────────────────────────────────────────────
ok("batch default when unset", resolveScheduledReportBatchLimit({}) === SCHEDULED_REPORT_BATCH_DEFAULT);
ok("batch env override honoured", resolveScheduledReportBatchLimit({ SCHEDULED_REPORT_BATCH_LIMIT: "40" }) === 40);
ok("batch clamped to MAX", resolveScheduledReportBatchLimit({ SCHEDULED_REPORT_BATCH_LIMIT: "9999" }) === SCHEDULED_REPORT_BATCH_MAX);
ok("batch invalid/small falls back to default", resolveScheduledReportBatchLimit({ SCHEDULED_REPORT_BATCH_LIMIT: "0" }) === SCHEDULED_REPORT_BATCH_DEFAULT);

// ── A. No due jobs ─────────────────────────────────────────────────────────
{
  const db = freshDb(); for (let i = 0; i < 3; i++) addWs(db, `ws${i}`);
  const g = makeGen(db);
  const s = await runBoundedScheduledReports(TUESDAY, { cybermeters_db: makeD1(db) }, { generate: g.generate, checkEligibility: okElig, log: silent });
  ok("A: no due jobs → not_due summary, zero work", s.not_due === true && s.jobs_due === 0 && s.reports_generated === 0);
  ok("A: generator never called on a non-report day", g.calls.length === 0);
  ok("A: no report rows written", db.prepare("SELECT COUNT(*) AS n FROM workspace_reports").get().n === 0);
}

// ── B. Jobs below limit → all processed once ─────────────────────────────────
{
  const db = freshDb(); for (let i = 0; i < 3; i++) addWs(db, `ws${i}`);
  const g = makeGen(db);
  const s = await runBoundedScheduledReports(MONDAY, { cybermeters_db: makeD1(db) }, { generate: g.generate, checkEligibility: okElig, batchLimit: 10, log: silent });
  ok("B: all 3 due jobs processed", s.jobs_processed === 3 && s.reports_generated === 3 && s.jobs_deferred_batch === 0);
  ok("B: each workspace generated exactly once", g.calls.length === 3 && new Set(g.calls.map(c => c.wsId)).size === 3);
}

// ── C. Jobs above limit → exactly batch processed, deterministic first batch ──
{
  const db = freshDb(); for (let i = 0; i < 5; i++) addWs(db, `ws${i}`); // ws0..ws4
  const g = makeGen(db);
  const s = await runBoundedScheduledReports(MONDAY, { cybermeters_db: makeD1(db) }, { generate: g.generate, checkEligibility: okElig, batchLimit: 2, log: silent });
  ok("C: exactly batch_limit processed, remainder deferred", s.jobs_processed === 2 && s.reports_generated === 2 && s.jobs_deferred_batch === 3 && s.jobs_due === 5);
  ok("C: deterministic first batch = lowest ids (ws0, ws1)", g.calls.map(c => c.wsId).join(",") === "ws0,ws1");
}

// ── D. Next invocation → deferred processed, completed not regenerated ────────
{
  const db = freshDb(); for (let i = 0; i < 5; i++) addWs(db, `ws${i}`);
  const env = { cybermeters_db: makeD1(db) };
  const g1 = makeGen(db);
  await runBoundedScheduledReports(MONDAY, env, { generate: g1.generate, checkEligibility: okElig, batchLimit: 2, log: silent }); // ws0,ws1 completed
  const g2 = makeGen(db);
  const s2 = await runBoundedScheduledReports(MONDAY, env, { generate: g2.generate, checkEligibility: okElig, batchLimit: 2, log: silent });
  ok("D: next invocation processes the next deferred batch (ws2, ws3)", g2.calls.map(c => c.wsId).join(",") === "ws2,ws3");
  ok("D: already-completed jobs are NOT regenerated", !g2.calls.some(c => c.wsId === "ws0" || c.wsId === "ws1"));
  ok("D: remaining deferred count shrinks", s2.jobs_due === 3 && s2.jobs_deferred_batch === 1);
}

// ── E. Deterministic tie (identical due time) resolves by stable id ──────────
{
  const db = freshDb(); ["ws_c", "ws_a", "ws_b"].forEach(id => addWs(db, id));
  const jobs = await selectDueReportJobs({ cybermeters_db: makeD1(db) }, getDueReportTypes(MONDAY));
  ok("E: identical due timestamp resolves by workspace id ascending",
    jobs.map(j => j.workspace_id).join(",") === "ws_a,ws_b,ws_c");
}

// ── F. Failure isolation → one fails, later jobs still process, stays retryable ─
{
  const db = freshDb(); for (let i = 0; i < 4; i++) addWs(db, `ws${i}`);
  const g = makeGen(db, { throwFor: new Set(["ws1"]) });
  const s = await runBoundedScheduledReports(MONDAY, { cybermeters_db: makeD1(db) }, { generate: g.generate, checkEligibility: okElig, batchLimit: 10, log: silent });
  ok("F: failing job isolated — later jobs still processed", s.reports_generated === 3 && s.failures === 1 && g.calls.length === 4);
  ok("F: failed job left NO completed report (retryable next invocation)",
    db.prepare("SELECT COUNT(*) AS n FROM workspace_reports WHERE workspace_id='ws1' AND status='completed'").get().n === 0);
  ok("F: successful jobs did complete", db.prepare("SELECT COUNT(*) AS n FROM workspace_reports WHERE status='completed'").get().n === 3);
}

// ── F2. Fairness: a persistently-failing job cannot starve fresh workspaces ──
{
  const db = freshDb(); for (let i = 0; i < 4; i++) addWs(db, `ws${i}`);
  // ws0 already has a FAILED attempt → it is "attempted"; fresh ws1..3 must sort first.
  addReport(db, "ws0", WEEKLY.report_type, WEEKLY.report_period, "failed");
  const jobs = await selectDueReportJobs({ cybermeters_db: makeD1(db) }, getDueReportTypes(MONDAY));
  ok("F2: never-attempted workspaces are ordered before a previously-failed one",
    jobs.map(j => j.workspace_id).join(",") === "ws1,ws2,ws3,ws0");
}

// ── G. Overlap/idempotency → two invocations create no duplicate reports ─────
{
  const db = freshDb(); for (let i = 0; i < 3; i++) addWs(db, `ws${i}`);
  const env = { cybermeters_db: makeD1(db) };
  const g = makeGen(db);
  await runBoundedScheduledReports(MONDAY, env, { generate: g.generate, checkEligibility: okElig, batchLimit: 10, log: silent });
  await runBoundedScheduledReports(MONDAY, env, { generate: g.generate, checkEligibility: okElig, batchLimit: 10, log: silent });
  ok("G: second invocation generates nothing (completed rows are the claim)", g.calls.length === 3);
  ok("G: exactly one completed report per workspace (no duplicates)",
    db.prepare("SELECT workspace_id, COUNT(*) AS n FROM workspace_reports WHERE status='completed' GROUP BY workspace_id").all().every(r => r.n === 1));
}

// ── H. Entitlement change → downgraded/cancelled skipped, zero side effects ──
{
  const db = freshDb();
  addWs(db, "ws_paid");      addSub(db, "ws_paid_owner", "starter");           // entitled
  addWs(db, "ws_free");      /* no subscription → free */                      // not entitled
  addWs(db, "ws_cancelled"); addSub(db, "ws_cancelled_owner", "professional", "canceled"); // effective free
  addWs(db, "ws_overquota"); addSub(db, "ws_overquota_owner", "starter");
  for (let i = 0; i < 50; i++) addReport(db, "ws_overquota", "manual", `m${i}`, "completed"); // hit starter 50/mo
  const env = { cybermeters_db: makeD1(db) };
  const g = makeGen(db);
  const s = await runBoundedScheduledReports(MONDAY, env, { generate: g.generate, batchLimit: 10, log: silent }); // REAL eligibility
  const genned = new Set(g.calls.map(c => c.wsId));
  ok("H: entitled paid workspace generated", genned.has("ws_paid"));
  ok("H: free workspace skipped (not entitled), no generation", !genned.has("ws_free"));
  ok("H: cancelled → effective free → skipped", !genned.has("ws_cancelled"));
  ok("H: over-quota workspace skipped", !genned.has("ws_overquota"));
  ok("H: skips counted as entitlement skips", s.jobs_skipped_entitlement === 3);
  ok("H: skipped workspaces created NO report side effect",
    db.prepare("SELECT COUNT(*) AS n FROM workspace_reports WHERE workspace_id IN ('ws_free','ws_cancelled') AND report_type='weekly_executive'").get().n === 0);
}

// ── I. Deleted workspace → skipped safely (not even selected) ────────────────
{
  const db = freshDb(); addWs(db, "ws_live"); addWs(db, "ws_gone", { deleted: true });
  const jobs = await selectDueReportJobs({ cybermeters_db: makeD1(db) }, getDueReportTypes(MONDAY));
  ok("I: soft-deleted workspace is excluded from selection",
    jobs.map(j => j.workspace_id).join(",") === "ws_live");
}

// ── J. R2/generation failure → no completed record; deferred jobs no side effects ─
{
  const db = freshDb(); for (let i = 0; i < 3; i++) addWs(db, `ws${i}`);
  const g = makeGen(db, { throwFor: new Set(["ws0"]) }); // ws0 throws (e.g. R2 put failed)
  const s = await runBoundedScheduledReports(MONDAY, { cybermeters_db: makeD1(db) }, { generate: g.generate, checkEligibility: okElig, batchLimit: 10, log: silent });
  ok("J: R2/generation failure counted, no completed report for it",
    s.failures === 1 && db.prepare("SELECT COUNT(*) AS n FROM workspace_reports WHERE workspace_id='ws0' AND status='completed'").get().n === 0);
}

// ── K. Completed-only dedup → a stale pending/failed row does NOT block retry ─
{
  const db = freshDb(); addWs(db, "ws0");
  addReport(db, "ws0", WEEKLY.report_type, WEEKLY.report_period, "pending"); // crashed mid-generation
  addReport(db, "ws0", WEEKLY.report_type, WEEKLY.report_period, "failed");  // prior failure
  const g = makeGen(db);
  await runBoundedScheduledReports(MONDAY, { cybermeters_db: makeD1(db) }, { generate: g.generate, checkEligibility: okElig, batchLimit: 10, log: silent });
  ok("K: a pending/failed (non-completed) period is retried, not skipped", g.calls.length === 1 && g.calls[0].wsId === "ws0");
}
// K2: a COMPLETED row DOES block (the R2-before-completed contract means a completed
// D1 record always has its artifact; dedup keys on it).
{
  const db = freshDb(); addWs(db, "ws0");
  addReport(db, "ws0", WEEKLY.report_type, WEEKLY.report_period, "completed");
  const g = makeGen(db);
  await runBoundedScheduledReports(MONDAY, { cybermeters_db: makeD1(db) }, { generate: g.generate, checkEligibility: okElig, batchLimit: 10, log: silent });
  ok("K2: a completed period is never regenerated", g.calls.length === 0);
}

// ── L. Generation delegates unchanged → engine does not touch PDF builders ────
{
  const fs = await import("node:fs");
  const src = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "scheduled-reports.js"), "utf8");
  ok("L: engine delegates to generateWorkspaceExecutiveReport (no bespoke PDF/report building)",
    /generateWorkspaceExecutiveReport/.test(src) && !/buildExecutivePdf|collectPdfData|assemblePdf/.test(src));
}

// ── Observability: summary carries every required field ──────────────────────
{
  const db = freshDb(); addWs(db, "ws0");
  const g = makeGen(db);
  const s = await runBoundedScheduledReports(MONDAY, { cybermeters_db: makeD1(db) }, { generate: g.generate, checkEligibility: okElig, batchLimit: 5, log: silent });
  const fields = ["due_types","jobs_due","jobs_processed","reports_generated","jobs_deferred_batch","jobs_skipped_entitlement","jobs_skipped_state","failures","batch_limit","duration_ms"];
  ok("Observability: summary contains all required fields", fields.every(f => f in s));
}

console.log(`\nbounded-scheduled-reports: ${pass} passed, ${fail} failed`);
if (fail) { console.error("bounded-scheduled-reports validation FAILED"); process.exit(1); }
console.log("bounded-scheduled-reports validation passed");
