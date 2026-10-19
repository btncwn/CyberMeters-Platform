#!/usr/bin/env node
//
// Bounded scheduled-report generation — behavioural proof that the hourly executive
// report cron is bounded, deterministic, idempotent, retry-safe, fair, entitlement-
// aware and observable. Drives the real exported runBoundedScheduledReports /
// selectDueReportJobs / checkScheduledReportEligibility (engines/scheduled-reports.js)
// against a node:sqlite DB, with the PDF/R2 generator injected so no artifacts are
// built. Node 24+. CI-blocking.
import crypto from "node:crypto";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const { splitStatements, isToleratedStatement } = await import(pathToFileURL(path.join(root, "scripts", "lib", "migration-apply-tolerated.js")).href);
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

// ── M. Report-ready notification names the period in the customer's words ────
{
  const { reportReadyMessage, reportPeriodPhrase } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "plan-usage.js")).href);
  // A report made on Monday 6 Jul covers the week that just ended (29 Jun – 5 Jul).
  // This pin read "6–12 Jul" until 19 Oct 2026, labelling the week the report was
  // made in — the defect migration 128 corrects.
  const weekly = reportReadyMessage(WEEKLY.report_type, WEEKLY.report_period);
  ok("M: the scheduled weekly report reads as a date range in sentence case, never an ISO week key",
    weekly === "Your weekly executive report for 29 Jun – 5 Jul is ready to download." && !/W\d{2}|period/.test(weekly), weekly);
  ok("M: week ranges cross months and years honestly",
    reportPeriodPhrase("weekly_executive", "2026-W42") === "12–18 Oct" &&
    reportPeriodPhrase("weekly_executive", "2026-W40") === "28 Sep – 4 Oct" &&
    reportPeriodPhrase("weekly_executive", "2026-W01") === "29 Dec 2025 – 4 Jan 2026");
  ok("M: monthly, quarterly and keyed periods",
    reportReadyMessage("monthly_executive", "2026-10") === "Your monthly executive report for October 2026 is ready to download." &&
    reportReadyMessage("quarterly_executive", "2026-Q4") === "Your quarterly executive report for Q4 2026 is ready to download." &&
    reportReadyMessage("manual", "manual-20261019101500") === "Your executive report is ready to download." &&
    reportReadyMessage("scan_snapshot", "scan-v2-scan_1-snap_1-abc") === "Your single-scan report is ready to download.");
}

// ── N. A scheduled report covers and names the period that just ended ────────
// The clock is frozen at the Monday the defect was seen; every other date here is
// a fixed calendar input to a pure period function, never compared with today.
const NOW = "2026-10-19T00:00:00.000Z";
{
  const { coveredReportPeriod, reportReadyMessage } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "plan-usage.js")).href);
  const mon = getDueReportTypes(NOW);
  ok("N: Monday 19 Oct 2026 → the weekly report is week 42 (12–18 Oct), not week 43",
    mon.length === 1 && mon[0].report_period === "2026-W42" &&
    reportReadyMessage("weekly_executive", mon[0].report_period) === "Your weekly executive report for 12–18 Oct is ready to download.", JSON.stringify(mon));
  const first = getDueReportTypes("2026-11-01T00:00:00.000Z");
  ok("N: 1 Nov 2026 → the monthly report is October 2026",
    first.some((d) => d.report_type === "monthly_executive" && d.report_period === "2026-10"), JSON.stringify(first));
  ok("N: a customer schedule on another weekday covers the last complete week, across the year end",
    coveredReportPeriod("weekly_executive", "2026-10-21T09:00:00Z") === "2026-W42" &&
    coveredReportPeriod("weekly_executive", "2026-10-25T23:59:00Z") === "2026-W42" &&
    coveredReportPeriod("weekly_executive", "2027-01-04T00:00:00Z") === "2026-W53" &&
    coveredReportPeriod("monthly_executive", "2027-01-01T00:00:00Z") === "2026-12");
  ok("N: quarterly and manual periods are not affected",
    coveredReportPeriod("quarterly_executive", "2026-10-10T00:00:00Z") === null && coveredReportPeriod("manual", "2026-10-10T00:00:00Z") === null);
}

// ── O. A skipped period is finished, like a completed one ────────────────────
{
  const db = freshDb(); addWs(db, "ws0"); addWs(db, "ws1");
  addReport(db, "ws0", WEEKLY.report_type, WEEKLY.report_period, "skipped");
  const jobs = await selectDueReportJobs({ cybermeters_db: makeD1(db) }, getDueReportTypes(MONDAY));
  ok("O: a period skipped for want of an assessment is not selected again", jobs.map((j) => j.workspace_id).join() === "ws1");
  const s = await runBoundedScheduledReports(MONDAY, { cybermeters_db: makeD1(db) }, {
    generate: async () => ({ status: "skipped", skip_reason: "no_assessment", claimed: true }),
    checkEligibility: okElig, batchLimit: 10, log: silent });
  ok("O: a skipped job is counted as skipped, never as generated", s.jobs_skipped_no_assessment === 1 && s.reports_generated === 0, JSON.stringify(s));
}

// ── O2. What the schedule list tells the customer ───────────────────────────
{
  const { describeScheduledReportOutcome } = mod;
  ok("O2: before its first run a schedule shows no outcome", describeScheduledReportOutcome({ last_outcome: null }) === null);
  const failed = describeScheduledReportOutcome({ last_outcome: "failed", last_outcome_reason: "plan_inactive", last_outcome_at: "2026-10-19T00:00:00Z", consecutive_failures: 3 });
  ok("O2: a failure carries its plain words, time and attempt count",
    failed.status === "failed" && failed.title === "An active plan is needed" && /no active plan/.test(failed.message) && failed.attempts === 3 && failed.at === "2026-10-19T00:00:00Z");
  const odd = describeScheduledReportOutcome({ last_outcome: "failed", last_outcome_reason: "D1_ERROR: boom", last_outcome_at: "2026-10-19T00:00:00Z" });
  ok("O2: an unrecognised stored reason reads as the generic failure, never as stored text",
    odd.reason === "generation_failed" && !JSON.stringify(odd).includes("D1_ERROR"));
  const sk = describeScheduledReportOutcome({ last_outcome: "skipped", last_outcome_reason: "no_assessment", last_outcome_at: "2026-10-19T00:00:00Z" });
  ok("O2: a skipped run says no scan has completed yet", sk.status === "skipped" && /no scan has completed/.test(sk.message) && !("attempts" in sk));
}

// ── P. The real generator never makes or announces a report without an assessment ──
{
  const fs = await import("node:fs");
  const { generateWorkspaceExecutiveReport, getWorkspaceReportStorageMetrics } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "plan-usage.js")).href);
  const { presentReportRow } = mod;
  const full = () => {
    const db = new DatabaseSync(":memory:");
    db.exec(fs.readFileSync(path.join(root, "database", "schema.sql"), "utf8"));
    for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
      const raw = fs.readFileSync(path.join(root, "database", "migrations", f), "utf8");
      const sha = crypto.createHash("sha256").update(raw).digest("hex");
      for (const stmt of splitStatements(raw)) {
        try { db.exec(stmt); }
        catch (e) { if (!isToleratedStatement(f, sha, stmt, e.message)) throw e; }
      }
    }
    db.exec("PRAGMA foreign_keys = OFF");
    db.prepare("INSERT INTO users (id, email, email_verified) VALUES ('u_p','p@example.co.uk',1)").run();
    db.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES ('ws_p','Empty','u_p')").run();
    db.prepare("INSERT INTO subscriptions (id, owner_user_id, workspace_id, plan, subscription_status, current_period_end) VALUES ('sub_p','u_p','ws_p','business','active', datetime('now','+30 day'))").run();
    return db;
  };
  const puts = [];
  const r2 = { put: async (k) => { puts.push(k); }, get: async () => null, head: async () => null, delete: async () => {} };
  const db = full();
  const env = { cybermeters_db: makeD1(db), cybermeters_reports: r2 };
  const res = await generateWorkspaceExecutiveReport("ws_p", env, { report_type: "weekly_executive", report_period: "2026-W42", scheduled: true });
  const row = db.prepare("SELECT status, metadata_json FROM workspace_reports WHERE workspace_id = 'ws_p'").get();
  ok("P: no completed scan → the scheduled report is skipped with its reason, not built",
    res.status === "skipped" && res.skip_reason === "no_assessment" && row?.status === "skipped" &&
    JSON.parse(row.metadata_json).skip_reason === "no_assessment", JSON.stringify({ res, row }));
  ok("P: nothing is stored in R2 and no 'report ready' notification is sent",
    puts.length === 0 && db.prepare("SELECT COUNT(*) c FROM notification_events WHERE workspace_id = 'ws_p' AND type = 'report_generated'").get().c === 0);
  const shown = presentReportRow(db.prepare("SELECT id, status, metadata_json FROM workspace_reports WHERE workspace_id = 'ws_p'").get());
  ok("P: the customer sees why in plain words", /no scan has completed in this workspace yet/.test(shown.status_reason?.message ?? ""), JSON.stringify(shown));
  const again = await generateWorkspaceExecutiveReport("ws_p", env, { report_type: "weekly_executive", report_period: "2026-W42", scheduled: true });
  ok("P: a later run for the same period does not try again", again.claimed === false &&
    db.prepare("SELECT COUNT(*) c FROM workspace_reports WHERE workspace_id = 'ws_p'").get().c === 1);
  const storage = await getWorkspaceReportStorageMetrics("ws_p", env);
  ok("P: a skipped report is not counted as a stored PDF", storage.reports_count === 0 && storage.storage_bytes === 0, JSON.stringify(storage));
  ok("P: error text kept for operations never reaches the customer",
    presentReportRow({ status: "failed", metadata_json: JSON.stringify({ error: "D1_ERROR: no such column: x" }) }).metadata_json === null &&
    presentReportRow({ status: "completed", metadata_json: JSON.stringify({ snapshots: [1] }) }).metadata_json === JSON.stringify({ snapshots: [1] }));

  // Snapshot rows that exist but cannot be read are a failure (retried), not "no assessment".
  const db2 = full();
  db2.prepare("INSERT INTO scan_report_snapshots (id, workspace_id, domain_id, scan_id, status, assessed_at, r2_key, checksum_sha256, snapshot_schema_version, resolver_version) VALUES ('snap_x','ws_p','dom_x','scan_x','completed','2026-10-18T10:00:00Z','missing/key.json','00','1','1')").run();
  let threw = false;
  try { await generateWorkspaceExecutiveReport("ws_p", { cybermeters_db: makeD1(db2), cybermeters_reports: r2 }, { report_type: "weekly_executive", report_period: "2026-W42", scheduled: true }); }
  catch { threw = true; }
  ok("P: an unreadable assessment fails the run (retryable) rather than being reported as missing",
    threw && db2.prepare("SELECT status FROM workspace_reports WHERE workspace_id = 'ws_p'").get()?.status === "failed" && puts.length === 0);

  // ── Q. Migration 128 relabels earlier reports to the period they cover ──────
  const db3 = full();
  const ins = db3.prepare("INSERT INTO workspace_reports (id, workspace_id, report_type, report_period, report_key, status, created_at, metadata_json) VALUES (?,?,?,?,?,?,?,?)");
  // The production shape on 19 Oct 2026: one workspace, consecutive Monday reports.
  const rows = [
    ["q38", "weekly_executive", "2026-W38", "completed", "2026-09-14T00:00:56.057Z", JSON.stringify({ snapshots: [] }), "2026-W37"],
    ["q39", "weekly_executive", "2026-W39", "failed", "2026-09-21T00:01:30.274Z", JSON.stringify({ error: "x" }), "2026-W38"],
    ["q40", "weekly_executive", "2026-W40", "completed", "2026-09-28T00:00:43.580Z", null, "2026-W39"],
    ["q41", "weekly_executive", "2026-W41", "completed", "2026-10-05T00:00:28.022Z", null, "2026-W40"],
    ["q42", "weekly_executive", "2026-W42", "completed", "2026-10-12T00:01:01.068Z", null, "2026-W41"],
    ["q43", "weekly_executive", "2026-W43", "completed", "2026-10-19T00:00:50.164Z", null, "2026-W42"],
    ["qm",  "monthly_executive", "2026-10", "completed", "2026-10-01T00:00:13.303Z", null, "2026-09"],
    ["qq",  "quarterly_executive", "2026-Q4", "completed", "2026-10-10T22:04:36.285Z", null, "2026-Q4"],
    ["qx",  "weekly_executive", "2026-W30", "completed", "2026-08-03T09:00:00.000Z", null, "2026-W30"], // made after its week: untouched
  ];
  for (const [id, ty, p, st, at, meta] of rows) ins.run(id, "ws_p", ty, p, "reports/k/" + id, st, at, meta);
  const before = new Map(db3.prepare("SELECT id, report_period, report_key, metadata_json FROM workspace_reports").all().map((r) => [r.id, r]));
  const m128 = fs.readFileSync(path.join(root, "database", "migrations", "128-scheduled-report-period-relabel.sql"), "utf8");
  let applied = true;
  try { db3.exec(m128); db3.exec(m128); } catch (e) { applied = false; console.log("128 apply error:", e.message); }
  ok("Q: 128 applies to a workspace with consecutive weekly reports, and re-running it is a no-op", applied);
  const after = new Map(db3.prepare("SELECT id, report_period, report_key, metadata_json FROM workspace_reports").all().map((r) => [r.id, r]));
  ok("Q: each report now names the period it covers", rows.every(([id, , , , , , want]) => after.get(id)?.report_period === want),
    JSON.stringify([...after.values()].map((r) => [r.id, r.report_period])));
  ok("Q: every changed row keeps its original label; unchanged rows and every R2 key are untouched",
    rows.every(([id, , p, , , meta, want]) => {
      const a = after.get(id), b = before.get(id);
      if (a.report_key !== b.report_key) return false;
      if (want === p) return a.metadata_json === b.metadata_json;
      const m = JSON.parse(a.metadata_json);
      return m.original_report_period === p && (!meta || Object.keys(JSON.parse(meta)).every((k) => k in m));
    }));
  const next = await selectDueReportJobs({ cybermeters_db: makeD1(db3) }, getDueReportTypes("2026-10-26T00:00:00.000Z"));
  ok("Q: next Monday's week-43 report is due again — the mislabelled week-43 row no longer holds its slot",
    next.some((j) => j.workspace_id === "ws_p" && j.report_period === "2026-W43"), JSON.stringify(next));
  const rollback = m128.split("-- Rollback")[1].split("\n").filter((l) => l.startsWith("--   ")).map((l) => l.slice(5)).join("\n");
  db3.exec(rollback);
  ok("Q: the rollback in the migration header restores every row exactly",
    db3.prepare("SELECT id, report_period, report_key, metadata_json FROM workspace_reports").all()
      .every((r) => { const b = before.get(r.id); return r.report_period === b.report_period && r.metadata_json === b.metadata_json; }));
}

// ── Observability: summary carries every required field ──────────────────────
{
  const db = freshDb(); addWs(db, "ws0");
  const g = makeGen(db);
  const s = await runBoundedScheduledReports(MONDAY, { cybermeters_db: makeD1(db) }, { generate: g.generate, checkEligibility: okElig, batchLimit: 5, log: silent });
  const fields = ["due_types","jobs_due","jobs_processed","reports_generated","jobs_deferred_batch","jobs_skipped_entitlement","jobs_skipped_state","jobs_skipped_no_assessment","failures","batch_limit","duration_ms"];
  ok("Observability: summary contains all required fields", fields.every(f => f in s));
}

console.log(`\nbounded-scheduled-reports: ${pass} passed, ${fail} failed`);
if (fail) { console.error("bounded-scheduled-reports validation FAILED"); process.exit(1); }
console.log("bounded-scheduled-reports validation passed");
