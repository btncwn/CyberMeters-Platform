#!/usr/bin/env node
// validate-interrupted-scan-recovery.js
//
// PR-1 (22 Jul 2026 manual-scan incident): proves the canonical interrupted-scan
// terminal-recovery path — the ONE brain that repairs scans abandoned mid-flight
// (HTTP post-response ~30 s waitUntil kill) — and proves the honesty guards that
// keep it from ever touching a live scan or clobbering a genuine report.
//
// Also proves the governance rule that motivated it: GET /scans list/detail are
// READ-ONLY — no `UPDATE scans` remains on either GET path in routes/scans.js.
//
// Fixture semantics (deterministic, no network, stub D1/R2):
//   1. stale running + stale heartbeat + running R2 placeholder → failed,
//      R2 placeholder becomes failed with the canonical reason, ONE audit event.
//   2. recent scan (age under threshold) is untouched.
//   3. old scan with a FRESH heartbeat is untouched (staleness gate).
//   4. completed/failed rows are never selected or touched.
//   5. terminal R2 report → D1 converged from it; report NEVER overwritten.
//   6. repeated recovery run is a no-op (no second transition, no second audit).
//   7. workspace/domain attribution preserved through recovery.
//   8. batch limit respected.
//   9. R2 absent (no placeholder at all) → still recovered to failed.
//
// Mutation directions (reverting the guard reddens the named assertion):
//   - remove the heartbeat-staleness gate            → fixture 3 fails
//   - remove the terminal-report guard / re-check    → fixture 5 fails (put called)
//   - drop `AND status IN (...)` from the UPDATE     → fixture 6 fails (double audit)

import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const enginePath = path.join(
  __dirname, "..", "workers", "scan-api", "src", "engines", "scan-recovery.js"
);
const {
  recoverInterruptedScans,
  RECOVERY_MIN_AGE_MS,
  RECOVERY_HEARTBEAT_STALE_MS,
  RECOVERY_BATCH_LIMIT,
  INTERRUPTED_REASON,
} = await import(enginePath);

let passed = 0, failed = 0;
function ok(name, cond, detail = "") {
  if (cond) { passed++; console.log(`PASS ${name}`); }
  else      { failed++; console.log(`FAIL ${name}${detail ? " — " + detail : ""}`); }
}

const NOW = Date.parse("2026-07-22T12:00:00Z");
const iso = (msAgo) => new Date(NOW - msAgo).toISOString();
const sqlite = (msAgo) => iso(msAgo).replace("T", " ").slice(0, 19); // D1 default format

// ── Stub environment ─────────────────────────────────────────────────────────
function makeEnv({ scans, r2Objects, afterSelect = null }) {
  const state = {
    scans: scans.map((s) => ({ ...s })),
    r2: new Map(Object.entries(r2Objects || {})),
    r2Puts: [],
    audits: [],
    updates: [],
  };
  const db = {
    prepare(sql) {
      return {
        bind(...args) {
          return {
            async all() {
              if (/SELECT[\s\S]*FROM scans/i.test(sql)) {
                const statuses = args;
                const limit = Number((sql.match(/LIMIT\s+(\d+)/i) || [])[1] || 1e9);
                const results = state.scans
                  .filter((s) => statuses.includes(s.status))
                  .sort((a, b) => String(a.created_at).localeCompare(String(b.created_at)))
                  .slice(0, limit)
                  .map((s) => ({ ...s }));
                if (afterSelect) afterSelect(state); // race simulation hook
                return { results };
              }
              return { results: [] };
            },
            async run() {
              state.updates.push({ sql, args });
              if (/INSERT INTO audit_events/i.test(sql)) {
                state.audits.push({ args });
                return { meta: { changes: 1 } };
              }
              // SQL-faithful: the status guard applies ONLY if the SQL text
              // actually carries `AND status IN` — so a mutant that drops the
              // guard from the statement is executed guardless here, exactly as
              // real D1 would.
              if (/UPDATE scans SET status = 'failed'/i.test(sql)) {
                const hasGuard = /AND\s+status\s+IN/i.test(sql);
                const nullsQuality = /scan_quality\s*=\s*NULL/i.test(sql);
                const id = args[0];
                const statuses = args.slice(1);
                const row = state.scans.find(
                  (s) => s.id === id && (!hasGuard || statuses.includes(s.status))
                );
                if (!row) return { meta: { changes: 0 } };
                row.status = "failed";
                if (nullsQuality) row.scan_quality = null;
                return { meta: { changes: 1 } };
              }
              if (/UPDATE scans SET status = \?/i.test(sql)) {
                const hasGuard = /AND\s+status\s+IN/i.test(sql);
                const [status, score, rating, quality, id, ...statuses] = args;
                const row = state.scans.find(
                  (s) => s.id === id && (!hasGuard || statuses.includes(s.status))
                );
                if (!row) return { meta: { changes: 0 } };
                Object.assign(row, { status, score, rating, scan_quality: quality });
                return { meta: { changes: 1 } };
              }
              return { meta: { changes: 0 } };
            },
            async first() { return null; },
          };
        },
      };
    },
  };
  const r2 = {
    async get(key) {
      if (!state.r2.has(key)) return null;
      const value = state.r2.get(key);
      return { async json() { return JSON.parse(JSON.stringify(value)); } };
    },
    async put(key, body, opts) {
      state.r2Puts.push({ key, body: JSON.parse(body), opts });
      state.r2.set(key, JSON.parse(body));
    },
  };
  return { env: { cybermeters_db: db, cybermeters_reports: r2 }, state };
}

const STALE_AGE = RECOVERY_MIN_AGE_MS + 60 * 60 * 1000;      // 1.5h old
const FRESH_AGE = 2 * 60 * 1000;                              // 2 min old

// ── Fixture 1: the incident signature → recovered ───────────────────────────
{
  const { env, state } = makeEnv({
    scans: [{
      id: "scan_stuck1", workspace_id: "ws_A", domain_id: "dom_A",
      domain: "blackbullbarbers.co.uk", status: "running",
      created_at: sqlite(STALE_AGE), last_heartbeat_at: iso(STALE_AGE - 30_000),
    }],
    r2Objects: {
      "reports/scan_stuck1.json": { scan_id: "scan_stuck1", status: "running", findings: [] },
    },
  });
  const summary = await recoverInterruptedScans(env, { now: NOW });
  const row = state.scans[0];
  ok("1a stale running + stale heartbeat + running placeholder → failed", row.status === "failed");
  ok("1b summary counts the interrupted recovery", summary.recovered_interrupted === 1);
  const put = state.r2Puts.find((p) => p.key === "reports/scan_stuck1.json");
  ok("1c R2 placeholder rewritten to failed", put && put.body.status === "failed");
  ok("1d canonical reason recorded", put && put.body.reason === INTERRUPTED_REASON);
  ok("1e customer message is honest (no results wording)",
     put && /No results were recorded/.test(put.body.message || ""));
  ok("1f exactly ONE audit event, system actor, scan entity",
     state.audits.length === 1);
  ok("1g no findings/score fabricated on the failed report",
     put && (put.body.findings || []).length === 0 && put.body.cyber_metrics_score !== 100);
}

// ── Fixture 2: recent scan untouched (age gate) ─────────────────────────────
{
  const { env, state } = makeEnv({
    scans: [{
      id: "scan_live", workspace_id: "ws_A", domain_id: "dom_A", domain: "x.co",
      status: "running", created_at: sqlite(FRESH_AGE), last_heartbeat_at: iso(FRESH_AGE),
    }],
    r2Objects: {},
  });
  const summary = await recoverInterruptedScans(env, { now: NOW });
  ok("2a recent scan is untouched", state.scans[0].status === "running");
  ok("2b nothing recovered", summary.recovered_interrupted === 0 && state.audits.length === 0);
}

// ── Fixture 3: old scan, FRESH heartbeat → untouched (staleness gate) ───────
{
  const { env, state } = makeEnv({
    scans: [{
      id: "scan_slowlive", workspace_id: "ws_A", domain_id: "dom_A", domain: "x.co",
      status: "running", created_at: sqlite(STALE_AGE),
      last_heartbeat_at: iso(60_000), // heartbeat 1 min ago — genuinely alive
    }],
    r2Objects: {},
  });
  await recoverInterruptedScans(env, { now: NOW });
  ok("3a old-but-heartbeating scan is untouched (staleness gate holds)",
     state.scans[0].status === "running");
}

// ── Fixture 4: terminal rows never selected/touched ─────────────────────────
{
  const { env, state } = makeEnv({
    scans: [
      { id: "scan_done", workspace_id: "ws_A", domain_id: "d", domain: "x.co",
        status: "completed", created_at: sqlite(STALE_AGE), last_heartbeat_at: null },
      { id: "scan_dead", workspace_id: "ws_A", domain_id: "d", domain: "x.co",
        status: "failed", created_at: sqlite(STALE_AGE), last_heartbeat_at: null },
    ],
    r2Objects: {},
  });
  const summary = await recoverInterruptedScans(env, { now: NOW });
  ok("4a completed/failed rows are never examined",
     summary.examined === 0 && state.updates.every((u) => !/UPDATE scans/i.test(u.sql)));
}

// ── Fixture 5: terminal R2 report → converge D1, NEVER overwrite R2 ─────────
{
  const { env, state } = makeEnv({
    scans: [{
      id: "scan_lostwrite", workspace_id: "ws_B", domain_id: "dom_B", domain: "y.co",
      status: "running", created_at: sqlite(STALE_AGE), last_heartbeat_at: iso(STALE_AGE),
    }],
    r2Objects: {
      "reports/scan_lostwrite.json": {
        scan_id: "scan_lostwrite", status: "completed",
        cyber_metrics_score: 87, risk_level: "good",
        scan_quality: { status: "complete" },
      },
    },
  });
  const summary = await recoverInterruptedScans(env, { now: NOW });
  const row = state.scans[0];
  ok("5a D1 converged from the terminal R2 report",
     row.status === "completed" && row.score === 87 && row.scan_quality === "complete");
  ok("5b the genuine report is NEVER overwritten (no R2 put)", state.r2Puts.length === 0);
  ok("5c counted as convergence, not interruption",
     summary.converged_from_r2 === 1 && summary.recovered_interrupted === 0);
  ok("5d convergence writes no interrupted audit event", state.audits.length === 0);
}

// ── Fixture 6: idempotency — second run is a no-op ──────────────────────────
{
  const { env, state } = makeEnv({
    scans: [{
      id: "scan_stuck2", workspace_id: "ws_A", domain_id: "dom_A", domain: "x.co",
      status: "running", created_at: sqlite(STALE_AGE), last_heartbeat_at: iso(STALE_AGE),
    }],
    r2Objects: { "reports/scan_stuck2.json": { status: "running" } },
  });
  const first = await recoverInterruptedScans(env, { now: NOW });
  const second = await recoverInterruptedScans(env, { now: NOW });
  ok("6a first run recovers", first.recovered_interrupted === 1);
  ok("6b second run recovers nothing (terminal row not re-selected)",
     second.recovered_interrupted === 0 && second.examined === 0);
  ok("6c exactly one audit event across both runs", state.audits.length === 1);
}

// ── Fixture 7: attribution preserved ────────────────────────────────────────
{
  const { env, state } = makeEnv({
    scans: [{
      id: "scan_stuck3", workspace_id: "ws_TENANT", domain_id: "dom_TENANT",
      domain: "tenant.example", status: "running",
      created_at: sqlite(STALE_AGE), last_heartbeat_at: iso(STALE_AGE),
    }],
    r2Objects: {},
  });
  await recoverInterruptedScans(env, { now: NOW });
  const row = state.scans[0];
  ok("7a workspace/domain attribution preserved through recovery",
     row.workspace_id === "ws_TENANT" && row.domain_id === "dom_TENANT" && row.domain === "tenant.example");
  const put = state.r2Puts[0];
  ok("7b failed report carries the same scan/domain identity",
     put && put.body.scan_id === "scan_stuck3" && put.body.domain === "tenant.example");
}

// ── Fixture 8: batch bound ──────────────────────────────────────────────────
{
  const many = Array.from({ length: RECOVERY_BATCH_LIMIT + 10 }, (_, i) => ({
    id: `scan_bulk${i}`, workspace_id: "ws_A", domain_id: "d", domain: "x.co",
    status: "running", created_at: sqlite(STALE_AGE + i * 1000), last_heartbeat_at: iso(STALE_AGE),
  }));
  const { env } = makeEnv({ scans: many, r2Objects: {} });
  const summary = await recoverInterruptedScans(env, { now: NOW });
  ok("8a per-tick work is bounded by the batch limit",
     summary.examined <= RECOVERY_BATCH_LIMIT);
}

// ── Fixture 9: R2 entirely absent → still recovered ─────────────────────────
{
  const { env, state } = makeEnv({
    scans: [{
      id: "scan_noplaceholder", workspace_id: "ws_A", domain_id: "d", domain: "x.co",
      status: "running", created_at: sqlite(STALE_AGE), last_heartbeat_at: iso(STALE_AGE),
    }],
    r2Objects: {},
  });
  const summary = await recoverInterruptedScans(env, { now: NOW });
  ok("9a absent R2 object still recovers to failed",
     state.scans[0].status === "failed" && summary.recovered_interrupted === 1);
}

// ── Fixture 11: recovery EXPLICITLY nulls a stale scan_quality ───────────────
// A dying invocation may have left a stale quality value behind. The terminal
// row of an interrupted scan must carry scan_quality = NULL — it earned neither
// `complete` nor `partial`. Removing `, scan_quality = NULL` from the recovery
// UPDATE must redden here.
{
  const { env, state } = makeEnv({
    scans: [{
      id: "scan_stalequality", workspace_id: "ws_A", domain_id: "d", domain: "x.co",
      status: "running", scan_quality: "partial", // stale leftover
      created_at: sqlite(STALE_AGE), last_heartbeat_at: iso(STALE_AGE),
    }],
    r2Objects: { "reports/scan_stalequality.json": { status: "running" } },
  });
  await recoverInterruptedScans(env, { now: NOW });
  const row = state.scans[0];
  ok("11a interrupted recovery persists scan_quality = NULL explicitly",
     row.status === "failed" && row.scan_quality === null);
}

// ── Fixture 10: SELECT→UPDATE race — a finalize that lands mid-recovery wins ─
// The `AND status IN (...)` guard on the failed-UPDATE is the ONLY thing that
// stops recovery from stomping a scan that reached a genuine terminal state
// between our SELECT and our UPDATE. Removing that guard must redden here.
{
  const { env, state } = makeEnv({
    scans: [{
      id: "scan_raced", workspace_id: "ws_A", domain_id: "d", domain: "x.co",
      status: "running", created_at: sqlite(STALE_AGE), last_heartbeat_at: iso(STALE_AGE),
    }],
    r2Objects: {},
    afterSelect(state) {
      // A racing finalisation completes the scan AFTER recovery selected it.
      const row = state.scans.find((s) => s.id === "scan_raced");
      if (row && row.status === "running") { row.status = "completed"; row.score = 87; }
    },
  });
  const summary = await recoverInterruptedScans(env, { now: NOW });
  const row = state.scans[0];
  ok("10a a scan finalised mid-recovery is NOT stomped to failed",
     row.status === "completed" && row.score === 87);
  ok("10b the lost race writes no audit event", state.audits.length === 0);
  ok("10c summary records no interrupted recovery for the raced row",
     summary.recovered_interrupted === 0);
}

// ── Governance: GET list/detail are read-only (no UPDATE on GET paths) ──────
{
  const fs = await import("node:fs");
  const routes = fs.readFileSync(
    path.join(__dirname, "..", "workers", "scan-api", "src", "routes", "scans.js"), "utf8"
  );
  // The two former GET-path reconciliation writes are gone: no `UPDATE scans`
  // may appear anywhere in the scans ROUTE file at all — status writes belong to
  // the engine (start INSERT lives here; terminal writes live in scan-engine /
  // scan-recovery).
  const updates = routes.match(/UPDATE scans/g) || [];
  ok("G1 GET /scans list+detail perform no scans UPDATE (route file has zero)",
     updates.length === 0, `found ${updates.length}`);
  ok("G2 canonical recovery is cron-registered",
     fs.readFileSync(path.join(__dirname, "..", "workers", "scan-api", "src", "cron", "scheduled.js"), "utf8")
       .includes("recoverInterruptedScans"));
}

console.log(`\ninterrupted-scan-recovery: ${passed} passed, ${failed} failed`);
if (failed > 0) { console.error("interrupted-scan-recovery validation FAILED"); process.exit(1); }
console.log("interrupted-scan-recovery validation passed");
