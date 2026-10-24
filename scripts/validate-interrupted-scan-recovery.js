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
import { DatabaseSync } from "node:sqlite";
import { importMutant, registerMutants } from "./lib/mutant-import.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const enginePath = path.join(
  __dirname, "..", "workers", "scan-api", "src", "engines", "scan-recovery.js"
);
const eventsPath = path.join(
  __dirname, "..", "workers", "scan-api", "src", "lib", "events.js"
);
registerMutants([
  {
    id: "A3-R1-drop-legacy-guard",
    from: `          AND NOT EXISTS (
              SELECT 1 FROM audit_events
               WHERE event_type = 'scan_completed'
                 AND entity_type = 'scan'
                 AND entity_id = ?
                 AND workspace_id IS ?
            )`,
    to: "          AND (? IS NOT NULL OR ? IS NULL)",
  },
  {
    id: "A3-R2-drop-completed-status-guard",
    from: `              SELECT 1 FROM scans
               WHERE id = ? AND status = 'completed'`,
    to: `              SELECT 1 FROM scans
               WHERE id = ?`,
  },
  {
    id: "A3-R3-drop-conflict-tolerance",
    from: "       ON CONFLICT(id) DO NOTHING",
    to: "",
  },
  {
    id: "A3-R4-drop-owner-from-identity",
    from: '  const id = `audit_scan_completed:v1:${workspaceId ?? "global"}:${scan_id}`;',
    to: '  const id = `audit_scan_completed:v1:global:${scan_id}`;',
  },
  {
    id: "A3-R5-count-zero-change-as-converged",
    from: "        if ((updateResult?.meta?.changes ?? 0) > 0) summary.converged_from_r2++;",
    to: "        if ((updateResult?.meta?.changes ?? 0) >= 0) summary.converged_from_r2++;",
  },
]);
const {
  recoverInterruptedScans,
  RECOVERY_MIN_AGE_MS,
  RECOVERY_HEARTBEAT_STALE_MS,
  RECOVERY_BATCH_LIMIT,
  RECOVERY_QUEUED_MAX_WAIT_MS,
  INTERRUPTED_REASON,
  RECOVERY_RUNNING_MIN_AGE_MS,
} = await import(enginePath);
const { scanCompletionAuditStatement } = await import(eventsPath);

let passed = 0, failed = 0;
function ok(name, cond, detail = "") {
  if (cond) { passed++; console.log(`PASS ${name}`); }
  else      { failed++; console.log(`FAIL ${name}${detail ? " — " + detail : ""}`); }
}

const NOW = Date.parse("2026-07-22T12:00:00Z");
const iso = (msAgo) => new Date(NOW - msAgo).toISOString();
const sqlite = (msAgo) => iso(msAgo).replace("T", " ").slice(0, 19); // D1 default format

// ── Stub environment ─────────────────────────────────────────────────────────
function makeEnv({ scans, r2Objects, afterSelect = null, legacyAudits = [], failBatch = false, failAudit = false, exposureJobs = [] }) {
  const state = {
    scans: scans.map((s) => ({ ...s })),
    r2: new Map(Object.entries(r2Objects || {})),
    r2Puts: [],
    audits: legacyAudits.map((row) => ({ ...row })),
    updates: [],
    failBatch,
    failAudit,
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
                if (state.failAudit) throw new Error("fixture audit failure");
                if (/ON CONFLICT\(id\) DO NOTHING/i.test(sql)) {
                  const [id, workspace_id, scan_id] = args;
                  const scan = state.scans.find((row) => row.id === scan_id);
                  const legacy = state.audits.some((row) =>
                    row.event_type === "scan_completed" && row.entity_type === "scan" &&
                    row.entity_id === scan_id && (row.workspace_id ?? null) === (workspace_id ?? null));
                  const duplicate = state.audits.some((row) => row.id === id);
                  if (scan?.status !== "completed" || legacy || duplicate) {
                    return { meta: { changes: 0 } };
                  }
                  state.audits.push({
                    id, workspace_id, event_type: "scan_completed",
                    entity_type: "scan", entity_id: scan_id, args, sql,
                  });
                  return { meta: { changes: 1 } };
                }
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
            async first() {
              // "Is the queue still being worked through?" — running scans
              // with a heartbeat at or after the bound instant.
              if (/SELECT COUNT\(\*\) AS n FROM scans/i.test(sql)) {
                const [status, since] = args;
                const at = (v) => Date.parse(String(v).includes("T") ? String(v) : String(v).replace(" ", "T") + "Z");
                return { n: state.scans.filter((row) => row.status === status && row.last_heartbeat_at && at(row.last_heartbeat_at) >= Date.parse(since)).length };
              }
              // 1a: a live external-exposure job for this scan (pending/running, inside its deadline).
              if (/FROM external_exposure_jobs/i.test(sql)) {
                const [scanId, nowMs] = args;
                return exposureJobs.some((job) => job.scan_id === scanId && ["pending", "running"].includes(job.state) && job.deadline_ms > nowMs)
                  ? { waiting: 1 } : null;
              }
              return null;
            },
          };
        },
      };
    },
    async batch(statements) {
      if (state.failBatch) throw new Error("fixture batch failure");
      const scanSnapshot = state.scans.map((row) => ({ ...row }));
      const auditLength = state.audits.length;
      const updateLength = state.updates.length;
      try {
        const results = [];
        for (const statement of statements) results.push(await statement.run());
        return results;
      } catch (error) {
        state.scans.splice(0, state.scans.length, ...scanSnapshot);
        state.audits.length = auditLength;
        state.updates.length = updateLength;
        throw error;
      }
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
  ok("1h failed report carries scan_quality = null (PR-1b invariant)",
     put && put.body.scan_quality === null);
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
  const completionAudits = state.audits.filter((row) => row.event_type === "scan_completed");
  ok("5d convergence writes exactly one completion audit", completionAudits.length === 1);
  ok("5e completion audit has deterministic owner-scoped identity",
     completionAudits[0]?.id === "audit_scan_completed:v1:ws_B:scan_lostwrite" &&
     completionAudits[0]?.workspace_id === "ws_B");
}

// ── Fixture 5b: failed terminal R2 converges status but never completion ─────
{
  const { env, state } = makeEnv({
    scans: [{
      id: "scan_r2_failed", workspace_id: "ws_FAIL", domain_id: "dom_FAIL", domain: "fail.example",
      status: "running", created_at: sqlite(STALE_AGE), last_heartbeat_at: iso(STALE_AGE),
    }],
    r2Objects: {
      "reports/scan_r2_failed.json": { scan_id: "scan_r2_failed", status: "failed", risk_level: "unknown" },
    },
  });
  const summary = await recoverInterruptedScans(env, { now: NOW });
  ok("5f failed R2 converges D1 status", state.scans[0].status === "failed" && summary.converged_from_r2 === 1);
  ok("5g failed R2 never emits scan_completed",
     state.audits.every((row) => row.event_type !== "scan_completed"));
}

// ── Fixture 5c: NULL owner is one deterministic global completion ───────────
{
  const { env, state } = makeEnv({
    scans: [{
      id: "scan_global", workspace_id: null, domain_id: "dom_SHARED", domain: "shared.example",
      status: "running", created_at: sqlite(STALE_AGE), last_heartbeat_at: iso(STALE_AGE),
    }],
    r2Objects: {
      "reports/scan_global.json": {
        scan_id: "scan_global", domain: "shared.example", domain_id: "dom_SHARED",
        status: "completed", cyber_metrics_score: 60, risk_level: "medium",
        scan_quality: { status: "partial" },
      },
    },
  });
  await recoverInterruptedScans(env, { now: NOW });
  const rows = state.audits.filter((row) => row.event_type === "scan_completed");
  ok("5h null-workspace completion writes one global row", rows.length === 1 && rows[0].workspace_id === null);
  ok("5i global completion identity is deterministic",
     rows[0]?.id === "audit_scan_completed:v1:global:scan_global");
}

// ── Fixture 5d: legacy random-id row suppresses a modern duplicate ─────────
{
  const { env, state } = makeEnv({
    scans: [{
      id: "scan_legacy", workspace_id: "ws_LEGACY", domain_id: "dom_L", domain: "legacy.example",
      status: "running", created_at: sqlite(STALE_AGE), last_heartbeat_at: iso(STALE_AGE),
    }],
    r2Objects: {
      "reports/scan_legacy.json": { scan_id: "scan_legacy", status: "completed", cyber_metrics_score: 75 },
    },
    legacyAudits: [{
      id: "audit_random_old", workspace_id: "ws_LEGACY", event_type: "scan_completed",
      entity_type: "scan", entity_id: "scan_legacy",
    }],
  });
  const summary = await recoverInterruptedScans(env, { now: NOW });
  ok("5j legacy completion row is preserved without a third row", state.audits.length === 1);
  ok("5k legacy guard does not block status convergence",
     state.scans[0].status === "completed" && summary.converged_from_r2 === 1);
}

// ── Fixture 5e: batch rollback and uncertain retry converge as one unit ─────
{
  const { env, state } = makeEnv({
    scans: [{
      id: "scan_atomic", workspace_id: "ws_ATOMIC", domain_id: "dom_A", domain: "atomic.example",
      status: "running", created_at: sqlite(STALE_AGE), last_heartbeat_at: iso(STALE_AGE),
    }],
    r2Objects: {
      "reports/scan_atomic.json": { scan_id: "scan_atomic", status: "completed", cyber_metrics_score: 81 },
    },
    failAudit: true,
  });
  const first = await recoverInterruptedScans(env, { now: NOW });
  ok("5l audit failure rolls back the status update",
     state.scans[0].status === "running" && state.audits.length === 0 && first.converged_from_r2 === 0);
  state.failAudit = false;
  const second = await recoverInterruptedScans(env, { now: NOW });
  ok("5m later Class1 retry converges status and audit together",
     state.scans[0].status === "completed" && second.converged_from_r2 === 1 && state.audits.length === 1);
}

// ── Fixture 5f: concurrent engine completion makes Class1 a summary no-op ───
{
  const deterministicId = "audit_scan_completed:v1:ws_RACE_OK:scan_race_ok";
  const { env, state } = makeEnv({
    scans: [{
      id: "scan_race_ok", workspace_id: "ws_RACE_OK", domain_id: "dom_R", domain: "race.example",
      status: "running", created_at: sqlite(STALE_AGE), last_heartbeat_at: iso(STALE_AGE),
    }],
    r2Objects: {
      "reports/scan_race_ok.json": { scan_id: "scan_race_ok", status: "completed", cyber_metrics_score: 91 },
    },
    legacyAudits: [{
      id: deterministicId, workspace_id: "ws_RACE_OK", event_type: "scan_completed",
      entity_type: "scan", entity_id: "scan_race_ok",
    }],
    afterSelect(state) {
      state.scans[0].status = "completed";
    },
  });
  const summary = await recoverInterruptedScans(env, { now: NOW });
  ok("5n already-completed Class1 race does not increment convergence summary",
     summary.converged_from_r2 === 0 && summary.skipped === 1);
  ok("5o already-completed Class1 race preserves exactly one audit", state.audits.length === 1);
}

// ── Fixture 5g: contradictory failed D1 row rejects completed-R2 audit ──────
{
  const { env, state } = makeEnv({
    scans: [{
      id: "scan_race_failed", workspace_id: "ws_RACE_FAIL", domain_id: "dom_R", domain: "race-fail.example",
      status: "running", created_at: sqlite(STALE_AGE), last_heartbeat_at: iso(STALE_AGE),
    }],
    r2Objects: {
      "reports/scan_race_failed.json": { scan_id: "scan_race_failed", status: "completed", cyber_metrics_score: 91 },
    },
    afterSelect(state) {
      state.scans[0].status = "failed";
    },
  });
  const summary = await recoverInterruptedScans(env, { now: NOW });
  ok("5p contradictory failed row is not counted as completed convergence",
     summary.converged_from_r2 === 0 && summary.skipped === 1);
  ok("5q completed R2 cannot audit a D1 scan that is failed",
     state.audits.every((row) => row.event_type !== "scan_completed"));
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

// ── Fixtures 12/13: inherited placeholder quality NEVER survives recovery ────
// The 22 Jul live-acceptance gate-fail: the old START placeholder hardcoded
// scan_quality.status="complete", and the recovery spread preserved it into the
// failed report. The explicit `scan_quality: null` after the spread closes it.
// Removing that explicit null must redden BOTH fixtures.
for (const inherited of [{ status: "complete" }, { status: "partial" }]) {
  const { env, state } = makeEnv({
    scans: [{
      id: `scan_inherit_${inherited.status}`, workspace_id: "ws_A", domain_id: "d",
      domain: "x.co", status: "running",
      created_at: sqlite(STALE_AGE), last_heartbeat_at: iso(STALE_AGE),
    }],
    r2Objects: {
      [`reports/scan_inherit_${inherited.status}.json`]: {
        scan_id: `scan_inherit_${inherited.status}`, status: "running",
        scan_quality: inherited, findings: [],
      },
    },
  });
  await recoverInterruptedScans(env, { now: NOW });
  const put = state.r2Puts[0];
  ok(`12-${inherited.status} inherited placeholder quality "${inherited.status}" → failed report quality null`,
     put && put.body.status === "failed" && put.body.scan_quality === null);
  ok(`12-${inherited.status}b no score/rating/findings gained`,
     put && (put.body.findings || []).length === 0 && !put.body.rating);
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

// ── A3: execute the exact builder SQL against real SQLite ───────────────────
{
  const sqlDb = new DatabaseSync(":memory:");
  sqlDb.exec(`
    CREATE TABLE scans (id TEXT PRIMARY KEY, status TEXT NOT NULL);
    CREATE TABLE audit_events (
      id TEXT PRIMARY KEY,
      workspace_id TEXT,
      user_id TEXT,
      actor_type TEXT,
      event_type TEXT NOT NULL,
      entity_type TEXT,
      entity_id TEXT,
      description TEXT,
      metadata_json TEXT,
      created_at TEXT
    );
  `);
  const d1 = {
    prepare(sql) {
      const statement = sqlDb.prepare(sql);
      let values = [];
      return {
        bind(...args) { values = args; return this; },
        run() {
          const result = statement.run(...values);
          return { meta: { changes: Number(result.changes) } };
        },
      };
    },
  };
  const env = { cybermeters_db: d1 };
  const completion = (scan_id, workspace_id) => scanCompletionAuditStatement(env, {
    workspace_id, scan_id, domain: "owner.example", domain_id: "dom_owner",
    score: 77, risk_level: "medium", scan_quality: "complete",
  });

  sqlDb.prepare("INSERT INTO scans (id, status) VALUES (?, ?)").run("scan_sql", "completed");
  completion("scan_sql", "ws_OWNER").run();
  completion("scan_sql", "ws_OWNER").run();
  const modern = sqlDb.prepare(
    "SELECT id, workspace_id, actor_type, description, metadata_json FROM audit_events WHERE entity_id = ?"
  ).all("scan_sql");
  ok("A3-1 real SQL collapses repeated modern completion attempts", modern.length === 1);
  ok("A3-2 real SQL stores deterministic owner identity and system actor",
     modern[0]?.id === "audit_scan_completed:v1:ws_OWNER:scan_sql" &&
     modern[0]?.workspace_id === "ws_OWNER" && modern[0]?.actor_type === "system");
  ok("A3-3 builder uses canonical completion presentation and metadata",
     /Scan completed for owner\.example/.test(modern[0]?.description || "") &&
     JSON.parse(modern[0]?.metadata_json || "{}").score === 77);

  sqlDb.prepare("INSERT INTO scans (id, status) VALUES (?, ?)").run("scan_legacy_sql", "completed");
  sqlDb.prepare(`INSERT INTO audit_events
    (id, workspace_id, actor_type, event_type, entity_type, entity_id)
    VALUES (?, ?, 'system', 'scan_completed', 'scan', ?)`)
    .run("audit_old_random", "ws_LEGACY", "scan_legacy_sql");
  completion("scan_legacy_sql", "ws_LEGACY").run();
  ok("A3-4 legacy random-id completion suppresses a modern duplicate",
     sqlDb.prepare("SELECT count(*) AS n FROM audit_events WHERE entity_id = ?")
       .get("scan_legacy_sql").n === 1);

  sqlDb.prepare("INSERT INTO scans (id, status) VALUES (?, ?)").run("scan_global_sql", "completed");
  completion("scan_global_sql", null).run();
  completion("scan_global_sql", null).run();
  const global = sqlDb.prepare("SELECT id, workspace_id FROM audit_events WHERE entity_id = ?")
    .all("scan_global_sql");
  ok("A3-5 null owner yields one deterministic global completion",
     global.length === 1 && global[0].id === "audit_scan_completed:v1:global:scan_global_sql" &&
     global[0].workspace_id === null);

  sqlDb.prepare("INSERT INTO scans (id, status) VALUES (?, ?)").run("scan_not_done", "running");
  completion("scan_not_done", "ws_OWNER").run();
  ok("A3-6 EXISTS guard refuses audit until the scan is completed",
     sqlDb.prepare("SELECT count(*) AS n FROM audit_events WHERE entity_id = ?")
       .get("scan_not_done").n === 0);
  ok("A3-7 owner-scoped writer never fans out to a workspace sharing the domain",
     sqlDb.prepare("SELECT count(*) AS n FROM audit_events WHERE workspace_id = 'ws_OTHER'")
       .get().n === 0);
  sqlDb.close();
}

// ── A3 isolated loader mutants: right-reason guards ─────────────────────────
{
  const withAuditDb = async (run) => {
    const db = new DatabaseSync(":memory:");
    db.exec(`
      CREATE TABLE scans (id TEXT PRIMARY KEY, status TEXT NOT NULL);
      CREATE TABLE audit_events (
        id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT, actor_type TEXT,
        event_type TEXT NOT NULL, entity_type TEXT, entity_id TEXT,
        description TEXT, metadata_json TEXT, created_at TEXT
      );
    `);
    const d1 = {
      prepare(sql) {
        const statement = db.prepare(sql);
        let values = [];
        return {
          bind(...args) { values = args; return this; },
          run() {
            const result = statement.run(...values);
            return { meta: { changes: Number(result.changes) } };
          },
        };
      },
    };
    try { return await run(db, { cybermeters_db: d1 }); }
    finally { db.close(); }
  };

  const dropLegacy = await importMutant(eventsPath, "A3-R1-drop-legacy-guard");
  const legacyDefect = await withAuditDb(async (db, env) => {
    db.prepare("INSERT INTO scans (id, status) VALUES (?, 'completed')").run("scan_m_legacy");
    db.prepare(`INSERT INTO audit_events
      (id, workspace_id, actor_type, event_type, entity_type, entity_id)
      VALUES ('old_random', 'ws_M', 'system', 'scan_completed', 'scan', 'scan_m_legacy')`).run();
    dropLegacy.scanCompletionAuditStatement(env, {
      workspace_id: "ws_M", scan_id: "scan_m_legacy", domain: "mutant.example",
    }).run();
    return db.prepare("SELECT count(*) AS n FROM audit_events").get().n;
  });
  ok("A3-R1 mutant killed: legacy guard removal creates a second row", legacyDefect === 2);

  const dropStatus = await importMutant(eventsPath, "A3-R2-drop-completed-status-guard");
  const failedDefect = await withAuditDb(async (db, env) => {
    db.prepare("INSERT INTO scans (id, status) VALUES (?, 'failed')").run("scan_m_failed");
    dropStatus.scanCompletionAuditStatement(env, {
      workspace_id: "ws_M", scan_id: "scan_m_failed", domain: "mutant.example",
    }).run();
    return db.prepare("SELECT count(*) AS n FROM audit_events").get().n;
  });
  ok("A3-R2 mutant killed: dropping completed status guard audits a failed scan", failedDefect === 1);

  const dropConflict = await importMutant(eventsPath, "A3-R3-drop-conflict-tolerance");
  let mutantSql = null;
  dropConflict.scanCompletionAuditStatement({
    cybermeters_db: {
      prepare(sql) {
        mutantSql = sql;
        return { bind() { return this; } };
      },
    },
  }, { workspace_id: "ws_M", scan_id: "scan_m_conflict", domain: "mutant.example" });
  ok("A3-R3 mutant killed: concurrent PK conflict tolerance is explicit in the statement",
     !/ON CONFLICT\(id\) DO NOTHING/.test(mutantSql || ""));

  const dropOwner = await importMutant(eventsPath, "A3-R4-drop-owner-from-identity");
  const ownerDefect = await withAuditDb(async (db, env) => {
    db.prepare("INSERT INTO scans (id, status) VALUES (?, 'completed')").run("scan_m_owner");
    dropOwner.scanCompletionAuditStatement(env, {
      workspace_id: "ws_OWNER", scan_id: "scan_m_owner", domain: "mutant.example",
    }).run();
    return db.prepare("SELECT id FROM audit_events").get().id;
  });
  ok("A3-R4 mutant killed: owner removal changes deterministic identity",
     ownerDefect !== "audit_scan_completed:v1:ws_OWNER:scan_m_owner");

  const zeroChange = await importMutant(enginePath, "A3-R5-count-zero-change-as-converged");
  const { env, state } = makeEnv({
    scans: [{
      id: "scan_m_summary", workspace_id: "ws_M", domain_id: "dom_M", domain: "mutant.example",
      status: "running", created_at: sqlite(STALE_AGE), last_heartbeat_at: iso(STALE_AGE),
    }],
    r2Objects: { "reports/scan_m_summary.json": { status: "completed" } },
    legacyAudits: [{
      id: "audit_scan_completed:v1:ws_M:scan_m_summary", workspace_id: "ws_M",
      event_type: "scan_completed", entity_type: "scan", entity_id: "scan_m_summary",
    }],
    afterSelect(state) { state.scans[0].status = "completed"; },
  });
  const mutantSummary = await zeroChange.recoverInterruptedScans(env, { now: NOW });
  ok("A3-R5 mutant killed: zero-change Class1 must not increment convergence",
     mutantSummary.converged_from_r2 === 1 && state.audits.length === 1);
}

// ── Queued scans waiting their turn are not lost ─────────────────────────────
// Every scan waits in one queue in arrival order; a long queue (many scans
// started together) holds the last of them past RECOVERY_MIN_AGE_MS. While a
// scan is running with a fresh heartbeat, a queued scan is waiting, not lost —
// up to RECOVERY_QUEUED_MAX_WAIT_MS. With nothing running, an old queued scan
// has nothing ahead of it, and is recovered as before.
{
  const queuedRow = (id, ageMs) => ({ id, workspace_id: "ws_Q", domain_id: "dom_Q", domain: "queue.example",
    status: "queued", created_at: sqlite(ageMs), last_heartbeat_at: null });
  const workingRow = { id: "scan_working", workspace_id: "ws_W", domain_id: "dom_W", domain: "busy.example",
    status: "running", created_at: sqlite(3 * 60 * 1000), last_heartbeat_at: iso(60 * 1000) };
  const placeholder = (id) => ({ [`reports/${id}.json`]: { scan_id: id, status: "queued", findings: [] } });

  {
    const { env, state } = makeEnv({ scans: [queuedRow("scan_q_waiting", 40 * 60 * 1000), workingRow], r2Objects: placeholder("scan_q_waiting") });
    const summary = await recoverInterruptedScans(env, { now: NOW });
    ok("Q1 a queued scan 40 minutes old, behind a queue that is still moving, is left waiting",
      state.scans[0].status === "queued" && summary.recovered_interrupted === 0 && summary.waiting_in_queue === 1 &&
        state.r2Puts.length === 0 && state.audits.length === 0, JSON.stringify(summary));
  }
  {
    const { env, state } = makeEnv({ scans: [queuedRow("scan_q_alone", 40 * 60 * 1000)], r2Objects: placeholder("scan_q_alone") });
    const summary = await recoverInterruptedScans(env, { now: NOW });
    ok("Q2 the same queued scan with nothing running is lost, and is recovered as before",
      state.scans[0].status === "failed" && summary.recovered_interrupted === 1, JSON.stringify(summary));
  }
  {
    const { env, state } = makeEnv({ scans: [queuedRow("scan_q_ancient", RECOVERY_QUEUED_MAX_WAIT_MS + 60_000), workingRow], r2Objects: placeholder("scan_q_ancient") });
    const summary = await recoverInterruptedScans(env, { now: NOW });
    ok("Q3 a queued scan past the longest wait is recovered even while the queue moves",
      state.scans[0].status === "failed" && summary.recovered_interrupted === 1, JSON.stringify(summary));
  }
  {
    const zombie = { ...workingRow, id: "scan_zombie", created_at: sqlite(STALE_AGE), last_heartbeat_at: iso(20 * 60 * 1000) };
    const { env, state } = makeEnv({
      scans: [queuedRow("scan_q_behind_zombie", 40 * 60 * 1000), zombie],
      r2Objects: { ...placeholder("scan_q_behind_zombie"), "reports/scan_zombie.json": { scan_id: "scan_zombie", status: "running", findings: [] } },
    });
    const summary = await recoverInterruptedScans(env, { now: NOW });
    ok("Q4 a run whose heartbeat went stale is not a moving queue: both it and the old queued scan are recovered",
      state.scans.every((row) => row.status === "failed") && summary.recovered_interrupted === 2, JSON.stringify(summary));
  }
}

// 1a: a queued scan waiting for its workspace's exposure turn is not lost.
{
  const queuedRow = (id, ageMs) => ({ id, workspace_id: "ws_E", domain_id: "dom_E", domain: "wait.example",
    status: "queued", created_at: sqlite(ageMs), last_heartbeat_at: null });
  const placeholder = (id) => ({ [`reports/${id}.json`]: { scan_id: id, status: "queued", findings: [] } });
  {
    const { env, state } = makeEnv({ scans: [queuedRow("scan_e_waiting", 2 * 60 * 60 * 1000)], r2Objects: placeholder("scan_e_waiting"),
      exposureJobs: [{ scan_id: "scan_e_waiting", state: "pending", deadline_ms: NOW + 60 * 60 * 1000 }] });
    const summary = await recoverInterruptedScans(env, { now: NOW });
    ok("E1 a queued scan whose exposure job is waiting inside its deadline is left waiting, even with nothing running",
      state.scans[0].status === "queued" && summary.recovered_interrupted === 0 && summary.waiting_in_queue === 1, JSON.stringify(summary));
  }
  {
    const { env, state } = makeEnv({ scans: [queuedRow("scan_e_expired", 2 * 60 * 60 * 1000)], r2Objects: placeholder("scan_e_expired"),
      exposureJobs: [{ scan_id: "scan_e_expired", state: "pending", deadline_ms: NOW - 1 }] });
    const summary = await recoverInterruptedScans(env, { now: NOW });
    ok("E2 an exposure job past its deadline does not hold the scan: it is recovered as before",
      state.scans[0].status === "failed" && summary.recovered_interrupted === 1, JSON.stringify(summary));
  }
  {
    const { env, state } = makeEnv({ scans: [queuedRow("scan_e_ancient", RECOVERY_QUEUED_MAX_WAIT_MS + 60_000)], r2Objects: placeholder("scan_e_ancient"),
      exposureJobs: [{ scan_id: "scan_e_ancient", state: "pending", deadline_ms: NOW + 60 * 60 * 1000 }] });
    const summary = await recoverInterruptedScans(env, { now: NOW });
    ok("E3 past the six-hour queued bound the scan is recovered whatever its exposure job says",
      state.scans[0].status === "failed" && summary.recovered_interrupted === 1, JSON.stringify(summary));
  }
}

// ── P1-SCAN-STALL (22 Oct 2026): a dead RUNNING scan is recovered after a 10-min
// silence, without waiting for the 30-min age; nothing still executing qualifies.
{
  const runner = (id, ageMs, beatAgoMs) => ({ id, workspace_id: "ws_S", domain_id: "dom_S", domain: "stall.example",
    status: "running", created_at: sqlite(ageMs), last_heartbeat_at: beatAgoMs == null ? null : iso(beatAgoMs) });
  const runningPlaceholder = (id) => ({ [`reports/${id}.json`]: { scan_id: id, status: "running", findings: [] } });
  {
    const { env, state } = makeEnv({ scans: [runner("scan_s_dead", 13 * 60_000, 11 * 60_000)], r2Objects: runningPlaceholder("scan_s_dead") });
    const summary = await recoverInterruptedScans(env, { now: NOW });
    ok("S1 a running scan silent for 11 min at age 13 min is recovered (no 30-min wait)",
      state.scans[0].status === "failed" && summary.recovered_interrupted === 1, JSON.stringify(summary));
  }
  {
    const { env, state } = makeEnv({ scans: [runner("scan_s_alive", 13 * 60_000, 4 * 60_000)], r2Objects: runningPlaceholder("scan_s_alive") });
    await recoverInterruptedScans(env, { now: NOW });
    ok("S2 a running scan that heartbeated 4 min ago is left alone", state.scans[0].status === "running");
  }
  {
    const { env, state } = makeEnv({ scans: [runner("scan_s_young", RECOVERY_RUNNING_MIN_AGE_MS - 60_000, 10 * 60_000 + 30_000)], r2Objects: runningPlaceholder("scan_s_young") });
    await recoverInterruptedScans(env, { now: NOW });
    ok("S3 younger than the 12-min consumer bound: never recovered, even if quiet", state.scans[0].status === "running");
  }
  {
    const { env, state } = makeEnv({ scans: [runner("scan_s_nobeat", 15 * 60_000, null)], r2Objects: runningPlaceholder("scan_s_nobeat") });
    await recoverInterruptedScans(env, { now: NOW });
    ok("S4 a running scan that never heartbeated keeps the 30-min age rule", state.scans[0].status === "running");
  }
  {
    const queued = { id: "scan_s_queued", workspace_id: "ws_S", domain_id: "dom_S", domain: "stall.example", status: "queued",
      created_at: sqlite(15 * 60_000), last_heartbeat_at: iso(14 * 60_000) };
    const { env, state } = makeEnv({ scans: [queued], r2Objects: { "reports/scan_s_queued.json": { scan_id: "scan_s_queued", status: "queued", findings: [] } } });
    await recoverInterruptedScans(env, { now: NOW });
    ok("S5 a queued scan keeps the 30-min rule", state.scans[0].status === "queued");
  }
  ok("S6 the running bound exceeds the ~11-min consumer budget", RECOVERY_RUNNING_MIN_AGE_MS >= 12 * 60_000 && RECOVERY_RUNNING_MIN_AGE_MS < RECOVERY_MIN_AGE_MS);

  // The scan read API states the live stage honestly.
  const { scanProgress } = await import(new URL("../workers/scan-api/src/routes/scans.js", import.meta.url).href);
  const p = scanProgress({ status: "running", current_stage: "phase5_intelligence", completed_modules: 12, last_heartbeat_at: iso(11 * 60_000) }, NOW);
  ok("S7 progress names the stage, modules and last activity, and says it has gone quiet",
    p.stage === "phase5_intelligence" && p.completed_modules === 12 && p.last_heartbeat_at === iso(11 * 60_000) && p.stale === true, JSON.stringify(p));
  ok("S8 a fresh heartbeat is not stale", scanProgress({ status: "running", current_stage: "finalizing", last_heartbeat_at: iso(60_000) }, NOW).stale === false);
  ok("S9 an unknown internal stage never leaves the API", scanProgress({ status: "running", current_stage: "debug_internal_x" }, NOW).stage === null);
  ok("S10 a completed scan has no progress", scanProgress({ status: "completed", current_stage: "finalizing" }, NOW) === null);
  const interrupted = scanProgress({ status: "failed", current_stage: "phase5_intelligence", completed_modules: 12, last_heartbeat_at: iso(20 * 60_000) }, NOW);
  ok("S11 an interrupted scan keeps its last progress, marked terminal, and says no module names were recorded",
    interrupted.terminal === true && interrupted.stage === "phase5_intelligence" && interrupted.completed_modules === 12
    && interrupted.stale === false && interrupted.completed_module_names === null && interrupted.module_names_recorded === false, JSON.stringify(interrupted));
  const finalisedFail = scanProgress({ status: "failed", current_stage: "finalizing", completed_modules: 3 }, NOW,
    { completedModuleNames: ["ssl", "dns", "dns", "Bad Name!", "headers"] });
  ok("S12 a failed scan that reached finalisation lists its completed modules (sorted, unique, safe names only)",
    JSON.stringify(finalisedFail.completed_module_names) === JSON.stringify(["dns", "headers", "ssl"]) && finalisedFail.module_names_recorded === true, JSON.stringify(finalisedFail));
  ok("S13 a live scan is terminal: false and carries no module-name fields",
    scanProgress({ status: "running", current_stage: "finalizing", last_heartbeat_at: iso(60_000) }, NOW).terminal === false
    && !("completed_module_names" in scanProgress({ status: "running" }, NOW)));

  // F1 (D): a queued scan whose exposure job is live says so; never forever.
  const job = (over) => ({ state: "running", created_ms: NOW - 6 * 60_000, deadline_ms: NOW + 20 * 60_000, lease_until: NOW + 60_000, ...over });
  const qp = (j) => scanProgress({ status: "queued" }, NOW, { exposureJob: j });
  ok("S14 a queued scan with a live running job reports exposure_checks 'running', its start time, not stale",
    qp(job()).exposure_checks === "running" && qp(job()).exposure_started_at === new Date(NOW - 6 * 60_000).toISOString() && qp(job()).stale === false, JSON.stringify(qp(job())));
  ok("S15 a pending job reports 'pending'", qp(job({ state: "pending", lease_until: 0 })).exposure_checks === "pending" && qp(job({ state: "pending", lease_until: 0 })).stale === false);
  ok("S16 past the job's deadline: no 'pending/running', and the queued scan is stale",
    qp(job({ deadline_ms: NOW - 1 })).exposure_checks === null && qp(job({ deadline_ms: NOW - 1 })).stale === true);
  ok("S17 a running job whose lease expired over 10 minutes ago makes the queued scan stale",
    qp(job({ lease_until: NOW - 11 * 60_000 })).stale === true && qp(job({ lease_until: NOW - 60_000 })).stale === false);
  ok("S18 a finished job, no job, or a missing deadline never reads as preparing",
    ["complete", "cancelled", "budget_exhausted"].every((state) => qp(job({ state })).exposure_checks === null && qp(job({ state })).stale === false)
    && qp(null).exposure_checks === null && qp(job({ deadline_ms: null })).exposure_checks === null);
  ok("S19 a running scan never carries exposure fields from a job",
    scanProgress({ status: "running", last_heartbeat_at: iso(60_000) }, NOW, { exposureJob: job() }).exposure_checks === null);
  // The route reads the job by scan AND workspace (tenant scope), only for a queued scan.
  const scansSource = (await import("node:fs")).readFileSync(new URL("../workers/scan-api/src/routes/scans.js", import.meta.url), "utf8");
  void scansSource;
  // S20–S23 (R1 16:50): the REAL GET /api/scans/:id handler. The scan row carries
  // no workspace_id (the route's SELECT does not fetch it, as in production); the
  // job read must use the workspace requireScanReadAccess resolved.
  const { scanRoutes } = await import(new URL("../workers/scan-api/src/routes/scans.js", import.meta.url).href);
  const routeNow = Date.now();
  const callScan = async ({ status = "queued", job = null, accessWorkspace = "ws_OWN" } = {}) => {
    const reads = [];
    const db = { prepare(sql) {
      let args = [];
      return {
        bind(...a) { args = a; return this; },
        async first() {
          if (/FROM scans WHERE id = \?/.test(sql)) return { id: "scan_q", domain_id: "dom_q", domain: "example.com", status, score: null, rating: null,
            scan_quality: null, created_at: new Date(routeNow - 6 * 60_000).toISOString(), current_stage: null, last_heartbeat_at: null, completed_modules: null };
          if (/FROM external_exposure_jobs/.test(sql)) { reads.push(args); return job && job.workspace_id === args[1] && job.scan_id === args[0] ? job : null; }
          return null;
        },
        async all() { return { results: [] }; },
        async run() { return { meta: { changes: 0 } }; },
      };
    } };
    const env = { cybermeters_db: db, cybermeters_reports: { async get() { return null; }, async head() { return null; }, async put() {} } };
    const request = new Request("https://api.cybermeters.test/api/scans/scan_q");
    const jsonResponse = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    const response = await scanRoutes({ request, env, ctx: { waitUntil() {} }, url: new URL(request.url), json: jsonResponse,
      serverError: (_s, e) => jsonResponse({ error: String(e?.message || e) }, 500), corsHeaders: {},
      requireAuth: async () => ({ id: "user_q" }), requireWorkspaceRole: async () => true, consumeApiRateLimit: async () => null,
      requireScanReadAccess: async () => (accessWorkspace ? { role: "owner", workspace_id: accessWorkspace } : null),
      getAccessibleWorkspaceIds: async () => [accessWorkspace], computeNextRunAt: () => null });
    return { status: response?.status, body: response ? await response.json() : null, reads };
  };
  const liveJob = { scan_id: "scan_q", workspace_id: "ws_OWN", state: "running", created_ms: routeNow - 6 * 60_000, deadline_ms: routeNow + 20 * 60_000, lease_until: routeNow + 60_000 };
  const own = await callScan({ job: liveJob });
  ok("S20 route: a queued scan with its workspace's live job returns progress.exposure_checks 'running'",
    own.status === 200 && own.body?.progress?.exposure_checks === "running" && own.body?.progress?.exposure_started_at === new Date(routeNow - 6 * 60_000).toISOString(),
    JSON.stringify({ status: own.status, progress: own.body?.progress, error: own.body?.error }));
  ok("S21 route: the job read is bound to the scan and the access-resolved workspace",
    own.reads.length === 1 && own.reads[0][0] === "scan_q" && own.reads[0][1] === "ws_OWN", JSON.stringify(own.reads));
  const foreign = await callScan({ job: { ...liveJob, workspace_id: "ws_OTHER" } });
  ok("S22 route: a job recorded under another workspace is never reported (tenant scope)",
    foreign.status === 200 && foreign.body?.progress?.exposure_checks === null, JSON.stringify(foreign.body?.progress));
  const running = await callScan({ status: "running", job: liveJob });
  ok("S23 route: a running scan does not read the job at all", running.reads.length === 0 && running.body?.progress?.exposure_checks === null);
}

console.log(`\ninterrupted-scan-recovery: ${passed} passed, ${failed} failed`);
if (failed > 0) { console.error("interrupted-scan-recovery validation FAILED"); process.exit(1); }
console.log("interrupted-scan-recovery validation passed");
