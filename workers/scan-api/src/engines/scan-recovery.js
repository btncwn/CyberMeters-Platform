// ── Interrupted-scan terminal recovery ───────────────────────────────────────
// Closes the permanent-`running` failure class discovered in the 22 Jul 2026
// manual-scan incident: a scan launched from the HTTP route runs inside
// post-response ctx.waitUntil, which the Workers runtime cancels ~30 s after the
// response. A scan killed mid-flight never reaches finalisation, so its D1 row
// stays `running` forever and its R2 object remains the `running` placeholder —
// a state the pre-existing reconcilers (which only converge D1 FROM a terminal
// R2 report) can never repair.
//
// Ownership: this is the ONE canonical recovery brain. It runs ONLY from the
// hourly cron (`tasks.recoverInterruptedScans`) — GET /scans list/detail are
// read-only and never mutate production state.
//
// Two recovery classes, in strict preference order per row:
//   1. TERMINAL REPORT EXISTS in R2 (completed/failed) — the engine finished but
//      the D1 status write was lost. Converge D1 from the R2 report. The R2
//      report is NEVER overwritten.
//   2. INTERRUPTED — R2 is absent or still the `running` placeholder and the row
//      is far beyond any legitimate runtime with a stale heartbeat. Mark the R2
//      placeholder failed first (after an optimistic re-check), then D1. Writing
//      R2 first is deliberate crash-safety: if we die between the two writes,
//      the next tick sees D1 `running` + R2 terminal and repairs it via class 1.
//
// Honesty invariants: recovery NEVER creates findings, alerts, cases, scores or
// any healthy posture. scan_quality stays NULL (the canonical vocabulary is
// complete/partial — an interrupted scan earned neither). The only outputs are a
// terminal `failed` status, a canonical machine reason, a customer-honest
// message, and one append-only audit event per actual transition.

import { createAuditEvent } from "../lib/events.js";

// Non-terminal statuses recovery may touch. PR-3 (durable Queue dispatch) adds
// its own pre-run states (e.g. "queued") here so an orphaned enqueue can also
// reach a terminal state through this same canonical path.
export const RECOVERY_ACTIVE_STATUSES = ["running"];

// Eligibility thresholds — deliberately conservative. Today's longest legitimate
// scan is ~60 s (21 s network budget + finalisation); the future Queue-consumer
// budget is ~11 min (10 min + reserve). 30 min age with a 10 min-stale heartbeat
// clears BOTH by a wide margin, so a genuinely executing scan can never qualify.
export const RECOVERY_MIN_AGE_MS = 30 * 60 * 1000;
export const RECOVERY_HEARTBEAT_STALE_MS = 10 * 60 * 1000;

// Bounded work per cron tick — recovery shares the tick's subrequest budget with
// every other task, and a pathological backlog must degrade gracefully, not
// consume the invocation.
export const RECOVERY_BATCH_LIMIT = 25;

export const INTERRUPTED_REASON = "interrupted_before_finalisation";
export const INTERRUPTED_CUSTOMER_MESSAGE =
  "This scan was interrupted before it could finish. No results were recorded. " +
  "Start a new scan to assess this domain.";

// D1 stores both `YYYY-MM-DD HH:MM:SS` (SQLite default) and ISO strings.
function parseDbTime(value) {
  if (!value) return null;
  const iso = String(value).includes("T")
    ? String(value)
    : String(value).replace(" ", "T") + "Z";
  const ms = new Date(iso).getTime();
  return Number.isFinite(ms) ? ms : null;
}

function isTerminalReport(raw) {
  return !!raw && (raw.status === "completed" || raw.status === "failed");
}

/**
 * recoverInterruptedScans — hourly cron task. Idempotent and bounded; returns a
 * summary object for cron telemetry. Never throws.
 */
export async function recoverInterruptedScans(env, { now = Date.now() } = {}) {
  const summary = { examined: 0, recovered_interrupted: 0, converged_from_r2: 0, skipped: 0 };
  const statusPlaceholders = RECOVERY_ACTIVE_STATUSES.map(() => "?").join(",");

  let rows;
  try {
    rows = await env.cybermeters_db
      .prepare(
        `SELECT id, workspace_id, domain_id, domain, status, created_at, last_heartbeat_at
           FROM scans
          WHERE status IN (${statusPlaceholders})
          ORDER BY created_at ASC
          LIMIT ${RECOVERY_BATCH_LIMIT}`
      )
      .bind(...RECOVERY_ACTIVE_STATUSES)
      .all();
  } catch {
    return summary; // D1 read failure — nothing safe to do this tick
  }

  for (const s of rows?.results || []) {
    summary.examined++;

    // ── Eligibility: age AND heartbeat staleness must BOTH hold ────────────
    const createdMs = parseDbTime(s.created_at);
    const heartbeatMs = parseDbTime(s.last_heartbeat_at) ?? createdMs;
    if (!createdMs || now - createdMs < RECOVERY_MIN_AGE_MS) { summary.skipped++; continue; }
    if (!heartbeatMs || now - heartbeatMs < RECOVERY_HEARTBEAT_STALE_MS) { summary.skipped++; continue; }

    const reportKey = `reports/${s.id}.json`;
    let raw = null;
    try {
      const obj = await env.cybermeters_reports.get(reportKey);
      raw = obj ? await obj.json() : null;
    } catch { raw = null; }

    // ── Class 1: terminal R2 report — converge D1, never overwrite R2 ──────
    if (isTerminalReport(raw)) {
      try {
        const res = await env.cybermeters_db
          .prepare(
            `UPDATE scans SET status = ?, score = ?, rating = ?, scan_quality = ?
              WHERE id = ? AND status IN (${statusPlaceholders})`
          )
          .bind(
            raw.status,
            raw.cyber_metrics_score ?? null,
            raw.risk_level ?? null,
            raw.scan_quality?.status ?? null,
            s.id,
            ...RECOVERY_ACTIVE_STATUSES
          )
          .run();
        if ((res?.meta?.changes ?? 0) > 0) summary.converged_from_r2++;
        else summary.skipped++;
      } catch { summary.skipped++; }
      continue;
    }

    // ── Class 2: interrupted — R2 first (optimistic re-check), then D1 ─────
    try {
      // Optimistic re-check immediately before the write: if a genuine terminal
      // report landed between our reads, never clobber it — the next tick
      // converges it via class 1 instead.
      let current = null;
      try {
        const obj2 = await env.cybermeters_reports.get(reportKey);
        current = obj2 ? await obj2.json() : null;
      } catch { current = null; }
      if (isTerminalReport(current)) { summary.skipped++; continue; }

      const failedReport = {
        ...(current || raw || {}),
        scan_id: s.id,
        domain_id: s.domain_id ?? current?.domain_id ?? null,
        domain: s.domain ?? current?.domain ?? null,
        status: "failed",
        reason: INTERRUPTED_REASON,
        interrupted_at: new Date(now).toISOString(),
        message: INTERRUPTED_CUSTOMER_MESSAGE,
      };
      await env.cybermeters_reports.put(
        reportKey,
        JSON.stringify(failedReport, null, 2),
        { httpMetadata: { contentType: "application/json" } }
      );
    } catch {
      // R2 write failure is non-fatal: D1 is the status authority and MUST
      // still reach a terminal state below. A `failed` D1 row with a stale
      // `running` placeholder is benign — nothing reads the placeholder for a
      // non-running row.
    }

    try {
      // scan_quality is EXPLICITLY persisted as NULL: an interrupted scan earned
      // neither `complete` nor `partial`, and any stale value a dying invocation
      // may have left behind must not survive into the terminal row.
      const res = await env.cybermeters_db
        .prepare(
          `UPDATE scans SET status = 'failed', scan_quality = NULL
            WHERE id = ? AND status IN (${statusPlaceholders})`
        )
        .bind(s.id, ...RECOVERY_ACTIVE_STATUSES)
        .run();
      const changed = res?.meta?.changes ?? 0;
      if (changed > 0) {
        summary.recovered_interrupted++;
        // Append-only audit evidence — exactly once per actual transition
        // (the optimistic `AND status IN (...)` guard makes re-runs a no-op,
        // so a repeated tick can never double-write this event).
        await createAuditEvent(env, {
          workspace_id: s.workspace_id ?? null,
          actor_type: "system",
          event_type: "scan_interrupted_recovered",
          entity_type: "scan",
          entity_id: s.id,
          description:
            "Scan marked failed: interrupted before finalisation (no results were produced)",
          metadata: {
            reason: INTERRUPTED_REASON,
            domain: s.domain ?? null,
            age_ms: now - createdMs,
            heartbeat_stale_ms: now - heartbeatMs,
            r2_state: raw ? "running_placeholder" : "absent",
          },
        });
      } else {
        summary.skipped++;
      }
    } catch { summary.skipped++; }
  }

  return summary;
}
