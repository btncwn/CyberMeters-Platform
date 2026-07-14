// ── Bounded scheduled executive-report generation ────────────────────────────
// The hourly cron generates weekly (Monday) and monthly (1st) executive PDF reports
// per workspace. The architecture audit flagged the original loop as unbounded — it
// iterated EVERY workspace in one cron invocation. This module bounds it:
//
//   • bounded  — at most SCHEDULED_REPORT_BATCH_LIMIT jobs per invocation;
//   • deterministic — never-attempted jobs first (fairness), then report_type, then
//     workspace id ascending; identical due-time within a tick resolves by id;
//   • idempotent — a COMPLETED report for (workspace, report_type, report_period) is
//     the claim; it is never regenerated. The R2 key is deterministic per that tuple,
//     so even an overlapping run writes ONE artifact, not duplicates;
//   • retry-safe — a failed/pending period is NOT treated as done, so it retries on a
//     later invocation (after never-attempted jobs, so a persistent failure cannot
//     starve fresh workspaces);
//   • entitlement-aware — re-checks workspace-active + effective-plan + report quota
//     via the canonical helpers at execution time (closes the free-plan auto-PDF gap);
//   • observable — emits one structured summary per invocation + per-failure reason
//     codes (no secrets, no report content).
//
// It does NOT change scan orchestration, other cron tasks, PDF content, or product
// naming. The deferred remainder is drained by subsequent hourly invocations on the
// same report-day (each completed report drops out of the next selection).
import {
  checkReportLimit,
  generateWorkspaceExecutiveReport,
  getWorkspaceBillingUserId,
} from "./plan-usage.js";
import { getEffectivePlan, hasFeatureEntitlement } from "./entitlements.js";

// Paid-Worker sizing: each executive report is ~a handful of subrequests (a few R2
// gets of latest scan reports + one R2 put) plus one PDF build. 25/invocation is a
// few hundred subrequests — comfortably within the per-invocation budget while
// leaving room for the other hourly cron tasks — and, drained across the day's 24
// invocations, covers hundreds of workspaces per report-day. Raise via env up to MAX.
export const SCHEDULED_REPORT_BATCH_DEFAULT = 25;
export const SCHEDULED_REPORT_BATCH_MAX = 100;

// Report generation requires the paid PDF-reports entitlement (starter+). Free plans
// never receive an auto-generated executive PDF.
const SCHEDULED_REPORT_FEATURE = "pdf_reports";

export function resolveScheduledReportBatchLimit(env) {
  const raw = env?.SCHEDULED_REPORT_BATCH_LIMIT;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 1) return SCHEDULED_REPORT_BATCH_DEFAULT;
  return Math.min(n, SCHEDULED_REPORT_BATCH_MAX);
}

// Which executive reports are due for this cron tick, with their canonical periods.
// Weekly = Monday (ISO 8601 week, Thursday-anchored — MUST match the period
// generateWorkspaceExecutiveReport derives). Monthly = 1st of month (YYYY-MM).
export function getDueReportTypes(now) {
  const d = new Date(now);
  const due = [];
  if (d.getUTCDay() === 1) {
    const t = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
    t.setUTCDate(t.getUTCDate() + 4 - (t.getUTCDay() || 7));
    const year = t.getUTCFullYear();
    const wk = Math.ceil((((t - Date.UTC(year, 0, 1)) / 86400000) + 1) / 7);
    due.push({ report_type: "weekly_executive", report_period: `${year}-W${String(wk).padStart(2, "0")}` });
  }
  if (d.getUTCDate() === 1) {
    due.push({ report_type: "monthly_executive", report_period: `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}` });
  }
  return due;
}

// Build the deterministic, fairness-ordered list of due report jobs that are NOT yet
// completed. One (workspace, report_type, period) = one job.
export async function selectDueReportJobs(env, dueTypes) {
  const wsRows = await env.cybermeters_db
    .prepare("SELECT id FROM workspaces WHERE deleted_at IS NULL ORDER BY id ASC")
    .all()
    .catch(() => ({ results: [] }));
  const workspaces = (wsRows.results || []).map((r) => r.id).filter(Boolean);

  const jobs = [];
  for (const dt of dueTypes) {
    // Completed = the claim (skip). Attempted = any non-deleted row (completed/
    // pending/failed) — used only to order never-attempted jobs first for fairness.
    const [completedRows, attemptedRows] = await Promise.all([
      env.cybermeters_db.prepare(
        `SELECT workspace_id FROM workspace_reports
         WHERE report_type = ? AND report_period = ? AND status = 'completed' AND deleted_at IS NULL`
      ).bind(dt.report_type, dt.report_period).all().catch(() => ({ results: [] })),
      env.cybermeters_db.prepare(
        `SELECT workspace_id FROM workspace_reports
         WHERE report_type = ? AND report_period = ? AND deleted_at IS NULL`
      ).bind(dt.report_type, dt.report_period).all().catch(() => ({ results: [] })),
    ]);
    const completed = new Set((completedRows.results || []).map((r) => r.workspace_id));
    const attempted = new Set((attemptedRows.results || []).map((r) => r.workspace_id));
    for (const wsId of workspaces) {
      if (completed.has(wsId)) continue; // already generated for this period → idempotent skip
      jobs.push({ workspace_id: wsId, report_type: dt.report_type, report_period: dt.report_period, attempted: attempted.has(wsId) });
    }
  }

  // Deterministic + fair: never-attempted first (so a persistently-failing job can't
  // starve fresh workspaces), then report_type, then workspace id ascending.
  jobs.sort((a, b) =>
    (Number(a.attempted) - Number(b.attempted)) ||
    a.report_type.localeCompare(b.report_type) ||
    a.workspace_id.localeCompare(b.workspace_id)
  );
  return jobs;
}

// Execution-time eligibility re-check via canonical helpers (no plan logic copied).
// Returns { ok:true } or { ok:false, reason }.
export async function checkScheduledReportEligibility(env, workspaceId) {
  const ws = await env.cybermeters_db
    .prepare("SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL LIMIT 1")
    .bind(workspaceId).first().catch(() => null);
  if (!ws) return { ok: false, reason: "workspace_inactive" };

  const ownerId = await getWorkspaceBillingUserId(workspaceId, null, env).catch(() => null);
  const plan = await getEffectivePlan(ownerId, env);
  if (!hasFeatureEntitlement(plan, SCHEDULED_REPORT_FEATURE)) return { ok: false, reason: "not_entitled" };

  const quota = await checkReportLimit({ id: ownerId }, workspaceId, env);
  if (quota) return { ok: false, reason: "quota_exceeded" };

  return { ok: true };
}

// One bounded cron invocation. `deps.generate` is injectable for tests (defaults to
// the real generator); `deps.batchLimit` overrides the env/default limit; `deps.nowMs`
// stamps the summary duration deterministically in tests.
export async function runBoundedScheduledReports(now, env, deps = {}) {
  const startedAt = deps.startedAtMs ?? Date.now();
  const batchLimit = deps.batchLimit ?? resolveScheduledReportBatchLimit(env);
  const generate = deps.generate ?? ((wsId, e, opts) => generateWorkspaceExecutiveReport(wsId, e, opts));
  const checkEligibility = deps.checkEligibility ?? ((e, wsId) => checkScheduledReportEligibility(e, wsId));
  const log = deps.log ?? ((msg, obj) => console.log(msg, JSON.stringify(obj)));

  const dueTypes = getDueReportTypes(now);
  if (dueTypes.length === 0) {
    const summary = emptySummary(batchLimit, deps.endedAtMs ?? startedAt, startedAt);
    summary.not_due = true;
    log("[scheduled-reports]", summary);
    return summary;
  }

  const jobs = await selectDueReportJobs(env, dueTypes);
  const batch = jobs.slice(0, batchLimit);

  let generated = 0, failures = 0, skippedEntitlement = 0, skippedState = 0;
  for (const job of batch) {
    let elig;
    try {
      elig = await checkEligibility(env, job.workspace_id);
    } catch {
      elig = { ok: false, reason: "eligibility_error" };
    }
    if (!elig.ok) {
      if (elig.reason === "not_entitled" || elig.reason === "quota_exceeded") skippedEntitlement++;
      else skippedState++;
      log("[scheduled-reports.skip]", { workspace_id: job.workspace_id, report_type: job.report_type, report_period: job.report_period, reason: elig.reason });
      continue; // deferred job: NO report row, NO R2 object, NO email, NO usage increment
    }
    try {
      await generate(job.workspace_id, env, { report_type: job.report_type, report_period: job.report_period });
      generated++;
    } catch (e) {
      failures++;
      // Reason code only — never the error detail/report content (avoid leaking).
      log("[scheduled-reports.fail]", { workspace_id: job.workspace_id, report_type: job.report_type, report_period: job.report_period, reason: "generation_failed" });
    }
  }

  const summary = {
    task: "scheduled_reports",
    due_types: dueTypes.map((d) => d.report_type),
    jobs_due: jobs.length,
    jobs_processed: batch.length,
    reports_generated: generated,
    jobs_deferred_batch: jobs.length - batch.length,
    jobs_skipped_entitlement: skippedEntitlement,
    jobs_skipped_state: skippedState,
    failures,
    batch_limit: batchLimit,
    duration_ms: Math.max(0, (deps.endedAtMs ?? Date.now()) - startedAt),
  };
  log("[scheduled-reports]", summary);
  return summary;
}

function emptySummary(batchLimit, endedAtMs, startedAt) {
  return {
    task: "scheduled_reports",
    due_types: [],
    jobs_due: 0,
    jobs_processed: 0,
    reports_generated: 0,
    jobs_deferred_batch: 0,
    jobs_skipped_entitlement: 0,
    jobs_skipped_state: 0,
    failures: 0,
    batch_limit: batchLimit,
    duration_ms: Math.max(0, endedAtMs - startedAt),
  };
}
