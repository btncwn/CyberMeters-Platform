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
  coveredReportPeriod,
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
// Weekly = Monday, monthly = 1st of month; each covers the period that just ended
// (coveredReportPeriod — the same rule the generator applies).
export function getDueReportTypes(now) {
  const d = new Date(now);
  const due = [];
  if (d.getUTCDay() === 1) due.push({ report_type: "weekly_executive", report_period: coveredReportPeriod("weekly_executive", d) });
  if (d.getUTCDate() === 1) due.push({ report_type: "monthly_executive", report_period: coveredReportPeriod("monthly_executive", d) });
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
    // Completed or skipped = the claim (skip). Attempted = any non-deleted row (completed/
    // pending/failed) — used only to order never-attempted jobs first for fairness.
    const [completedRows, attemptedRows] = await Promise.all([
      env.cybermeters_db.prepare(
        `SELECT workspace_id FROM workspace_reports
         WHERE report_type = ? AND report_period = ? AND status IN ('completed', 'skipped') AND deleted_at IS NULL`
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

  let generated = 0, deduplicated = 0, failures = 0, skippedEntitlement = 0, skippedState = 0, skippedNoAssessment = 0;
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
      const result = await generate(job.workspace_id, env, { report_type: job.report_type, report_period: job.report_period, scheduled: true });
      // A concurrent invocation that lost the atomic occurrence claim returns
      // claimed:false and generated nothing — count it as deduplicated, not generated.
      if (result && result.claimed === false) deduplicated++;
      else if (result?.status === "skipped") skippedNoAssessment++;
      else generated++;
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
    jobs_deduplicated: deduplicated,
    jobs_deferred_batch: jobs.length - batch.length,
    jobs_skipped_entitlement: skippedEntitlement,
    jobs_skipped_state: skippedState,
    jobs_skipped_no_assessment: skippedNoAssessment,
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
    jobs_deduplicated: 0,
    jobs_deferred_batch: 0,
    jobs_skipped_entitlement: 0,
    jobs_skipped_state: 0,
    jobs_skipped_no_assessment: 0,
    failures: 0,
    batch_limit: batchLimit,
    duration_ms: Math.max(0, endedAtMs - startedAt),
  };
}

// ── What the customer is told about a scheduled report ──────────────────────
// Outcomes are stored as reason codes, never error text, and reach the customer
// only through these sentences. Plan rejections carry their canonical reason on
// err.quota (trial-allowance.js / getOperationAdmission); anything else is an
// unexpected failure and stays generic.
export const SCHEDULED_REPORT_RETRY_MS = 60 * 60 * 1000;

export const SCHEDULED_REPORT_REASONS = Object.freeze({
  no_assessment: {
    outcome: "skipped",
    title: "No assessment to report on",
    message: "This report was not created because no scan has completed in this workspace yet. The next one will be created once a scan has completed.",
  },
  trial_daily_allowance: {
    outcome: "failed",
    title: "Today's trial report allowance is used",
    message: "This report was not created because today's trial allowance is used. We will try again after it resets at 00:00 UTC.",
  },
  trial_expired: {
    outcome: "failed",
    title: "Your trial has ended",
    message: "This report was not created because your trial has ended. Choose a plan to restart scheduled reports.",
  },
  plan_inactive: {
    outcome: "failed",
    title: "An active plan is needed",
    message: "This report was not created because the workspace has no active plan. Start a trial or choose a plan to restart scheduled reports.",
  },
  plan_check_unavailable: {
    outcome: "failed",
    title: "Your plan could not be checked",
    message: "This report was not created because we could not check your plan when it was due. We will try again automatically within the hour.",
  },
  generation_failed: {
    outcome: "failed",
    title: "The report could not be created",
    message: "Something went wrong on our side while creating this report. We will try again automatically within the hour.",
  },
});

export function classifyScheduledReportFailure(err) {
  const body = err?.quota?.body;
  const reason = body?.reason;
  if (reason && Object.hasOwn(SCHEDULED_REPORT_REASONS, reason) && SCHEDULED_REPORT_REASONS[reason].outcome === "failed") return reason;
  if (body?.error === "plan_state_unavailable" || body?.error === "operation_unavailable") return "plan_check_unavailable";
  return "generation_failed";
}

// The customer-facing last outcome of one scheduled_reports row, or null before
// its first run. An unrecognised stored code reads as the generic failure.
export function describeScheduledReportOutcome(row) {
  if (!row?.last_outcome || !row.last_outcome_at) return null;
  if (row.last_outcome === "completed") return { status: "completed", at: row.last_outcome_at };
  const known = Object.hasOwn(SCHEDULED_REPORT_REASONS, row.last_outcome_reason)
    && SCHEDULED_REPORT_REASONS[row.last_outcome_reason].outcome === row.last_outcome;
  const reason = known ? row.last_outcome_reason : "generation_failed";
  const { title, message, outcome } = SCHEDULED_REPORT_REASONS[reason];
  const out = { status: outcome, reason, title, message, at: row.last_outcome_at };
  if (outcome === "failed") out.attempts = Math.max(1, Number(row.consecutive_failures) || 1);
  return out;
}

// A workspace_reports row as the customer may see it: error text stored for
// operations is removed, and a skipped report carries its plain reason.
export function presentReportRow(row) {
  if (!row) return row;
  let meta = null;
  if (row.metadata_json) {
    try { meta = JSON.parse(row.metadata_json); } catch { meta = null; }
  }
  const out = { ...row };
  if (meta && typeof meta === "object") {
    const { error: _error, ...rest } = meta;
    out.metadata_json = Object.keys(rest).length ? JSON.stringify(rest) : null;
  } else if (row.metadata_json) {
    out.metadata_json = null;
  }
  if (row.status === "skipped") {
    const reason = Object.hasOwn(SCHEDULED_REPORT_REASONS, meta?.skip_reason) ? meta.skip_reason : "no_assessment";
    out.status_reason = { reason, title: SCHEDULED_REPORT_REASONS[reason].title, message: SCHEDULED_REPORT_REASONS[reason].message };
  }
  return out;
}
