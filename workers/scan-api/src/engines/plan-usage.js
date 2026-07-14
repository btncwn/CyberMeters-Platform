// ── Plan usage / report lifecycle engine ──
// Plan limits, usage metering (scans/reports/schedules per month), retention
// policy, quota checkers, report-schedule cadence helpers, and the workspace
// executive report generator that consumes them. Extracted verbatim from
// index.js (router split, Phase 2 PR #4).
import { buildExecutivePdf, collectPdfData } from "./pdf.js";
import { createAuditEvent, createNotificationEvent } from "../lib/events.js";
import { createId } from "../lib/util.js";
import { getEffectivePlan, hasFeatureEntitlement, normalizePlan, PLAN_LIMITS } from "./entitlements.js";
import { isWorkspaceDomainVerified } from "../lib/domain-verification.js";

/**
 * Compute next_run_at for a scheduled_reports row.
 * weekly   → next Monday 00:00 UTC
 * monthly  → 1st of next month 00:00 UTC
 * quarterly→ 1st of next calendar quarter 00:00 UTC
 */
export function computeScheduledReportNextRunAt(frequency) {
  const now = new Date();
  const y   = now.getUTCFullYear();
  const m   = now.getUTCMonth(); // 0-based

  if (frequency === "weekly") {
    // Next Monday
    const d = new Date(Date.UTC(y, m, now.getUTCDate()));
    const dow = d.getUTCDay(); // 0=Sun
    const daysUntilMonday = dow === 0 ? 1 : (8 - dow);
    d.setUTCDate(d.getUTCDate() + daysUntilMonday);
    return d.toISOString();
  }
  if (frequency === "monthly") {
    // 1st of next month
    return new Date(Date.UTC(y, m + 1, 1)).toISOString();
  }
  if (frequency === "quarterly") {
    // 1st of next calendar quarter
    const nextQ = Math.floor(m / 3) + 1;
    const nextQYear  = y + Math.floor(nextQ / 4);
    const nextQMonth = (nextQ % 4) * 3; // 0, 3, 6, 9
    return new Date(Date.UTC(nextQYear, nextQMonth, 1)).toISOString();
  }
  // fallback: 30 days
  return new Date(Date.now() + 30 * 24 * 60 * 60 * 1_000).toISOString();
}

export function calculateNextRun(frequency, from = new Date()) {
  const base = new Date(from);
  if (frequency === "weekly") {
    return new Date(base.getTime() + 7 * 24 * 60 * 60 * 1_000).toISOString();
  }
  if (frequency === "monthly") {
    return new Date(Date.UTC(
      base.getUTCFullYear(),
      base.getUTCMonth() + 1,
      base.getUTCDate(),
      base.getUTCHours(),
      base.getUTCMinutes(),
      base.getUTCSeconds()
    )).toISOString();
  }
  return null;
}

export function normalizeReportScheduleFrequency(value) {
  const frequency = typeof value === "string" ? value.trim().toLowerCase() : "";
  return ["weekly", "monthly"].includes(frequency) ? frequency : null;
}

export function normalizeReportScheduleRecipients(value) {
  if (!Array.isArray(value)) return null;
  const recipients = [...new Set(value.map((v) => String(v || "").trim().toLowerCase()).filter(Boolean))];
  const emailPattern = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/;
  if (recipients.length === 0 || recipients.length > 20) return null;
  if (!recipients.every((email) => emailPattern.test(email))) return null;
  return recipients;
}

// generateWorkspaceExecutiveReport — collect data, build PDF, upload to R2,
// write a workspace_reports row.  Returns the completed row on success.
// Throws on fatal error (the row is marked failed before throwing).

export async function generateWorkspaceExecutiveReport(workspaceId, env, options = {}) {
  const {
    report_type   = 'manual',
    report_period = null,
    scan_id       = null,
  } = options;

  const now = new Date();

  // ── Derive report_period when not supplied ────────────────────────────────
  const period = report_period ?? (() => {
    if (report_type === 'weekly_executive') {
      // ISO 8601 week: YYYY-Www (Thursday-anchored)
      const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
      d.setUTCDate(d.getUTCDate() + 4 - (d.getUTCDay() || 7));  // move to Thursday
      const year = d.getUTCFullYear();
      const wk   = Math.ceil((((d - Date.UTC(year, 0, 1)) / 86400000) + 1) / 7);
      return `${year}-W${String(wk).padStart(2, '0')}`;
    }
    if (report_type === 'monthly_executive') {
      return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
    }
    if (report_type === 'quarterly_executive') {
      const q = Math.floor(now.getUTCMonth() / 3) + 1;
      return `${now.getUTCFullYear()}-Q${q}`;
    }
    if (report_type === 'scan_snapshot' && scan_id) {
      return `scan-${scan_id}`;
    }
    // manual: timestamp-based period so re-runs don't collide
    const ts = now.toISOString().replace(/[-:T]/g, '').slice(0, 14);
    return `manual-${ts}`;
  })();

  const reportId  = createId('rpt');
  const createdAt = now.toISOString();
  const r2Key     = `reports/executive/${workspaceId}/${report_type}/${period}/executive-report.pdf`;
  const retentionPolicy = await getReportRetentionPolicyForWorkspace(workspaceId, env);

  // Insert a pending row first so we can always flip it to failed on error
  await env.cybermeters_db.prepare(
    `INSERT INTO workspace_reports
       (id, workspace_id, report_type, report_period, report_key, status, created_at, retention_policy)
     VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)`
  ).bind(reportId, workspaceId, report_type, period, r2Key, createdAt, retentionPolicy).run();

  let pdfData, bytes;
  try {
    pdfData = await collectPdfData(workspaceId, env);
    if (!pdfData) throw new Error('Workspace not found');
    pdfData.report_id = reportId;
    bytes   = buildExecutivePdf(pdfData);
  } catch (genErr) {
    await env.cybermeters_db.prepare(
      `UPDATE workspace_reports
         SET status = 'failed', generated_at = ?, metadata_json = ?
       WHERE id = ?`
    ).bind(new Date().toISOString(), JSON.stringify({ error: String(genErr?.message ?? genErr) }), reportId).run();
    throw genErr;
  }

  const generatedAt = new Date().toISOString();

  await env.cybermeters_reports.put(r2Key, bytes, {
    httpMetadata: { contentType: 'application/pdf' },
    customMetadata: {
      workspace_id:  workspaceId,
      report_type,
      report_period: period,
      generated_at:  generatedAt,
    },
  });

  const reportSizeBytes = typeof bytes?.byteLength === "number"
    ? bytes.byteLength
    : (typeof bytes?.length === "number" ? bytes.length : null);

  await env.cybermeters_db.prepare(
    `UPDATE workspace_reports
     SET status = 'completed', generated_at = ?, report_size_bytes = ?
     WHERE id = ?`
  ).bind(generatedAt, reportSizeBytes, reportId).run();

  // Notification + audit — report generated. Non-fatal: report generation must not fail
  // if notification or audit persistence is unavailable.
  try {
    await createNotificationEvent(env, workspaceId, {
      type:     "report_generated",
      severity: "info",
      title:    `Executive report ready`,
      message:  `${report_type.replace(/_/g, " ")} report for period ${period} is available for download.`,
      metadata: { report_id: reportId, report_type, report_period: period },
    });
    await createAuditEvent(env, {
      workspace_id: workspaceId,
      event_type:   "report_generated",
      entity_type:  "report",
      entity_id:    reportId,
      description:  `Executive report generated (${report_type}, period ${period})`,
      metadata:     { report_id: reportId, report_type, report_period: period },
    });
  } catch { /* non-fatal */ }

  return {
    id:            reportId,
    workspace_id:  workspaceId,
    report_type,
    report_period: period,
    report_key:    r2Key,
    status:        'completed',
    generated_at:  generatedAt,
    created_at:    createdAt,
    retention_policy: retentionPolicy,
  };
}

export function getPlanLimits(plan) {
  const normalized = normalizePlan(plan);
  const limits = PLAN_LIMITS[normalized] ?? PLAN_LIMITS.free;
  return {
    ...limits,
    // Backward-compatible aliases for existing v1 screens/checks.
    domains_per_workspace: limits.domains,
    members_per_workspace: limits.users,
    users_per_workspace: limits.users,
  };
}

export function getPlanRetentionDays(plan) {
  const normalized = normalizePlan(plan);
  if (normalized === "enterprise") return null;
  if (normalized === "business") return 730;
  if (normalized === "professional") return 365;
  if (normalized === "starter") return 90;
  return 30;
}

export function retentionDaysToPolicy(days) {
  if (days === null || days === undefined) return "forever";
  const n = Number(days);
  if (n <= 30) return "30_days";
  if (n <= 90) return "90_days";
  if (n <= 365) return "1_year";
  return "2_years";
}

export function retentionPolicyToDays(policy) {
  if (policy === "forever") return null;
  if (policy === "30_days") return 30;
  if (policy === "90_days") return 90;
  if (policy === "1_year") return 365;
  if (policy === "2_years") return 730;
  if (policy === "7_years") return 2555;
  return 730;
}

export function getRetentionCutoffForDays(days, now = new Date()) {
  if (days === null || days === undefined) return null;
  const n = Number(days);
  if (!Number.isFinite(n) || n <= 0) return null;
  const date = new Date(now.getTime());
  date.setUTCDate(date.getUTCDate() - n);
  return date.toISOString();
}

export async function getWorkspaceRetentionSettings(workspaceId, env) {
  const ownerId = await getWorkspaceOwnerId(workspaceId, env);
  const plan = await getEffectivePlan(ownerId, env);
  const planDefaultDays = getPlanRetentionDays(plan);
  let row = null;
  try {
    row = await env.cybermeters_db
      .prepare("SELECT retention_days, auto_cleanup, updated_at FROM workspace_retention_settings WHERE workspace_id = ?")
      .bind(workspaceId)
      .first();
  } catch { /* migration may not be applied yet */ }
  const configuredDays = row ? (row.retention_days === null ? null : Number(row.retention_days)) : undefined;
  const effectiveDays = configuredDays === undefined ? planDefaultDays : configuredDays;
  return {
    plan,
    retention_days: effectiveDays,
    plan_default_retention_days: planDefaultDays,
    retention_policy: retentionDaysToPolicy(effectiveDays),
    auto_cleanup: row ? row.auto_cleanup !== 0 : true,
    source: row ? "workspace_setting" : "plan_default",
    updated_at: row?.updated_at ?? null,
  };
}

export async function getWorkspaceReportStorageMetrics(workspaceId, env) {
  const retention = await getWorkspaceRetentionSettings(workspaceId, env);
  let row;
  try {
    row = await env.cybermeters_db
      .prepare(
        `SELECT COUNT(*) AS reports_count,
                COALESCE(SUM(report_size_bytes), 0) AS stored_bytes,
                SUM(CASE WHEN report_size_bytes IS NULL THEN 1 ELSE 0 END) AS estimated_reports
         FROM workspace_reports
         WHERE workspace_id = ? AND deleted_at IS NULL`
      )
      .bind(workspaceId)
      .first();
  } catch {
    row = await env.cybermeters_db
      .prepare(
        `SELECT COUNT(*) AS reports_count
         FROM workspace_reports
         WHERE workspace_id = ? AND deleted_at IS NULL`
      )
      .bind(workspaceId)
      .first();
  }
  const reportsCount = Number(row?.reports_count ?? 0);
  const estimatedReports = Number(row?.estimated_reports ?? reportsCount);
  const estimatedReportBytes = 250_000;
  const storageBytes = Number(row?.stored_bytes ?? 0) + (estimatedReports * estimatedReportBytes);
  return {
    reports_count: reportsCount,
    storage_bytes: storageBytes,
    storage_estimated: estimatedReports > 0,
    retention_days: retention.retention_days,
    retention_policy: retention.retention_policy,
    auto_cleanup: retention.auto_cleanup,
  };
}

export async function getReportRetentionPolicyForWorkspace(workspaceId, env) {
  return (await getWorkspaceRetentionSettings(workspaceId, env)).retention_policy;
}

export function getRetentionCutoff(policy, now = new Date()) {
  if (policy === "forever") return null;
  const date = new Date(now.getTime());
  if (policy === "30_days") date.setUTCDate(date.getUTCDate() - 30);
  else if (policy === "90_days") date.setUTCDate(date.getUTCDate() - 90);
  else if (policy === "1_year") date.setUTCFullYear(date.getUTCFullYear() - 1);
  else if (policy === "2_years") date.setUTCFullYear(date.getUTCFullYear() - 2);
  else if (policy === "7_years") date.setUTCFullYear(date.getUTCFullYear() - 7);
  else date.setUTCFullYear(date.getUTCFullYear() - 2);
  return date.toISOString();
}

export function getReportExpiresAt(policy, effectiveAt) {
  if (!effectiveAt || policy === "forever") return null;
  const date = new Date(effectiveAt);
  if (Number.isNaN(date.getTime())) return null;
  if (policy === "30_days") date.setUTCDate(date.getUTCDate() + 30);
  else if (policy === "90_days") date.setUTCDate(date.getUTCDate() + 90);
  else if (policy === "1_year") date.setUTCFullYear(date.getUTCFullYear() + 1);
  else if (policy === "2_years") date.setUTCFullYear(date.getUTCFullYear() + 2);
  else if (policy === "7_years") date.setUTCFullYear(date.getUTCFullYear() + 7);
  else date.setUTCFullYear(date.getUTCFullYear() + 2);
  return date.toISOString();
}

export function planLimitExceeded(resource, limit, usage = null) {
  return {
    error: "plan_limit_exceeded",
    resource,
    limit,
    ...(usage === null ? {} : { usage }),
  };
}

export async function getOwnedWorkspaceIds(userId, env) {
  const rows = await env.cybermeters_db
    .prepare("SELECT id FROM workspaces WHERE owner_user_id = ? AND deleted_at IS NULL")
    .bind(userId)
    .all();
  return (rows.results || []).map((row) => row.id).filter(Boolean);
}

export async function getAccountUsage(userId, env) {
  const workspaceIds = await getOwnedWorkspaceIds(userId, env);
  let domains = 0;
  let users = 0;

  if (workspaceIds.length > 0) {
    const placeholders = workspaceIds.map(() => "?").join(",");
    const [domainRow, userRow] = await Promise.all([
      env.cybermeters_db
        .prepare(
          `SELECT COUNT(DISTINCT domain_id) AS cnt
           FROM workspace_domains
           WHERE workspace_id IN (${placeholders})`
        )
        .bind(...workspaceIds)
        .first(),
      env.cybermeters_db
        .prepare(
          `SELECT COUNT(DISTINCT user_id) AS cnt
           FROM workspace_members
           WHERE workspace_id IN (${placeholders})`
        )
        .bind(...workspaceIds)
        .first(),
    ]);
    domains = domainRow?.cnt ?? 0;
    users = userRow?.cnt ?? 0;
  }

  return {
    workspaces: workspaceIds.length,
    domains,
    users,
  };
}

export async function getEntitlementUsage(user, env, workspaceId = null) {
  const [accountUsage, tokRow] = await Promise.all([
    getAccountUsage(user.id, env),
    env.cybermeters_db
      .prepare("SELECT COUNT(*) AS cnt FROM api_tokens WHERE user_id = ? AND status = 'active'")
      .bind(user.id)
      .first(),
  ]);

  const usage = {
    ...accountUsage,
    api_tokens: tokRow?.cnt ?? 0,
    domains_in_workspace: null,
    scheduled_reports_in_workspace: null,
    scans_this_month: null,
    reports_this_month: null,
    scheduled_scans_in_workspace: null,
  };

  if (workspaceId) {
    const [domRow, srRow, schedScanRow, rptRow] = await Promise.all([
      env.cybermeters_db
        .prepare("SELECT COUNT(*) AS cnt FROM workspace_domains WHERE workspace_id = ?")
        .bind(workspaceId)
        .first(),
      env.cybermeters_db
        .prepare("SELECT COUNT(*) AS cnt FROM scheduled_reports WHERE workspace_id = ? AND enabled = 1")
        .bind(workspaceId)
        .first(),
      env.cybermeters_db
        .prepare("SELECT COUNT(*) AS cnt FROM scheduled_scans WHERE workspace_id = ? AND enabled = 1")
        .bind(workspaceId)
        .first(),
      env.cybermeters_db
        .prepare(
          `SELECT COUNT(*) AS cnt FROM workspace_reports
           WHERE workspace_id = ? AND status = 'completed' AND deleted_at IS NULL AND created_at >= ?`
        )
        .bind(workspaceId, getMonthStart())
        .first(),
    ]);
    usage.domains_in_workspace             = domRow?.cnt       ?? 0;
    usage.scheduled_reports_in_workspace   = srRow?.cnt        ?? 0;
    usage.scheduled_scans_in_workspace     = schedScanRow?.cnt ?? 0;
    usage.reports_this_month               = rptRow?.cnt       ?? 0;
  }

  // Scans-this-month is scoped to the billing owner, not a workspace
  const ownerUserId = workspaceId
    ? await getWorkspaceBillingUserId(workspaceId, user.id, env)
    : user.id;
  usage.scans_this_month = await countScansThisMonth(ownerUserId, env);

  return usage;
}

export async function getPlanContext(user, env) {
  const plan = await getEffectivePlan(user.id, env);
  const limits = getPlanLimits(plan);
  const usage = await getAccountUsage(user.id, env);
  return { plan, limits, usage };
}

// ── Upgrade Recommendation Engine ────────────────────────────────────────────
// Evaluates account-level usage against plan limits and emits upgrade signals
// at three severity thresholds: warning (≥80%), danger (≥90%), critical (=100%).
// Returns an array sorted by descending percentage so the most urgent signal
// is first. Returns [] for unlimited (enterprise) resources.

export function getUpgradeRecommendation(limits, usage) {
  const RESOURCES = [
    { key: "workspaces", label: "workspace" },
    { key: "domains",    label: "domain"    },
    { key: "users",      label: "user"      },
  ];

  const signals = [];

  for (const { key, label } of RESOURCES) {
    const limit = limits[key];
    const used  = usage[key];
    if (!limit || limit >= 999999 || used === null || used === undefined) continue;

    const pct = Math.round((used / limit) * 100);

    if (pct >= 100) {
      signals.push({
        resource:    key,
        level:       "critical",
        pct:         100,
        used,
        limit,
        message:     `You have reached your ${label} limit. Upgrade your plan to add more.`,
        upgrade_url: "/billing",
      });
    } else if (pct >= 90) {
      signals.push({
        resource:    key,
        level:       "danger",
        pct,
        used,
        limit,
        message:     `You are close to your ${label} limit (${pct}% used). Consider upgrading soon.`,
        upgrade_url: "/billing",
      });
    } else if (pct >= 80) {
      signals.push({
        resource:    key,
        level:       "warning",
        pct,
        used,
        limit,
        message:     `You are approaching your ${label} limit (${pct}% used).`,
        upgrade_url: "/billing",
      });
    }
  }

  // Sort highest percentage first
  signals.sort((a, b) => b.pct - a.pct);
  return signals;
}

export async function getWorkspaceOwnerId(workspaceId, env) {
  const row = await env.cybermeters_db
    .prepare("SELECT owner_user_id FROM workspaces WHERE id = ?")
    .bind(workspaceId)
    .first();
  return row?.owner_user_id || null;
}

export async function getWorkspaceBillingUserId(workspaceId, fallbackUserId, env) {
  return (await getWorkspaceOwnerId(workspaceId, env)) || fallbackUserId;
}

// ── Usage counting helpers (derived from source tables, no extra migration) ──

/** ISO timestamp for the first moment of the current calendar month (UTC). */
export function getMonthStart() {
  const d = new Date();
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}-01T00:00:00.000Z`;
}

/**
 * Count scans created this calendar month across all workspaces owned by ownerUserId.
 * Uses workspace ownership to scope correctly across multi-workspace accounts.
 */
export async function countScansThisMonth(ownerUserId, env) {
  try {
    const row = await env.cybermeters_db
      .prepare(
        `SELECT COUNT(s.id) AS cnt
         FROM scans s
         JOIN workspaces w ON w.id = s.workspace_id
         WHERE w.owner_user_id = ?
           AND s.created_at >= ?`
      )
      .bind(ownerUserId, getMonthStart())
      .first();
    return row?.cnt ?? 0;
  } catch {
    return 0;
  }
}

/**
 * Count completed workspace_reports created this calendar month for a specific workspace.
 */
export async function countReportsThisMonth(wsId, env) {
  try {
    const row = await env.cybermeters_db
      .prepare(
        `SELECT COUNT(id) AS cnt
         FROM workspace_reports
         WHERE workspace_id = ?
           AND status = 'completed'
           AND deleted_at IS NULL
           AND created_at >= ?`
      )
      .bind(wsId, getMonthStart())
      .first();
    return row?.cnt ?? 0;
  } catch {
    return 0;
  }
}

/**
 * Count enabled scheduled_scans for a workspace (cumulative, not per-month).
 * Scheduled scans are persistent config objects, not consumed resources.
 */
export async function countEnabledScheduledScans(wsId, env) {
  try {
    const row = await env.cybermeters_db
      .prepare(
        `SELECT COUNT(id) AS cnt
         FROM scheduled_scans
         WHERE workspace_id = ?
           AND enabled = 1`
      )
      .bind(wsId)
      .first();
    return row?.cnt ?? 0;
  } catch {
    return 0;
  }
}

// ── Plan enforcement helpers ─────────────────────────────────────────────────

/**
 * Returns the next month reset ISO timestamp (first moment of next month, UTC).
 */
export function getMonthResetAt() {
  const d = new Date();
  d.setUTCMonth(d.getUTCMonth() + 1, 1);
  d.setUTCHours(0, 0, 0, 0);
  return d.toISOString();
}

/**
 * Check scan monthly quota for the billing owner of workspaceId.
 * Returns null when quota is available, or { status, body } when blocked.
 * Fails open — quota check errors never block scans.
 */
export async function checkScanLimit(user, workspaceId, env) {
  try {
    const ownerUserId = await getWorkspaceBillingUserId(workspaceId, user.id, env);
    const plan   = await getEffectivePlan(ownerUserId, env);
    const limits = getPlanLimits(plan);
    const used   = await countScansThisMonth(ownerUserId, env);
    if (used >= limits.scans_per_month) {
      return {
        status: 403,
        body: {
          ...planLimitExceeded("scans_per_month", limits.scans_per_month, used),
          upgrade_message: `You have used ${used} of ${limits.scans_per_month} scans this month. Upgrade your plan for more scans.`,
          reset_at: getMonthResetAt(),
        },
      };
    }
    return null;
  } catch {
    return null; // fail-open: counting errors must never block legitimate scans
  }
}

/**
 * Check report generation monthly quota for workspaceId.
 * Returns null when quota is available, or { status, body } when blocked.
 * Fails open.
 */
export async function checkReportLimit(user, workspaceId, env) {
  try {
    const ownerUserId = await getWorkspaceBillingUserId(workspaceId, user.id, env);
    const plan   = await getEffectivePlan(ownerUserId, env);
    const limits = getPlanLimits(plan);
    const used   = await countReportsThisMonth(workspaceId, env);
    if (used >= limits.reports_per_month) {
      return {
        status: 403,
        body: {
          ...planLimitExceeded("reports_per_month", limits.reports_per_month, used),
          upgrade_message: `You have generated ${used} of ${limits.reports_per_month} reports this month. Upgrade your plan for more reports.`,
          reset_at: getMonthResetAt(),
        },
      };
    }
    return null;
  } catch {
    return null; // fail-open
  }
}

/**
 * Check whether workspaceId can add another enabled scheduled scan.
 * Returns null when quota is available, or { status, body } when blocked.
 * Fails open.
 */
export async function checkScheduledScanLimit(user, workspaceId, env) {
  try {
    const ownerUserId = await getWorkspaceBillingUserId(workspaceId, user.id, env);
    const plan   = await getEffectivePlan(ownerUserId, env);
    const limits = getPlanLimits(plan);
    const used   = await countEnabledScheduledScans(workspaceId, env);
    if (used >= limits.scheduled_scans) {
      return {
        status: 403,
        body: {
          ...planLimitExceeded("scheduled_scans", limits.scheduled_scans, used),
          upgrade_message: `You have ${used} of ${limits.scheduled_scans} scheduled scans configured. Upgrade your plan to add more.`,
        },
      };
    }
    return null;
  } catch {
    return null; // fail-open
  }
}

/**
 * evaluateScheduledScanEligibility — canonical run-time gate for a scheduled scan.
 *
 * A scheduled scan must satisfy the SAME current security/entitlement/quota rules
 * as a manual scan at EXECUTION time — never only the checks made when the schedule
 * was created. This reuses the canonical helpers (no plan rules are copied here) and
 * returns a stable reason code so the caller can skip with zero side effects.
 *
 * Order matters: cheap security/entitlement checks first; the rate limiter (which
 * CONSUMES a token) runs last, only once we would actually start.
 *
 * @param {object} params.consumeRateLimit optional async ({billingOwnerId, plan}) =>
 *        null (allowed) | {status} (blocked/fail-closed). Injected so this module
 *        stays free of the index.js rate limiter (avoids a circular import).
 * @returns {{ok: true} | {ok: false, reason: string}}
 *   reasons: workspace_not_accessible | domain_verification_required |
 *            feature_not_entitled | scan_limit_exceeded | rate_limit_unavailable
 */
export async function evaluateScheduledScanEligibility(env, { workspaceId, domainId, ownerUserId, consumeRateLimit } = {}) {
  // 1 + 3 + 6. Workspace must exist, not be soft-deleted, and be resolvable.
  if (!workspaceId || !domainId) return { ok: false, reason: "workspace_not_accessible" };
  const ws = await env.cybermeters_db
    .prepare("SELECT owner_user_id FROM workspaces WHERE id = ? AND deleted_at IS NULL LIMIT 1")
    .bind(workspaceId).first().catch(() => null);
  if (!ws) return { ok: false, reason: "workspace_not_accessible" };

  // 1 + 2. Exact (workspace_id, domain_id) link must exist AND be verified.
  const verified = await isWorkspaceDomainVerified(env, workspaceId, domainId).catch(() => false);
  if (!verified) return { ok: false, reason: "domain_verification_required" };

  // Resolve the billing owner + current effective plan (subscriptions-based,
  // grace/expiry aware) once, for the feature/quota/rate checks below.
  const billingOwnerId = await getWorkspaceBillingUserId(workspaceId, ownerUserId, env).catch(() => ownerUserId);
  const plan = await getEffectivePlan(billingOwnerId, env);

  // 4. Scheduled-scans feature must be entitled on the CURRENT effective plan.
  if (!hasFeatureEntitlement(plan, "scheduled_scans")) return { ok: false, reason: "feature_not_entitled" };

  // 5. Monthly scan quota must allow another scan (canonical checker; fail-open on
  // counting errors, exactly like the manual path).
  const quota = await checkScanLimit({ id: ownerUserId }, workspaceId, env);
  if (quota) return { ok: false, reason: "scan_limit_exceeded" };

  // 7. Scan-start rate limit — fail CLOSED (expensive action). Consumes a token, so last.
  if (typeof consumeRateLimit === "function") {
    const rl = await consumeRateLimit({ billingOwnerId, plan });
    if (rl) return { ok: false, reason: "rate_limit_unavailable" };
  }

  return { ok: true };
}

