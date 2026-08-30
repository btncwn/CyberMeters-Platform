// ── Operational health signals ───────────────────────────────────────────────
// Read-only checks for the classes of failure that don't surface as a single
// request error but accumulate silently: stuck scans, a backlog of undelivered
// emails, deletion purges that never completed. The daily cron heartbeat
// (opsHealthHeartbeat) runs these and emails ops ONLY when something is breached,
// so a healthy system stays quiet. Real-time 5xx/error-rate alerting is a
// separate concern handled by Cloudflare Notification rules (see
// docs/MONITORING.md) fed by the http_5xx metric and [request-error] logs.
//
// Every check is independent and defensive: a query that throws (e.g. a table
// that doesn't exist yet) yields a skipped signal, never a false alarm.
//
// F-027 EXTENDS this file (additive): the /ready operational booleans + deadman
// verdict below reuse the operational_events ledger. The existing daily heartbeat
// (computeOpsHealth / formatOpsHealthEmail) is UNCHANGED.
import { latestOperationalEvent, readRecentOperationalEventCount, OPS_EVENT_TYPES } from "./operational-events.js";

// Thresholds — a small number of transient failures is normal; a standing
// backlog is the signal. Tuned conservatively to avoid noise; adjust here.
export const OPS_THRESHOLDS = {
  stuck_scans: 3,             // scans stuck 'running' well past the ~15s completion
  failed_lifecycle_emails: 10, // undelivered lifecycle emails past auto-retry
  lifecycle_emails_outcome_unknown: 1, // any stale provider-ambiguous lifecycle outcome
  failed_asset_alerts: 10,    // undelivered asset-change alerts
  overdue_deletions: 1,       // any deletion request past the 30-day window + buffer
};

async function count(env, sql) {
  try {
    const row = await env.cybermeters_db.prepare(sql).first();
    const n = row ? Number(row.c ?? Object.values(row)[0]) : 0;
    return Number.isFinite(n) ? n : null;
  } catch {
    return null; // table/column absent or DB unreachable — skip, don't alarm
  }
}

/**
 * computeOpsHealth(env) → { healthy, checkedAt, dbReachable, signals: [...] }
 * Each signal: { key, label, count, threshold, breached, skipped }.
 * Read-only. Never throws.
 */
export async function computeOpsHealth(env) {
  const checks = [
    {
      key: "stuck_scans",
      label: "Scans stuck in 'running'",
      sql: "SELECT COUNT(*) c FROM scans WHERE status = 'running' AND created_at < datetime('now','-15 minutes')",
    },
    {
      key: "failed_lifecycle_emails",
      label: "Undelivered lifecycle emails (past retry)",
      sql: "SELECT COUNT(*) c FROM lifecycle_email_events WHERE status = 'failed' AND type != 'lifecycle_payment_failed'",
    },
    {
      key: "lifecycle_emails_outcome_unknown",
      label: "Lifecycle email outcomes requiring reconciliation",
      sql: `SELECT COUNT(*) c
            FROM lifecycle_email_events
            WHERE type NOT IN ('lifecycle_payment_failed','lifecycle_weekly_digest')
              AND created_at < datetime('now','-15 minutes')
              AND (
                status = 'sending'
                OR (status = 'pending' AND COALESCE(error, '') != 'provider_not_started')
                OR (status = 'failed' AND error IN ('timeout','network_error'))
              )`,
    },
    {
      key: "failed_asset_alerts",
      label: "Undelivered asset-change alerts",
      sql: "SELECT COUNT(*) c FROM asset_alert_records WHERE status = 'failed'",
    },
    {
      key: "overdue_deletions",
      label: "Deletion requests overdue for purge (>35d)",
      sql: "SELECT COUNT(*) c FROM deletion_requests WHERE status IN ('pending','purging') AND created_at < datetime('now','-35 days')",
    },
  ];

  const signals = [];
  for (const chk of checks) {
    const n = await count(env, chk.sql);
    const threshold = OPS_THRESHOLDS[chk.key];
    signals.push({
      key: chk.key,
      label: chk.label,
      count: n,
      threshold,
      skipped: n === null,
      breached: n !== null && n >= threshold,
    });
  }

  // D1 reachability: if every signal was skipped, the database is likely down.
  const dbReachable = signals.some((s) => !s.skipped);
  const outcomeUnknownReadable = signals.find((s) => s.key === "lifecycle_emails_outcome_unknown")?.skipped === false;
  const healthy = dbReachable && outcomeUnknownReadable && signals.every((s) => !s.breached);

  return { healthy, dbReachable, signals };
}

/**
 * formatOpsHealthEmail(health) → { subject, text, html } | null
 * Returns null when healthy (nothing to send). Pure formatting.
 */
export function formatOpsHealthEmail(health, { version = "dev" } = {}) {
  if (health.healthy) return null;

  const breached = health.signals.filter((s) => s.breached);
  const unavailable = health.signals.filter((s) => s.skipped);
  const lines = [];
  if (!health.dbReachable) {
    lines.push("• Database appears UNREACHABLE — every health query was skipped.");
  }
  for (const s of breached) {
    lines.push(`• ${s.label}: ${s.count} (threshold ${s.threshold})`);
  }
  if (health.dbReachable) {
    for (const s of unavailable) lines.push(`• ${s.label}: query unavailable`);
  }

  const issueCount = breached.length + unavailable.length;
  const subject = `⚠️ CyberMeters ops health: ${!health.dbReachable
    ? "DB unreachable"
    : unavailable.length > 0
      ? `${issueCount} check(s) require attention`
      : `${breached.length} check(s) breached`}`;
  const text =
    `CyberMeters operational health check found issues (version ${version}):\n\n` +
    lines.join("\n") +
    `\n\nThis is the daily self-check. See docs/MONITORING.md for the response runbook.`;
  const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const html =
    `<h2>CyberMeters ops health check</h2>` +
    `<p>The daily self-check found issues (version ${esc(version)}):</p>` +
    `<ul>${lines.map((l) => `<li>${esc(l.replace(/^•\s*/, ""))}</li>`).join("")}</ul>` +
    `<p>See <code>docs/MONITORING.md</code> for the response runbook.</p>`;

  return { subject, text, html };
}

// ── F-027: /ready operational booleans + deadman verdict (additive) ───────────

// Age in minutes of an ISO-8601 timestamp, or null if unparseable/absent.
function ageMinutes(iso, nowMs) {
  if (typeof iso !== "string" || !iso) return null;
  const t = Date.parse(iso.includes("T") ? iso : `${iso.replace(" ", "T")}Z`);
  if (!Number.isFinite(t)) return null;
  return (nowMs - t) / 60000;
}

const CRON_STALE_AFTER_MIN   = 90;   // hourly cron: stale if no tick in 90m
const BACKUP_STALE_AFTER_MIN = 1560; // daily backup: stale if none in 26h (F-004 emits the event)
const DLQ_RECENT_WINDOW_MIN  = 60;
const STALE_SCAN_AFTER_MIN   = 60;   // a scan stuck 'queued'/'running' > 60m

/**
 * Compute the operational booleans for /ready and the deadman. Every check FAILS
 * CLOSED: an unavailable read yields the UNHEALTHY value, never an optimistic
 * true. Non-sensitive only — no raw content.
 */
export async function computeOperationalHealth(env, { nowMs = null } = {}) {
  const now = Number.isFinite(nowMs) ? nowMs : Date.parse(new Date().toISOString());

  const cronRow   = await latestOperationalEvent(env, OPS_EVENT_TYPES.CRON_TICK).catch(() => null);
  const backupRow = await latestOperationalEvent(env, "backup_completed").catch(() => null);
  const cronAge   = cronRow ? ageMinutes(cronRow.created_at, now) : null;
  const backupAge = backupRow ? ageMinutes(backupRow.created_at, now) : null;

  // Recent-DLQ read: a read FAILURE must be DISTINGUISHABLE from a proven zero
  // (R1-02). readRecentOperationalEventCount reports readability, so an unreadable
  // window fails closed to unhealthy instead of fabricating a reassuring 0.
  const recentDlqRead = await readRecentOperationalEventCount(
    env, OPS_EVENT_TYPES.SCAN_DLQ_OBSERVED, DLQ_RECENT_WINDOW_MIN,
  ).catch(() => ({ readable: false, count: null }));

  let staleQueuedScan = false;
  try {
    const row = await env.cybermeters_db
      .prepare(
        `SELECT COUNT(*) AS n FROM scans
          WHERE status IN ('queued','running')
            AND created_at < strftime('%Y-%m-%dT%H:%M:%fZ','now', ?)`
      )
      .bind(`-${STALE_SCAN_AFTER_MIN} minutes`).first();
    staleQueuedScan = Number(row?.n || 0) > 0;
  } catch {
    // Read failed → we cannot prove there is no stuck scan → report the unsafe
    // value (true) so the deadman errs toward alerting, never toward silence.
    staleQueuedScan = true;
  }

  return {
    cron_fresh:        cronAge !== null && cronAge <= CRON_STALE_AFTER_MIN,
    cron_age_minutes:  cronAge === null ? null : Math.round(cronAge),
    backup_fresh:      backupAge !== null && backupAge <= BACKUP_STALE_AFTER_MIN,
    backup_age_minutes: backupAge === null ? null : Math.round(backupAge),
    // A read failure is NOT a proven zero: events null + readable false carry that
    // distinctly, and recent_dlq_readable is the fail-closed signal the deadman reads.
    recent_dlq_events: recentDlqRead.readable ? recentDlqRead.count : null,
    recent_dlq:        recentDlqRead.readable ? recentDlqRead.count > 0 : false,
    recent_dlq_readable: recentDlqRead.readable,
    stale_queued_scan: staleQueuedScan,
  };
}

/**
 * Single "operationally healthy" verdict for the deadman: cron fresh, backup
 * fresh, no stuck scan, and the recent-DLQ window PROVEN READABLE. recent-DLQ
 * readability is held to the SAME typed contract as the other operational fields:
 * only the literal boolean `true` clears it. A string "true"/"false", null, or an
 * absent field (an older/malformed/schema-drifted body) fails closed — an
 * unproved readability signal is never healthy. The presence of recent DLQ EVENTS
 * (recent_dlq) stays advisory and does not by itself flip this verdict.
 */
export function isOperationallyHealthy(booleans) {
  if (!booleans || typeof booleans !== "object") return false;
  return booleans.cron_fresh === true &&
    booleans.backup_fresh === true &&
    booleans.stale_queued_scan === false &&
    booleans.recent_dlq_readable === true;
}

/**
 * Deadman verdict (contract item 5): HEALTHY only when the HTTP probe is 200 AND
 * the body is valid JSON carrying true operational fields. A 200 with missing/
 * garbled JSON or stale operational booleans is NOT healthy — fail closed so a
 * broken deploy that still returns 200 cannot silence the deadman.
 */
export function evaluateDeadman(httpOk, parsedBody) {
  if (httpOk !== true) return { healthy: false, reason: "http_not_ok" };
  if (!parsedBody || typeof parsedBody !== "object") return { healthy: false, reason: "invalid_json" };
  const op = parsedBody.operational;
  if (!op || typeof op !== "object") return { healthy: false, reason: "no_operational_fields" };
  if (op.cron_fresh !== true) return { healthy: false, reason: "cron_stale" };
  if (op.backup_fresh !== true) return { healthy: false, reason: "backup_stale" };
  if (op.stale_queued_scan !== false) return { healthy: false, reason: "stale_queued_scan" };
  // R1-02 (delta): the recent-DLQ window must be PROVEN readable — the same
  // TYPE-AND-VALUE contract as the fields above (reject unless literal `true`).
  // A string "true"/"false", null, or an absent field (older/malformed/schema-
  // drifted body) fails closed, so a body that never proved the window readable
  // cannot silence the deadman.
  if (op.recent_dlq_readable !== true) return { healthy: false, reason: "recent_dlq_unreadable" };
  return { healthy: true, reason: "ok" };
}

export { CRON_STALE_AFTER_MIN, BACKUP_STALE_AFTER_MIN, STALE_SCAN_AFTER_MIN, DLQ_RECENT_WINDOW_MIN };
