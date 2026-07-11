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

// Thresholds — a small number of transient failures is normal; a standing
// backlog is the signal. Tuned conservatively to avoid noise; adjust here.
export const OPS_THRESHOLDS = {
  stuck_scans: 3,             // scans stuck 'running' well past the ~15s completion
  failed_lifecycle_emails: 10, // undelivered lifecycle emails past auto-retry
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
  const healthy = dbReachable && signals.every((s) => !s.breached);

  return { healthy, dbReachable, signals };
}

/**
 * formatOpsHealthEmail(health) → { subject, text, html } | null
 * Returns null when healthy (nothing to send). Pure formatting.
 */
export function formatOpsHealthEmail(health, { version = "dev" } = {}) {
  if (health.healthy) return null;

  const breached = health.signals.filter((s) => s.breached);
  const lines = [];
  if (!health.dbReachable) {
    lines.push("• Database appears UNREACHABLE — every health query was skipped.");
  }
  for (const s of breached) {
    lines.push(`• ${s.label}: ${s.count} (threshold ${s.threshold})`);
  }

  const subject = `⚠️ CyberMeters ops health: ${!health.dbReachable ? "DB unreachable" : `${breached.length} check(s) breached`}`;
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
