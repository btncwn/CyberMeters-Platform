// ── Cron orchestration module ─────────────────────────────────────────────────
// Sprint 9 phase-1 extraction: the scheduled() entry and its timing/telemetry
// wrapper live here. Task BODIES stay in index.js (their closure reaches the
// scan engine — moving them is phase 2) and are injected via the `tasks`
// registry, so this module has no import cycle.
import { recordMetric } from "../lib/metrics.js";

// Runs a scheduled task with duration + outcome telemetry. A failure is recorded
// as a cron_task metric and an [cron-error] alert-level log (which a Cloudflare
// Logpush / notification rule can trigger on), but never rethrows — matching the
// existing fire-and-forget cron isolation where one task never aborts another.
export async function runCronTask(env, name, fn) {
  const start = Date.now();
  try {
    await fn();
    recordMetric(env, "cron_task", { blobs: [name, "ok"], doubles: [Date.now() - start], indexes: [name] });
  } catch (e) {
    const dur = Date.now() - start;
    recordMetric(env, "cron_task", { blobs: [name, "error"], doubles: [dur], indexes: [name] });
    console.error("[cron-error]", JSON.stringify({ task: name, duration_ms: dur, error: String(e?.message ?? e) }));
  }
}

// ── Cron Handler ──────────────────────────────────────────────────────
export async function runScheduled(event, env, ctx, tasks) {
  const now = new Date().toISOString();

  // ── Scheduled scans ────────────────────────────────────────────────────
  let result;
  try {
    result = await env.cybermeters_db
      .prepare(
        `SELECT id, domain, frequency, workspace_id
         FROM scheduled_scans
         WHERE enabled = 1
           AND (next_run_at IS NULL OR next_run_at <= ?)
         ORDER BY next_run_at ASC
         LIMIT 20`
      )
      .bind(now)
      .all();
  } catch {
    // Table may not exist yet — nothing to process
  }

  for (const schedule of (result?.results || [])) {
    // Each schedule runs independently so one failure cannot abort others
    ctx.waitUntil(tasks.triggerScheduledScan(schedule, env));
  }

  // ── Scheduled executive reports ────────────────────────────────────────
  // Weekly on Mondays, monthly on the 1st of the month.
  // generateScheduledReports is a no-op on all other days.
  ctx.waitUntil(runCronTask(env, "scheduled_reports", () => tasks.generateScheduledReports(now, env)));

	    // ── User-configured scheduled reports ─────────────────────────────────
	    // Canonical beta path: scheduled_reports, which is used by the active
	    // Workspace Reports UI. The newer report_schedules processor is paused
	    // until existing schedules can be migrated without duplicate generation.
	    ctx.waitUntil(runCronTask(env, "user_scheduled_reports", () => tasks.processScheduledReports(now, env)));

	    // ── Hosted DNS records verification (Hosted Records Engine) ──────────
	    // Retries pending Cloudflare creations, verifies both sides of every
	    // hosted DMARC record, alerts on disconnection, completes safe removals.
	    ctx.waitUntil(runCronTask(env, "hosted_dns_sweep", () => tasks.runHostedDnsVerificationSweep(env)));

	    // ── DMARC operational alerts (new sender / spoofing spike) ───────────
	    // Turns classified sender data into actionable alerts through the
	    // notification pipeline; deduped, tenant-scoped, read-only.
	    if (tasks.runDmarcAlertsSweep) {
	      ctx.waitUntil(runCronTask(env, "dmarc_alerts_sweep", () => tasks.runDmarcAlertsSweep(env)));
	    }

	    // ── Report retention cleanup ─────────────────────────────────────────
  // The Worker cron also drives scheduled scans, so keep the hourly trigger
  // and run retention once daily at 02:00 UTC.
  if (new Date(now).getUTCHours() === 2) {
    ctx.waitUntil(runCronTask(env, "report_retention", () => tasks.cleanupExpiredReports(now, env)));
  }

  // ── Ops-health heartbeat ─────────────────────────────────────────────
  // Once daily at 08:00 UTC: read-only self-check for silent-accumulation
  // failures (stuck scans, undelivered-email backlog, overdue purges). Emails
  // ops only when a threshold is breached; at most one alert per day, no spam.
  if (tasks.opsHealthHeartbeat && new Date(now).getUTCHours() === 8) {
    ctx.waitUntil(runCronTask(env, "ops_health_heartbeat", () => tasks.opsHealthHeartbeat(env)));
  }

  // ── Weekly Exposure Timeline digest ──────────────────────────────────
  // Mondays at 08:00 UTC: the "what changed this week" email to active
  // workspaces. Deduped per ISO week; quiet weeks send a short reassurance,
  // dormant workspaces get nothing.
  if (tasks.sendWeeklyDigests && new Date(now).getUTCDay() === 1 && new Date(now).getUTCHours() === 8) {
    ctx.waitUntil(runCronTask(env, "weekly_digest", () => tasks.sendWeeklyDigests(env)));
  }

  // ── Deletion purge (soft-delete → 30-day window → hard delete) ────────
  // Bounded per run; requests inside the restore window are never touched.
  ctx.waitUntil(runCronTask(env, "deletion_purge", () => tasks.processDeletionRequests(env)));

  // ── Retry failed lifecycle emails from this clean context ─────────────
  // Recovers emails whose first send failed inside a heavy invocation
  // (e.g. first-scan-completed sent at the end of the scan engine).
  ctx.waitUntil(runCronTask(env, "lifecycle_email_retry", () => tasks.retryFailedLifecycleEmails(env)));

  // ── Retry failed asset change alert emails ────────────────────────────
  // Same recovery pattern: the original send runs at the end of the
  // subrequest-heavy scan engine, where the outbound Resend fetch can fail.
  ctx.waitUntil(runCronTask(env, "asset_alert_retry", () => tasks.retryFailedAssetAlerts(env)));

  // ── Domain verification auto-retry ─────────────────────────────────────
  // Re-checks recently initiated/failed DNS TXT verifications for 48h so
  // slow registrar propagation (e.g. GoDaddy) verifies without the customer
  // having to keep pressing the Verify button.
  ctx.waitUntil(runCronTask(env, "domain_verify_retry", () => tasks.retryPendingDomainVerifications(env)));
}
