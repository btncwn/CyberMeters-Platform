// ── Cron orchestration module ─────────────────────────────────────────────────
// Sprint 9 phase-1 extraction: the scheduled() entry and its timing/telemetry
// wrapper live here. Task BODIES stay in index.js (their closure reaches the
// scan engine — moving them is phase 2) and are injected via the `tasks`
// registry, so this module has no import cycle.
import { recordMetric } from "../lib/metrics.js";
import { persistOperationalEvent, OPS_EVENT_TYPES } from "../lib/operational-events.js";
import { isScheduledQueueDispatchMode } from "../engines/scan-dispatch.js";
import { cleanupExpiredAuditEvents } from "./audit-retention.js";
import { cleanupExpiredMcpRateLimits } from "./mcp-rate-retention.js";
import { drainRevokedMcpOAuthGrantBacklog, purgeExpiredMcpOAuthRefreshUses } from "../routes/mcp-oauth-purge.js";

// Scheduled-scan burst controls. Each full scan fans out ~80-250 subrequests,
// and every due scan in a tick shares the ONE Worker invocation's 1,000-
// subrequest budget (waitUntil work does not get a fresh budget). So we cap both
// how many are picked per tick AND how many run concurrently: peak fan-out ≈
// CONCURRENCY × max_per_scan, kept well under 1,000. In queue mode a pick is
// admission + dispatch only (~20 D1 queries, measured by scripts/lab/load-lab.mjs),
// and the same cap keeps a tick inside the invocation's 1,000-query D1 budget.
export const SCHEDULED_SCAN_MAX_PER_TICK = 12;
export const SCHEDULED_SCAN_CONCURRENCY = 3;

// The hourly tick runs every task. The dispatch ticks between the hours run the
// scheduled-scan dispatch alone, so a schedule waits at most ten minutes for
// its turn and each tick hands the queue a small batch rather than one large
// burst on the hour.
export const HOURLY_CRON = "0 * * * *";
export const DISPATCH_CRON = "10,20,30,40,50 * * * *";
export const DISPATCH_TICK_MS = 10 * 60 * 1000;

// Free previews use one-hour windows and also write the shared five-minute
// per-IP API guard; the free tools use up to 24-hour windows. Delete only these
// expired public API counter families;
// login, scan admission and email rate limits are outside this policy.
export async function cleanupExpiredPublicApiRateLimits(env, nowIso) {
  const nowMs = Date.parse(nowIso);
  if (!Number.isFinite(nowMs)) throw new TypeError("Invalid public API cleanup time");
  const freeCutoff = new Date(nowMs - (24 * 60 * 60 + 3600) * 1000).toISOString();
  const globalCutoff = new Date(nowMs - (24 * 60 * 60 + 300) * 1000).toISOString();
  // Free tools: rolling 24-hour slots and hourly/daily windows. A row whose
  // window started over 25 hours ago can no longer refuse anyone.
  const toolCutoff = new Date(nowMs - (25 * 60 * 60) * 1000).toISOString();
  return env.cybermeters_db.prepare(
    `DELETE FROM api_rate_limits
     WHERE (action IN ('free_scan', 'free_scan_domain', 'free_scan_global')
            AND window_seconds = 3600 AND window_start < ?)
        OR (action IN ('global_read', 'global_write')
            AND window_seconds = 300 AND window_start < ?)
        OR (action LIKE 'free!_tool!_%' ESCAPE '!'
            AND window_seconds <= 86400 AND window_start < ?)`,
  ).bind(freeCutoff, globalCutoff, toolCutoff).run();
}

// Due schedules are picked one account at a time: every account's oldest due
// schedule first (oldest account first), then every account's second, and so
// on. An account with hundreds of schedules due at once takes its turn beside
// accounts with one, instead of ahead of them.
export const FAIR_DUE_SCHEDULES_SQL = `
  SELECT id, domain, frequency, workspace_id, next_run_at, last_run_at, created_at
  FROM (
    SELECT ss.id, ss.domain, ss.frequency, ss.workspace_id, ss.next_run_at, ss.last_run_at, ss.created_at,
           ROW_NUMBER() OVER (
             PARTITION BY COALESCE(w.owner_user_id, ss.workspace_id, ss.id)
             ORDER BY ss.next_run_at ASC, ss.id ASC
           ) AS account_turn
    FROM scheduled_scans ss
    LEFT JOIN workspaces w ON w.id = ss.workspace_id
    WHERE ss.enabled = 1
      AND (ss.next_run_at IS NULL OR ss.next_run_at <= ?)
  )
  ORDER BY account_turn ASC, next_run_at ASC, id ASC
  LIMIT ${SCHEDULED_SCAN_MAX_PER_TICK}`;

// The next dispatch tick after `nowMs`: where a schedule that could not start
// this tick goes back in line.
export function nextDispatchTickIso(nowMs) {
  return new Date((Math.floor(nowMs / DISPATCH_TICK_MS) + 1) * DISPATCH_TICK_MS).toISOString();
}

const DAY_MS = 24 * 60 * 60 * 1000;
export const LONG_FAILING_RETRY_MS = 60 * 60 * 1000;

// D1 holds both `YYYY-MM-DD HH:MM:SS` (SQLite default) and ISO strings.
function parseScheduleTime(value) {
  if (!value) return null;
  const text = String(value);
  const ms = Date.parse(text.includes("T") ? text : `${text.replace(" ", "T")}Z`);
  return Number.isFinite(ms) ? ms : null;
}

// Where a schedule that did not start goes back in line. Most reasons pass
// within minutes (a scan of the domain already running, the account's waiting
// scans), so it is retried on the next dispatch tick. A schedule that has not
// started for two of its periods is waiting on its customer (verification
// removed, plan ended), so it is retried hourly and leaves the ticks between
// to schedules that can run.
export function retryAtFor(schedule, nowMs) {
  const periodMs = schedule?.frequency === "weekly" ? 7 * DAY_MS : DAY_MS;
  const lastStarted = parseScheduleTime(schedule?.last_run_at) ?? parseScheduleTime(schedule?.created_at);
  const failingLong = lastStarted == null || nowMs - lastStarted > 2 * periodMs;
  return failingLong ? nextDispatchTickIso(nowMs + LONG_FAILING_RETRY_MS - DISPATCH_TICK_MS) : nextDispatchTickIso(nowMs);
}

// One due schedule: start it, and if it did not start — its workspace has no
// owner, it is no longer eligible, a scan of that domain is already running,
// or admission refused it — move it back in line (retryAtFor). Left due, it
// would stay the oldest due schedule and be picked first on every tick, and a
// dozen such schedules would take every slot from every account for good. The
// write only moves a schedule whose due time this tick did not change, so a
// schedule the trigger stamped is never touched.
export async function dispatchDueSchedule(schedule, env, tasks, nowMs) {
  try {
    await tasks.triggerScheduledScan(schedule, env);
  } finally {
    await env.cybermeters_db
      .prepare(
        `UPDATE scheduled_scans SET next_run_at = ?
         WHERE id = ? AND enabled = 1 AND next_run_at IS ?`
      )
      .bind(retryAtFor(schedule, nowMs), schedule.id, schedule.next_run_at ?? null)
      .run()
      .catch(() => { /* the schedule stays due; the next tick retries it */ });
  }
}

// Bounded worker pool: at most `concurrency` fn(item) run at once. Per-item
// failures are isolated — one scan can never abort another — preserving the
// prior fire-and-forget isolation while capping concurrent subrequest fan-out.
export async function runBoundedPool(items, concurrency, fn) {
  let cursor = 0;
  const worker = async () => {
    while (cursor < items.length) {
      const item = items[cursor++];
      try { await fn(item); } catch { /* isolated — the pool continues */ }
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, items.length)) }, worker));
}

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
  const dispatchOnly = event?.cron === DISPATCH_CRON;
  // Outside queue mode a pick runs the whole scan inline, for minutes; a
  // dispatch tick ten minutes later could pick a schedule the previous tick
  // has not stamped yet and run it twice. Those ticks dispatch only in queue
  // mode, where a pick is admission and a queue message.
  if (dispatchOnly && !isScheduledQueueDispatchMode(env)) return;

  // F-027: durable proof the hourly cron actually ran. One idempotent event per
  // hour bucket (safe correlation id, no content), so a deadman monitor can tell
  // "cron is firing" from "cron silently stopped". Never fatal to the tick.
  if (!dispatchOnly) {
    const hourBucket = now.slice(0, 13);
    await persistOperationalEvent(env, {
      eventType:     OPS_EVENT_TYPES.CRON_TICK,
      correlationId: `cron:${hourBucket}`,
      status:        "ok",
    }).catch(() => { /* observability is best-effort; the tick's real work follows */ });
  }

  // ── Scheduled scans ────────────────────────────────────────────────────
  let result;
  const queryCorrelationId = `scheduled-scan:${now.slice(0, 16)}:${crypto.randomUUID()}`;
  await runCronTask(env, "scheduled_scan_dispatch", async () => {
    let status = "ok";
    try {
      result = await env.cybermeters_db
        .prepare(FAIR_DUE_SCHEDULES_SQL)
        .bind(now)
        .all();
    } catch (error) {
      if (/no such table:\s*scheduled_scans\b/i.test(String(error?.message ?? error))) {
        status = "table_missing";
      } else {
        status = "error";
        const recorded = await persistOperationalEvent(env, {
          eventType: OPS_EVENT_TYPES.SCHEDULED_SCAN_QUERY,
          correlationId: queryCorrelationId,
          status,
        });
        if (!recorded.persisted) console.error("[scheduled-scan-query] failure event unavailable");
        throw error;
      }
    }
    const recorded = await persistOperationalEvent(env, {
      eventType: OPS_EVENT_TYPES.SCHEDULED_SCAN_QUERY,
      correlationId: queryCorrelationId,
      status,
    });
    if (!recorded.persisted) throw new Error("scheduled scan query outcome could not be recorded");
  });

  // Run the due scans through a bounded pool so at most SCHEDULED_SCAN_CONCURRENCY
  // full scans fan out at once — the shared 1,000-subrequest budget is never blown
  // even when many rich-domain schedules are due in the same tick.
  const dueScans = result?.results || [];
  if (dueScans.length > 0) {
    const nowMs = Date.parse(now);
    ctx.waitUntil(runBoundedPool(dueScans, SCHEDULED_SCAN_CONCURRENCY, (schedule) => dispatchDueSchedule(schedule, env, tasks, nowMs)));
  }
  if (dispatchOnly) return;

  // One revoked MCP grant per hourly tick. D1 already rejects its tokens;
  // this bounded retry removes provider KV state after transient failures.
  ctx.waitUntil(runCronTask(env, "mcp_revoked_grant_cleanup",
    () => drainRevokedMcpOAuthGrantBacklog(env)));

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

	    // ── DMARC sender alerts: REMOVED in PR-B3, deliberately not replaced ──
	    // `dmarc_alerts_sweep` ran hourly and graded senders from the CUMULATIVE
	    // email_sender_sources counters, which never decrease. Its threshold
	    // therefore latched true forever once crossed, and only a 24h dedupe
	    // stopped it re-alerting every single day for the life of the sender.
	    // Recovery was not merely missing — it was inexpressible.
	    //
	    // The canonical replacement is NOT a sweep. Sender evaluation runs in
	    // dmarc-ingest.js when a new aggregate report lands, because that is the
	    // only moment receiver-reported evidence can change. Nothing to schedule:
	    // no new evidence, no evaluation, no alert. Do not re-add a sweep here.

	    // ── Managed-alert delivery retry (bounded) ──────────────────────────
	    // Re-attempts ONLY transient email failures from the append-only ledger:
	    // bounded LIMIT, max attempts, max age and deterministic backoff, and it
	    // re-checks workspace/entitlement/preference/recipients before resending.
	    // Terminal suppressions are never revisited.
	    if (tasks.retryFailedAlertDeliveries) {
	      ctx.waitUntil(runCronTask(env, "alert_delivery_retry", () => tasks.retryFailedAlertDeliveries(env)));
	    }

	    // ── Interrupted-scan terminal recovery (bounded, idempotent) ─────────
	    // The ONE canonical repair path for scans abandoned mid-flight (e.g. the
	    // HTTP post-response ~30 s waitUntil kill, 22 Jul 2026 incident): a row
	    // far beyond any legitimate runtime, with a stale heartbeat and no
	    // terminal R2 report, becomes an honest `failed` — never healthy, never
	    // scored, one append-only audit event. GET list/detail are read-only and
	    // never perform this repair.
	    if (tasks.recoverInterruptedScans) {
	      ctx.waitUntil(runCronTask(env, "interrupted_scan_recovery", () => tasks.recoverInterruptedScans(env)));
	    }

	    // ── Managed Brand Protection follow-up ───────────────────────────────
	    // Advances takedown submissions through provider follow-up and performs
	    // CyberMeters-only technical verification of resolved/reappeared cases.
	    if (tasks.runBrandTakedownFollowupSweep) {
	      ctx.waitUntil(runCronTask(env, "brand_takedown_followup", () => tasks.runBrandTakedownFollowupSweep(env)));
	    }

	    // ── Brand DNS enrichment (bounded, incremental) ──────────────────────
	    // Scan-time typosquat candidates are persisted UNCHECKED (DNS probe deferred
	    // to keep the scan within its subrequest budget). Without this sweep they
	    // would stay unchecked forever unless a user hit manual refresh — so
	    // "Active DNS" read 0. This runs a bounded batch each hour so candidates are
	    // eventually deterministically validated with no user action.
	    if (tasks.runBrandDnsEnrichmentSweep) {
	      ctx.waitUntil(runCronTask(env, "brand_dns_enrichment", () => tasks.runBrandDnsEnrichmentSweep(env)));
	    }

	    // ── Brand HTTP/TLS live enrichment (daily) ───────────────────────────
	    // For lookalike candidates DNS has confirmed live, probe the live web
	    // surface (through the SSRF-safe fetcher) to set https_available and detect a
	    // real login/password form. Runs at 04:00 UTC, one hour after discovery, so
	    // hosts found by the discovery sweep have had a DNS-enrichment tick first.
	    if (tasks.runBrandHttpEnrichmentSweep && new Date(now).getUTCHours() === 4) {
	      ctx.waitUntil(runCronTask(env, "brand_http_enrichment", () => tasks.runBrandHttpEnrichmentSweep(env)));
	    }

	    // ── Deferred free-tool results (bounded) ─────────────────────────────
	    // Visitors who met the free tools' daily breaker left an email for the
	    // result. Once the budget has room, run a small batch and email them;
	    // each address is deleted once its result is sent, or after 72 hours.
	    if (tasks.processFreeToolDeferredChecks) {
	      ctx.waitUntil(runCronTask(env, "free_tool_deferred_checks", () => tasks.processFreeToolDeferredChecks(env)));
	    }

	    // ── Report retention cleanup ─────────────────────────────────────────
  // The Worker cron also drives scheduled scans, so keep the hourly trigger
  // and run retention once daily at 02:00 UTC.
  if (new Date(now).getUTCHours() === 2) {
    ctx.waitUntil(runCronTask(env, "report_retention", () => tasks.cleanupExpiredReports(now, env)));
    ctx.waitUntil(runCronTask(env, "public_api_rate_limit_retention", () => cleanupExpiredPublicApiRateLimits(env, now)));
    ctx.waitUntil(runCronTask(env, "audit_retention", () => cleanupExpiredAuditEvents(env, now)));
    ctx.waitUntil(runCronTask(env, "mcp_rate_retention", () => cleanupExpiredMcpRateLimits(env, now)));
    ctx.waitUntil(runCronTask(env, "mcp_refresh_replay_retention", () => purgeExpiredMcpOAuthRefreshUses(env, now)));
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
