// ── Asset-change alert delivery ──
// Sends the per-scan asset-change alert (decides worthiness, builds + delivers email + webhook
// channel alerts, records for retry) and the cron retry of previously-failed asset alerts.
// Extracted verbatim from index.js (monolith decomposition, Phase 1c).
import {
  ASSET_ALERT_EVENTS,
  ASSET_ALERT_INVENTORY_ONLY_REASON,
  ASSET_ALERT_WITHHELD_REASON,
  assetAlertCounts,
  assetAlertSeverity,
  assetAlertWorthy,
  buildAssetAlertEmail,
  buildAssetChangeRecords,
  evaluateAssetAlertEligibility,
} from "./asset-alerts.js";
import { deliverWorkspaceAlert, sendTenantAlertEmail } from "./alerts.js";
import { filterCustomerTimelineEventsForScan } from "./timeline-trust.js";
import { createId } from "../lib/util.js";
import { getEmailFrontendOrigin } from "../lib/lifecycle-email.js";
import {
  loadAssetLifecycleEventSupport,
  projectLifecycleCollectionForCustomer,
} from "./asset-lifecycle-event-support.js";

// Delivery outcome → the row's terminal state. Retry is for TRANSIENT failures:
// the sweep only picks up 'failed'. A workspace with no verified recipient (or one
// that is soft-deleted) is not a transient condition — retrying it hourly for three
// days would never succeed and would bury real failures, so it settles as 'skipped'
// with an honest reason. A recipient LOOKUP failure is transient, so it stays
// retryable.
// Reasons that are a DECISION, not a transient failure. Recorded as `skipped` so
// the hourly retry sweep (which matches `failed`) leaves them alone: retrying an
// entitlement or an opt-out could never succeed, and would burn attempts hourly
// while burying real failures. `feature_not_entitled` / `channel_disabled` /
// `preference_filtered` joined this set when the alert gate moved into
// sendTenantAlertEmail — without them a free workspace's suppressed alert would
// have been retried forever.
const SUPPRESSED_DELIVERY_REASONS = new Set([
  "no_verified_recipient",
  "feature_not_entitled",
  "channel_disabled",
  "preference_filtered",
]);

export function deliveryOutcome(delivery) {
  if (delivery.sent) return { status: "sent", error: null };
  if (SUPPRESSED_DELIVERY_REASONS.has(delivery.reason)) return { status: "skipped", error: delivery.reason };
  return { status: "failed", error: delivery.reason || "send_failed" };
}

function evidenceReadStatus(error) {
  return /no such (?:table|column)/i.test(String(error?.message || ""))
    ? "schema_absent"
    : "unavailable";
}

// Two bounded reads per workspace, never one read per event. The lifecycle
// window needs at most the current row plus the three qualifying observations
// required by the canonical removal policy.
export async function loadAssetAlertEligibilityEvidence(
  env,
  workspaceId,
  scanId,
  events = [],
  preloadedLifecycleProjection = null,
) {
  const signalRead = env.cybermeters_db
    .prepare(
      `SELECT signal_key, state, reason, evidence_count, sources_json,
              limitations_json, model_version
       FROM attack_surface_signal_observations
       WHERE workspace_id = ? AND scan_id = ?`
    )
    .bind(workspaceId, scanId)
    .all();
  const lifecycleRead = preloadedLifecycleProjection
    ? Promise.resolve(preloadedLifecycleProjection)
    : loadAssetLifecycleEventSupport(env, {
        workspaceId,
        events: events.filter((event) =>
          event?.event_type === "asset_no_longer_seen" ||
          event?.event_type === "asset_reappeared"),
        scope: `asset-alert-delivery:${scanId}`,
      });
  const [signals, lifecycle] = await Promise.allSettled([
    signalRead,
    lifecycleRead,
  ]);
  const signalRows = signals.status === "fulfilled"
    ? signals.value.results || []
    : [];
  return {
    signal_status: signals.status === "fulfilled"
      ? "available"
      : evidenceReadStatus(signals.reason),
    lifecycle_status: lifecycle.status === "fulfilled"
      ? lifecycle.value?.coverage_reason === "lifecycle_schema_absent"
        ? "schema_absent"
        : lifecycle.value?.coverage_reason === "lifecycle_evidence_read_failed"
          ? "unavailable"
          : "available"
      : evidenceReadStatus(lifecycle.reason),
    signal_states: Object.fromEntries(
      signalRows.map((row) => [row.signal_key, row]),
    ),
    lifecycle_projection: lifecycle.status === "fulfilled"
      ? lifecycle.value
      : {
          coverage: "unavailable",
          coverage_reason: "lifecycle_evidence_read_failed",
          claims_by_event_id: new Map(),
        },
  };
}

function hostnamesByType(events) {
  const result = {};
  for (const event of events || []) {
    if (!event.hostname) continue;
    if (!result[event.event_type]) result[event.event_type] = [];
    result[event.event_type].push(event.hostname);
  }
  return result;
}

async function recordWithheldAlertDecision(
  env,
  recordId,
  workspaceId,
  scanId,
  eligibility,
  reasonCode = ASSET_ALERT_WITHHELD_REASON,
) {
  try {
    await env.cybermeters_db
      .prepare(
        `UPDATE asset_alert_records
         SET status = 'skipped', error = ?
         WHERE id = ? AND workspace_id = ? AND scan_id = ?`
      )
      .bind(reasonCode, recordId, workspaceId, scanId)
      .run();
    console.info("[asset-alert] not notified", JSON.stringify({
      workspace_id: workspaceId,
      scan_id: scanId,
      reason_code: reasonCode,
      decisions: eligibility.record.withheld,
    }));
  } catch (error) {
    console.error("[asset-alert] withheld decision not recorded", JSON.stringify({
      workspace_id: workspaceId,
      scan_id: scanId,
      reason_code: reasonCode,
      error_type: error?.name || "Error",
    }));
  }
}

// When the workspace's previous completed scan of the domain ran, for the
// "before" side of a change. Best effort: an unknown time is left out.
async function previousScanCompletedAt(env, { domainId, workspaceId, scanId }) {
  try {
    const row = await env.cybermeters_db
      .prepare(
        `SELECT p.created_at FROM scans p
         JOIN scans s ON s.id = ?
         WHERE p.domain_id = ? AND p.workspace_id = ? AND p.status = 'completed'
           AND p.id != s.id AND p.created_at < s.created_at
         ORDER BY p.created_at DESC, p.id DESC LIMIT 1`
      )
      .bind(scanId, domainId, workspaceId)
      .first();
    return row?.created_at ?? null;
  } catch {
    return null;
  }
}

// opts (all optional, from the scan engine): `modules` and `assetEvidence`
// (this scan's per-name evidence) describe each change; `observedAt` is when
// the scan completed.
export async function sendAssetChangeAlert(domainId, domain, scanId, env, scanQuality = null, opts = {}) {
  try {
    // Find all LIVE workspaces that own this domain. A soft-deleted workspace is
    // treated as nonexistent: it receives no email, no channel fan-out and no
    // dedupe/retry row. The join is the gate for BOTH channels and email — the
    // recipient resolver re-checks deleted_at independently (defence in depth).
    const wsResult = await env.cybermeters_db
      .prepare(`SELECT wd.workspace_id
                FROM workspace_domains wd
                JOIN workspaces w ON w.id = wd.workspace_id
                WHERE wd.domain_id = ? AND w.deleted_at IS NULL`)
      .bind(domainId)
      .all();
    const workspaceIds = (wsResult.results || []).map((r) => r.workspace_id);
    if (workspaceIds.length === 0) return;

    // Only the workspace the scan belongs to is notified: its own inventory
    // and its own previous scan are what changed. Another workspace linked to
    // the same domain is never told about this scan, and a scan with no
    // workspace notifies nobody.
    const scanRow = await env.cybermeters_db
      .prepare(`SELECT workspace_id, scan_quality FROM scans WHERE id = ?`)
      .bind(scanId)
      .first()
      .catch(() => null);
    const scanWorkspaceId = scanRow?.workspace_id ?? null;
    const persistedScanQuality = scanRow?.scan_quality ?? scanQuality;
    const alertTargets = scanWorkspaceId && workspaceIds.includes(scanWorkspaceId)
      ? [scanWorkspaceId]
      : [];

    // Fetch the scan's asset events plus recent same-domain context so presentation
    // collapse can suppress short-lived remove/reappear churn without mutating rows.
    const eventsResult = await env.cybermeters_db
      .prepare(
        `SELECT id, workspace_id, domain_id, asset_id, scan_id, event_type,
                hostname, severity, created_at
         FROM asset_events
         WHERE scan_id = ?
            OR (domain_id = ? AND scan_id IS NOT NULL AND julianday(created_at) >= julianday('now', '-24 hours'))`
      )
      .bind(scanId, domainId)
      .all();
    const allEvents = eventsResult.results || [];

    // Group events by workspace_id
    const byWorkspace = new Map();
    for (const ev of allEvents) {
      if (!byWorkspace.has(ev.workspace_id)) byWorkspace.set(ev.workspace_id, []);
      byWorkspace.get(ev.workspace_id).push(ev);
    }

    for (const workspace_id of alertTargets) {
      try {
        const rawWorkspaceEvents = byWorkspace.get(workspace_id) || [];
        const lifecycleProjection = await loadAssetLifecycleEventSupport(env, {
          workspaceId: workspace_id,
          events: rawWorkspaceEvents.filter((event) =>
            event?.event_type === "asset_no_longer_seen" ||
            event?.event_type === "asset_reappeared"),
          scope: `asset-alert-delivery:${scanId}`,
        });
        const projectedWorkspaceEvents = projectLifecycleCollectionForCustomer(
          rawWorkspaceEvents,
          lifecycleProjection,
        );
        const events = filterCustomerTimelineEventsForScan(
          projectedWorkspaceEvents,
          scanId,
          { missingScanIdMatches: true },
        );
        if (events.length === 0) continue;

        const alertEvents = events.filter((event) =>
          ASSET_ALERT_EVENTS.has(event.event_type));
        if (alertEvents.length === 0) continue;
        const evidence = await loadAssetAlertEligibilityEvidence(
          env,
          workspace_id,
          scanId,
          alertEvents,
          lifecycleProjection,
        );
        const eligibility = evaluateAssetAlertEligibility(alertEvents, evidence);
        const counts = assetAlertCounts(
          eligibility.eligible_events,
          eligibility.record,
        );
        const worthy = assetAlertWorthy(counts);
        // What changed, with before/now, evidence and the recommended action.
        // Stored with the record, so a retried email says the same.
        const details = worthy
          ? {
            ...buildAssetChangeRecords(eligibility.eligible_events, {
              modules: opts.modules ?? null,
              evidenceByHost: opts.assetEvidence ?? null,
              observedAt: opts.observedAt ?? null,
              previousScanAt: await previousScanCompletedAt(env, { domainId, workspaceId: workspace_id, scanId }),
              domain,
            }),
          }
          : null;
        // The most severe change decides the notification's severity; the
        // event counts are the fallback.
        const severity = worthy ? (details?.severity || assetAlertSeverity(counts)) : "info";
        const eligibleHostnamesByType = hostnamesByType(
          eligibility.eligible_events,
        );

        // Collect top hostnames — prioritise high-severity event types
        const topHostnames = [
          ...(eligibleHostnamesByType.takeover_risk_detected || []),
          ...(eligibleHostnamesByType.admin_surface_detected || []),
          ...(eligibleHostnamesByType.new_asset_discovered   || []),
          ...(eligibleHostnamesByType.certificate_new_san_detected || []),
          ...(eligibleHostnamesByType.certificate_new_detected || []),
          ...(eligibleHostnamesByType.certificate_new_issuer_detected || []),
          ...(eligibleHostnamesByType.cloud_storage_detected || []),
          ...(eligibleHostnamesByType.wildcard_dns_detected  || []),
          ...(eligibleHostnamesByType.asset_reappeared       || []),
          ...(eligibleHostnamesByType.asset_no_longer_seen   || []),
        ].filter((v, i, a) => a.indexOf(v) === i).slice(0, 5);

        // Dedup: INSERT OR IGNORE — if this (workspace_id, scan_id) already has a
        // record the insert is silently skipped and we don't send the email again.
        const now    = new Date().toISOString();
        const recId  = createId("aar");
        const insert = await env.cybermeters_db
          .prepare(
            `INSERT OR IGNORE INTO asset_alert_records
               (id, workspace_id, scan_id, domain, severity, event_counts, top_hostnames, sent_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .bind(
            recId,
            workspace_id,
            scanId,
            domain,
            severity,
            JSON.stringify(details ? { ...counts, _changes: details } : counts),
            JSON.stringify(topHostnames),
            now
          )
          .run();

        // meta.changes === 0 means the row already existed — skip email
        if (!insert.meta || insert.meta.changes === 0) continue;

        if (!worthy) {
          // Supported inventory changes are recorded, not notified; otherwise
          // every claim was withheld for lack of evidence.
          await recordWithheldAlertDecision(
            env,
            recId,
            workspace_id,
            scanId,
            eligibility,
            eligibility.eligible_events.length > 0 ? ASSET_ALERT_INVENTORY_ONLY_REASON : ASSET_ALERT_WITHHELD_REASON,
          );
          continue;
        }

        // Build + send email
        const frontendOrigin = getEmailFrontendOrigin(env);
        const { subject, text, html } = buildAssetAlertEmail(
          domain,
          workspace_id,
          scanId,
          counts,
          topHostnames,
          severity,
          frontendOrigin ? `${frontendOrigin}/assets` : null,
          persistedScanQuality,
          details ? { ...details, settings_url: frontendOrigin ? `${frontendOrigin}/settings` : null } : null,
        );
        // Tenant alert: recipients come from THIS workspace (verified, live) — never
        // the operator fallback. No verified audience => skipped + recorded, not sent.
        const delivery = await sendTenantAlertEmail(env, workspace_id, { subject, text, html, fromKey: "ALERT_EMAIL_FROM", severity });
        // Record the delivery outcome: a 'failed' row is what the hourly retry
        // cron (retryFailedAssetAlerts) picks up — without it the dedupe row
        // permanently swallows the alert. The INSERT above deliberately keeps
        // the pre-067 column list and this UPDATE has its own catch, so a
        // worker deployed ahead of migration 067 (auto-deploy on push) degrades
        // to the old fire-and-forget behaviour instead of losing the alert or
        // the channel fan-out below.
        let queuedForRetry = false;
        const outcome = deliveryOutcome(delivery);
        try {
          await env.cybermeters_db
            .prepare(`UPDATE asset_alert_records SET status = ?, error = ? WHERE id = ?`)
            .bind(outcome.status, outcome.error, recId)
            .run();
          queuedForRetry = outcome.status === "failed";
        } catch (outcomeErr) {
          console.error("[asset-alert] outcome not recorded", JSON.stringify({ workspace_id, scanId, reason: outcomeErr?.message }));
        }
        if (delivery.sent) {
          console.log("[asset-alert] accepted", JSON.stringify({ workspace_id, scanId, severity, counts, provider_id: delivery.provider_id || null }));
        } else {
          console.error("[asset-alert] delivery failed", JSON.stringify({ workspace_id, scanId, reason: delivery.reason, queued_for_retry: queuedForRetry }));
        }

        // Slack/Teams/webhook fan-out mirrors the email; never blocks the sweep.
        try {
          await deliverWorkspaceAlert(env, workspace_id, {
            kind: "asset_change",
            severity,
            title: `Asset changes detected on ${domain}`,
            summary: subject,
            domain,
            link: frontendOrigin ? `${frontendOrigin}/assets` : null,
          });
        } catch { /* channel fan-out is best-effort */ }
      } catch (wsErr) {
        console.error("[asset-alert] workspace error", workspace_id, wsErr?.message);
      }
    }
  } catch (err) {
    console.error("[asset-alert] failed:", err?.message);
  }
}

/**
 * retryFailedAssetAlerts
 *
 * Hourly cron sweep that re-sends asset change alert emails whose delivery
 * FAILED. sendAssetChangeAlert runs at the end of the subrequest-heavy scan
 * engine, where the outbound Resend fetch can fail (observed: network_error
 * during the 2026-07-08 11:00 UTC scheduled-scan cron); this sweep runs in a
 * clean invocation with full subrequest budget — the same recovery pattern as
 * retryFailedLifecycleEmails.
 *
 * The failed asset_alert_records row already stores everything needed to
 * rebuild the exact email (domain, severity, event_counts, top_hostnames), so
 * no asset_events re-read is needed. Each row is claimed back to 'pending'
 * before sending so overlapping sweeps can never double-send. The
 * Slack/Teams/webhook fan-out is NOT repeated — it already ran at scan time,
 * independent of email delivery. Bounded to a 3-day window and 10 rows per
 * run, mirroring the lifecycle retry. Never throws.
 *
 * Delivery semantics: AT-LEAST-ONCE, deliberately. A send classed as failed
 * (e.g. timeout / network_error) may in fact have been delivered by the
 * provider — that ambiguity cannot be resolved client-side, so the sweep
 * re-sends and a customer may occasionally receive the same alert twice.
 * A duplicate alert is accepted over a silently lost one; identical to the
 * lifecycle_email_retry semantics.
 */
export async function retryFailedAssetAlerts(env) {
  try {
    const rows = await env.cybermeters_db
      .prepare(
        `SELECT aar.id, aar.workspace_id, aar.scan_id, aar.domain, aar.severity,
                aar.event_counts, aar.top_hostnames, s.scan_quality
         FROM asset_alert_records aar
         LEFT JOIN scans s ON s.id = aar.scan_id
         WHERE aar.status = 'failed'
           AND aar.sent_at > datetime('now', '-3 days')
         ORDER BY aar.sent_at ASC
         LIMIT 10`
      )
      .all().catch(() => null);

    for (const row of (rows?.results || [])) {
      try {
        // Claim the row so a concurrent sweep cannot send the same alert twice.
        const claim = await env.cybermeters_db
          .prepare(`UPDATE asset_alert_records SET status = 'pending', error = NULL WHERE id = ? AND status = 'failed'`)
          .bind(row.id)
          .run();
        if ((claim.meta?.changes ?? 0) === 0) continue;

        let counts = {};
        let topHostnames = [];
        try { counts = JSON.parse(row.event_counts || "{}") || {}; } catch { /* degrade to a counts-less summary */ }
        try { topHostnames = JSON.parse(row.top_hostnames || "[]") || []; } catch { /* hostname list is optional */ }

        const frontendOrigin = getEmailFrontendOrigin(env);
        const details = counts?._changes && typeof counts._changes === "object" ? counts._changes : null;
        const { subject, text, html } = buildAssetAlertEmail(
          row.domain,
          row.workspace_id,
          row.scan_id,
          counts,
          topHostnames,
          row.severity || "info",
          frontendOrigin ? `${frontendOrigin}/assets` : null,
          row.scan_quality ?? null,
          details ? { ...details, settings_url: frontendOrigin ? `${frontendOrigin}/settings` : null } : null,
        );
        const delivery = await sendTenantAlertEmail(env, row.workspace_id, { subject, text, html, fromKey: "ALERT_EMAIL_FROM", severity: row.severity || "info" });
        // A missing verified audience is not a transient failure — retrying it forever
        // would never succeed, so it settles as 'skipped' (the sweep matches 'failed').
        const outcome = deliveryOutcome(delivery);
        await env.cybermeters_db
          .prepare(`UPDATE asset_alert_records SET status = ?, error = ? WHERE id = ?`)
          .bind(outcome.status, outcome.error, row.id)
          .run();
        if (delivery.sent) {
          console.log("[asset-alert-retry] delivered", JSON.stringify({ workspace_id: row.workspace_id, scan_id: row.scan_id, provider_id: delivery.provider_id || null }));
        } else {
          console.error("[asset-alert-retry] delivery failed", JSON.stringify({ workspace_id: row.workspace_id, scan_id: row.scan_id, reason: delivery.reason }));
        }
      } catch (rowErr) {
        console.error("[asset-alert-retry] row error", row.id, rowErr?.message);
      }
    }
  } catch (err) {
    console.error("[asset-alert-retry] failed:", err?.message);
  }
}
