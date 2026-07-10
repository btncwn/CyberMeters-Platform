// ── Asset-change alert delivery ──
// Sends the per-scan asset-change alert (decides worthiness, builds + delivers email + webhook
// channel alerts, records for retry) and the cron retry of previously-failed asset alerts.
// Extracted verbatim from index.js (monolith decomposition, Phase 1c).
import { ASSET_ALERT_EVENTS, assetAlertSeverity, assetAlertWorthy, buildAssetAlertEmail } from "./asset-alerts.js";
import { deliverWorkspaceAlert, sendAlertEmail } from "./alerts.js";
import { createId } from "../lib/util.js";
import { getEmailFrontendOrigin } from "../lib/lifecycle-email.js";

export async function sendAssetChangeAlert(domainId, domain, scanId, env) {
  try {
    // Find all workspaces that own this domain
    const wsResult = await env.cybermeters_db
      .prepare(`SELECT workspace_id FROM workspace_domains WHERE domain_id = ?`)
      .bind(domainId)
      .all();
    const workspaceIds = (wsResult.results || []).map((r) => r.workspace_id);
    if (workspaceIds.length === 0) return;

    // Fetch all asset events for this scan (across all workspaces in one query)
    const eventsResult = await env.cybermeters_db
      .prepare(
        `SELECT workspace_id, event_type, hostname
         FROM asset_events
         WHERE scan_id = ?`
      )
      .bind(scanId)
      .all();
    const allEvents = eventsResult.results || [];

    // Group events by workspace_id
    const byWorkspace = new Map();
    for (const ev of allEvents) {
      if (!byWorkspace.has(ev.workspace_id)) byWorkspace.set(ev.workspace_id, []);
      byWorkspace.get(ev.workspace_id).push(ev);
    }

    for (const workspace_id of workspaceIds) {
      try {
        const events = byWorkspace.get(workspace_id) || [];
        if (events.length === 0) continue;

        // Count events by type
        const counts = {};
        const hostnamesByType = {};
        for (const ev of events) {
          if (!ASSET_ALERT_EVENTS.has(ev.event_type)) continue;
          counts[ev.event_type] = (counts[ev.event_type] || 0) + 1;
          if (ev.hostname) {
            if (!hostnamesByType[ev.event_type]) hostnamesByType[ev.event_type] = [];
            hostnamesByType[ev.event_type].push(ev.hostname);
          }
        }

        if (!assetAlertWorthy(counts)) continue;

        const severity = assetAlertSeverity(counts);

        // Collect top hostnames — prioritise high-severity event types
        const topHostnames = [
          ...(hostnamesByType.takeover_risk_detected || []),
          ...(hostnamesByType.new_asset_discovered   || []),
          ...(hostnamesByType.certificate_new_san_detected || []),
          ...(hostnamesByType.certificate_new_detected || []),
          ...(hostnamesByType.certificate_new_issuer_detected || []),
          ...(hostnamesByType.cloud_storage_detected || []),
          ...(hostnamesByType.wildcard_dns_detected  || []),
          ...(hostnamesByType.asset_reappeared       || []),
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
            JSON.stringify(counts),
            JSON.stringify(topHostnames),
            now
          )
          .run();

        // meta.changes === 0 means the row already existed — skip email
        if (!insert.meta || insert.meta.changes === 0) continue;

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
        );
        const delivery = await sendAlertEmail(subject, text, html, env, "ALERT_EMAIL_FROM");
        // Record the delivery outcome: a 'failed' row is what the hourly retry
        // cron (retryFailedAssetAlerts) picks up — without it the dedupe row
        // permanently swallows the alert. The INSERT above deliberately keeps
        // the pre-067 column list and this UPDATE has its own catch, so a
        // worker deployed ahead of migration 067 (auto-deploy on push) degrades
        // to the old fire-and-forget behaviour instead of losing the alert or
        // the channel fan-out below.
        let queuedForRetry = false;
        try {
          await env.cybermeters_db
            .prepare(`UPDATE asset_alert_records SET status = ?, error = ? WHERE id = ?`)
            .bind(delivery.sent ? "sent" : "failed", delivery.sent ? null : (delivery.reason || "send_failed"), recId)
            .run();
          queuedForRetry = !delivery.sent;
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
        `SELECT id, workspace_id, scan_id, domain, severity, event_counts, top_hostnames
         FROM asset_alert_records
         WHERE status = 'failed'
           AND sent_at > datetime('now', '-3 days')
         ORDER BY sent_at ASC
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
        const { subject, text, html } = buildAssetAlertEmail(
          row.domain,
          row.workspace_id,
          row.scan_id,
          counts,
          topHostnames,
          row.severity || "info",
          frontendOrigin ? `${frontendOrigin}/assets` : null,
        );
        const delivery = await sendAlertEmail(subject, text, html, env, "ALERT_EMAIL_FROM");
        await env.cybermeters_db
          .prepare(`UPDATE asset_alert_records SET status = ?, error = ? WHERE id = ?`)
          .bind(delivery.sent ? "sent" : "failed", delivery.sent ? null : (delivery.reason || "send_failed"), row.id)
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
