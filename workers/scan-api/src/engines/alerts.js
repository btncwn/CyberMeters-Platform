// ── Email + webhook alert engine ──
// Alert email building/sending, recipient resolution, duplicate suppression,
// alert-channel (webhook/Slack/etc.) validation + payload signing + delivery, and
// the per-workspace alert processor. Extracted verbatim from index.js (monolith
// decomposition, Phase 1c). Internal: isAlertDuplicate, ALERT_CHANNEL_TYPES,
// _alertChannelText.
//
// Two chokepoints live here, and every rule about whether a customer may be told
// something is enforced inside them rather than by their callers:
//   • sendTenantAlertEmail   — the ONLY way an alert reaches a customer by email.
//   • deliverWorkspaceAlert  — the ONLY way one reaches Slack/Teams/webhook.
// The decisions themselves (entitlement, preference, severity) are in alert-gate.js
// so this module and managed-alerts.js can share them without a circular import.
//
// shouldSendAlert/buildAlertEmail were removed here: they were dead code — defined,
// exported to nothing, called by nothing, while processAlertsForWorkspace
// re-implemented five triggers inline. Two drifting copies of "is this alert-worthy"
// is one more than the product can defend.
import { createId } from "../lib/util.js";
import { deliverEmail, escapeEmailHtml, getEmailFrontendOrigin } from "../lib/lifecycle-email.js";
import { alertEmailFrequencyForUser, channelEnabledForWorkspace, resolveAlertEntitlement, severityAllowedByFrequency, workspaceAlertsEntitled } from "./alert-gate.js";

// Reasons that mean "we deliberately did not send", as opposed to "the send broke".
// Recorded as `skipped`, never `failed`: a deliberate rule is not a transient error,
// must not be retried, and must not be shown to a customer as a delivery problem.
const SUPPRESSION_REASONS = new Set([
  "feature_not_entitled",
  "channel_disabled",
  "preference_filtered",
  "no_verified_recipient",
]);

// ── OPS-ONLY sender ──────────────────────────────────────────────────────────
// Falls back to env.ALERT_EMAIL_TO — the OPERATOR's inbox — when no recipient is
// given. That fallback is correct for operational self-monitoring (e.g. the
// opsHealthHeartbeat threshold breach in index.js), and WRONG for anything a
// tenant should receive: it silently redirects a customer's alert to the operator
// and aggregates every tenant's domains into one personal mailbox.
//
// NEVER call this for a tenant/customer alert. Use sendTenantAlertEmail below,
// which resolves the workspace's own verified recipients and refuses to send when
// there are none. validate-alert-recipients.js enforces this boundary.
export async function sendAlertEmail(subject, text, html, env, fromKey = "ALERT_EMAIL_FROM", toEmails = null) {
  const to = Array.isArray(toEmails) && toEmails.length > 0
    ? toEmails
    : typeof toEmails === "string" && toEmails.trim()
      ? [toEmails]
      : [env.ALERT_EMAIL_TO];
  return deliverEmail(subject, text, html, env, fromKey, to);
}

// ── Tenant alert sender (never falls back to the operator inbox) ──────────────
// The ONE way an alert reaches a customer by email, and therefore the right place
// for every rule that decides whether it may. Four gates, in order:
//
//   1. ENTITLEMENT — proactive delivery is the paid feature. Fails closed.
//   2. AUDIENCE    — this workspace's own verified recipients, never an operator.
//   3. PREFERENCE  — per-recipient, per-workspace. One member's opt-out silences
//                    only their own address.
//   4. SEVERITY    — `critical_only` means exactly critical.
//
// The gates live HERE rather than at call sites deliberately. Before this, the
// legacy scan-alert path resolved recipients and called deliverEmail directly,
// bypassing every rule — so free workspaces got paid alerts. A caller that forgets
// a gate is a bug waiting to be written; a chokepoint cannot be forgotten.
//
// `severity` is required to honour `critical_only`. It defaults to null, which a
// `critical_only` recipient will (correctly) filter out — fail closed: an unlabelled
// alert is not provably critical, so a customer who asked for critical-only does not
// get it. Pass the real severity.
//
// Returns the deliverEmail shape ({ sent, reason, provider_id }) so existing
// callers record the outcome unchanged, plus `recipients` (the addresses actually
// mailed, post-filter) for auditing.
export async function sendTenantAlertEmail(env, workspaceId, { subject, text, html, fromKey = "ALERT_EMAIL_FROM", severity = null } = {}) {
  // 1. Entitlement. "Not entitled" and "could not check" are different facts and
  //    get different reasons — one is terminal, the other must be retried.
  const ent = await resolveAlertEntitlement(env, workspaceId);
  if (!ent.ok)       return { sent: false, reason: "entitlement_lookup_failed", recipients: [] };
  if (!ent.entitled) return { sent: false, reason: "feature_not_entitled", recipients: [] };

  // 2. Audience.
  const resolved = await resolveWorkspaceAlertRecipients(env, workspaceId);
  if (!resolved.ok) {
    // A lookup failure is NOT evidence that the workspace has no recipients.
    // Reporting it as "no recipients" would store a transient D1 error as a
    // permanent fact about the customer.
    return { sent: false, reason: resolved.reason, recipients: [] };
  }
  if (resolved.recipients.length === 0) {
    return { sent: false, reason: resolved.reason || "no_verified_recipient", recipients: [] };
  }

  // 3 + 4. Preference and severity, per recipient.
  const allowed = [];
  let optedOut = false, severityFiltered = false, prefLookupFailed = false;
  for (const r of resolved.recipients) {
    const pref = await alertEmailFrequencyForUser(env, workspaceId, r.user_id);
    if (!pref.ok) { prefLookupFailed = true; continue; }        // fail closed for this address
    if (pref.frequency === "disabled") { optedOut = true; continue; }
    if (!severityAllowedByFrequency(pref.frequency, severity)) { severityFiltered = true; continue; }
    allowed.push(r.email);
  }

  if (allowed.length === 0) {
    // Distinguish the three silences — they are different facts about the
    // customer and the retry sweep treats them differently.
    if (prefLookupFailed && !optedOut && !severityFiltered) {
      return { sent: false, reason: "recipient_lookup_failed", recipients: [] }; // retryable
    }
    if (severityFiltered && !optedOut) {
      return { sent: false, reason: "preference_filtered", recipients: [] };     // severity below their threshold
    }
    return { sent: false, reason: "channel_disabled", recipients: [] };          // they opted out
  }

  const delivery = await deliverEmail(subject, text, html, env, fromKey, allowed);
  return { ...delivery, recipients: allowed };
}


// ─────────────────────────────────────────────────────────────────────────────
// Dedicated alert functions — each fires via the appropriate sender address
// and is swallowed on error so the scan pipeline is never interrupted.
// ─────────────────────────────────────────────────────────────────────────────

// ── Canonical tenant-alert recipient resolver ────────────────────────────────
// The ONE place that decides who may receive a workspace's alerts, so every alert
// path inherits the same three guarantees:
//
//   1. TENANT SCOPE — recipients come from THIS workspace's own membership only.
//      There is no global/operator fallback: a workspace with no audience gets
//      nothing rather than someone else's mail.
//   2. VERIFIED ONLY — u.email_verified is required. Security findings must never
//      be mailed to an unverified, potentially attacker-controlled address. Every
//      other sender already does this (weekly-digest.js, lifecycle-email.js:253);
//      this path did not.
//   3. SOFT-DELETED WORKSPACES ARE NONEXISTENT — a workspace inside its deletion
//      window receives no alerts.
//
// Returns { ok, emails, reason }. `ok:false` means we could not determine the
// audience (a D1 error) — deliberately distinct from `ok:true, emails:[]` ("this
// workspace genuinely has no verified recipient"). Collapsing the two would store
// a transient database failure forever as a fact about the customer.
export async function resolveWorkspaceAlertRecipients(env, workspaceId) {
  try {
    // Owners/admins of a LIVE workspace, with a verified address. The workspace
    // owner is included via the same query (owner_user_id) rather than a second
    // unguarded lookup, so the verified + soft-delete rules cannot be bypassed.
    // u.id travels with the address: alert preferences are per-user-per-workspace,
    // so a caller that only knows the email literally cannot honour an opt-out.
    // `emails` is retained for existing consumers; `recipients` is the richer shape.
    const result = await env.cybermeters_db
      .prepare(
        `SELECT DISTINCT u.id AS user_id, u.email
         FROM workspaces w
         JOIN users u ON u.id IN (
           SELECT wm.user_id FROM workspace_members wm
           WHERE wm.workspace_id = w.id AND wm.role IN ('owner', 'admin')
           UNION
           SELECT w.owner_user_id
         )
         WHERE w.id = ?
           AND w.deleted_at IS NULL
           AND u.email_verified = 1
           AND u.email IS NOT NULL`
      )
      .bind(workspaceId)
      .all();

    const seen = new Set();
    const recipients = [];
    for (const r of (result.results || [])) {
      if (!r.email || seen.has(r.email)) continue;
      seen.add(r.email);
      recipients.push({ user_id: r.user_id, email: r.email });
    }
    const emails = recipients.map((r) => r.email);
    return {
      ok: true,
      recipients,
      emails,
      reason: emails.length === 0 ? "no_verified_recipient" : null,
    };
  } catch (err) {
    console.error("[alerts] recipient lookup failed", JSON.stringify({ workspace_id: workspaceId, reason: err?.message }));
    return { ok: false, recipients: [], emails: [], reason: "recipient_lookup_failed" };
  }
}

async function isAlertDuplicate(env, workspaceId, alertType, relatedEntity, checkThresholdFn = null) {
  try {
    const query = await env.cybermeters_db
      .prepare(
        `SELECT metadata_json, created_at FROM notification_events
         WHERE workspace_id = ? AND type = ?
         ORDER BY created_at DESC`
      )
      .bind(workspaceId, alertType)
      .all();
    
    const rows = query.results || [];
    const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;
    
    for (const row of rows) {
      let meta = {};
      try {
        meta = JSON.parse(row.metadata_json || '{}');
      } catch (e) {
        continue;
      }
      
      if (meta.related_entity === relatedEntity) {
        const rowDateStr = row.created_at.includes('Z') || row.created_at.includes('+')
          ? row.created_at
          : row.created_at.replace(' ', 'T') + 'Z';
        const createdAtTime = new Date(rowDateStr).getTime();
        
        if (createdAtTime >= oneDayAgo) {
          return true;
        }
        
        if (checkThresholdFn) {
          const thresholdDup = checkThresholdFn(meta);
          if (thresholdDup) {
            return true;
          }
        }
      }
    }
    return false;
  } catch (err) {
    return false;
  }
}








// ─── Workspace alert channels (Slack / Teams / signed generic webhooks) ──────
// SMB teams live in Slack/Teams, not in another dashboard. Channels mirror the
// events that already trigger alert emails. Generic webhooks are HMAC-signed so
// receivers can verify authenticity. URLs are validated at creation: https
// only, provider host allow-list for slack/teams, private/loopback hosts
// rejected (SSRF guard).

const ALERT_CHANNEL_TYPES = ["slack", "teams", "webhook"];
export const ALERT_CHANNEL_MAX_PER_WORKSPACE = 5;

export function validateAlertChannelInput(channelType, rawUrl) {
  if (!ALERT_CHANNEL_TYPES.includes(channelType)) {
    return { ok: false, error: "channel_type must be one of: slack, teams, webhook." };
  }
  const urlStr = String(rawUrl || "").trim();
  if (!urlStr || urlStr.length > 2048) {
    return { ok: false, error: "A webhook URL is required (max 2048 characters)." };
  }
  let parsed;
  try { parsed = new URL(urlStr); }
  catch { return { ok: false, error: "The webhook URL is not a valid URL." }; }
  if (parsed.protocol !== "https:") {
    return { ok: false, error: "Webhook URLs must use https." };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, error: "Webhook URLs must not embed credentials." };
  }
  const host = parsed.hostname.toLowerCase();
  // SSRF guard: no loopback/private/link-local/internal targets.
  const privateHost =
    host === "localhost" || host.endsWith(".localhost") ||
    host.endsWith(".local") || host.endsWith(".internal") ||
    !host.includes(".") ||
    /^127\.|^10\.|^192\.168\.|^169\.254\.|^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
    host === "::1" || host.startsWith("[::1]") ||
    /^\[?f[cd]/i.test(host) || /^\[?fe80/i.test(host);
  if (privateHost) {
    return { ok: false, error: "Webhook URLs must point to a public https endpoint." };
  }
  if (channelType === "slack" && host !== "hooks.slack.com") {
    return { ok: false, error: "Slack channels must use a hooks.slack.com incoming-webhook URL." };
  }
  if (channelType === "teams" && !host.endsWith(".webhook.office.com") && !host.endsWith(".logic.azure.com")) {
    return { ok: false, error: "Teams channels must use a *.webhook.office.com or *.logic.azure.com workflow URL." };
  }
  return { ok: true, url: parsed.href };
}

function _alertChannelText(value, max) {
  return String(value ?? "").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, max);
}

export function buildAlertChannelPayload(channelType, event = {}) {
  const title   = _alertChannelText(event.title, 200) || "CyberMeters alert";
  const summary = _alertChannelText(event.summary, 1000);
  const domain  = _alertChannelText(event.domain, 253) || null;
  const link    = typeof event.link === "string" && /^https:\/\//.test(event.link)
    ? event.link.slice(0, 1024) : null;
  const severity = ["critical", "high", "medium", "low", "info"].includes(event.severity)
    ? event.severity : "info";

  if (channelType === "slack") {
    const lines = [`*${title}*`];
    if (summary) lines.push(summary);
    if (link) lines.push(`<${link}|Open in CyberMeters>`);
    return { text: lines.join("\n") };
  }
  if (channelType === "teams") {
    const themeColor = severity === "critical" || severity === "high" ? "B4232A"
      : severity === "medium" ? "B45309" : "00876A";
    const card = {
      "@type": "MessageCard",
      "@context": "https://schema.org/extensions",
      summary: title,
      themeColor,
      title,
      text: summary || title,
    };
    if (link) {
      card.potentialAction = [{
        "@type": "OpenUri", name: "Open in CyberMeters",
        targets: [{ os: "default", uri: link }],
      }];
    }
    return card;
  }
  // Generic signed webhook: stable machine-readable envelope.
  return {
    source: "cybermeters",
    event: _alertChannelText(event.kind, 64) || "alert",
    severity,
    title,
    summary: summary || null,
    domain,
    workspace_name: _alertChannelText(event.workspace_name, 120) || null,
    link,
    sent_at: new Date().toISOString(),
  };
}

export async function signAlertWebhookBody(secret, body) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(String(secret)),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(String(body)));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function alertChannelToApi(row) {
  let preview = null;
  try {
    const u = new URL(row.webhook_url);
    preview = `${u.hostname}/…${String(u.pathname).slice(-4)}`;
  } catch { preview = "configured"; }
  return {
    id: row.id,
    channel_type: row.channel_type,
    url_preview: preview,
    enabled: Boolean(row.enabled),
    has_secret: Boolean(row.secret),
    created_at: row.created_at,
    last_delivery_at: row.last_delivery_at || null,
    last_delivery_status: row.last_delivery_status || null,
    failure_count: Number(row.failure_count || 0),
  };
}

// deliverWorkspaceAlert — fan an event out to every enabled channel. Never
// throws; delivery state is recorded per channel with customer-safe status
// strings. fetchImpl is injectable for tests (house pattern: dnsQueryImpl).
export async function deliverWorkspaceAlert(env, workspaceId, event, { fetchImpl = fetch, channelId = null } = {}) {
  // ── The channel gate ───────────────────────────────────────────────────────
  // This function is the shared trunk for every Slack/Teams/webhook alert:
  // emitManagedAlert, the legacy scan alerts, dmarc-alerts, the four inline
  // hosted-dmarc sites, notifyCase and notifyBrandCase all end up here. It had no
  // gate of its own and trusted callers to check — and most did not, so free
  // workspaces received paid channel deliveries.
  //
  // Gating the trunk covers all of them at once, including the channel TEST
  // endpoint: a test send is a delivery, so an unentitled workspace cannot use it
  // as a side door. Fails closed.
  if (!(await workspaceAlertsEntitled(env, workspaceId))) {
    return { attempted: 0, delivered: 0, suppressed_reason: "feature_not_entitled" };
  }
  // One preference gate for the whole channel family — these endpoints are
  // workspace-owned, so the toggle is workspace-wide (see alert-gate.js).
  if (!(await channelEnabledForWorkspace(env, workspaceId, { channel: "webhook" }))) {
    return { attempted: 0, delivered: 0, suppressed_reason: "channel_disabled" };
  }

  let channels = [];
  try {
    const r = channelId
      ? await env.cybermeters_db
          .prepare(`SELECT id, channel_type, webhook_url, secret FROM workspace_alert_channels
                    WHERE workspace_id = ? AND id = ? AND enabled = 1 LIMIT 1`)
          .bind(workspaceId, channelId)
          .all()
      : await env.cybermeters_db
          .prepare(`SELECT id, channel_type, webhook_url, secret FROM workspace_alert_channels
                    WHERE workspace_id = ? AND enabled = 1
                    ORDER BY created_at ASC LIMIT ?`)
          .bind(workspaceId, ALERT_CHANNEL_MAX_PER_WORKSPACE)
          .all();
    channels = r.results || [];
  } catch { return { attempted: 0, delivered: 0 }; }

  let delivered = 0;
  for (const ch of channels) {
    const body = JSON.stringify(buildAlertChannelPayload(ch.channel_type, event));
    const headers = { "content-type": "application/json" };
    if (ch.channel_type === "webhook" && ch.secret) {
      headers["X-CyberMeters-Signature"] = `sha256=${await signAlertWebhookBody(ch.secret, body)}`;
      headers["X-CyberMeters-Event"] = _alertChannelText(event?.kind, 64) || "alert";
    }
    let status;
    try {
      const res = await fetchImpl(ch.webhook_url, {
        method: "POST", headers, body, signal: AbortSignal.timeout(5000),
      });
      status = res.ok ? "ok" : `failed:http_${res.status}`;
      if (res.ok) delivered += 1;
    } catch {
      status = "failed:unreachable";
    }
    try {
      await env.cybermeters_db
        .prepare(`UPDATE workspace_alert_channels
                  SET last_delivery_at = ?, last_delivery_status = ?,
                      failure_count = CASE WHEN ? = 'ok' THEN 0 ELSE failure_count + 1 END
                  WHERE id = ?`)
        .bind(new Date().toISOString(), status, status, ch.id)
        .run();
    } catch { /* delivery bookkeeping must never break the caller */ }
  }
  return { attempted: channels.length, delivered };
}

// Monitoring-alert email body. These are NON-PROMOTIONAL service messages about the
// customer's own security posture: no advertising, no upgrade copy, no discount, no
// cross-sell. `preferencesLink` points at the monitoring-preference centre — it is
// deliberately NOT a marketing unsubscribe, and is labelled as such, because turning
// monitoring off is a product setting the customer controls per channel.
export function formatAlertEmail({ workspaceName, domain, whatChanged, recommendation, link, preferencesLink = null }) {
  const text = `CyberMeters Alert

Workspace: ${workspaceName}
Affected Domain: ${domain || "N/A"}

What Changed:
${whatChanged}

Recommended Next Action:
${recommendation}

View Dashboard/Report:
${link || "Open CyberMeters to review this alert."}

--
CyberMeters — Attack Surface Management
This is an automated security-monitoring alert for your workspace.${preferencesLink ? `
Manage your monitoring alert preferences: ${preferencesLink}` : ""}`;

  const html = `<!DOCTYPE html>
<html>
<body style="font-family: sans-serif; color: #111; max-width: 600px; margin: 0 auto; padding: 20px; line-height: 1.5;">
  <h2 style="color: #00876A;">CyberMeters Alert</h2>
  <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
    <tr>
      <td style="padding: 6px 0; font-weight: bold; width: 150px;">Workspace:</td>
      <td>${escapeEmailHtml(workspaceName)}</td>
    </tr>
    ${domain ? `<tr>
      <td style="padding: 6px 0; font-weight: bold;">Affected Domain:</td>
      <td>${escapeEmailHtml(domain)}</td>
    </tr>` : ''}
  </table>
  
  <div style="background: #F9FAFB; border-left: 4px solid #F59E0B; padding: 15px; margin-bottom: 20px;">
    <h4 style="margin: 0 0 8px 0; color: #374151;">What Changed:</h4>
    <p style="margin: 0; color: #4B5563; white-space: pre-wrap;">${escapeEmailHtml(whatChanged)}</p>
  </div>

  <div style="margin-bottom: 25px;">
    <h4 style="margin: 0 0 8px 0; color: #374151;">Recommended Next Action:</h4>
    <p style="margin: 0; color: #4B5563;">${escapeEmailHtml(recommendation)}</p>
  </div>

  ${link ? `<p style="margin-top: 20px;">
    <a href="${escapeEmailHtml(link)}" style="background: #00876A; color: white; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: bold; display: inline-block;">
      View Dashboard / Report
    </a>
  </p>` : ''}
  
  <hr style="border: none; border-top: 1px solid #E5E7EB; margin: 30px 0;" />
  <p style="font-size: 12px; color: #9CA3AF; margin: 0;">
    CyberMeters &mdash; Attack Surface Management<br>
    This is an automated security-monitoring alert for your workspace, sent to
    workspace owners and admins.${preferencesLink ? `<br>
    <a href="${escapeEmailHtml(preferencesLink)}" style="color: #6B7280;">Manage your monitoring alert preferences</a>` : ""}
  </p>
</body>
</html>`;

  return { text, html };
}

export async function processAlertsForWorkspace(workspaceId, domainId, domain, scanId, currentScore, currentFindings, currentModules, startedAt, env) {
  try {
    const wsRow = await env.cybermeters_db
      .prepare("SELECT name FROM workspaces WHERE id = ?")
      .bind(workspaceId)
      .first();
    const workspaceName = wsRow?.name || "Unknown Workspace";

    const triggerAlert = async ({ type, severity, title, message, relatedEntity, whatChanged, recommendation, fromKey = "ALERT_EMAIL_FROM", threshold = null }) => {
      const notifId = createId("notif");
      const metadata = { scan_id: scanId, domain, related_entity: relatedEntity };
      if (threshold !== null) {
        metadata.threshold = threshold;
      }

      // Email goes through the canonical chokepoint — entitlement, audience,
      // per-user preference and severity are all decided there.
      //
      // This path used to resolve recipients itself and call sendCustomerEmail
      // directly, which bypassed every rule: no entitlement check meant free
      // workspaces received these alerts by email on every scan, and no
      // preference check meant an opt-out was ignored. It now cannot bypass them
      // because it no longer holds the recipients.
      let emailSentAt = null;
      const frontendOrigin = getEmailFrontendOrigin(env);
      const { text, html } = formatAlertEmail({
        workspaceName,
        domain,
        whatChanged,
        recommendation,
        link: frontendOrigin ? `${frontendOrigin}/scans/${encodeURIComponent(scanId)}` : null,
        preferencesLink: frontendOrigin ? `${frontendOrigin}/settings` : null,
      });
      const delivery = await sendTenantAlertEmail(env, workspaceId, {
        subject: title, text, html, fromKey, severity,
      });
      if (delivery.sent) {
        metadata.email_delivery = { status: "accepted", provider_id: delivery.provider_id || null };
        emailSentAt = new Date().toISOString();
      } else if (SUPPRESSION_REASONS.has(delivery.reason)) {
        // A deliberate decision (not entitled / opted out / below their severity
        // threshold / nobody verified), not a failure. Recorded as skipped so it
        // is not retried and not reported to the customer as a broken send.
        metadata.email_delivery = { status: "skipped", reason: delivery.reason };
      } else {
        metadata.email_delivery = { status: "failed", reason: delivery.reason };
      }

      await env.cybermeters_db
        .prepare(
          `INSERT INTO notification_events
             (id, workspace_id, type, severity, title, message, metadata_json, status, created_at, sent_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'unread', datetime('now'), ?)`
        )
        .bind(notifId, workspaceId, type, severity, title, message, JSON.stringify(metadata), emailSentAt)
        .run();

      // Fan the same event out to Slack/Teams/webhook channels. Channel
      // delivery must never break scan-alert processing.
      try {
        const alertOrigin = getEmailFrontendOrigin(env);
        await deliverWorkspaceAlert(env, workspaceId, {
          kind: type,
          severity,
          title,
          summary: whatChanged || message || "",
          domain,
          workspace_name: workspaceName,
          link: alertOrigin ? `${alertOrigin}/scans/${encodeURIComponent(scanId)}` : null,
        });
      } catch { /* never block on channel fan-out */ }
    };

    const hist = currentModules.historical_changes;
    const ssl = currentModules.ssl;

    // ── 1. Score Drop Alert ── (comparable/complete assessments only)
    if (hist?.has_previous && hist.comparable !== false && hist.score_change != null && hist.score_change <= -10) {
      const isDuplicate = await isAlertDuplicate(env, workspaceId, "score_drop", domain);
      if (!isDuplicate) {
        const scoreDiff = Math.abs(hist.score_change);
        await triggerAlert({
          type: "score_drop",
          severity: "high",
          title: `⚠ CyberMeters: ${domain} score dropped ${scoreDiff} points`,
          message: `Security score dropped from ${hist.previous_score} to ${hist.current_score} (-${scoreDiff} points).`,
          relatedEntity: domain,
          whatChanged: `The security score for ${domain} dropped by ${scoreDiff} points (${hist.previous_score} → ${hist.current_score}).`,
          recommendation: "A drop of this magnitude indicates new critical or high-severity findings. Review the full report immediately to resolve these issues.",
          fromKey: "ALERT_EMAIL_FROM"
        });
      }
    }

    // ── 2. New Critical/High Finding Alert ──
    if (hist?.has_previous && Array.isArray(hist.new_findings)) {
      const newCritHigh = hist.new_findings.filter(f => f.severity === "critical" || f.severity === "high");
      const nonDupNew = [];
      for (const f of newCritHigh) {
        const isDuplicate = await isAlertDuplicate(env, workspaceId, "new_finding", f.id);
        if (!isDuplicate) {
          nonDupNew.push(f);
        }
      }
      
      if (nonDupNew.length > 0) {
        const count = nonDupNew.length;
        const highestSeverity = nonDupNew.some(f => f.severity === "critical") ? "critical" : "high";
        const findingsListStr = nonDupNew.map(f => `• [${f.severity.toUpperCase()}] ${f.title}`).join("\n");
        
        await triggerAlert({
          type: "new_finding",
          severity: highestSeverity,
          title: `🚨 CyberMeters: ${count} new finding${count !== 1 ? "s" : ""} on ${domain}`,
          message: `Detected ${count} new high/critical severity finding${count !== 1 ? "s" : ""} requiring attention.`,
          relatedEntity: nonDupNew[0].id,
          whatChanged: `New high/critical security findings were discovered:\n${findingsListStr}`,
          recommendation: "Review the recommended remediation actions in the report and apply patches or configuration fixes.",
          fromKey: "ALERT_EMAIL_FROM"
        });
      }
    }

    // ── 3. Certificate Expiry Alert ──
    if (ssl?.cert_expiry_days != null && ssl.cert_expiry_days <= 14) {
      const currentThreshold = ssl.cert_expiry_days <= 7 ? 7 : 14;
      const isDuplicate = await isAlertDuplicate(env, workspaceId, "cert_expiry", domain, (meta) => {
        return (meta.threshold || 14) <= currentThreshold;
      });
      
      if (!isDuplicate) {
        const urgency = ssl.cert_expiry_days <= 7 ? "CRITICAL" : "URGENT";
        const barColor = ssl.cert_expiry_days <= 7 ? "critical" : "high";
        const expiryDateStr = ssl.cert_not_after 
          ? new Date(ssl.cert_not_after).toUTCString().slice(0, 22) + " UTC"
          : "unknown";
        
        await triggerAlert({
          type: "cert_expiry",
          severity: barColor,
          title: `[${urgency}] SSL certificate for ${domain} expires in ${ssl.cert_expiry_days} days`,
          message: `SSL certificate expires on ${expiryDateStr} (${ssl.cert_expiry_days} days remaining).`,
          relatedEntity: domain,
          whatChanged: `The SSL certificate for ${domain} is expiring in ${ssl.cert_expiry_days} days (Expiry: ${expiryDateStr}).`,
          recommendation: "An expired SSL certificate will cause browsers to block visitors to your site. Renew the certificate immediately.",
          fromKey: ssl.cert_expiry_days <= 14 ? "ALERT_EMAIL_FROM" : "SAFE_EMAIL_FROM",
          threshold: currentThreshold
        });
      }
    }

    // ── 4. New Vendor Discovered Alert ──
    if (currentModules.vendor_risk?.detected && currentModules.vendor_risk.vendors?.length) {
      const newVendorsQuery = await env.cybermeters_db
        .prepare(
          `SELECT id, vendor_name, category, risk_level
           FROM workspace_vendors
           WHERE workspace_id = ? AND first_seen >= ? AND status = 'active'`
        )
        .bind(workspaceId, startedAt)
        .all();
      const newVendors = newVendorsQuery.results || [];
      
      const nonDupVendors = [];
      for (const v of newVendors) {
        const isDuplicate = await isAlertDuplicate(env, workspaceId, "new_vendor", v.vendor_name);
        if (!isDuplicate) {
          nonDupVendors.push(v);
        }
      }
      
      if (nonDupVendors.length > 0) {
        const count = nonDupVendors.length;
        const vendorListStr = nonDupVendors.map(v => `• ${v.vendor_name} (${v.category || "General"})`).join("\n");
        await triggerAlert({
          type: "new_vendor",
          severity: "info",
          title: `🔍 CyberMeters: ${count} new vendor${count !== 1 ? "s" : ""} discovered for ${domain}`,
          message: `Discovered new active vendor${count !== 1 ? "s" : ""}: ${nonDupVendors.map(v => v.vendor_name).join(", ")}.`,
          relatedEntity: nonDupVendors[0].vendor_name,
          whatChanged: `New active vendor(s) detected on your attack surface:\n${vendorListStr}`,
          recommendation: "Review the vendor's security posture and ensure their compliance with security policies.",
          fromKey: "ALERT_EMAIL_FROM"
        });
      }
    }

    // ── 5. Supply Chain Risk Increase Alert ──
    const scHistoryQuery = await env.cybermeters_db
      .prepare(
        `SELECT resilience_score, concentration_level
         FROM workspace_supply_chain_history
         WHERE workspace_id = ?
         ORDER BY calculated_at DESC
         LIMIT 2`
      )
      .bind(workspaceId)
      .all();
    const scHistory = scHistoryQuery.results || [];
    if (scHistory.length === 2) {
      const curr = scHistory[0];
      const prev = scHistory[1];
      
      const resDropped = curr.resilience_score <= prev.resilience_score - 10;
      const levels = { 'low': 1, 'medium': 2, 'high': 3, 'critical': 4 };
      const conWorsened = (levels[curr.concentration_level] || 0) > (levels[prev.concentration_level] || 0);
      
      if (resDropped || conWorsened) {
        const isDuplicate = await isAlertDuplicate(env, workspaceId, "supply_chain_risk_increase", "supply_chain");
        if (!isDuplicate) {
          let changeDesc = "";
          if (resDropped) {
            changeDesc += `• Operational resilience score dropped from ${prev.resilience_score} to ${curr.resilience_score} (score drop: ${prev.resilience_score - curr.resilience_score} points)\n`;
          }
          if (conWorsened) {
            changeDesc += `• Third-party concentration risk level worsened from "${prev.concentration_level}" to "${curr.concentration_level}"\n`;
          }
          
          await triggerAlert({
            type: "supply_chain_risk_increase",
            severity: "high",
            title: `⚠️ CyberMeters Alert: Supply chain risk increased for workspace`,
            message: `Supply chain risk increase detected in workspace: ` +
              (resDropped ? `Resilience score dropped. ` : '') + (conWorsened ? `Concentration level worsened.` : ''),
            relatedEntity: "supply_chain",
            whatChanged: `Workspace supply chain security indicators have worsened:\n${changeDesc}`,
            recommendation: "Review your third-party vendor concentration and redundancy plans on the Supply Chain dashboard to mitigate systemic dependencies.",
            fromKey: "ALERT_EMAIL_FROM"
          });
        }
      }
    }

  } catch (err) {
    // Graceful error handling for alerts
  }
}
