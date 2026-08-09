// ── Asset change alert engine ──
// Decides when an asset-inventory change is alert-worthy (severity) and builds the
// customer alert email. Extracted verbatim from index.js (monolith decomposition, Phase 1c).
import { escapeEmailHtml } from "../lib/lifecycle-email.js";
import { scanCompletionQualityDisclosure } from "./assessment-presentation.js";
import { evaluateAssetLifecycleEventSupport } from "./asset-lifecycle-event-support.js";

// ── Asset Change Alert Engine ─────────────────────────────────────────────────
//
// Fires once per workspace per scan, grouped into a single summary email.
// Dedup is enforced by asset_alert_records UNIQUE(workspace_id, scan_id):
//   INSERT OR IGNORE silently no-ops if an alert record already exists.
// Delivery outcome is tracked on the record (status/error); failed sends are
// re-sent by the hourly asset_alert_retry cron (retryFailedAssetAlerts).
//
// Alert-worthy event types and their severity contribution:
//   takeover_risk_detected  → critical
//   new_asset_discovered    → high
//   wildcard_dns_detected   → medium
//   cloud_storage_detected  → medium
//   certificate_new_detected / certificate_new_san_detected /
//   certificate_new_issuer_detected → medium
//   asset_reappeared        → medium
//   asset_no_longer_seen    → info  (triggers only after evidence eligibility)

export const ASSET_ALERT_EVENTS = new Set([
  "new_asset_discovered",
  "asset_reappeared",
  "asset_no_longer_seen",
  "takeover_risk_detected",
  "cloud_storage_detected",
  "wildcard_dns_detected",
  "admin_surface_detected",
  "certificate_new_detected",
  "certificate_new_san_detected",
  "certificate_new_issuer_detected",
]);

export const ASSET_ALERT_EMAIL_LABELS = Object.freeze({
  new_asset_discovered: "New assets observed",
  asset_reappeared: "Seen again",
  asset_no_longer_seen: "No longer seen",
  takeover_risk_detected: "Takeover candidates observed",
  cloud_storage_detected: "Cloud storage references observed",
  wildcard_dns_detected: "Wildcard DNS observed",
  admin_surface_detected: "Admin surfaces observed",
  certificate_new_detected: "New certificates observed",
  certificate_new_san_detected: "New certificate names observed",
  certificate_new_issuer_detected: "New certificate issuers observed",
});

const missingAssetAlertEmailLabels = [...ASSET_ALERT_EVENTS].filter(
  (eventType) => !ASSET_ALERT_EMAIL_LABELS[eventType],
);
if (missingAssetAlertEmailLabels.length > 0) {
  throw new Error(
    `Missing customer-facing asset alert email labels: ${missingAssetAlertEmailLabels.join(", ")}`,
  );
}

export const ASSET_ALERT_ELIGIBILITY_VERSION = "asset-alert-eligibility-v1";
export const ASSET_ALERT_WITHHELD_REASON =
  "withheld_all_claims_unsupported";

// Frozen, machine-readable vocabulary. Every per-claim decision and the
// withheld-only delivery record uses one of these values; callers must never
// substitute free text or an unlabelled false.
export const ASSET_ALERT_ELIGIBILITY_REASON_CODES = Object.freeze([
  "eligible_signal_observed",
  "eligible_event_evidence",
  "eligible_event_evidence_fallback",
  "eligible_confirmed_removal",
  "eligible_reappearance_after_confirmed_removal",
  "withheld_signal_not_supported",
  "withheld_lifecycle_schema_absent",
  "withheld_evidence_lookup_unavailable",
  "withheld_removal_confirmation_not_satisfied",
  "withheld_reappearance_predecessor_unconfirmed",
  "withheld_support_not_evaluable",
  "withheld_lifecycle_evidence_not_recorded",
  "withheld_lifecycle_policy_unknown",
  "withheld_lifecycle_source_detail_malformed",
  "withheld_lifecycle_timestamp_invalid",
  "withheld_lifecycle_replay_truncated",
  ASSET_ALERT_WITHHELD_REASON,
]);

const CLAIM_SIGNAL_KEYS = Object.freeze({
  new_asset_discovered: "subdomain_discovery",
  takeover_risk_detected: "takeover_candidate",
  cloud_storage_detected: "cloud_storage",
  admin_surface_detected: "exposure_admin_surface",
});

const LIFECYCLE_CLAIMS = new Set([
  "asset_no_longer_seen",
  "asset_reappeared",
]);

const DIRECT_EVENT_CLAIMS = new Set([
  "wildcard_dns_detected",
  "certificate_new_detected",
  "certificate_new_san_detected",
  "certificate_new_issuer_detected",
]);

function claimFromProjection(event, evidence) {
  const claims = evidence.lifecycle_projection?.claims_by_event_id;
  if (claims instanceof Map) return claims.get(event?.id);
  if (claims && typeof claims === "object") return claims[event?.id];
  return null;
}

function decisionForEvent(event, evidence) {
  if (LIFECYCLE_CLAIMS.has(event.event_type)) {
    const claim = claimFromProjection(event, evidence) ||
      evaluateAssetLifecycleEventSupport({
        event,
        observations: evidence.lifecycle_observations || [],
        lifecycleStatus: evidence.lifecycle_status || "available",
        replayComplete: evidence.lifecycle_replay_complete !== false,
      });
    return {
      eligible: claim.state === "supported",
      reason_code: claim.reason_code,
      support_state: claim.state,
      evidence_backed: claim.evidence_backed,
      limitation_codes: claim.limitation_codes || [],
    };
  }

  const signalKey = CLAIM_SIGNAL_KEYS[event.event_type];
  if (signalKey) {
    const signal = evidence.signal_states?.[signalKey];
    if (signal) {
      return signal.state === "observed"
        ? { eligible: true, reason_code: "eligible_signal_observed" }
        : { eligible: false, reason_code: "withheld_signal_not_supported" };
    }
    // Migration 102 absent, a failed evidence read, or an individual missing
    // row must not silence an independently persisted detection event.
    return {
      eligible: true,
      reason_code: "eligible_event_evidence_fallback",
    };
  }

  if (DIRECT_EVENT_CLAIMS.has(event.event_type)) {
    return { eligible: true, reason_code: "eligible_event_evidence" };
  }

  // ASSET_ALERT_EVENTS is frozen and exhaustive. Retain an explicit reason if
  // a future caller evaluates an event before extending this policy.
  return { eligible: false, reason_code: "withheld_signal_not_supported" };
}

function groupedDecisions(decisions, eligible) {
  const grouped = new Map();
  for (const decision of decisions.filter((item) => item.eligible === eligible)) {
    const key = `${decision.event_type}:${decision.reason_code}`;
    const current = grouped.get(key) || {
      event_type: decision.event_type,
      reason_code: decision.reason_code,
      count: 0,
    };
    current.count += 1;
    grouped.set(key, current);
  }
  return [...grouped.values()].sort((a, b) =>
    a.event_type.localeCompare(b.event_type) ||
    a.reason_code.localeCompare(b.reason_code));
}

export function evaluateAssetAlertEligibility(events, evidence = {}) {
  const alertEvents = (events || []).filter((event) =>
    ASSET_ALERT_EVENTS.has(event?.event_type));
  const decisions = alertEvents.map((event) => {
    const result = decisionForEvent(event, evidence);
    return {
      event_id: event.id || null,
      event_type: event.event_type,
      eligible: result.eligible,
      reason_code: result.reason_code,
      ...(result.support_state ? { support_state: result.support_state } : {}),
      ...(Object.hasOwn(result, "evidence_backed")
        ? { evidence_backed: result.evidence_backed }
        : {}),
      ...(result.limitation_codes?.length
        ? { limitation_codes: result.limitation_codes }
        : {}),
    };
  });
  const eligibleEvents = [];
  const withheldEvents = [];
  for (const [index, event] of alertEvents.entries()) {
    const decision = decisions[index];
    (decision?.eligible ? eligibleEvents : withheldEvents).push(event);
  }
  return {
    policy_version: ASSET_ALERT_ELIGIBILITY_VERSION,
    eligible_events: eligibleEvents,
    withheld_events: withheldEvents,
    decisions,
    record: {
      policy_version: ASSET_ALERT_ELIGIBILITY_VERSION,
      eligible: groupedDecisions(decisions, true),
      withheld: groupedDecisions(decisions, false),
    },
  };
}

export function assetAlertCounts(events, eligibilityRecord = null) {
  const counts = {};
  for (const event of events || []) {
    if (!ASSET_ALERT_EVENTS.has(event?.event_type)) continue;
    counts[event.event_type] = (counts[event.event_type] || 0) + 1;
  }
  if (eligibilityRecord) counts._eligibility = eligibilityRecord;
  return counts;
}

// Severity thresholds — highest matching rule wins.
export function assetAlertSeverity(counts) {
  if ((counts.takeover_risk_detected || 0) > 0) return "critical";
  if ((counts.admin_surface_detected || 0) > 0) return "high";
  if ((counts.new_asset_discovered   || 0) > 0) return "high";
  if ((counts.wildcard_dns_detected  || 0) > 0 ||
      (counts.cloud_storage_detected || 0) > 0 ||
      (counts.certificate_new_detected || 0) > 0 ||
      (counts.certificate_new_san_detected || 0) > 0 ||
      (counts.certificate_new_issuer_detected || 0) > 0 ||
      (counts.asset_reappeared       || 0) > 0)  return "medium";
  return "info";
}

// Returns true when there is something worth emailing about.
// A confirmed asset_no_longer_seen is alert-worthy at info severity. Eligibility
// filters unsupported legacy/one-scan removal claims before this count gate.
export function assetAlertWorthy(counts) {
  return (
    (counts.new_asset_discovered   || 0) > 0 ||
    (counts.asset_reappeared       || 0) > 0 ||
    (counts.asset_no_longer_seen   || 0) > 0 ||
    (counts.takeover_risk_detected || 0) > 0 ||
    (counts.cloud_storage_detected || 0) > 0 ||
    (counts.wildcard_dns_detected  || 0) > 0 ||
    (counts.admin_surface_detected || 0) > 0 ||
    (counts.certificate_new_detected || 0) > 0 ||
    (counts.certificate_new_san_detected || 0) > 0 ||
    (counts.certificate_new_issuer_detected || 0) > 0
  );
}

export function buildAssetAlertEmail(domain, workspaceId, scanId, counts, topHostnames, severity, assetsUrl = null, scanQuality = null) {
  const SEVERITY_COLOR = {
    critical: "#dc2626",
    high:     "#ea580c",
    medium:   "#d97706",
    info:     "#00876A",
  };
  const color = SEVERITY_COLOR[severity] || SEVERITY_COLOR.info;
  const quality = scanCompletionQualityDisclosure(scanQuality);

  const lines = [];
  for (const type of ASSET_ALERT_EVENTS) {
    const n = counts[type] || 0;
    if (n > 0) lines.push(`${ASSET_ALERT_EMAIL_LABELS[type]}: ${n}`);
  }

  const hostList = (topHostnames || []).slice(0, 5);
  const hostLine = hostList.length > 0
    ? `Top affected hostnames: ${hostList.join(", ")}`
    : null;

  const takeoverCount = counts.takeover_risk_detected || 0;
  const newAssetCount = counts.new_asset_discovered || 0;
  const adminSurfaceCount = counts.admin_surface_detected || 0;
  const subject = takeoverCount > 0
    ? `🚨 CyberMeters: Takeover risk on ${domain}`
    : newAssetCount > 0 && adminSurfaceCount > 0
    ? `⚠ CyberMeters: Asset changes observed on ${domain}`
    : adminSurfaceCount > 0
    ? `⚠ CyberMeters: Admin surfaces observed on ${domain}`
    : newAssetCount > 0
    ? `⚠ CyberMeters: New assets observed on ${domain}`
    : `CyberMeters: Asset changes on ${domain}`;

  const text = [
    `Asset change alert for ${domain} (workspace ${workspaceId})`,
    `Severity: ${severity.toUpperCase()}`,
    ...(quality.disclosure ? [`Scan quality: ${quality.disclosure}`] : []),
    "",
    ...lines,
    ...(hostLine ? [hostLine] : []),
    "",
    assetsUrl ? `View asset inventory: ${assetsUrl}` : "Open CyberMeters to review the asset inventory.",
  ].join("\n");

  const listItems = lines
    .map((l) => `<li style="margin-bottom:6px">${escapeEmailHtml(l)}</li>`)
    .join("\n      ");

  const hostnameSection = hostList.length > 0
    ? `<p style="font-size:13px;color:#555;margin-top:12px;">
        <strong>Affected hostnames:</strong> ${hostList.map((h) => `<code style="background:#f3f4f6;padding:1px 5px;border-radius:4px;font-size:12px">${escapeEmailHtml(h)}</code>`).join(" ")}
       </p>`
    : "";

  const html = `<!DOCTYPE html>
<html lang="en">
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#111;max-width:600px;margin:0 auto;padding:24px;">
  <div style="border-left:4px solid ${color};padding-left:16px;margin-bottom:20px;">
    <h2 style="margin:0 0 4px;color:${color};font-size:18px;">Asset Change Alert</h2>
    <p style="margin:0;color:#555;font-size:14px;">
      Scan completed for <strong>${escapeEmailHtml(domain)}</strong> &mdash;
      ${quality.complete ? "" : "Event severity: "}<span style="font-weight:600;color:${color};text-transform:uppercase;font-size:12px">${severity}</span>
    </p>${quality.disclosure ? `
    <p style="margin:8px 0 0;color:#92400e;font-size:13px;line-height:1.5;">${escapeEmailHtml(quality.disclosure)}</p>` : ""}
  </div>
  <ul style="padding-left:20px;line-height:1.8;font-size:14px;color:#333;">
    ${listItems}
  </ul>
  ${hostnameSection}
  ${assetsUrl ? `<p style="margin-top:24px;">
    <a href="${escapeEmailHtml(assetsUrl)}"
       style="background:${color};color:white;padding:10px 20px;border-radius:8px;
              text-decoration:none;font-size:14px;font-weight:600;display:inline-block;">
      View Asset Inventory
    </a>
  </p>` : ""}
  <hr style="border:none;border-top:1px solid #eee;margin:28px 0;" />
  <p style="font-size:12px;color:#999;margin:0;">
    CyberMeters &mdash; Attack Surface Management<br>
    Scan ID: <code style="font-size:11px">${escapeEmailHtml(scanId)}</code>
  </p>
</body>
</html>`;

  return { subject, text, html };
}
