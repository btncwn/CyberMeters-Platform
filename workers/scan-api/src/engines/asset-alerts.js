// ── Asset change alert engine ──
// Decides when an asset-inventory change is alert-worthy (severity) and builds the
// customer alert email. Extracted verbatim from index.js (monolith decomposition, Phase 1c).
import { escapeEmailHtml } from "../lib/lifecycle-email.js";
import { scanCompletionQualityDisclosure } from "./assessment-presentation.js";
import { evaluateAssetLifecycleEventSupport } from "./asset-lifecycle-event-support.js";
import { findingRemediation } from "./remediation-registry.js";

// ── Asset Change Alert Engine ─────────────────────────────────────────────────
//
// Fires once per workspace per scan, grouped into a single summary email.
// Dedup is enforced by asset_alert_records UNIQUE(workspace_id, scan_id):
//   INSERT OR IGNORE silently no-ops if an alert record already exists.
// Delivery outcome is tracked on the record (status/error); failed sends are
// re-sent by the hourly asset_alert_retry cron (retryFailedAssetAlerts).
//
// Two kinds of change. A notable change can start a notification on its own;
// its severity is the highest one present:
//   takeover_risk_detected  → critical  (a name points at an unclaimed resource)
//   admin_surface_detected  → high      (a sign-in or management page became reachable)
//   wildcard_dns_detected / cloud_storage_detected /
//   certificate_new_san_detected / certificate_new_issuer_detected /
//   asset_reappeared        → medium
// An inventory change — a new name, a name confirmed no longer seen, a renewed
// certificate — is recorded and listed with a notification, but never starts
// one: finding a name is not a risk by itself. Every claim still passes
// evidence eligibility first.

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

// Changes that can start a notification on their own.
export const ASSET_NOTABLE_EVENTS = new Set([
  "takeover_risk_detected",
  "admin_surface_detected",
  "wildcard_dns_detected",
  "cloud_storage_detected",
  "certificate_new_san_detected",
  "certificate_new_issuer_detected",
  "asset_reappeared",
]);

// Inventory changes: recorded, and listed when a notification goes out.
export const ASSET_INVENTORY_EVENTS = new Set([
  "new_asset_discovered",
  "asset_no_longer_seen",
  "certificate_new_detected",
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
// Every supported claim was an inventory change: recorded, not notified.
export const ASSET_ALERT_INVENTORY_ONLY_REASON = "inventory_changes_only";

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
  ASSET_ALERT_INVENTORY_ONLY_REASON,
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

// Severity thresholds — highest matching rule wins. Inventory changes alone
// are information.
export function assetAlertSeverity(counts) {
  if ((counts.takeover_risk_detected || 0) > 0) return "critical";
  if ((counts.admin_surface_detected || 0) > 0) return "high";
  if ((counts.wildcard_dns_detected  || 0) > 0 ||
      (counts.cloud_storage_detected || 0) > 0 ||
      (counts.certificate_new_san_detected || 0) > 0 ||
      (counts.certificate_new_issuer_detected || 0) > 0 ||
      (counts.asset_reappeared       || 0) > 0)  return "medium";
  return "info";
}

// True when a notable change is present. Inventory changes — a new name, a
// confirmed removal, a renewed certificate — never notify on their own.
// Eligibility filters unsupported claims before this count gate.
export function assetAlertWorthy(counts) {
  return [...ASSET_NOTABLE_EVENTS].some((eventType) => (counts?.[eventType] || 0) > 0);
}

// ── What changed, for the notification ──────────────────────────────────────
// One record per notable change: before and now, when, why this severity, the
// evidence it rests on, how sure the match is, and the canonical recommended
// action (remediation registry) where one exists. Inventory changes are
// summarised beside them. Bounded and free of URL paths, queries and page
// content beyond a shortened title.
export const ASSET_CHANGE_RECORD_VERSION = "asset-change-record-v1";
const MAX_CHANGE_RECORDS = 20;
const MAX_INVENTORY_NAMES = 10;

const ADMIN_SEVERITIES = new Set(["critical", "high", "medium"]);
const short = (value, max = 160) => (typeof value === "string" && value.trim() ? value.trim().slice(0, max) : null);
const lowerHost = (value) => String(value || "").trim().toLowerCase().replace(/\.$/, "");

function utcLabel(value) {
  const ms = Date.parse(String(value || ""));
  if (!Number.isFinite(ms)) return null;
  return `${new Date(ms).toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

function registryAction(findingType) {
  const remediation = findingRemediation({ id: findingType });
  return remediation?.recommended_action ? short(remediation.recommended_action, 300) : null;
}

// How the web service answered, from this scan's evidence for the name.
function reachabilityFrom(evidence, probe) {
  const attempt = (evidence?.service?.attempts || []).find((item) => item?.outcome === "responded")
    ?? (probe?.attempts || []).find((item) => item?.outcome === "responded");
  if (attempt?.protocol) {
    return `${String(attempt.protocol).toUpperCase()} port ${attempt.port} answered${Number.isInteger(attempt.status) ? ` with HTTP ${attempt.status}` : ""}`;
  }
  if (Number.isInteger(probe?.status)) return `A web request answered with HTTP ${probe.status}`;
  return null;
}

function previousLabel(previousScanAt) {
  const at = utcLabel(previousScanAt);
  return at ? `the previous scan (${at})` : "the previous scan";
}

function changeRecord(event, { modules, evidenceByHost, observedAt, previousScanAt, domain }) {
  const host = lowerHost(event.hostname);
  const evidence = evidenceByHost?.get?.(host) ?? null;
  const probe = (modules?.asset_exposure?.assets || []).find((asset) => lowerHost(asset?.host) === host) ?? null;
  const base = {
    version: ASSET_CHANGE_RECORD_VERSION,
    type: event.event_type,
    hostname: host || null,
    observed_at: observedAt || event.created_at || null,
  };
  switch (event.event_type) {
    case "takeover_risk_detected": {
      const risk = (modules?.subdomain_takeover?.risks || []).find((item) => lowerHost(item?.host) === host) ?? null;
      const provider = short(risk?.provider ?? risk?.service, 60);
      return {
        ...base,
        severity: "critical",
        title: "A name points at an unclaimed resource",
        before: `Not a takeover candidate in ${previousLabel(previousScanAt)}`,
        now: `${host} is an alias for ${lowerHost(risk?.cname) || "a provider name"}${provider ? ` (${provider})` : ""}, which answers that the resource is unclaimed`,
        evidence: "The provider's own unclaimed-resource answer was matched; the resource was not claimed to prove it.",
        severity_reason: "Whoever claims that resource decides what this name serves to your visitors.",
        action: registryAction("subdomain_takeover"),
      };
    }
    case "admin_surface_detected": {
      const service = (modules?.admin_surface_detection?.services || [])
        .find((item) => lowerHost(item?.hostname) === host && item?.finding_type !== "observation") ?? null;
      const product = short(service?.product, 60) || "A management tool";
      const signals = (service?.evidence_signals || [])
        .map((signal) => ({ product_title: "the page title", server_header: "the Server header", hostname: "the name" }[signal]))
        .filter(Boolean);
      // Severity is the tool's own classification (what it manages), kept
      // apart from how sure the match is and from what answered.
      const severity = ADMIN_SEVERITIES.has(event.severity) ? event.severity : "high";
      return {
        ...base,
        severity,
        title: `${product} sign-in or management page now reachable`,
        before: `Not reachable as ${product} in ${previousLabel(previousScanAt)}`,
        now: `${product} answered on ${host}`,
        evidence: [reachabilityFrom(evidence, probe), signals.length ? `matched on ${signals.join(" and ")}${service?.confidence ? ` (${service.confidence} confidence)` : ""}` : null]
          .filter(Boolean).join("; ") || null,
        severity_reason: `${product} is classed ${severity} by the kind of system it manages, and a management page reachable from the internet is a target for password guessing. Reachable does not mean anyone has signed in, or that the tool can be exploited.`,
        action: registryAction(severity === "critical" ? "admin_surface_critical" : "admin_surface_high"),
      };
    }
    case "wildcard_dns_detected":
      return {
        ...base,
        hostname: lowerHost(domain) || host || null,
        severity: "medium",
        title: "The zone now answers every name",
        before: "Names that do not exist returned no address",
        now: `Any name under ${lowerHost(domain) || host} returns an address`,
        evidence: "A random name that cannot exist was asked and answered with an address.",
        severity_reason: "Mistyped and unused names now resolve, and new names under the zone can no longer be told apart from the catch-all answer.",
        // The registry's entry under this id is the certificate-change review,
        // which is not what a zone-wide wildcard needs; no action is invented.
        action: null,
      };
    case "asset_reappeared":
      return {
        ...base,
        severity: "medium",
        title: "A name confirmed gone answers again",
        before: "Confirmed no longer seen over repeated scans",
        now: reachabilityFrom(evidence, probe) ? `${host} answers again: ${reachabilityFrom(evidence, probe)}` : `${host} answers in DNS again`,
        evidence: reachabilityFrom(evidence, probe),
        severity_reason: "A name that comes back may be a service restarted outside the usual review.",
        action: null,
      };
    case "certificate_new_issuer_detected":
      return {
        ...base,
        severity: "medium",
        title: "A new certificate issuer",
        before: "Certificates on this domain came from other issuers",
        now: short(event.description, 200),
        evidence: "Read from the certificate the live site presented.",
        severity_reason: "A new issuer is usually a planned change of provider; an unplanned one is worth confirming.",
        action: registryAction("certificate_unexpected_issuer"),
      };
    case "certificate_new_san_detected":
      return {
        ...base,
        severity: event.severity === "high" ? "high" : "medium",
        title: "A new name on the live certificate",
        before: "Not on the certificates seen before",
        now: short(event.description, 200),
        evidence: "Read from the certificate the live site presented.",
        severity_reason: "A name added to the certificate is usually a planned change; an unplanned one is worth confirming.",
        action: registryAction("certificate_unexpected_san"),
      };
    default:
      return {
        ...base,
        severity: "medium",
        title: ASSET_ALERT_EMAIL_LABELS[event.event_type] || "Change observed",
        before: null,
        now: short(event.description, 200),
        evidence: null,
        severity_reason: null,
        action: null,
      };
  }
}

/**
 * The notification's content for one workspace and scan: a record per notable
 * change (most severe first) and a summary of inventory changes. `events` are
 * the eligible events of this scan.
 */
export function buildAssetChangeRecords(events, { modules = null, evidenceByHost = null, observedAt = null, previousScanAt = null, domain = null } = {}) {
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const changes = (events || [])
    .filter((event) => ASSET_NOTABLE_EVENTS.has(event?.event_type))
    .map((event) => changeRecord(event, { modules, evidenceByHost, observedAt, previousScanAt, domain }))
    .sort((a, b) => (rank[a.severity] ?? 5) - (rank[b.severity] ?? 5) || String(a.hostname).localeCompare(String(b.hostname)));
  const namesOf = (type) => [...new Set((events || []).filter((event) => event?.event_type === type).map((event) => lowerHost(event.hostname)).filter(Boolean))].sort();
  const newNames = namesOf("new_asset_discovered");
  const gone = namesOf("asset_no_longer_seen");
  return {
    version: ASSET_CHANGE_RECORD_VERSION,
    // The notification's severity: its most severe change.
    severity: changes[0]?.severity ?? null,
    changes: changes.slice(0, MAX_CHANGE_RECORDS),
    more_changes: Math.max(0, changes.length - MAX_CHANGE_RECORDS),
    inventory: {
      new_names: newNames.slice(0, MAX_INVENTORY_NAMES),
      new_name_count: newNames.length,
      no_longer_seen: gone.slice(0, MAX_INVENTORY_NAMES),
      no_longer_seen_count: gone.length,
      renewed_certificates: (events || []).filter((event) => event?.event_type === "certificate_new_detected").length,
    },
  };
}

function inventorySentence(inventory) {
  if (!inventory) return null;
  const parts = [];
  if (inventory.new_name_count > 0) {
    parts.push(`${inventory.new_name_count} new name${inventory.new_name_count === 1 ? "" : "s"} (${inventory.new_names.join(", ")}${inventory.new_name_count > inventory.new_names.length ? ", …" : ""})`);
  }
  if (inventory.no_longer_seen_count > 0) {
    parts.push(`${inventory.no_longer_seen_count} name${inventory.no_longer_seen_count === 1 ? "" : "s"} confirmed no longer seen (${inventory.no_longer_seen.join(", ")}${inventory.no_longer_seen_count > inventory.no_longer_seen.length ? ", …" : ""})`);
  }
  if (inventory.renewed_certificates > 0) parts.push(`${inventory.renewed_certificates} new certificate${inventory.renewed_certificates === 1 ? "" : "s"} on the live site`);
  return parts.length ? `Also in the inventory: ${parts.join("; ")}.` : null;
}

// `details` (optional): the change records from buildAssetChangeRecords, plus
// `settings_url`. With them the email states, per change, before and now, the
// time, why this severity, the evidence and the recommended action. Without
// them (an alert recorded before change records existed) it lists counts.
export function buildAssetAlertEmail(domain, workspaceId, scanId, counts, topHostnames, severity, assetsUrl = null, scanQuality = null, details = null) {
  const SEVERITY_COLOR = {
    critical: "#dc2626",
    high:     "#ea580c",
    medium:   "#d97706",
    info:     "#117362",
  };
  const color = SEVERITY_COLOR[severity] || SEVERITY_COLOR.info;
  const quality = scanCompletionQualityDisclosure(scanQuality);
  if (Array.isArray(details?.changes) && details.changes.length > 0) {
    return buildAssetChangeEmail(domain, scanId, severity, color, quality, assetsUrl, details);
  }

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
    `Asset change alert for ${domain}`,
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

function buildAssetChangeEmail(domain, scanId, severity, color, quality, assetsUrl, details) {
  const changes = details.changes;
  const top = changes[0];
  const subject = top.type === "takeover_risk_detected"
    ? `🚨 CyberMeters: Takeover risk on ${domain}`
    : top.type === "admin_surface_detected"
    ? `${top.severity === "critical" ? "🚨" : "⚠"} CyberMeters: Management page now reachable on ${domain}`
    : `CyberMeters: ${changes.length === 1 ? top.title : "Changes"} on ${domain}`;
  const observed = utcLabel(top.observed_at);
  const inventory = inventorySentence(details.inventory);
  const settingsUrl = typeof details.settings_url === "string" ? details.settings_url : null;

  const blocks = changes.map((change, index) => [
    `${index + 1}. [${String(change.severity || "info").toUpperCase()}] ${change.title}${change.hostname ? ` — ${change.hostname}` : ""}`,
    ...(change.before ? [`   Before: ${change.before}`] : []),
    ...(change.now ? [`   Now: ${change.now}`] : []),
    ...(utcLabel(change.observed_at) ? [`   Observed: ${utcLabel(change.observed_at)}`] : []),
    ...(change.evidence ? [`   Evidence: ${change.evidence}`] : []),
    ...(change.severity_reason ? [`   Why this severity: ${change.severity_reason}`] : []),
    `   Recommended: ${change.action || "Review this change in the asset inventory."}`,
  ].join("\n"));

  const text = [
    `Changes on ${domain}${observed ? ` found by the scan completed ${observed}` : ""}`,
    `Highest severity: ${String(severity).toUpperCase()}`,
    ...(quality.disclosure ? [`Scan quality: ${quality.disclosure}`] : []),
    "",
    ...blocks.flatMap((block) => [block, ""]),
    ...(details.more_changes > 0 ? [`${details.more_changes} more change${details.more_changes === 1 ? "" : "s"} in the asset inventory.`, ""] : []),
    ...(inventory ? [inventory, ""] : []),
    assetsUrl ? `View the changes: ${assetsUrl}` : "Open CyberMeters to review the asset inventory.",
    ...(settingsUrl ? [`Notification settings: ${settingsUrl}`] : []),
  ].join("\n");

  const row = (label, value) => value
    ? `<tr><td style="padding:2px 12px 2px 0;color:#6b7280;font-size:13px;vertical-align:top;white-space:nowrap">${escapeEmailHtml(label)}</td><td style="padding:2px 0;font-size:13px;color:#111827">${escapeEmailHtml(value)}</td></tr>`
    : "";
  const changeHtml = changes.map((change) => {
    const changeColor = { critical: "#dc2626", high: "#ea580c", medium: "#d97706" }[change.severity] || "#117362";
    return `<div style="border:1px solid #e5e7eb;border-left:4px solid ${changeColor};border-radius:8px;padding:12px 14px;margin:0 0 12px">
      <p style="margin:0 0 6px;font-size:14px;font-weight:600;color:#111827">${escapeEmailHtml(change.title)}${change.hostname ? ` <span style="font-weight:400;color:#374151">— ${escapeEmailHtml(change.hostname)}</span>` : ""}</p>
      <p style="margin:0 0 8px;font-size:12px;font-weight:600;color:${changeColor};text-transform:uppercase">${escapeEmailHtml(change.severity || "info")}</p>
      <table style="border-collapse:collapse">${row("Before", change.before)}${row("Now", change.now)}${row("Observed", utcLabel(change.observed_at))}${row("Evidence", change.evidence)}${row("Why this severity", change.severity_reason)}${row("Recommended", change.action || "Review this change in the asset inventory.")}</table>
    </div>`;
  }).join("\n    ");

  const html = `<!DOCTYPE html>
<html lang="en">
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#111;max-width:600px;margin:0 auto;padding:24px;">
  <div style="border-left:4px solid ${color};padding-left:16px;margin-bottom:20px;">
    <h2 style="margin:0 0 4px;color:${color};font-size:18px;">Changes on ${escapeEmailHtml(domain)}</h2>
    <p style="margin:0;color:#555;font-size:14px;">${observed ? `Found by the scan completed ${escapeEmailHtml(observed)}. ` : ""}Highest severity: <span style="font-weight:600;color:${color};text-transform:uppercase;font-size:12px">${escapeEmailHtml(severity)}</span></p>${quality.disclosure ? `
    <p style="margin:8px 0 0;color:#92400e;font-size:13px;line-height:1.5;">${escapeEmailHtml(quality.disclosure)}</p>` : ""}
  </div>
    ${changeHtml}
  ${details.more_changes > 0 ? `<p style="font-size:13px;color:#555">${escapeEmailHtml(`${details.more_changes} more change${details.more_changes === 1 ? "" : "s"} in the asset inventory.`)}</p>` : ""}
  ${inventory ? `<p style="font-size:13px;color:#555;margin-top:12px;">${escapeEmailHtml(inventory)}</p>` : ""}
  ${assetsUrl ? `<p style="margin-top:24px;">
    <a href="${escapeEmailHtml(assetsUrl)}"
       style="background:${color};color:white;padding:10px 20px;border-radius:8px;
              text-decoration:none;font-size:14px;font-weight:600;display:inline-block;">
      View the changes
    </a>
  </p>` : ""}
  <hr style="border:none;border-top:1px solid #eee;margin:28px 0;" />
  <p style="font-size:12px;color:#999;margin:0;">
    CyberMeters &mdash; Attack Surface Management${settingsUrl ? `<br><a href="${escapeEmailHtml(settingsUrl)}" style="color:#999">Notification settings</a>` : ""}<br>
    Scan ID: <code style="font-size:11px">${escapeEmailHtml(scanId)}</code>
  </p>
</body>
</html>`;

  return { subject, text, html };
}
