// ── Asset change alert engine ──
// Decides when an asset-inventory change is alert-worthy (severity) and builds the
// customer alert email. Extracted verbatim from index.js (monolith decomposition, Phase 1c).
import { escapeEmailHtml } from "../lib/lifecycle-email.js";

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
//   asset_no_longer_seen    → info  (included in summary but does not trigger alone)

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
// asset_no_longer_seen alone is not alert-worthy.
export function assetAlertWorthy(counts) {
  return (
    (counts.new_asset_discovered   || 0) > 0 ||
    (counts.asset_reappeared       || 0) > 0 ||
    (counts.takeover_risk_detected || 0) > 0 ||
    (counts.cloud_storage_detected || 0) > 0 ||
    (counts.wildcard_dns_detected  || 0) > 0 ||
    (counts.admin_surface_detected || 0) > 0 ||
    (counts.certificate_new_detected || 0) > 0 ||
    (counts.certificate_new_san_detected || 0) > 0 ||
    (counts.certificate_new_issuer_detected || 0) > 0
  );
}

export function buildAssetAlertEmail(domain, workspaceId, scanId, counts, topHostnames, severity, assetsUrl = null) {
  const SEVERITY_COLOR = {
    critical: "#dc2626",
    high:     "#ea580c",
    medium:   "#d97706",
    info:     "#00876A",
  };
  const color = SEVERITY_COLOR[severity] || SEVERITY_COLOR.info;

  const LABELS = {
    new_asset_discovered:   "New assets discovered",
    asset_reappeared:       "Assets reappeared",
    asset_no_longer_seen:   "Assets no longer seen",
    takeover_risk_detected: "Subdomain takeover risks",
    cloud_storage_detected: "Cloud storage references",
    wildcard_dns_detected:  "Wildcard DNS events",
  };

  const lines = [];
  for (const [type, label] of Object.entries(LABELS)) {
    const n = counts[type] || 0;
    if (n > 0) lines.push(`${label}: ${n}`);
  }

  const hostList = (topHostnames || []).slice(0, 5);
  const hostLine = hostList.length > 0
    ? `Top affected hostnames: ${hostList.join(", ")}`
    : null;

  const subject = severity === "critical"
    ? `🚨 CyberMeters: Takeover risk on ${domain}`
    : severity === "high"
    ? `⚠ CyberMeters: New assets detected on ${domain}`
    : `CyberMeters: Asset changes on ${domain}`;

  const text = [
    `Asset change alert for ${domain} (workspace ${workspaceId})`,
    `Severity: ${severity.toUpperCase()}`,
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
      <span style="font-weight:600;color:${color};text-transform:uppercase;font-size:12px">${severity}</span>
    </p>
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
