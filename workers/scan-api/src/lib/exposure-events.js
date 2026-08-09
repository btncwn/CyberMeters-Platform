// ── Exposure Timeline event metadata ─────────────────────────────────────────
// Pure helpers for enriching asset_events rows with stable category/title data.
// Used by the Exposure Timeline feed and digest surfaces.

import { formatSpfAuthorizationDescriptionForDisplay } from "../engines/spf-resolver.js";

export const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export const EXPOSURE_EVENT_META = {
  new_asset_discovered:              { category: "asset",       title: "New subdomain" },
  asset_no_longer_seen:              { category: "asset",       title: "Asset no longer seen" },
  asset_reappeared:                  { category: "asset",       title: "Asset reappeared" },
  wildcard_dns_detected:             { category: "asset",       title: "Wildcard DNS detected" },
  cloud_storage_detected:            { category: "asset",       title: "Cloud storage detected" },
  takeover_risk_detected:            { category: "asset",       title: "Takeover risk detected" },
  dns_ip_changed:                    { category: "dns",         title: "IP address changed" },
  dns_cname_changed:                 { category: "dns",         title: "CNAME changed" },
  dns_redirect_changed:              { category: "dns",         title: "Redirect target changed" },
  email_spf_changed:                 { category: "email",       title: "SPF record changed" },
  email_spf_authorization_changed:   { category: "email",       title: "SPF authorised senders changed" },
  email_dmarc_policy_changed:        { category: "email",       title: "DMARC policy changed" },
  email_dkim_changed:                { category: "email",       title: "DKIM changed" },
  certificate_new_detected:          { category: "certificate", title: "New certificate" },
  certificate_expiring_soon:         { category: "certificate", title: "Certificate expiring soon" },
  certificate_new_issuer_detected:   { category: "certificate", title: "New certificate issuer" },
  certificate_new_san_detected:      { category: "certificate", title: "New certificate SAN" },
  certificate_sensitive_host_detected: { category: "certificate", title: "Sensitive host certificate" },
  certificate_growth_detected:       { category: "certificate", title: "Certificate footprint grew" },
  certificate_authority:             { category: "certificate", title: "Certificate authority note" },
  exposed_service_detected:          { category: "exposure",    title: "New exposed service" },
  exposed_service_resolved:          { category: "exposure",    title: "Exposed service resolved" },
};

function fallbackTitle(eventType) {
  return String(eventType || "unknown_event")
    .split("_")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export function enrichEvent(row) {
  try {
    const meta = EXPOSURE_EVENT_META[row?.event_type] || {
      category: "asset",
      title: fallbackTitle(row?.event_type),
    };
    return {
      ...row,
      description: formatSpfAuthorizationDescriptionForDisplay(row?.description),
      category: meta.category,
      title: row?.title || meta.title,
    };
  } catch {
    return { ...(row || {}), category: "asset", title: "Unknown event" };
  }
}

export function eventTypesForCategory(cat) {
  return Object.entries(EXPOSURE_EVENT_META)
    .filter(([, meta]) => meta.category === cat)
    .map(([type]) => type);
}
