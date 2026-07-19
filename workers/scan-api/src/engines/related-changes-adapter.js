// ── M6 Phase B1: Related Changes — read-only event adapter ──
//
// This module does NOT correlate the eight customer-facing domains. It projects the
// raw CHANGE-EVENT PRODUCERS into ONE canonical event shape, keyed by canonical entity
// keys, so the deterministic rules engine (related-changes-rules.js) can pair
// independent signal families on the same registrable domain. (design note §1, §2, §3.)
//
// Adapter, NOT migration: every producer keeps its own table. Nothing is copied or
// moved — we read the existing rows within a bounded scan window and emit pointers.
//
// Canonical event shape:
//   { producer_family, entity_key, registrable_domain, event_type, direction,
//     observed_at, source_table, source_record_id, evidence_ref }
//
// Producers wired in v1 (design §2 substrate audit):
//   asset          — asset_events (asset-inventory event types)      host:<fqdn>
//   cert           — asset_events (certificate_* event types)        host:<fqdn>
//   email_config   — asset_events (email_* event types)              domain:<root>
//   email_sender   — email_sender_sources (new source by first_seen) domain:<root>
//   identity       — identity_assets (new/changed login/IdP surface) host:<fqdn>
//   brand          — workspace_brand_assets + brand_abuse_campaigns  brand-target:<root>
//   shadow_it      — shadow_it_inventory (independent provenance)     technology + hosts
//
// Design decisions recorded here (honesty-critical):
//   • cert family reads asset_events certificate_* events (hostname-keyed). A cert is
//     also logged in certificate_lifecycle_events; the two are the SAME producer, so
//     v1 counts the cert ONCE via asset_events and does not separately pull the
//     lifecycle log (design §4.3 double-count guard).
//   • Only MATERIALISING signals are emitted for correlation (appeared/changed/
//     degraded). Resolutions/improvements (exposed_service_resolved, asset_no_longer_
//     seen recoveries) carry direction 'resolved' and the rules engine drops them —
//     "Related Changes observed" is about new/worsening posture to verify, and a
//     cluster mixing materialising + resolving events would be mixed noise (§4.5).

import { getRegisteredDomain } from "./whois-scan.js";

export const SIGNAL_FAMILY = Object.freeze({
  ASSET: "asset",
  CERT: "cert",
  EMAIL_CONFIG: "email_config",
  EMAIL_SENDER: "email_sender",
  IDENTITY: "identity",
  BRAND: "brand",
  SHADOW_IT: "shadow_it",
});

// asset_events.event_type → { family, direction }. An event type absent here is not a
// change signal we correlate. Directions: appeared|changed|degraded (materialising) or
// resolved (improving — dropped by the rules engine).
const ASSET_EVENT_MAP = Object.freeze({
  // asset-inventory.js (attack-surface asset family)
  new_asset_discovered:      { family: SIGNAL_FAMILY.ASSET, direction: "appeared" },
  asset_reappeared:          { family: SIGNAL_FAMILY.ASSET, direction: "appeared" },
  dns_ip_changed:            { family: SIGNAL_FAMILY.ASSET, direction: "changed" },
  dns_cname_changed:         { family: SIGNAL_FAMILY.ASSET, direction: "changed" },
  dns_redirect_changed:      { family: SIGNAL_FAMILY.ASSET, direction: "changed" },
  takeover_risk_detected:    { family: SIGNAL_FAMILY.ASSET, direction: "degraded" },
  wildcard_dns_detected:     { family: SIGNAL_FAMILY.ASSET, direction: "degraded" },
  asset_no_longer_seen:      { family: SIGNAL_FAMILY.ASSET, direction: "resolved" },
  // posture-events.js exposed-service (attack-surface)
  exposed_service_detected:  { family: SIGNAL_FAMILY.ASSET, direction: "appeared" },
  exposed_service_resolved:  { family: SIGNAL_FAMILY.ASSET, direction: "resolved" },
  // posture-events.js email-authentication configuration
  email_spf_changed:            { family: SIGNAL_FAMILY.EMAIL_CONFIG, direction: "changed" },
  email_dmarc_policy_changed:   { family: SIGNAL_FAMILY.EMAIL_CONFIG, direction: "changed" },
  email_dkim_changed:           { family: SIGNAL_FAMILY.EMAIL_CONFIG, direction: "changed" },
  // cert-events.js (certificates)
  certificate_new_detected:          { family: SIGNAL_FAMILY.CERT, direction: "appeared" },
  certificate_new_san_detected:      { family: SIGNAL_FAMILY.CERT, direction: "appeared" },
  certificate_new_issuer_detected:   { family: SIGNAL_FAMILY.CERT, direction: "changed" },
  certificate_growth_detected:       { family: SIGNAL_FAMILY.CERT, direction: "changed" },
  certificate_sensitive_host_detected: { family: SIGNAL_FAMILY.CERT, direction: "degraded" },
  certificate_expiring_soon:         { family: SIGNAL_FAMILY.CERT, direction: "degraded" },
});

export function hostEntityKey(hostname) {
  return `host:${String(hostname || "").toLowerCase()}`;
}
export function domainEntityKey(domain) {
  return `domain:${String(domain || "").toLowerCase()}`;
}
export function brandTargetEntityKey(domain) {
  return `brand-target:${String(domain || "").toLowerCase()}`;
}

// email_config events are keyed on the bare root domain already (posture-events.js
// writes hostname = domain). Everything else resolves its hostname to eTLD+1.
function registrableOf(hostname) {
  const h = String(hostname || "").toLowerCase().trim();
  if (!h) return "";
  return getRegisteredDomain(h);
}

function parseJsonArray(text) {
  if (!text) return [];
  try {
    const v = JSON.parse(text);
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

/**
 * collectChangeEvents — read every wired producer within a bounded window and return
 * canonical change events. Pure read; performs no writes. Bounded by workspace_id and
 * by observation time within [windowStart, windowEnd] (the "same/adjacent scan" window,
 * design §4.2), so it never scans a tenant's whole history.
 *
 * @returns {Promise<Array<{producer_family,entity_key,registrable_domain,event_type,
 *   direction,observed_at,source_table,source_record_id,evidence_ref,source_type?}>>}
 */
export async function collectChangeEvents(env, { workspaceId, windowStart, windowEnd }) {
  const db = env.cybermeters_db;
  const events = [];
  const start = windowStart;
  const end = windowEnd;

  // 1–3. asset_events → asset / cert / email_config families, by event_type.
  try {
    const rows = await db
      .prepare(
        `SELECT id, event_type, hostname, created_at
           FROM asset_events
          WHERE workspace_id = ?
            AND created_at >= ? AND created_at <= ?`
      )
      .bind(workspaceId, start, end)
      .all();
    for (const r of rows.results || []) {
      const map = ASSET_EVENT_MAP[r.event_type];
      if (!map) continue; // not a correlated change signal
      const hostname = String(r.hostname || "");
      if (!hostname) continue;
      const isEmail = map.family === SIGNAL_FAMILY.EMAIL_CONFIG;
      events.push({
        producer_family: map.family,
        entity_key: isEmail ? domainEntityKey(hostname) : hostEntityKey(hostname),
        registrable_domain: registrableOf(hostname),
        event_type: r.event_type,
        direction: map.direction,
        observed_at: r.created_at,
        source_table: "asset_events",
        source_record_id: String(r.id),
        evidence_ref: String(r.id),
      });
    }
  } catch { /* producer absent / query error — degrade to no events from this source */ }

  // 4. email_sender_sources → email_sender family (new sender by first_seen in window).
  try {
    const rows = await db
      .prepare(
        `SELECT id, domain, source_ip, provider_guess, first_seen
           FROM email_sender_sources
          WHERE workspace_id = ?
            AND first_seen >= ? AND first_seen <= ?`
      )
      .bind(workspaceId, start, end)
      .all();
    for (const r of rows.results || []) {
      const domain = String(r.domain || "");
      if (!domain) continue;
      events.push({
        producer_family: SIGNAL_FAMILY.EMAIL_SENDER,
        entity_key: `${domainEntityKey(domain)}|sender:${String(r.source_ip || "")}`,
        registrable_domain: registrableOf(domain),
        event_type: "email_sender_new_source",
        direction: "appeared",
        observed_at: r.first_seen,
        source_table: "email_sender_sources",
        source_record_id: String(r.id),
        evidence_ref: String(r.id),
      });
    }
  } catch { /* non-fatal */ }

  // 5. identity_assets → identity family (new login/IdP surface by first_seen in window).
  try {
    const rows = await db
      .prepare(
        `SELECT id, hostname, identity_type, provider, first_seen
           FROM identity_assets
          WHERE workspace_id = ?
            AND first_seen >= ? AND first_seen <= ?`
      )
      .bind(workspaceId, start, end)
      .all();
    for (const r of rows.results || []) {
      const hostname = String(r.hostname || "");
      if (!hostname) continue;
      events.push({
        producer_family: SIGNAL_FAMILY.IDENTITY,
        entity_key: hostEntityKey(hostname),
        registrable_domain: registrableOf(hostname),
        event_type: "identity_surface_observed",
        direction: "appeared",
        observed_at: r.first_seen,
        source_table: "identity_assets",
        source_record_id: String(r.id),
        evidence_ref: String(r.id),
      });
    }
  } catch { /* non-fatal */ }

  // 6. Brand — workspace_brand_assets (candidate with active DNS/HTTP evidence) +
  //    brand_abuse_campaigns (infrastructure linkage). The brand-target is the
  //    PROTECTED domain (the `domain` column); the lookalike is a different
  //    registrable domain and is carried only as evidence. A campaign is a distinct
  //    INDEPENDENT producer (shared cert/IP/favicon across candidates, §5), which is
  //    what lets a brand cluster reach >=2 independent producers.
  try {
    const rows = await db
      .prepare(
        `SELECT id, domain, candidate_domain, dns_resolves, https_available, status, first_seen, last_checked_at
           FROM workspace_brand_assets
          WHERE workspace_id = ?
            AND status = 'active'
            AND (first_seen >= ? AND first_seen <= ?)`
      )
      .bind(workspaceId, start, end)
      .all();
    for (const r of rows.results || []) {
      const brandTarget = String(r.domain || "");
      const candidate = String(r.candidate_domain || "");
      if (!brandTarget || !candidate) continue;
      // Only an ACTIVE, resolving candidate is materialising evidence.
      if (Number(r.dns_resolves) !== 1) continue;
      events.push({
        producer_family: SIGNAL_FAMILY.BRAND,
        entity_key: brandTargetEntityKey(brandTarget),
        registrable_domain: registrableOf(brandTarget),
        event_type: Number(r.https_available) === 1 ? "brand_candidate_active_http" : "brand_candidate_active_dns",
        direction: "appeared",
        observed_at: r.first_seen,
        source_table: "workspace_brand_assets",
        source_record_id: String(r.id),
        evidence_ref: `${candidate}`,
      });
    }
  } catch { /* non-fatal */ }

  try {
    const rows = await db
      .prepare(
        `SELECT id, brand_profile_id, linked_domains, first_seen_at, last_seen_at
           FROM brand_abuse_campaigns
          WHERE workspace_id = ?
            AND (first_seen_at >= ? AND first_seen_at <= ?)`
      )
      .bind(workspaceId, start, end)
      .all();
    for (const r of rows.results || []) {
      const linked = parseJsonArray(r.linked_domains);
      // A campaign is anchored on the protected brand-target. We take the first linked
      // domain's registrable root as the join key when present; else skip (no anchor).
      const anchor = linked.length ? registrableOf(String(linked[0])) : "";
      if (!anchor) continue;
      events.push({
        producer_family: SIGNAL_FAMILY.BRAND,
        entity_key: `campaign:${String(r.id)}`,
        registrable_domain: anchor,
        event_type: "brand_campaign_linked",
        direction: "appeared",
        observed_at: r.first_seen_at,
        source_table: "brand_abuse_campaigns",
        source_record_id: String(r.id),
        evidence_ref: String(r.id),
      });
    }
  } catch { /* non-fatal */ }

  // 7. shadow_it_inventory → shadow_it family, tagged with its source_type so the rules
  //    engine can apply the provenance guard (§5): a shadow-it row is INDEPENDENT
  //    corroboration only if its source_type is not already represented by another
  //    producer in the cluster.
  try {
    const rows = await db
      .prepare(
        `SELECT id, canonical_technology_key, source_type, observed_hostnames_json,
                first_seen_at, last_changed_at
           FROM shadow_it_inventory
          WHERE workspace_id = ?
            AND ((first_seen_at >= ? AND first_seen_at <= ?)
              OR (last_changed_at >= ? AND last_changed_at <= ?))`
      )
      .bind(workspaceId, start, end, start, end)
      .all();
    for (const r of rows.results || []) {
      const hostnames = parseJsonArray(r.observed_hostnames_json);
      // source_type is stored as a comma-joined set; each member is a provenance tag.
      const sourceTypes = String(r.source_type || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      // Anchor on the registrable root of the first observed hostname where present,
      // else the technology key cannot join a host/domain tier and is skipped in v1.
      const anchorHost = hostnames.find(Boolean);
      const registrable = anchorHost ? registrableOf(String(anchorHost)) : "";
      if (!registrable) continue;
      events.push({
        producer_family: SIGNAL_FAMILY.SHADOW_IT,
        entity_key: `tech:${String(r.canonical_technology_key || "")}`,
        registrable_domain: registrable,
        event_type: "shadow_it_observed",
        direction: "appeared",
        observed_at: r.first_seen_at || r.last_changed_at,
        source_table: "shadow_it_inventory",
        source_record_id: String(r.id),
        evidence_ref: String(r.id),
        source_type: sourceTypes,
      });
    }
  } catch { /* non-fatal */ }

  return events;
}
