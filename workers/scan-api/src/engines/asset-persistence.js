// ── Asset persistence (identity + brand) ──
// Persists discovered identity assets and brand candidates/assets to D1 (upsert with
// candidate risk scoring + variant classification). Extracted verbatim from index.js
// (monolith decomposition, Phase 1c).
import { createId } from "../lib/util.js";
import { BRAND_SUSPICIOUS_TLDS, brandSimilarityScore, normalizeBrandVariantType, scoreBrandCandidateRisk } from "./brand-protection.js";
import { HIGH_RISK_BRAND_KEYWORDS, extractBrandParts } from "./brand-typosquat.js";

// ── Identity Asset Discovery ──────────────────────────────────────────────────
//
// Phase 7j: pure computation, zero network I/O.
//
// Identifies authentication surfaces, login portals, SSO/OAuth/SAML endpoints,
// and identity provider relationships from signals already captured in other
// modules.  No new subrequests are made.
//
// Two classes of identity assets are discovered:
//
//   1. PROVIDER DETECTION — matches CNAME / SPF / MX / CSP / server header
//      signals against known IdP patterns (Okta, Auth0, Entra ID, etc.).
//      Returns structured provider records with risk_score elevation.
//
//   2. HOSTNAME CLASSIFICATION — scans the discovered subdomain list for
//      hostnames whose prefix matches known identity/auth naming conventions
//      (sso.*, vpn.*, login.*, auth.*, idp.*, adfs.*, etc.).
//
// identity_type values:
//   sso | vpn | admin_login | oauth | saml | login_portal | idp | remote_access
//
// risk_score additions (additive):
//   vpn portal               +15
//   sso portal               +20
//   admin login              +10
//   federated identity (saml/oauth) +15
//   internet-facing IdP      +20

/**
 * upsertIdentityAssets(domainId, scanId, identityMod, env)
 * Phase 8f: Persists identity_discovery results into identity_assets table.
 * INSERT OR IGNORE preserves first_seen; UPDATE refreshes last_seen + risk_score.
 * Also upserts detected IdP providers into workspace_vendors.
 */
export async function upsertIdentityAssets(domainId, scanId, identityMod, env) {
  if (!identityMod?.detected) return;

  let wsRows;
  try {
    const r = await env.cybermeters_db
      .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
      .bind(domainId)
      .all();
    wsRows = r.results || [];
  } catch { return; }
  if (wsRows.length === 0) return;

  const now = new Date().toISOString();
  const allAssets = [...(identityMod.providers ?? []), ...(identityMod.portals ?? [])];

  for (const { workspace_id } of wsRows) {
    for (const asset of allAssets) {
      try {
        const id           = createId("idasset");
        const evidenceJson = JSON.stringify(asset.evidence ?? []);
        const hostname     = asset.hostname ?? null;

        await env.cybermeters_db
          .prepare(
            `INSERT OR IGNORE INTO identity_assets
               (id, workspace_id, domain_id, scan_id, hostname, asset_type,
                identity_type, provider, internet_exposed, source, risk_score,
                evidence, first_seen, last_seen, status, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)`
          )
          .bind(
            id, workspace_id, domainId, scanId,
            hostname, asset.asset_type, asset.identity_type,
            asset.provider ?? null, asset.internet_exposed ? 1 : 0,
            asset.source, asset.risk_score, evidenceJson,
            now, now, now, now
          )
          .run();

        await env.cybermeters_db
          .prepare(
            `UPDATE identity_assets
             SET last_seen = ?, risk_score = ?, evidence = ?,
                 scan_id = ?, status = 'active', updated_at = ?
             WHERE workspace_id = ? AND identity_type = ?
               AND (hostname = ? OR (hostname IS NULL AND ? IS NULL))
               AND (provider = ? OR (provider IS NULL AND ? IS NULL))`
          )
          .bind(
            now, asset.risk_score, evidenceJson, scanId, now,
            workspace_id, asset.identity_type,
            hostname, hostname,
            asset.provider ?? null, asset.provider ?? null
          )
          .run();
      } catch { /* non-fatal per-asset failure */ }
    }

    // Also upsert identity providers into workspace_vendors so they appear
    // in the vendor risk layer. Category = 'identity_provider', risk_level = 'high'.
    for (const provider of (identityMod.providers ?? [])) {
      try {
        const vid = createId("vendor");
        const evJson = JSON.stringify(provider.evidence ?? []);
        await env.cybermeters_db
          .prepare(
            `INSERT OR IGNORE INTO workspace_vendors
               (id, workspace_id, vendor_name, category, source, evidence,
                confidence, risk_level, first_seen, last_seen, status,
                source_module, created_at, updated_at)
             VALUES (?, ?, ?, 'identity_provider', ?, ?, ?, 'high', ?, ?, 'active',
                     'identity_discovery', ?, ?)`
          )
          .bind(vid, workspace_id, provider.provider, "identity_discovery", evJson,
                provider.confidence, now, now, now, now)
          .run();

        await env.cybermeters_db
          .prepare(
            `UPDATE workspace_vendors
             SET last_seen = ?, evidence = ?, confidence = ?,
                 risk_level = 'high', status = 'active',
                 source_module = 'identity_discovery', updated_at = ?
             WHERE workspace_id = ? AND vendor_name = ? AND category = 'identity_provider'`
          )
          .bind(now, evJson, provider.confidence, now, workspace_id, provider.provider)
          .run();
      } catch { /* non-fatal */ }
    }
  }
}

/**
 * upsertBrandAssets(domainId, brandMod, env)
 * Phase 8e: Persists generated candidates as 'unverified' rows in
 * workspace_brand_assets.  INSERT OR IGNORE preserves first_seen and any
 * existing validation state; ON CONFLICT UPDATE refreshes last_seen and
 * risk fields so each scan re-asserts the candidate is still being watched.
 */
export async function upsertBrandAssets(domainId, brandMod, env) {
  if (!brandMod || brandMod.error || !brandMod.domains?.length) return;

  let wsRows;
  try {
    const r = await env.cybermeters_db
      .prepare('SELECT workspace_id FROM workspace_domains WHERE domain_id = ?')
      .bind(domainId)
      .all();
    wsRows = r.results || [];
  } catch { return; }
  if (wsRows.length === 0) return;

  // Resolve domain name (needed as FK / display column in workspace_brand_assets)
  // NOTE: domains table uses column 'domain', not 'name'.
  let domainName;
  try {
    const r = await env.cybermeters_db
      .prepare('SELECT domain FROM domains WHERE id = ?')
      .bind(domainId)
      .first();
    domainName = r?.domain;
  } catch { return; }
  if (!domainName) return;

  const now = new Date().toISOString();
  const inferredBrand = extractBrandParts(domainName).brand;

  for (const { workspace_id } of wsRows) {
    for (const c of brandMod.domains) {
      try {
        const similarity = brandSimilarityScore(c.candidate_domain, inferredBrand);
        const risk = scoreBrandCandidateRisk({
          variant_type: c.variant_type,
          similarity_score: similarity,
          contains_brand_keyword: c.candidate_domain.split('.')[0].includes(inferredBrand),
          suspicious_tld: BRAND_SUSPICIOUS_TLDS.has(c.candidate_domain.split('.').pop()),
          looks_like_login: HIGH_RISK_BRAND_KEYWORDS.some((keyword) => c.candidate_domain.split('.')[0].includes(keyword)),
          classification: "unreviewed",
        });
        const candidateSld = c.candidate_domain.split('.')[0];
        const evidence = [
          { signal: "similar_to_brand", value: similarity },
          { signal: "variant_type", value: normalizeBrandVariantType(c.variant_type) },
        ];
        if (candidateSld.includes(inferredBrand)) evidence.push({ signal: "contains_brand_keyword", value: true });
        if (BRAND_SUSPICIOUS_TLDS.has(c.candidate_domain.split('.').pop())) evidence.push({ signal: "suspicious_tld", value: true });
        if (HIGH_RISK_BRAND_KEYWORDS.some((keyword) => candidateSld.includes(keyword))) evidence.push({ signal: "looks_like_login", value: true });
        await env.cybermeters_db
          .prepare(
            `INSERT INTO workspace_brand_assets
               (id, workspace_id, domain, candidate_domain, variant_type,
                similarity_score, risk_level, risk_reasons, evidence_json, dns_resolves, https_available,
                ip_address, status, first_seen, last_seen, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, 'unverified',
                     ?, ?, ?, ?)
             ON CONFLICT (workspace_id, domain, candidate_domain) DO UPDATE SET
               similarity_score = excluded.similarity_score,
               risk_level   = CASE WHEN workspace_brand_assets.classification IN ('owned','ignored','false_positive')
                                   THEN 'info' ELSE excluded.risk_level END,
               risk_reasons = excluded.risk_reasons,
               evidence_json = excluded.evidence_json,
               last_seen    = excluded.last_seen,
               updated_at   = excluded.updated_at`
          )
          .bind(
            createId('bra'),
            workspace_id,
            domainName,
            c.candidate_domain,
            c.variant_type,
            similarity,
            risk.risk_level,
            JSON.stringify(risk.reasons),
            JSON.stringify(evidence),
            now,  // first_seen
            now,  // last_seen
            now,  // created_at
            now   // updated_at
          )
          .run();
      } catch { /* non-fatal per candidate */ }
    }
    try {
      await env.cybermeters_db
        .prepare(`UPDATE workspace_brand_assets
                  SET brand_profile_id = (SELECT id FROM workspace_brand_profiles WHERE workspace_id = ?)
                  WHERE workspace_id = ? AND brand_profile_id IS NULL`)
        .bind(workspace_id, workspace_id).run();
    } catch { /* profile is optional and migration-safe */ }
  }
}
