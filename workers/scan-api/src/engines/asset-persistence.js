// ── Asset persistence (identity + brand) ──
// Persists discovered identity assets and brand candidates/assets to D1 (upsert with
// candidate risk scoring + variant classification). Extracted verbatim from index.js
// (monolith decomposition, Phase 1c).
import { createId } from "../lib/util.js";
import { BRAND_SUSPICIOUS_TLDS, brandSimilarityScore, buildBrandIdnEvidence, normalizeBrandVariantType, scoreBrandCandidateRisk } from "./brand-protection.js";
import { HIGH_RISK_BRAND_KEYWORDS, extractBrandParts } from "./brand-typosquat.js";

const PROTECTED_BRAND_CLASSIFICATIONS = new Set([
  "owned", "ignored", "benign", "false_positive", "dismissed",
]);
const BRAND_CT_EVIDENCE_ENTRY_CAP = 20;
const BRAND_PERSIST_RETRIES = 3;

function safeJsonArray(value) {
  if (Array.isArray(value)) return value;
  if (typeof value !== "string") return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function stableJsonValue(value) {
  if (Array.isArray(value)) return value.map(stableJsonValue);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort()
    .map((key) => [key, stableJsonValue(value[key])]));
}

function evidenceKey(item) {
  if (item?.signal === "ct_observation" && item.value && typeof item.value === "object") {
    const source = String(item.value.source || "");
    const entryId = String(item.value.entry_id || "");
    const serial = String(item.value.serial_number || "");
    if (source && (entryId || serial)) {
      return `ct_observation:${source}:${entryId}:${serial}`;
    }
  }
  return `${String(item?.signal || "")}:${JSON.stringify(stableJsonValue(item?.value))}`;
}

/**
 * Merge durable Brand evidence without dropping unrelated observations.
 * Scalar product signals are singletons; CT observation metadata is an
 * append-only, bounded set keyed by its stable upstream identity.
 */
export function mergeBrandCandidateEvidence(existingValue, incomingValue) {
  const out = safeJsonArray(existingValue)
    .filter((item) => item && typeof item === "object" && typeof item.signal === "string")
    .map((item) => stableJsonValue(item));
  const incoming = safeJsonArray(incomingValue)
    .filter((item) => item && typeof item === "object" && typeof item.signal === "string")
    .map((item) => stableJsonValue(item));

  for (const item of incoming) {
    if (item.signal === "ct_observation") {
      const ctCount = out.filter((entry) => entry.signal === "ct_observation").length;
      if (ctCount >= BRAND_CT_EVIDENCE_ENTRY_CAP) continue;
      if (!out.some((entry) => evidenceKey(entry) === evidenceKey(item))) out.push(item);
      continue;
    }
    const at = out.findIndex((entry) => entry.signal === item.signal);
    if (at >= 0) out[at] = item;
    else out.push(item);
  }
  return out;
}

function isProductRiskReason(reason) {
  return /^(variant_|classification_|high_brand_similarity$|moderate_brand_similarity$|dns_active$|https_active$|mx_present_possible_mail_abuse$|contains_brand_keyword$|suspicious_tld$|looks_like_login$|newly_seen$|idn_visual_confusable$|mixed_script$|whole_script_confusable$|observed_in_certificate_log$|not_registered_watchlist$|registered_with_mail_capability$|certificate_observed_not_yet_live$|idn_candidate_not_yet_live$|idn_dns_only_not_critical$|marked_suspicious$|confirmed_abuse$)/.test(String(reason || ""));
}

function latestIso(left, right) {
  if (!left) return right || null;
  if (!right) return left;
  return String(left) >= String(right) ? left : right;
}

function observationBoolean(row, evidence, column, signal) {
  if (row?.[column] === 1 || row?.[column] === true) return true;
  if (row?.[column] === 0 || row?.[column] === false) return false;
  return evidence.some((item) => item.signal === signal && item.value === true)
    ? true : null;
}

function buildMergedBrandState(existing, observation) {
  const evidence = mergeBrandCandidateEvidence(existing?.evidence_json, observation.evidence);
  const classification = String(existing?.classification || "unreviewed");
  const protectedState = PROTECTED_BRAND_CLASSIFICATIONS.has(classification);
  const signalTrue = (signal) => evidence.some((item) => item.signal === signal && item.value === true);
  const signalValue = (signal) => evidence.find((item) => item.signal === signal)?.value;
  const similarity = existing?.similarity_score == null
    ? observation.similarity : Number(existing.similarity_score);
  const variant = existing?.variant_type || observation.variant_type;
  const canonicalRisk = scoreBrandCandidateRisk({
    variant_type: variant,
    similarity_score: similarity,
    dns_active: observationBoolean(existing, evidence, "dns_resolves", "dns_active"),
    https_active: observationBoolean(existing, evidence, "https_available", "https_active"),
    mx_present: observationBoolean(existing, evidence, "mx_present", "mx_present"),
    contains_brand_keyword: signalTrue("contains_brand_keyword"),
    suspicious_tld: signalTrue("suspicious_tld"),
    looks_like_login: signalTrue("looks_like_login"),
    newly_seen: signalTrue("newly_seen"),
    ct_observed: signalTrue("ct_observed"),
    idn_visual_confusable: signalTrue("idn_visual_confusable"),
    mixed_script: signalTrue("mixed_script"),
    whole_script_confusable: signalTrue("whole_script_confusable"),
    classification,
  });
  const existingReasons = safeJsonArray(existing?.risk_reasons);
  const unrelatedReasons = existingReasons.filter((reason) => !isProductRiskReason(reason));
  const riskReasons = protectedState
    ? existingReasons
    : [...new Set([...canonicalRisk.reasons, ...unrelatedReasons])];
  const now = observation.now;
  return {
    variant_type: variant,
    similarity_score: Number.isFinite(similarity) ? similarity : (signalValue("similar_to_brand") ?? null),
    risk_level: protectedState ? (existing?.risk_level || "info") : canonicalRisk.risk_level,
    risk_reasons: JSON.stringify(riskReasons),
    evidence_json: JSON.stringify(evidence),
    first_seen: existing?.first_seen || now,
    last_seen: latestIso(existing?.last_seen, now),
    updated_at: latestIso(existing?.updated_at, now),
  };
}

function runChanges(result) {
  const value = result?.meta?.changes ?? result?.changes;
  return Number.isFinite(Number(value)) ? Number(value) : null;
}

/**
 * Canonical persistence for generated and CT Brand candidate observations.
 * One successful INSERT or guarded UPDATE carries the whole state transition,
 * so an error cannot leave a positive-evidence half-state.
 */
export async function persistBrandCandidateObservation(env, {
  workspaceId,
  domain,
  candidateDomain,
  variantType,
  similarity,
  evidence,
  now = new Date().toISOString(),
}) {
  const db = env?.cybermeters_db;
  if (!db || !workspaceId || !domain || !candidateDomain) {
    return { status: "failed", error: "invalid_persistence_input" };
  }
  const observation = {
    variant_type: normalizeBrandVariantType(variantType),
    similarity,
    evidence,
    now,
  };

  for (let attempt = 0; attempt < BRAND_PERSIST_RETRIES; attempt++) {
    let existing;
    try {
      existing = await db.prepare(
        `SELECT id, workspace_id, domain, candidate_domain, variant_type,
                similarity_score, risk_level, risk_reasons, evidence_json,
                dns_resolves, https_available, mx_present, status, classification,
                first_seen, last_seen, updated_at
           FROM workspace_brand_assets
          WHERE workspace_id = ? AND domain = ? AND candidate_domain = ? LIMIT 1`
      ).bind(workspaceId, domain, candidateDomain).first();
    } catch {
      return { status: "failed", error: "candidate_read_failed" };
    }

    const state = buildMergedBrandState(existing, observation);
    if (!existing) {
      const id = createId("bra");
      try {
        const result = await db.prepare(
          `INSERT OR IGNORE INTO workspace_brand_assets
             (id, workspace_id, domain, candidate_domain, variant_type,
              similarity_score, risk_level, risk_reasons, evidence_json,
              dns_resolves, https_available, ip_address, status, classification,
              first_seen, last_seen, last_checked_at, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, 'unverified',
                   'unreviewed', ?, ?, NULL, ?, ?)`
        ).bind(
          id, workspaceId, domain, candidateDomain, state.variant_type,
          state.similarity_score, state.risk_level, state.risk_reasons,
          state.evidence_json, state.first_seen, state.last_seen, now, state.updated_at,
        ).run();
        if (runChanges(result) === 1) return { status: "inserted", candidate_id: id };
        const winner = await db.prepare(
          `SELECT id FROM workspace_brand_assets
            WHERE workspace_id = ? AND domain = ? AND candidate_domain = ? LIMIT 1`
        ).bind(workspaceId, domain, candidateDomain).first();
        if (winner?.id === id) return { status: "inserted", candidate_id: id };
      } catch {
        return { status: "failed", error: "candidate_insert_failed" };
      }
      continue;
    }

    const unchanged = existing.variant_type === state.variant_type &&
      Number(existing.similarity_score) === Number(state.similarity_score) &&
      existing.risk_level === state.risk_level &&
      String(existing.risk_reasons || "[]") === state.risk_reasons &&
      String(existing.evidence_json || "[]") === state.evidence_json &&
      existing.last_seen === state.last_seen &&
      existing.updated_at === state.updated_at;
    if (unchanged) return { status: "unchanged", candidate_id: existing.id };

    try {
      const result = await db.prepare(
        `UPDATE workspace_brand_assets
            SET variant_type = ?, similarity_score = ?, risk_level = ?,
                risk_reasons = ?, evidence_json = ?, last_seen = ?, updated_at = ?
          WHERE id = ? AND workspace_id = ? AND domain = ? AND candidate_domain = ?
            AND variant_type IS ? AND similarity_score IS ?
            AND risk_level IS ? AND risk_reasons IS ?
            AND evidence_json IS ? AND last_seen IS ? AND updated_at IS ?
            AND dns_resolves IS ? AND https_available IS ? AND mx_present IS ?
            AND classification IS ?`
      ).bind(
        state.variant_type, state.similarity_score, state.risk_level,
        state.risk_reasons, state.evidence_json, state.last_seen, state.updated_at,
        existing.id, workspaceId, domain, candidateDomain,
        existing.variant_type, existing.similarity_score,
        existing.risk_level, existing.risk_reasons,
        existing.evidence_json, existing.last_seen, existing.updated_at,
        existing.dns_resolves, existing.https_available, existing.mx_present,
        existing.classification,
      ).run();
      if (runChanges(result) === 1) return { status: "merged", candidate_id: existing.id };
      const verified = await db.prepare(
        `SELECT id, evidence_json, risk_level, risk_reasons, last_seen, updated_at
           FROM workspace_brand_assets WHERE id = ? AND workspace_id = ? LIMIT 1`
      ).bind(existing.id, workspaceId).first();
      if (verified && verified.evidence_json === state.evidence_json &&
          verified.risk_level === state.risk_level &&
          verified.risk_reasons === state.risk_reasons &&
          verified.last_seen === state.last_seen) {
        return { status: "merged", candidate_id: existing.id };
      }
    } catch {
      return { status: "failed", error: "candidate_merge_failed" };
    }
  }
  return { status: "failed", error: "candidate_concurrent_update" };
}

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
        const idn = buildBrandIdnEvidence(c.candidate_domain, inferredBrand);
        const candidateSld = c.candidate_domain.split('.')[0];
        const containsBrandKeyword = !idn.analysis.is_homograph && candidateSld.includes(inferredBrand);
        const looksLikeLogin = !idn.analysis.is_homograph &&
          HIGH_RISK_BRAND_KEYWORDS.some((keyword) => candidateSld.includes(keyword));
        const evidence = [
          { signal: "similar_to_brand", value: similarity },
          { signal: "variant_type", value: normalizeBrandVariantType(c.variant_type) },
          ...idn.evidence,
        ];
        if (containsBrandKeyword) evidence.push({ signal: "contains_brand_keyword", value: true });
        if (BRAND_SUSPICIOUS_TLDS.has(c.candidate_domain.split('.').pop())) evidence.push({ signal: "suspicious_tld", value: true });
        if (looksLikeLogin) evidence.push({ signal: "looks_like_login", value: true });
        await persistBrandCandidateObservation(env, {
          workspaceId: workspace_id,
          domain: domainName,
          candidateDomain: c.candidate_domain,
          variantType: c.variant_type,
          similarity,
          evidence,
          now,
        });
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
