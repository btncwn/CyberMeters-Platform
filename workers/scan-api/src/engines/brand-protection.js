// ── Brand protection module ──
// Brand-monitoring core: variant/classification/risk-level/TLD tables, brand-similarity +
// candidate risk scoring, brand-profile inference/scope/filtering, classification audit, and
// the brand API serializers + workspace profile loader. Extracted verbatim from index.js
// (monolith decomposition, Phase 1c). BRAND_VARIANT_TYPES/BRAND_RISK_LEVELS/
// BRAND_EVIDENCE_SIGNALS, safeJsonArray and brandProtectedDomains are module-internal.
import { HIGH_RISK_BRAND_KEYWORDS, extractBrandParts } from "./brand-typosquat.js";
import { analyzeIdnHomograph, levenshteinDistance } from "./idn-homograph.js";
import { isValidDomain, parseBoundedInteger } from "../lib/util.js";

// ── Brand Monitoring — Typosquat & Brand Asset Tracking ──────────────────────
//
// Pure candidate generation (Phase 7i, zero network I/O) + deferred DNS
// validation via POST /brand-monitoring/refresh (separate request with its own
// 50-subrequest budget — scan already uses ~47 by the time Phase 7 runs).

const BRAND_VARIANT_TYPES = new Set([
  "homoglyph", "typosquat", "substitution", "insertion", "omission",
  "transposition", "hyphenation", "tld_variation", "keyword_abuse",
  "nested_host", "unknown",
]);
export const BRAND_CLASSIFICATIONS = new Set([
  "unreviewed", "monitoring", "suspicious", "owned", "ignored",
  "confirmed_abuse", "false_positive",
]);
const BRAND_RISK_LEVELS = new Set(["critical", "high", "medium", "low", "info"]);
export const BRAND_SUSPICIOUS_TLDS = new Set([
  "zip", "mov", "top", "click", "link", "work", "support", "help", "live", "shop", "xyz",
]);
const BRAND_EVIDENCE_SIGNALS = new Set([
  "similar_to_brand", "variant_type", "dns_active", "mx_present", "https_active",
  "newly_seen", "suspicious_tld", "contains_brand_keyword", "looks_like_login",
  "possible_mail_abuse", "known_owned_domain_match", "ct_observed", "nested_host",
]);

function safeJsonArray(value) {
  if (Array.isArray(value)) return value;
  if (typeof value !== "string") return [];
  try { const parsed = JSON.parse(value); return Array.isArray(parsed) ? parsed : []; }
  catch { return []; }
}

export function normalizeBrandVariantType(value) {
  const raw = String(value || "unknown").toLowerCase();
  const legacy = {
    duplication: "insertion",
    keyboard_adjacent: "substitution",
    hyphen_keyword: "keyword_abuse",
    prefix_keyword: "keyword_abuse",
  };
  const normalized = legacy[raw] || raw;
  return BRAND_VARIANT_TYPES.has(normalized) ? normalized : "unknown";
}

export function brandSimilarityScore(candidateDomain, brandName) {
  const candidate = String(candidateDomain || "").toLowerCase().split(".")[0].replace(/[^a-z0-9]/g, "").slice(0, 100);
  const brand = String(brandName || "").toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 100);
  if (!candidate || !brand) return null;
  const asciiDistance = levenshteinDistance(candidate, brand);
  const asciiScore = Math.max(0, Math.round((1 - asciiDistance / Math.max(candidate.length, brand.length)) * 100));
  // Additive path: existing ASCII scoring remains byte-for-byte equivalent.
  // A validated IDN homograph may lift the score through its confusable
  // skeleton; unrelated/malformed IDNs retain the legacy ASCII result.
  const rawCandidate = String(candidateDomain || "");
  if (!/[^\x00-\x7f]/.test(rawCandidate) && !/(^|\.)xn--/i.test(rawCandidate)) return asciiScore;
  const idn = analyzeIdnHomograph(candidateDomain, brandName);
  return idn.is_homograph ? Math.max(asciiScore, idn.similarity_score) : asciiScore;
}

export function brandIdnHomographAnalysis(candidateDomain, brandName) {
  return analyzeIdnHomograph(candidateDomain, brandName);
}

export function scoreBrandCandidateRisk(candidate = {}) {
  const classification = BRAND_CLASSIFICATIONS.has(candidate.classification)
    ? candidate.classification : "unreviewed";
  if (["owned", "ignored", "false_positive"].includes(classification)) {
    return { score: 0, risk_level: "info", reasons: [`classification_${classification}`] };
  }

  const reasons = [];
  let score = 0;
  const variant = normalizeBrandVariantType(candidate.variant_type);
  const variantWeight = {
    homoglyph: 25, substitution: 22, typosquat: 20, omission: 20,
    insertion: 18, transposition: 18, hyphenation: 15,
    tld_variation: 18, keyword_abuse: 20, nested_host: 20, unknown: 5,
  }[variant];
  score += variantWeight;
  reasons.push(`variant_${variant}`);

  const similarity = Number(candidate.similarity_score);
  if (Number.isFinite(similarity)) {
    const bounded = Math.max(0, Math.min(100, similarity));
    score += Math.round(bounded * 0.35);
    if (bounded >= 80) reasons.push("high_brand_similarity");
    else if (bounded >= 50) reasons.push("moderate_brand_similarity");
  }
  if (candidate.dns_active === true) { score += 10; reasons.push("dns_active"); }
  if (candidate.https_active === true) { score += 10; reasons.push("https_active"); }
  if (candidate.mx_present === true) { score += 20; reasons.push("mx_present_possible_mail_abuse"); }
  if (candidate.contains_brand_keyword === true) { score += 8; reasons.push("contains_brand_keyword"); }
  if (candidate.suspicious_tld === true) { score += 10; reasons.push("suspicious_tld"); }
  if (candidate.looks_like_login === true) { score += 12; reasons.push("looks_like_login"); }
  if (candidate.newly_seen === true) { score += 5; reasons.push("newly_seen"); }
  // A certificate NAMING this host was observed in a public CT log — real external
  // evidence the host was provisioned, stronger than a pure generated permutation.
  const ctObserved = candidate.ct_observed === true;
  if (ctObserved) { score += 12; reasons.push("observed_in_certificate_log"); }

  // Registration-reality gate. String similarity alone does not make a threat:
  // an unregistered permutation nobody has taken is a watchlist item, not a
  // high-risk lookalike. A candidate escapes the watchlist cap only when it is
  // confirmed live (DNS resolves or MX present) OR a certificate for it was
  // logged in CT (strong evidence it was provisioned) — or a human classified it.
  const confirmedLive = candidate.dns_active === true || candidate.mx_present === true;
  if (classification === "unreviewed") {
    if (!confirmedLive && !ctObserved) {
      score = Math.min(score, 30); // caps at "low"
      reasons.push("not_registered_watchlist");
    } else if (candidate.mx_present === true) {
      // Registered AND able to send/receive mail as the brand — real
      // impersonation capability; ensure it surfaces as at least high.
      score = Math.max(score, 65);
      reasons.push("registered_with_mail_capability");
    } else if (ctObserved && !confirmedLive) {
      // A logged certificate is strong, but reserve "critical" for a lookalike
      // confirmed live and mail/serving-capable. Cap CT-only evidence at "high".
      score = Math.min(score, 84);
      reasons.push("certificate_observed_not_yet_live");
    }
  }

  if (classification === "suspicious") { score = Math.max(score, 70); reasons.push("marked_suspicious"); }
  if (classification === "confirmed_abuse") { score = Math.max(score, 90); reasons.push("confirmed_abuse"); }

  score = Math.max(0, Math.min(100, score));
  const risk_level = score >= 85 ? "critical" : score >= 65 ? "high"
    : score >= 40 ? "medium" : score >= 20 ? "low" : "info";
  return { score, risk_level, reasons: [...new Set(reasons)] };
}

export function inferBrandProfileFromDomains(workspaceId, domainRows = []) {
  const domains = [...new Set(domainRows.map((row) => String(row?.domain || "").trim().toLowerCase())
    .filter((domain) => isValidDomain(domain)))];
  if (domains.length === 0) return null;
  const primaryDomain = domains[0];
  const inferredBrand = extractBrandParts(primaryDomain).brand;
  return {
    id: null,
    workspace_id: workspaceId,
    brand_name: inferredBrand,
    primary_domain: primaryDomain,
    keywords: [],
    protected_domains: [primaryDomain],
    inferred: true,
    inference_confidence: "low",
    created_at: null,
    updated_at: null,
  };
}

function brandProtectedDomains(profile) {
  const configured = Array.isArray(profile?.protected_domains) ? profile.protected_domains : [];
  const domains = [...new Set(configured.map((domain) => String(domain).trim().toLowerCase())
    .filter((domain) => isValidDomain(domain)))].slice(0, 100);
  const primary = String(profile?.primary_domain || "").trim().toLowerCase();
  if (domains.length === 0 && isValidDomain(primary)) return [primary];
  return domains;
}

// SQL structure is fixed; only validated domain values become bound parameters.
export function buildBrandProfileDomainScope(profile) {
  const domains = brandProtectedDomains(profile);
  return domains.length > 0
    ? { clause: `domain IN (${domains.map(() => "?").join(",")})`, bindings: domains }
    : { clause: "1 = 0", bindings: [] };
}

export function filterBrandCandidatesToProfile(candidates = [], profile = null) {
  const allowed = new Set(brandProtectedDomains(profile));
  return candidates.filter((candidate) => allowed.has(String(candidate?.domain || "").trim().toLowerCase()));
}

export function brandProfileToApi(row) {
  if (!row) return null;
  return {
    id: row.id || null,
    workspace_id: row.workspace_id,
    brand_name: row.brand_name,
    primary_domain: row.primary_domain,
    keywords: safeJsonArray(row.keywords_json).filter((value) => typeof value === "string").slice(0, 20),
    protected_domains: safeJsonArray(row.protected_domains_json).filter((value) => typeof value === "string").slice(0, 100),
    inferred: false,
    inference_confidence: null,
    created_at: row.created_at || null,
    updated_at: row.updated_at || null,
  };
}

export function validateBrandProfileInput(body, workspaceDomains = []) {
  if (!body || typeof body !== "object") return { ok: false, error: "invalid_body" };
  const brandName = typeof body.brand_name === "string" ? body.brand_name.trim() : "";
  if (brandName.length < 2 || brandName.length > 100 || !/^[\p{L}\p{N} .&'_-]+$/u.test(brandName)) {
    return { ok: false, error: "invalid_brand_name" };
  }
  const owned = new Set(workspaceDomains.map((domain) => String(domain).toLowerCase()));
  const primaryDomain = String(body.primary_domain || "").trim().toLowerCase();
  if (!isValidDomain(primaryDomain) || !owned.has(primaryDomain)) {
    return { ok: false, error: "primary_domain_not_in_workspace" };
  }
  const protectedInput = Array.isArray(body.protected_domains) ? body.protected_domains : [primaryDomain];
  const protectedDomains = [...new Set(protectedInput.map((domain) => String(domain).trim().toLowerCase()))];
  if (protectedDomains.length === 0 || protectedDomains.length > 100 ||
      protectedDomains.some((domain) => !isValidDomain(domain) || !owned.has(domain))) {
    return { ok: false, error: "protected_domain_not_in_workspace" };
  }
  if (!protectedDomains.includes(primaryDomain)) protectedDomains.unshift(primaryDomain);
  const keywordInput = Array.isArray(body.keywords) ? body.keywords : [];
  const keywords = [...new Set(keywordInput.map((value) => String(value).trim().toLowerCase()).filter(Boolean))];
  if (keywords.length > 20 || keywords.some((value) => value.length > 64 || !/^[\p{L}\p{N} .&'_-]+$/u.test(value))) {
    return { ok: false, error: "invalid_keywords" };
  }
  return { ok: true, value: { brand_name: brandName, primary_domain: primaryDomain,
    keywords, protected_domains: protectedDomains } };
}

export function parseBrandCandidateListParams(searchParams) {
  const risk = searchParams.get("risk");
  const status = searchParams.get("status");
  const classification = searchParams.get("classification");
  return {
    risk: BRAND_RISK_LEVELS.has(risk) ? risk : null,
    status: ["active", "inactive", "unverified"].includes(status) ? status : null,
    classification: BRAND_CLASSIFICATIONS.has(classification) ? classification : null,
    limit: parseBoundedInteger(searchParams.get("limit"), 50, 1, 100),
    offset: parseBoundedInteger(searchParams.get("offset"), 0, 0, 100000),
  };
}

export function brandCandidateToApi(row, profile = null) {
  const candidateDomain = String(row?.candidate_domain || "").toLowerCase();
  const brandName = profile?.brand_name || extractBrandParts(row?.domain || "").brand;
  const similarity = row?.similarity_score != null && Number.isFinite(Number(row.similarity_score))
    ? Math.max(0, Math.min(100, Number(row.similarity_score)))
    : brandSimilarityScore(candidateDomain, brandName);
  const classification = BRAND_CLASSIFICATIONS.has(row?.classification) ? row.classification : "unreviewed";
  const variant = normalizeBrandVariantType(row?.variant_type);
  const sld = candidateDomain.split(".")[0];
  const tld = candidateDomain.split(".").slice(1).join(".");
  const brandToken = String(brandName || "").toLowerCase().replace(/[^a-z0-9]/g, "");
  const dnsActive = row?.dns_resolves == null ? null : Boolean(row.dns_resolves);
  const httpsActive = row?.https_available == null ? null : Boolean(row.https_available);
  const mxPresent = row?.mx_present == null ? null : Boolean(row.mx_present);
  const containsBrandKeyword = Boolean(brandToken && sld.replace(/[^a-z0-9]/g, "").includes(brandToken));
  const suspiciousTld = BRAND_SUSPICIOUS_TLDS.has(tld.split(".").pop());
  const firstSeen = row?.first_seen || null;
  const newlySeen = firstSeen ? Date.now() - new Date(firstSeen).getTime() <= 30 * 86400000 : false;
  // Durable evidence signals recorded by the enrichment sweeps must feed the
  // recompute, or the API band would silently disagree with the persisted band.
  // - ct_observed (PR-B): a certificate for this host was logged.
  // - looks_like_login (PR-C): a live password/login form was observed. This is
  //   stronger than the name heuristic, so a lookalike whose HOSTNAME has no
  //   login-ish word but whose live page harvests credentials still scores it.
  const persistedSignals = safeJsonArray(row?.evidence_json);
  const ctObserved = persistedSignals.some((item) => item?.signal === "ct_observed" && item.value === true);
  const liveLoginObserved = persistedSignals.some((item) => item?.signal === "looks_like_login" && item.value === true);
  const looksLikeLogin = liveLoginObserved || HIGH_RISK_BRAND_KEYWORDS.some((keyword) => sld.includes(keyword));
  const risk = scoreBrandCandidateRisk({
    variant_type: variant, similarity_score: similarity, dns_active: dnsActive,
    https_active: httpsActive, mx_present: mxPresent, contains_brand_keyword: containsBrandKeyword,
    suspicious_tld: suspiciousTld, looks_like_login: looksLikeLogin, ct_observed: ctObserved,
    classification,
  });

  const evidence = [];
  if (similarity != null) evidence.push({ signal: "similar_to_brand", value: similarity });
  evidence.push({ signal: "variant_type", value: variant });
  if (dnsActive != null) evidence.push({ signal: "dns_active", value: dnsActive });
  if (httpsActive != null) evidence.push({ signal: "https_active", value: httpsActive });
  if (mxPresent != null) evidence.push({ signal: "mx_present", value: mxPresent });
  if (newlySeen) evidence.push({ signal: "newly_seen", value: true });
  if (suspiciousTld) evidence.push({ signal: "suspicious_tld", value: true });
  if (containsBrandKeyword) evidence.push({ signal: "contains_brand_keyword", value: true });
  if (looksLikeLogin) evidence.push({ signal: "looks_like_login", value: true });
  if (ctObserved) evidence.push({ signal: "ct_observed", value: true });
  if (variant === "nested_host") evidence.push({ signal: "nested_host", value: true });
  if (mxPresent) evidence.push({ signal: "possible_mail_abuse", value: true });
  if (classification === "owned") evidence.push({ signal: "known_owned_domain_match", value: true });
  for (const item of safeJsonArray(row?.evidence_json)) {
    if (BRAND_EVIDENCE_SIGNALS.has(item?.signal) && ["string", "number", "boolean"].includes(typeof item.value) &&
        !evidence.some((existing) => existing.signal === item.signal)) evidence.push({ signal: item.signal, value: item.value });
  }
  const closed = ["owned", "ignored", "false_positive"].includes(classification);
  return {
    id: row.id,
    candidate_domain: candidateDomain,
    protected_domain: row.domain || profile?.primary_domain || null,
    variant_type: variant,
    similarity_score: similarity,
    risk_score: risk.score,
    risk_level: risk.risk_level,
    risk_reasons: risk.reasons,
    status: row.status || "unverified",
    classification,
    action_required: !closed && (["critical", "high"].includes(risk.risk_level) ||
      ["suspicious", "confirmed_abuse"].includes(classification)),
    first_seen_at: firstSeen,
    last_seen_at: row.last_seen || null,
    last_checked_at: row.last_checked_at || null,
    dns_active: dnsActive,
    https_active: httpsActive,
    mx_present: mxPresent,
    registrar_or_whois_summary: typeof row.registrar_or_whois_summary === "string"
      ? row.registrar_or_whois_summary.slice(0, 500) : null,
    evidence,
    created_at: row.created_at || null,
    updated_at: row.updated_at || null,
  };
}

export function buildBrandProtectionSummary(candidates = []) {
  // Tri-state DNS truth is surfaced explicitly so the UI never presents an
  // unchecked candidate as inactive: dns_active === true → active, === false →
  // inactive (checked, not resolving), null/undefined → not yet checked.
  // Invariant (asserted in validate-brand-dns-enrichment.js):
  //   active_dns + inactive_dns + unchecked_dns === total_candidates
  const summary = { total_candidates: candidates.length,
    active_dns: 0, inactive_dns: 0, unchecked_dns: 0, dns_checked_total: 0,
    high_risk: 0, confirmed_abuse: 0, suspicious: 0, ignored: 0, owned: 0, unreviewed: 0,
    last_updated_at: null };
  for (const candidate of candidates) {
    if (candidate.dns_active === true) { summary.active_dns++; summary.dns_checked_total++; }
    else if (candidate.dns_active === false) { summary.inactive_dns++; summary.dns_checked_total++; }
    else summary.unchecked_dns++;
    if (["critical", "high"].includes(candidate.risk_level)) summary.high_risk++;
    if (["confirmed_abuse", "suspicious", "ignored", "owned", "unreviewed"].includes(candidate.classification)) {
      summary[candidate.classification]++;
    }
    const updated = candidate.updated_at || candidate.last_seen_at;
    if (updated && (!summary.last_updated_at || updated > summary.last_updated_at)) summary.last_updated_at = updated;
  }
  return summary;
}

export function brandClassificationAuditMetadata(candidate, previousClassification, classification, riskLevel) {
  return {
    candidate_domain: candidate.candidate_domain,
    classification,
    previous_classification: previousClassification,
    risk_level: BRAND_RISK_LEVELS.has(riskLevel) ? riskLevel : "info",
  };
}

export function legacyBrandAssetToApi(row) {
  return {
    ...row,
    dns_resolves: row.dns_resolves !== null ? Boolean(row.dns_resolves) : null,
    https_available: row.https_available !== null ? Boolean(row.https_available) : null,
    risk_reasons: safeJsonArray(row.risk_reasons),
  };
}

export async function loadWorkspaceBrandProfile(env, workspaceId) {
  const persisted = await env.cybermeters_db
    .prepare(`SELECT id, workspace_id, brand_name, primary_domain, keywords_json,
                     protected_domains_json, created_at, updated_at
              FROM workspace_brand_profiles WHERE workspace_id = ? LIMIT 1`)
    .bind(workspaceId).first();
  if (persisted) return brandProfileToApi(persisted);
  const domains = await env.cybermeters_db
    .prepare(`SELECT d.domain FROM workspace_domains wd
              JOIN domains d ON d.id = wd.domain_id
              WHERE wd.workspace_id = ? ORDER BY d.created_at ASC, d.domain ASC`)
    .bind(workspaceId).all();
  return inferBrandProfileFromDomains(workspaceId, domains.results || []);
}
