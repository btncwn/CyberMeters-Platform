// ── Confidence engine ──
// Numeric confidence (0–100) for findings: legacy-string mapping, per-ID lookup,
// prefix heuristics. Extracted verbatim from index.js (monolith decomposition, Phase 1c).
// Behavior-preserving — no logic change.
import { findingHasApprovedTlsAbsence } from "./tls-evidence.js";

// ── Sprint 9B: Confidence Engine ─────────────────────────────────────────────
//
// Converts legacy string confidence values and assigns deterministic numeric
// confidence scores (0–100) to all findings.
//
// Scale:
//   95  Verified observation     — direct probe, deterministic result
//   90  Multiple confirmations   — strong single source or corroborating signals
//   80  Strong evidence          — single validated probe, no ambiguity
//   70  Probable                 — heuristic with reasonable signal quality
//   60  Weak signal              — indirect inference or common-pattern heuristic
//   40  Unvalidated candidate    — generated algorithmically, no probe validation

/** Convert legacy string confidence values to numeric equivalents. */
const CONFIDENCE_STRING_TO_NUMERIC = {
  confirmed: 95,
  high:      90,
  medium:    70,
  low:       60,
};

/**
 * Per-finding-ID confidence scores (null-state assignments).
 * Applied when a finding has no existing confidence value.
 * Dynamic IDs (header_missing_*, subdomain_sensitive_*) are handled
 * by prefix patterns in resolveConfidence() below.
 */
const FINDING_CONFIDENCE_SCORES = {
  // ── DNS ──────────────────────────────────────────────────────────────────
  dns_no_resolution:               90, // fallback — string "high"→90 normally
  dns_resolver_disagreement:       70, // fallback — string "medium"→70 normally
  dnssec_not_enabled:              90, // fallback — string "high"→90 normally
  dnssec_misconfigured:            70, // fallback — string "medium"→70 normally
  // ── SSL ──────────────────────────────────────────────────────────────────
  ssl_not_available:               90, // only after approved positive-absence evidence
  ssl_no_http_redirect:            90, // confirmed variant; uncertain gets "low"→60
  canonical_url_uncertain:         70, // inferred from redirect chain
  // ── Email security ───────────────────────────────────────────────────────
  email_not_applicable:            90, // deterministic: no MX records
  email_missing_dmarc:             90, // direct DNS TXT lookup
  email_dmarc_policy_none:         90, // DMARC record parsed
  email_missing_spf:               90, // direct DNS TXT lookup
  email_dkim_not_detected:         60, // fallback default; finding sets 60/70/80 dynamically based on provider
  // ── Subdomains ───────────────────────────────────────────────────────────
  subdomains_large_attack_surface: 60, // CT inventory count is observed, reachability is not confirmed
  // ── Subdomain takeover ───────────────────────────────────────────────────
  subdomain_takeover:              90, // CNAME suffix + body fingerprint — dual signal
  // ── Asset exposure ───────────────────────────────────────────────────────
  asset_exposure_sensitive_tool:   90, // fallback — string "high"→90 normally
  asset_exposure_admin_interface:  70, // fallback — string "medium"→70 normally
  asset_exposure_dev_env:          70, // fallback — string "medium"→70 normally
  // ── WHOIS intelligence ───────────────────────────────────────────────────
  whois_domain_expired:            95, // RDAP expiry date is deterministic
  whois_expiry_critical:           95, // RDAP expiry date is deterministic
  whois_expiry_warning:            90, // deterministic date; 90d threshold is policy
  whois_new_domain:                90, // RDAP registration date is deterministic
  whois_registrar_info:            95, // RDAP entity data directly reported
  // ── Email security intelligence ──────────────────────────────────────────
  email_intel_dmarc_missing:        95, // same DNS probe as email_missing_dmarc
  email_intel_dmarc_reporting_only: 95, // DMARC record parsed
  email_intel_spf_missing:          95, // direct DNS TXT lookup
  email_intel_spf_permissive:       95, // SPF parsed — +all directly observed
  email_intel_dkim_not_found:       60, // common selector heuristic only
  email_intel_mta_sts_missing:      90, // HTTP probe to mta-sts. subdomain
  email_intel_tls_rpt_missing:      90, // DNS TXT at _smtp._tls.{domain}
  // ── Cloud storage discovery ──────────────────────────────────────────────
  cloud_storage_takeover_risk:      80, // fallback — string already set on most
  cloud_storage_public_listing:     90, // listing confirmed from HTTP body
  cloud_storage_exposure_observed:  80, // fallback — string already set on most
  // ── Admin surface detection ──────────────────────────────────────────────
  admin_surface_critical:  70, // fingerprint heuristic; authentication unverified
  admin_surface_high:      70, // fingerprint heuristic; authentication unverified
  admin_surface_medium:    60, // hostname pattern only; auth likely enforced
  // ── Domain security enrichment ───────────────────────────────────────────
  dse_missing_caa:               95, // direct DNS CAA lookup — deterministic
  dse_caa_no_issuers:            95, // CAA record parsed — no issue tags
  dse_hsts_short_maxage:         95, // HSTS header observed and parsed
  dse_hsts_not_preload_eligible: 90, // HSTS parsed; multiple eligibility criteria
  dse_cookie_no_secure:          90, // Set-Cookie header observed; one response
  dse_cookie_no_httponly:        90, // Set-Cookie header observed; one response
  dse_cookie_no_samesite:        90, // Set-Cookie header observed; one response
  // ── Technology detection ─────────────────────────────────────────────────
  tech_xpoweredby_version_disclosure: 90, // X-Powered-By header with version observed
  tech_server_version_disclosure:     90, // Server header with version observed
};

/**
 * resolveConfidence(finding) → number (0–100)
 *
 * Returns a deterministic numeric confidence score for any finding.
 * Priority order:
 *   1. Already numeric — return as-is (idempotent)
 *   2. Legacy string ("high", "medium", etc.) — convert to numeric
 *   3. Direct ID lookup in FINDING_CONFIDENCE_SCORES
 *   4. Prefix-based pattern match for dynamic finding IDs
 *   5. Default: 70
 */
export function resolveConfidence(finding) {
  // Historical/bare ssl_not_available carried 90 with no source capable of
  // proving absence. Do not preserve or manufacture that confidence unless the
  // canonical evidence envelope is present and approved.
  if ((finding?.id ?? "") === "ssl_not_available") {
    if (!findingHasApprovedTlsAbsence(finding)) return null;
    if (typeof finding.confidence === "number") return finding.confidence;
    if (typeof finding.confidence === "string") {
      const mapped = CONFIDENCE_STRING_TO_NUMERIC[finding.confidence.toLowerCase()];
      if (mapped != null) return mapped;
    }
    return FINDING_CONFIDENCE_SCORES.ssl_not_available;
  }

  // 1. Already numeric — preserve
  if (typeof finding.confidence === "number") return finding.confidence;

  // 2. Legacy string confidence — convert
  if (typeof finding.confidence === "string") {
    const mapped = CONFIDENCE_STRING_TO_NUMERIC[finding.confidence.toLowerCase()];
    if (mapped != null) return mapped;
  }

  // 3. Direct ID lookup
  const id = finding.id ?? "";
  if (FINDING_CONFIDENCE_SCORES[id] != null) return FINDING_CONFIDENCE_SCORES[id];

  // 4. Prefix-based patterns for dynamic IDs
  if (id.startsWith("header_missing_"))       return 90; // direct HTTP header observation
  if (id.startsWith("header_malformed_"))     return 90; // direct HTTP header parse
  if (id.startsWith("subdomain_sensitive_"))  return 70; // keyword heuristic, unverified reachability
  if (id.startsWith("email_intel_"))          return 90; // DNS/HTTP verified
  if (id.startsWith("whois_"))               return 90; // RDAP verified
  if (id.startsWith("dse_"))                 return 90; // direct probe
  if (id.startsWith("tech_"))                return 90; // HTTP header observation
  if (id.startsWith("cloud_storage_"))       return 80; // probe-validated
  if (id.startsWith("admin_surface_"))       return 70; // fingerprint heuristic

  // 5. Default
  return 70;
}
