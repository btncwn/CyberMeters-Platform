#!/usr/bin/env node
//
// Production finding-type COVERAGE contract. CI-blocking.
//
// Unlike validate-remediation-registry.js (which checks the registry against
// itself), this checks PRODUCTION EMITTERS against the registry:
//   • every active customer-ACTIONABLE finding type a production constructor can
//     emit resolves to exactly ONE primary canonical remediation;
//   • every intentionally INFORMATIONAL finding type is explicitly declared
//     remediation_not_required (never silently forgotten);
//   • a static sweep of the finding-emitting engine files discovers literal
//     finding ids and fails if any is neither actionable-mapped, informational,
//     nor a known dynamic prefix — so a NEW unmapped emitter breaks CI.
// It also reports registry entries whose finding types are not emitted anywhere
// (dead / forward-looking) as informational output.
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const enginesDir = path.join(root, "workers", "scan-api", "src", "engines");
const imp = (f) => import(pathToFileURL(path.join(enginesDir, f)).href);
const { resolveRemediation, REMEDIATION_REGISTRY, remediationRegistryFingerprint } = await imp("remediation-registry.js");

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };

// ── ACTIONABLE production finding types (from the finding-emitter audit) ──────
// Each MUST resolve to exactly one primary canonical remediation.
const ACTIONABLE = [
  // email — scoring.js
  "email_missing_dmarc", "email_dmarc_policy_none", "email_missing_spf",
  // email — email-intel.js
  "email_intel_dmarc_missing", "email_intel_dmarc_reporting_only", "email_intel_spf_missing",
  "email_intel_spf_permissive", "email_intel_mta_sts_missing", "email_intel_tls_rpt_missing",
  // email — email-analysis.js guided action ids
  "dmarc_missing", "dmarc_multiple_records", "dmarc_invalid_record", "dmarc_policy_monitoring_only",
  "dmarc_reporting_missing", "dmarc_partial_percentage", "spf_missing", "spf_multiple_records",
  "spf_permissive_all", "spf_neutral_all", "spf_softfail_all", "spf_lookup_limit", "spf_ptr_mechanism",
  "bimi_dmarc_enforcement_required", "mta_sts_policy_missing",
  // web / attack surface — scoring.js + scan-engine.js DSE + admin surface
  "dns_no_resolution", "ssl_not_available", "ssl_no_http_redirect", "no_https_redirect",
  "header_missing_strict_transport_security", "csp_weak_policy", "subdomain_takeover", "subdomain_sensitive",
  "asset_exposure_sensitive_tool", "asset_exposure_admin_interface", "asset_exposure_dev_env",
  "cloud_storage_takeover_risk", "cloud_storage_public_listing", "cloud_storage_exposure_observed",
  "kev_active_exploitation",
  "admin_surface_critical", "admin_surface_high", "admin_surface_medium",
  "dse_hsts_short_maxage",
  "dse_cookie_no_secure", "dse_cookie_no_httponly", "dse_cookie_no_samesite",
  "certificate_expiring_critical", "certificate_expiring_soon",
  // certificates — cert-trust-l2.js `type:` values
  "expired", "expiring_soon", "self_signed", "unexpected_issuer", "unexpected_san", "unexpected_wildcard",
  // whois — whois-scan.js
  "whois_domain_expired", "whois_expiry_critical", "whois_expiry_warning",
  // brand — scoring.js
  "brand_homoglyph_detected", "brand_lookalike_detected", "brand_typosquat_detected",
];

// ── INFORMATIONAL production finding types → remediation_not_required ─────────
// Observation-only / advisory emitters where NO customer action is expected.
// Declared explicitly so none is silently forgotten. Some are ALSO registry-
// mapped (a remediation is available but not required); that is allowed.
const REMEDIATION_NOT_REQUIRED = new Set([
  "dns_resolver_disagreement", "canonical_url_uncertain", "security_headers_not_observed",
  "email_not_applicable", "email_dkim_not_detected", "email_intel_dkim_not_found",
  "dkim_verification_uncertain", "bimi_not_configured", "bimi_certificate_not_listed",
  "tls_rpt_missing", "subdomains_large_attack_surface", "asset_provider_infrastructure_observed",
  "asset_exposure_interface_observed", "whois_new_domain", "whois_registrar_info",
  "ct_source_incomplete", "coverage_gap", "parallel_certificate", "unknown",
  // header info variants (non-HSTS): observed-elsewhere / low-quality / malformed non-scored
  "header_weak_hsts",
  // Explicit producer observations. Some retain a registry mapping for historical
  // compatibility, but finding_type=observation prevents action admission.
  "dse_missing_caa", "dse_caa_no_issuers", "dse_hsts_not_preload_eligible",
  // dnssec info variants (score 0) — registry-mapped but not scored/forced
  "dnssec_not_enabled", "dnssec_misconfigured",
  // tech version disclosure (low, score 0) — registry-mapped, advisory
  "tech_server_version_disclosure", "tech_xpoweredby_version_disclosure",
  // AS-B2 Stage 1: version-blind catalogue correlation is observation-only.
  "cve_high_severity_detected",
]);

// Dynamic / suffixed emitters normalise to a stable prefix the resolver handles.
const DYNAMIC_PREFIXES = ["subdomain_sensitive_", "header_missing_", "header_malformed_"];

// ── 1. Every actionable finding type → exactly one primary remediation ───────
const missing = [];
for (const ft of ACTIONABLE) {
  const r = resolveRemediation({ finding_type: ft });
  if (r.status !== "resolved" || !r.remediation_id) missing.push(ft);
}
ok("every ACTIONABLE production finding type resolves to a canonical remediation",
  missing.length === 0, `unmapped: ${missing.join(", ")}`);

// Exactly-one-primary: resolution is deterministic and via a real match.
const multi = ACTIONABLE.filter((ft) => {
  const r = resolveRemediation({ finding_type: ft });
  return r.status === "resolved" && !["primary", "alias", "deprecated"].includes(r.matched_via);
});
ok("each actionable finding type maps via a real primary/alias (single owner)", multi.length === 0, multi.join(", "));

// ── 2. Informational finding types are explicitly declared ───────────────────
ok("informational set is non-empty and explicit", REMEDIATION_NOT_REQUIRED.size > 0);
// An informational type must NOT accidentally be in the actionable set.
const overlap = ACTIONABLE.filter((ft) => REMEDIATION_NOT_REQUIRED.has(ft));
ok("no finding type is both actionable and remediation_not_required", overlap.length === 0, overlap.join(", "));

// B1 registry identity: exactly four entries move to v2 and every other entry remains v1.
const byId = new Map(REMEDIATION_REGISTRY.map((entry) => [entry.remediation_id, entry]));
const v2Ids = REMEDIATION_REGISTRY.filter((entry) => entry.version === 2).map((entry) => entry.remediation_id).sort();
ok("exactly the four B1 remediation identities are version 2",
  JSON.stringify(v2Ids) === JSON.stringify(["cert.expiry.expired", "cert.expiry.expiring", "web.cookie.flags", "web.header.csp"]));
ok("all other remediation identities remain version 1",
  REMEDIATION_REGISTRY.filter((entry) => !v2Ids.includes(entry.remediation_id)).every((entry) => entry.version === 1));
ok("registry stays at 67 entries", REMEDIATION_REGISTRY.length === 67);
ok("B1 registry fingerprint is exact", remediationRegistryFingerprint() === "r67-c98a810a", remediationRegistryFingerprint());
ok("certificate_expiring_critical maps to expiring, never expired",
  resolveRemediation({ finding_type: "certificate_expiring_critical" }).remediation_id === "cert.expiry.expiring"
  && !byId.get("cert.expiry.expired")?.finding_types.includes("certificate_expiring_critical"));
ok("expired identity keeps the exact historical pair",
  JSON.stringify(byId.get("cert.expiry.expired")?.finding_types) === JSON.stringify(["ssl_certificate_expired", "certificate_expired"]));
ok("CSP remediation names strengthening and exact parsed verification",
  /Add or strengthen/.test(byId.get("web.header.csp")?.customer_title || "")
  && /parseable/i.test(byId.get("web.header.csp")?.verification_evidence_requirements || "")
  && /script-src\/default-src/.test(byId.get("web.header.csp")?.verification_evidence_requirements || ""));
ok("cookie remediation names SameSite and preserves zero-cookie inconclusive semantics",
  /SameSite=Lax/.test(byId.get("web.cookie.flags")?.recommended_action || "")
  && /SameSite=Strict/.test(byId.get("web.cookie.flags")?.recommended_action || "")
  && /zero cookies is inconclusive/i.test(byId.get("web.cookie.flags")?.verification_evidence_requirements || ""));

// ── 3. Static emitter sweep — discover literal ids, assert each is classified ─
// Finding-emitting engine files. We extract `id:`/`type:` string literals and
// require each plausible finding id to be actionable, informational, a dynamic
// prefix, or an explicitly-allowed non-finding literal.
const EMITTER_FILES = [
  "scoring.js", "email-intel.js", "email-analysis.js", "cloud-storage-scan.js",
  "asset-intel.js", "tech-scan.js", "whois-scan.js", "cert-trust-l2.js", "scan-engine.js",
];
// Literals that appear as id:/type: but are NOT finding types (evidence types,
// module names, classifications, hosted-service ids, workflow states…).
const NON_FINDING = new Set([
  // evidence_type values
  "dns_lookup", "dns_cross_check", "dnssec_lookup", "https_probe", "http_redirect_probe",
  "canonical_url_probe", "http_header_probe", "dns_mx_lookup", "dns_txt_lookup",
  "certificate_transparency", "certificate_transparency_observation", "supporting_infrastructure_observation",
  "http_fingerprint_observation", "http_probe", "whois", "self_attestation", "scan_findings",
  "technology_kev_correlation",
  "identity_discovery", "saas_exposure", "supporting_infrastructure_observation",
  // finding_type CLASS values (not ids)
  "finding", "observation",
  // cloud-storage/discovery classifications + exposure types
  "provider_dependency", "login_portal", "crm_portal", "dev_portal", "support_portal",
  "ecommerce_portal", "email_gateway",
  // hosted-service capability ids (hosted-dmarc catalog, not scan findings)
  "dmarc", "tls_rpt", "mta_sts", "bimi", "caa",
  // lifecycle / audit event type literals (not scan findings)
  "lifecycle_first_scan_completed",
]);
const idRe = /\b(?:id|type)\s*:\s*["'`]([a-z][a-z0-9_]+)["'`]/g;
const discovered = new Map(); // id -> file
for (const f of EMITTER_FILES) {
  const src = fs.readFileSync(path.join(enginesDir, f), "utf8");
  let m;
  while ((m = idRe.exec(src)) !== null) {
    const id = m[1];
    if (!discovered.has(id)) discovered.set(id, f);
  }
}
const actionableSet = new Set(ACTIONABLE);
const classify = (id) =>
  actionableSet.has(id) || REMEDIATION_NOT_REQUIRED.has(id) || NON_FINDING.has(id) ||
  DYNAMIC_PREFIXES.some((p) => id.startsWith(p)) ||
  // dynamic header/subdomain bases already covered; also accept a template base
  id === "subdomain_sensitive";
const unclassified = [...discovered.keys()].filter((id) => !classify(id));
ok("every discovered emitter id literal is classified (actionable / informational / non-finding / dynamic)",
  unclassified.length === 0,
  unclassified.map((id) => `${id} (${discovered.get(id)})`).join(", "));

// ── 4. Report registry entries not reached by any emitter OR derived ref ─────
// Resolution-accurate: an entry is "reached" if resolving any emitted scan id,
// dynamic-header variant, or a canonical-registry consumer's reference
// (ce-readiness.js / posture-scoring.js) lands on it. The remainder are genuinely
// forward-looking (registered for intended coverage, no producer yet) — reported
// for visibility per the coverage-audit requirement, not a hard failure.
const DYNAMIC_HEADER_VARIANTS = [
  "header_missing_x_frame_options", "header_missing_x_content_type_options",
  "header_missing_referrer_policy", "header_missing_permissions_policy",
  "header_missing_content_security_policy", "header_missing_strict_transport_security",
  "subdomain_sensitive",
];
// Finding types referenced by canonical-registry CONSUMERS (not scan emitters):
// ce-readiness.js addGap refs + posture-scoring.js pushRem refs.
const DERIVED_REFS = [
  "ce_open_findings_backlog", "ce_saas_access_review", "ce_cert_review",
  "certificate_intelligence_review", "vendor_risk_detected", "third_party_js_detected",
  "saas_exposure", "brand_lookalike_detected", "brand_typosquat_detected",
];
const reachedRemediationIds = new Set();
for (const id of [...discovered.keys(), ...ACTIONABLE, ...REMEDIATION_NOT_REQUIRED, ...DYNAMIC_HEADER_VARIANTS, ...DERIVED_REFS]) {
  const r = resolveRemediation({ finding_type: id });
  if (r.status === "resolved") reachedRemediationIds.add(r.remediation_id);
}
const forwardLooking = REMEDIATION_REGISTRY
  .filter((e) => e.status === "active" && !reachedRemediationIds.has(e.remediation_id))
  .map((e) => `${e.remediation_id} [${e.finding_types.join(",")}]`);
if (forwardLooking.length) {
  console.log(`\nINFO — forward-looking registry entries (registered, no current producer):`);
  for (const d of forwardLooking) console.log(`  • ${d}`);
}

console.log(`\n${pass} passed, ${fail} failed`);
console.log(`(discovered ${discovered.size} emitter id literals across ${EMITTER_FILES.length} files; ${ACTIONABLE.length} actionable, ${REMEDIATION_NOT_REQUIRED.size} informational classified)`);
process.exit(fail ? 1 : 0);
