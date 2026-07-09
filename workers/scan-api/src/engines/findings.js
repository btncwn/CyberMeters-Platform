// ── Findings / evidence engine ──
// Evidence-quality validation, structured-evidence building, v2 schema normalization
// (numeric confidence via the confidence engine), finding-vs-observation classification.
// Extracted verbatim from index.js (monolith decomposition, Phase 1c). Behavior-preserving.
import { resolveConfidence } from "./confidence.js";

// Sprint 9E.1: updated to support the Sprint 9C evidence array format.
// Sprint 9C changed finding.evidence from an object to an array of evidence items.
// Previously this function checked object fields directly on finding.evidence, which
// always produced "partial" quality after 9C because array fields (source, probe_target,
// etc.) are on the first array item, not on the array itself.
// Now normalizes to evidence[0] when evidence is an array; legacy object format still works.
export function validateFindingEvidence(finding) {
  const warnings = [];
  const ev = finding?.evidence ?? null;

  // Normalize: Sprint 9C produces arrays; pre-9C scans may have legacy objects.
  const evidence = Array.isArray(ev) ? (ev[0] ?? null) : ev;

  if (!evidence) {
    warnings.push("missing evidence_json");
    return { evidence_quality: "missing", evidence_warnings: warnings };
  }

  if (!finding.confidence) warnings.push("missing confidence");

  // source: identical field name in both array-item and legacy object formats
  if (!evidence.source) warnings.push("missing source");

  // probe target: array-item format uses "label"; legacy uses probe_target/target/etc.
  if (!(evidence.label ?? evidence.probe_target ?? evidence.target ?? evidence.queried_hostname ?? evidence.requested_url)) {
    warnings.push("missing target or queried hostname");
  }

  // observed value: array-item format uses "value"; legacy uses observed_value/headers_observed/etc.
  const hasValue = evidence.value !== undefined
    || evidence.observed_value !== undefined
    || evidence.headers_observed
    || evidence.returned_records;
  if (!hasValue) warnings.push("missing observed value");

  // expected_value: same field name in both formats (preserved by Case B wrapping in Sprint 9C)
  if (finding.score_impact !== 0 && evidence.expected_value === undefined) {
    warnings.push("missing expected value");
  }

  // manual_verification_command and checked_at: same field names in both formats
  if (!evidence.manual_verification_command) warnings.push("missing manual verification command");
  if (!evidence.checked_at) warnings.push("missing checked_at timestamp");

  const evidence_quality = warnings.length === 0
    ? "excellent"
    : warnings.length <= 2
      ? "good"
      : "partial";

  return { evidence_quality, evidence_warnings: warnings };
}

export function applyEvidenceQuality(findings) {
  return (findings || []).map((finding) => {
    const quality = validateFindingEvidence(finding);
    // Sprint 10A: propagate finding_type so it appears in computeScore output.
    // "finding" is set by the finding() helper; everything else defaults to "observation".
    return { ...finding, ...quality, finding_type: finding.finding_type ?? "observation" };
  });
}

/**
 * normalizeFindingSchema(finding)
 * Sprint 9A schema fields + Sprint 9B numeric confidence.
 *
 * Ensures every finding conforms to v2 schema with a numeric confidence score.
 * Spread-first — existing fields are preserved; only missing fields get defaults.
 */
// Sprint 9C: Build structured evidence array from any finding.
// Three cases:
//   A — evidence is already a non-empty array → return as-is
//   B — evidence is a non-null, non-array object (rich object) → normalize to array
//   C — evidence is null/undefined/[] → generate from finding fields (never invented)
function buildEvidenceArray(finding) {
  const ev = finding.evidence;

  // Case A: already a populated array — do not modify
  if (Array.isArray(ev) && ev.length > 0) return ev;

  // Case B: rich evidence object — normalize to array, preserving all fields
  if (ev != null && typeof ev === "object" && !Array.isArray(ev)) {
    const {
      evidence_type,
      probe_target,
      observed_value,
      expected_value,
      source,
      checked_at,
      manual_verification_command,
      ...rest
    } = ev;
    return [{
      type:                        evidence_type ?? "scan_probe",
      label:                       probe_target  ?? "Probe target",
      value:                       observed_value != null ? String(observed_value) : null,
      source:                      source ?? "CyberMeters",
      expected_value:              expected_value ?? null,
      checked_at:                  checked_at ?? null,
      manual_verification_command: manual_verification_command ?? null,
      ...rest,
    }];
  }

  // Case C: no evidence set — derive from finding fields
  return buildEvidenceFromFields(finding);
}

function buildEvidenceFromFields(finding) {
  const { id = "", module: mod = "", description = "" } = finding;

  // Subdomain sensitive — reconstruct subdomain from ID
  if (id.startsWith("subdomain_sensitive_")) {
    const sub = id.replace("subdomain_sensitive_", "").replace(/_/g, ".");
    return [{
      type:   "certificate_transparency",
      label:  "Subdomain discovered in CT logs",
      value:  sub,
      source: "certificate_transparency_log",
    }];
  }

  if (id === "subdomains_large_attack_surface") {
    return [{
      type:   "certificate_transparency",
      label:  "Subdomain count from CT logs",
      value:  description,
      source: "certificate_transparency_log",
    }];
  }

  if (id === "subdomain_takeover") {
    return [{
      type:   "dns_cname",
      label:  "Dangling CNAME detected",
      value:  description,
      source: "dns_lookup",
    }];
  }

  if (id === "asset_exposure_sensitive_tool" ||
      id === "asset_exposure_admin_interface" ||
      id === "asset_exposure_dev_env") {
    return [{
      type:   "http_probe",
      label:  "Reachable asset detected",
      value:  description,
      source: "cloudflare_workers_fetch",
    }];
  }

  if (id.startsWith("whois_")) {
    return [{
      type:   "rdap_lookup",
      label:  "RDAP registry query result",
      value:  description,
      source: "rdap",
    }];
  }

  if (id.startsWith("admin_surface_")) {
    return [{
      type:   "http_probe",
      label:  "Admin service fingerprint match",
      value:  description,
      source: "cloudflare_workers_fetch",
    }];
  }

  if (id === "dse_missing_caa" || id === "dse_caa_no_issuers") {
    return [{
      type:   "dns_lookup",
      label:  "DNS CAA record query",
      value:  description,
      source: "cloudflare_doh",
    }];
  }

  if (id.startsWith("dse_hsts_") || id.startsWith("dse_cookie_")) {
    return [{
      type:   "http_header_probe",
      label:  "HTTP response header observation",
      value:  description,
      source: "cloudflare_workers_fetch",
    }];
  }

  if (id.startsWith("tech_")) {
    return [{
      type:   "http_header_probe",
      label:  "Version disclosure in HTTP response header",
      value:  description,
      source: "cloudflare_workers_fetch",
    }];
  }

  if (id.startsWith("email_intel_")) {
    return [{
      type:   "dns_txt_lookup",
      label:  "DNS TXT record query",
      value:  description,
      source: "cloudflare_doh",
    }];
  }

  // Generic fallback — description always contains the observed condition
  return [{
    type:   "scanner_detection",
    label:  "Detection basis",
    value:  description,
    source: `CyberMeters/${mod}`,
  }];
}

export function normalizeFindingSchema(finding) {
  return {
    ...finding,
    module:             finding.module             ?? null,
    confidence:         resolveConfidence(finding),         // Sprint 9B: always numeric
    validation_quality: finding.validation_quality ?? null,
    evidence:           buildEvidenceArray(finding),        // Sprint 9C: always array
    remediation_owner:  finding.remediation_owner  ?? null,
    finding_type:       finding.finding_type       ?? (finding.score_impact < 0 ? "finding" : "observation"),
  };
}

export function isActionableFinding(finding) {
  return finding?.finding_type === "finding"
    || (finding?.finding_type == null && Number(finding?.score_impact) < 0);
}
