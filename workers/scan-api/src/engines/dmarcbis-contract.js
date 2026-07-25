// Item 7 P3 — immutable DMARCbis snapshot/API contract.
//
// This module does not derive policy. P1/P2 own protocol interpretation and
// observation; P3 only seals that already-derived object, verifies it on read,
// and projects it additively onto technical API responses.
import { DMARCBIS_IDNA_PROFILE } from "./dmarcbis-idna.js";
import { DMARCBIS_PARSER_VERSION } from "./dmarcbis-parser.js";
import { buildDmarcPolicyPresentation } from "./dmarcbis-presentation.js";
import { DMARCBIS_METHODOLOGY_VERSION } from "./dmarcbis-resolver.js";

export const DMARCBIS_POLICY_EVIDENCE_SCHEMA = "dmarc-policy.v2";
export const DMARCBIS_RESOLVER_PROFILE =
  "primary-plus-decisive-corroboration-v1";
export const DMARCBIS_EVIDENCE_CANONICALIZATION = "json-stringify-v1";
export const DMARCBIS_HISTORICAL_METHODOLOGY_NOTICE =
  "This report preserves the DMARC methodology and conclusions used when the scan completed.";

const OBSERVATION_STATES = new Set([
  "absent",
  "present_valid",
  "present_valid_with_defaults",
  "present_invalid",
  "multiple",
  "unavailable",
  "incomplete_oversized",
  "resolver_disagreement",
]);
const RECORD_VALIDITIES = new Set([
  "valid",
  "valid_with_defaults",
  "invalid",
  "indeterminate",
  "not_applicable",
]);
const POLICY_SOURCE_KINDS = new Set([
  "exact",
  "organisational",
  "psd",
  "none",
  "unknown",
]);
const ORGANISATIONAL_DOMAIN_PROVENANCE = new Set([
  "psd_n",
  "below_psd_y",
  "highest_valid_record",
  "exact_shortcut",
  "fallback_initial_target",
  "unresolved",
]);
const DOMAIN_EXISTENCE = new Set([
  "exists",
  "nonexistent",
  "unknown",
  "not_required",
]);
const INHERITANCE_REASONS = new Set([
  "exact_p",
  "organisational_p",
  "organisational_sp",
  "organisational_np",
  "psd_p",
  "psd_sp",
  "psd_np",
  "invalid_policy_fallback_none",
  "none",
  "unknown",
]);
const TESTING_ADJUSTMENTS = new Set([
  "none",
  "one_level_below",
  "no_effect_on_none",
  "not_applicable",
  "unknown",
]);
const CORROBORATION_STATES = new Set([
  "not_applicable",
  "unavailable",
  "corroborated",
  "resolver_disagreement",
]);
const MONITORING_STATES = new Set([
  "monitoring_healthy",
  "monitoring_degraded",
]);
const POLICIES = new Set(["none", "quarantine", "reject"]);
const COMPLETENESS = new Set([
  "complete",
  "incomplete",
  "unavailable",
  "not_applicable",
]);

function withoutFingerprint(evidence) {
  const {
    evidence_fingerprint: _fingerprint,
    evidence_fingerprint_algorithm: _algorithm,
    evidence_canonicalization: _canonicalization,
    ...payload
  } = evidence || {};
  return payload;
}

function fingerprintMaterial(evidence) {
  return {
    ...withoutFingerprint(evidence),
    evidence_fingerprint_algorithm: "sha256",
    evidence_canonicalization: DMARCBIS_EVIDENCE_CANONICALIZATION,
  };
}

async function sha256Hex(value) {
  const bytes = new TextEncoder().encode(String(value));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function dmarcPolicyEvidenceFingerprint(evidence) {
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) {
    return null;
  }
  return sha256Hex(JSON.stringify(fingerprintMaterial(evidence)));
}

function contractProblem(evidence) {
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) {
    return "not_an_object";
  }
  if (evidence.schema !== DMARCBIS_POLICY_EVIDENCE_SCHEMA) {
    return "unsupported_schema";
  }
  if (evidence.methodology_version !== DMARCBIS_METHODOLOGY_VERSION) {
    return "unsupported_methodology";
  }
  if (evidence.parser_version !== DMARCBIS_PARSER_VERSION) {
    return "unsupported_parser";
  }
  if (evidence.resolver_profile !== DMARCBIS_RESOLVER_PROFILE) {
    return "unsupported_resolver_profile";
  }
  if (
    JSON.stringify(evidence.idna_profile) !==
    JSON.stringify(DMARCBIS_IDNA_PROFILE)
  ) {
    return "unsupported_idna_profile";
  }
  if (!OBSERVATION_STATES.has(evidence.observation_state)) {
    return "unknown_observation_state";
  }
  if (!RECORD_VALIDITIES.has(evidence.record_validity)) {
    return "unknown_record_validity";
  }
  if (!POLICY_SOURCE_KINDS.has(evidence.policy_source_kind)) {
    return "unknown_policy_source_kind";
  }
  if (!ORGANISATIONAL_DOMAIN_PROVENANCE.has(
    evidence.organisational_domain_provenance,
  )) {
    return "unknown_organisational_domain_provenance";
  }
  if (!DOMAIN_EXISTENCE.has(evidence.domain_existence)) {
    return "unknown_domain_existence";
  }
  if (!INHERITANCE_REASONS.has(evidence.inheritance_reason)) {
    return "unknown_inheritance_reason";
  }
  if (
    evidence.testing_adjustment != null &&
    !TESTING_ADJUSTMENTS.has(evidence.testing_adjustment)
  ) {
    return "unknown_testing_adjustment";
  }
  if (!CORROBORATION_STATES.has(evidence.corroboration_state)) {
    return "unknown_corroboration_state";
  }
  if (!MONITORING_STATES.has(evidence.monitoring_state)) {
    return "unknown_monitoring_state";
  }
  if (
    evidence.effective_policy_tag != null &&
    !["p", "sp", "np"].includes(evidence.effective_policy_tag)
  ) {
    return "unknown_effective_policy_tag";
  }
  if (
    evidence.declared_policy != null &&
    !POLICIES.has(evidence.declared_policy)
  ) {
    return "unknown_declared_policy";
  }
  if (
    evidence.effective_requested_policy != null &&
    !POLICIES.has(evidence.effective_requested_policy)
  ) {
    return "unknown_effective_requested_policy";
  }
  for (const field of [
    "policy_completeness",
    "organisational_domain_completeness",
    "existence_completeness",
    "rua_authorisation_completeness",
    "core_completeness",
  ]) {
    if (!COMPLETENESS.has(evidence[field])) return `unknown_${field}`;
  }
  if (!Array.isArray(evidence.lookup_path)) return "lookup_path_not_array";
  if (evidence.raw_records !== null && !Array.isArray(evidence.raw_records)) {
    return "raw_records_not_array";
  }
  if (evidence.parsed_tags !== null && !Array.isArray(evidence.parsed_tags)) {
    return "parsed_tags_not_array";
  }
  if (
    evidence.rua_destinations !== null &&
    !Array.isArray(evidence.rua_destinations)
  ) {
    return "rua_destinations_not_array";
  }
  if (
    evidence.ruf_destinations !== null &&
    !Array.isArray(evidence.ruf_destinations)
  ) {
    return "ruf_destinations_not_array";
  }
  if (evidence.legacy_pct?.applied_to_effective_policy !== false) {
    return "legacy_pct_not_explicitly_nonoperative";
  }
  if (evidence.receiver_enforcement_observed !== false) {
    return "receiver_enforcement_claim";
  }
  return null;
}

export async function sealDmarcPolicyEvidence(evidence) {
  if (evidence == null) return null;
  const problem = contractProblem({
    parser_version: DMARCBIS_PARSER_VERSION,
    resolver_profile: DMARCBIS_RESOLVER_PROFILE,
    idna_profile: DMARCBIS_IDNA_PROFILE,
    ...evidence,
  });
  if (problem) throw new Error(`dmarc_policy_evidence_${problem}`);

  // P2's structured unavailable fallback predates the P3 contract seal. Add
  // only fixed producer-version metadata; never fill an observed/derived value.
  const material = fingerprintMaterial({
    parser_version: DMARCBIS_PARSER_VERSION,
    resolver_profile: DMARCBIS_RESOLVER_PROFILE,
    idna_profile: DMARCBIS_IDNA_PROFILE,
    ...evidence,
  });
  const fingerprint = await sha256Hex(JSON.stringify(material));
  if (
    evidence.evidence_fingerprint != null &&
    evidence.evidence_fingerprint !== fingerprint
  ) {
    throw new Error("dmarc_policy_evidence_fingerprint_mismatch");
  }
  return {
    ...material,
    evidence_fingerprint: fingerprint,
  };
}

export async function readDmarcPolicyEvidenceFromSnapshot(snapshot) {
  const evidence = snapshot?.protocol_evidence?.dmarc;
  if (evidence == null) {
    return {
      status: "legacy_snapshot",
      evidence: null,
      notice: DMARCBIS_HISTORICAL_METHODOLOGY_NOTICE,
      reason: "dmarc_block_absent",
    };
  }

  const problem = contractProblem(evidence);
  if (problem) {
    return {
      status: problem === "unsupported_schema"
        ? "unsupported_schema"
        : "invalid_contract",
      evidence: null,
      notice: null,
      reason: problem,
    };
  }
  if (
    evidence.evidence_fingerprint_algorithm !== "sha256" ||
    evidence.evidence_canonicalization !==
      DMARCBIS_EVIDENCE_CANONICALIZATION ||
    typeof evidence.evidence_fingerprint !== "string"
  ) {
    return {
      status: "integrity_error",
      evidence: null,
      notice: null,
      reason: "fingerprint_metadata_missing",
    };
  }
  const fingerprint = await dmarcPolicyEvidenceFingerprint(evidence);
  if (fingerprint !== evidence.evidence_fingerprint) {
    return {
      status: "integrity_error",
      evidence: null,
      notice: null,
      reason: "fingerprint_mismatch",
    };
  }
  return {
    status: "current",
    evidence,
    notice: null,
    reason: null,
  };
}

export function dmarcPolicyApiProjection(read) {
  const status = read?.status || "not_available";
  const projection = {
    dmarc_policy_evidence_status: status,
    dmarc_policy_presentation: buildDmarcPolicyPresentation(read),
  };
  if (status === "current" && read?.evidence) {
    projection.dmarc_policy_evidence = read.evidence;
  } else if (status === "legacy_snapshot") {
    projection.dmarc_methodology_notice =
      read.notice || DMARCBIS_HISTORICAL_METHODOLOGY_NOTICE;
  } else if (read?.reason) {
    projection.dmarc_policy_evidence_unavailable_reason = read.reason;
  }
  return projection;
}

export function hostedDmarcReadOnlyProjection(read) {
  const evidence = read?.status === "current" ? read.evidence : null;
  return {
    mode: "read_only",
    automation_status: "suspended",
    suggestion_only: true,
    policy_evidence_status: read?.status || "not_available",
    policy_source_domain: evidence?.policy_source_domain ?? null,
    policy_source_kind: evidence?.policy_source_kind ?? "unknown",
    effective_requested_policy:
      evidence?.effective_requested_policy ?? null,
    policy_completeness: evidence?.policy_completeness ?? "unavailable",
    receiver_enforcement_observed: false,
    evidence_fingerprint: evidence?.evidence_fingerprint ?? null,
    methodology_notice:
      read?.status === "legacy_snapshot" ? read.notice : null,
  };
}
