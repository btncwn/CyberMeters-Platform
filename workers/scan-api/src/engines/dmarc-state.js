// ── Canonical DMARC enforcement state derivation ─────────────────────────────
//
// Pure ADR-003 state model. This module intentionally performs no DNS lookup,
// persistence, scoring, API serialization, reporting, alerting, or UI work.
// Production consumers are not switched to this module in PR-1.

export const DMARC_STATE_MODEL_VERSION = "2026-07-18";

export const DMARC_ENFORCEMENT_LEVELS = Object.freeze([
  "not_yet_assessed",
  "not_observed",
  "no_record",
  "invalid_record",
  "monitoring",
  "partial_quarantine",
  "quarantine_enforced",
  "partial_reject",
  "reject_enforced",
]);

export const DMARC_CAVEAT_PRIORITY = Object.freeze([
  "policy_applies_to_zero_percent",
  "subdomain_gap",
  "pct_below_100",
]);

const VALID_POLICIES = new Set(["none", "quarantine", "reject"]);
const VALID_SUBDOMAIN_POLICIES = new Set(["none", "quarantine", "reject"]);

function baseState(overrides = {}) {
  return {
    evidence_status: "observed",
    record_presence: "unknown",
    record_validity: "not_applicable",
    invalid_reason: null,
    policy: null,
    pct: null,
    subdomain_policy: null,
    policy_source: "observed_dns",
    enforcement_level: "not_observed",
    caveats: [],
    confidence: "low",
    last_observed: null,
    state_model_version: DMARC_STATE_MODEL_VERSION,
    ...overrides,
  };
}

function normalizePolicy(value) {
  const policy = value == null ? null : String(value).trim().toLowerCase();
  return policy || null;
}

function normalizePct(value) {
  return Number.isInteger(value) && value >= 0 && value <= 100 ? value : null;
}

function isUnavailableSignal(value) {
  return [
    "unavailable",
    "not_observed",
    "failed",
    "failure",
    "timeout",
    "servfail",
    "rejected",
    "error",
  ].includes(String(value || "").trim().toLowerCase());
}

function invalidReasonFor(parsed) {
  const recordCount = Number(parsed?.record_count ?? 0);
  const tags = parsed?.tags || {};
  const raw = parsed?.raw || null;

  if (recordCount > 1) return "multiple_records";
  if (raw && String(tags.v || "").toUpperCase() !== "DMARC1") return "not_dmarc1";

  const policy = normalizePolicy(parsed?.policy);
  if (raw && !VALID_POLICIES.has(policy)) return "unknown_policy_token";

  const pctRaw = tags.pct;
  if (pctRaw != null && pctRaw !== "") {
    const pctParsed = Number(pctRaw);
    if (!(Number.isInteger(pctParsed) && pctParsed >= 0 && pctParsed <= 100)) return "malformed_pct";
  }

  const sp = normalizePolicy(parsed?.subdomain_policy);
  if (sp && !VALID_SUBDOMAIN_POLICIES.has(sp)) return "unknown_policy_token";

  return "other";
}

function orderedCaveats(caveats) {
  const present = new Set(caveats);
  return DMARC_CAVEAT_PRIORITY.filter((caveat) => present.has(caveat));
}

function confidenceForObservedRecord(policySource, parsed, recordValidity) {
  if (policySource === "customer_asserted") return "low";
  if (policySource === "hosted_managed_verified") return "high";
  if (recordValidity === "valid") return parsed?.has_reporting ? "high" : "medium";
  return "high";
}

/**
 * deriveDmarcState(input)
 *
 * Pure canonical ADR-003 derivation from parser primitives plus explicit
 * observation metadata. Accepted input:
 *   {
 *     assessed: boolean,              // false => not_yet_assessed
 *     evidence_status: string,         // unavailable/not_yet_assessed/observed
 *     lookup_status: string,           // alternate observation signal
 *     dns_status: string,              // alternate observation signal
 *     dmarc: parseDmarcRecord(...) output,
 *     policy_source: observed_dns|hosted_managed_verified|customer_asserted,
 *     last_observed: ISO string|null
 *   }
 */
export function deriveDmarcState(input = {}) {
  const assessed = input.assessed !== false && input.evidence_status !== "not_yet_assessed";
  if (!assessed) {
    return baseState({
      evidence_status: "not_yet_assessed",
      enforcement_level: "not_yet_assessed",
      confidence: "low",
    });
  }

  const observationSignal = input.evidence_status ?? input.lookup_status ?? input.dns_status ?? "observed";
  const lastObserved = input.last_observed ?? input.lastObserved ?? null;
  if (isUnavailableSignal(observationSignal)) {
    return baseState({
      evidence_status: "unavailable",
      enforcement_level: "not_observed",
      confidence: "low",
      last_observed: lastObserved,
    });
  }

  const parsed = input.dmarc ?? input.dmarc_detail ?? null;
  const recordCount = Number(parsed?.record_count ?? 0);
  const raw = parsed?.raw || null;
  const policySource = input.policy_source || "observed_dns";

  if (recordCount === 0 || (!raw && recordCount <= 0)) {
    return baseState({
      evidence_status: "observed",
      record_presence: "absent",
      record_validity: "not_applicable",
      enforcement_level: "no_record",
      policy_source: policySource,
      confidence: confidenceForObservedRecord(policySource, parsed, "absent"),
      last_observed: lastObserved,
    });
  }

  const policy = normalizePolicy(parsed?.policy);
  const pct = normalizePct(parsed?.pct ?? parsed?.percentage);
  const sp = normalizePolicy(parsed?.subdomain_policy);
  const spValid = !sp || VALID_SUBDOMAIN_POLICIES.has(sp);

  if (recordCount > 1 || parsed?.valid !== true || !VALID_POLICIES.has(policy) || pct == null || !spValid) {
    return baseState({
      evidence_status: "observed",
      record_presence: "present",
      record_validity: "invalid",
      invalid_reason: invalidReasonFor(parsed),
      policy: VALID_POLICIES.has(policy) ? policy : null,
      pct,
      subdomain_policy: spValid ? (sp || "inherit") : null,
      policy_source: policySource,
      enforcement_level: "invalid_record",
      confidence: confidenceForObservedRecord(policySource, parsed, "invalid"),
      last_observed: lastObserved,
    });
  }

  const subdomainPolicy = sp || "inherit";
  const enforcing = policy === "quarantine" || policy === "reject";
  const caveats = [];
  if (enforcing && pct === 0) caveats.push("policy_applies_to_zero_percent");
  if (enforcing && subdomainPolicy === "none") caveats.push("subdomain_gap");
  if (enforcing && pct > 0 && pct < 100) caveats.push("pct_below_100");
  const ordered = orderedCaveats(caveats);

  let enforcementLevel = "monitoring";
  if (policy === "quarantine") {
    enforcementLevel = ordered.length === 0 ? "quarantine_enforced" : "partial_quarantine";
  } else if (policy === "reject") {
    enforcementLevel = ordered.length === 0 ? "reject_enforced" : "partial_reject";
  }

  return baseState({
    evidence_status: "observed",
    record_presence: "present",
    record_validity: "valid",
    policy,
    pct,
    subdomain_policy: subdomainPolicy,
    policy_source: policySource,
    enforcement_level: enforcementLevel,
    caveats: ordered,
    confidence: confidenceForObservedRecord(policySource, parsed, "valid"),
    last_observed: lastObserved,
  });
}

const VALID_POLICY_OBSERVATIONS = new Set([
  "present_valid",
  "present_valid_with_defaults",
]);
const VALID_POLICY_RECORDS = new Set(["valid", "valid_with_defaults"]);
const POLICY_SOURCE_KINDS = new Set(["exact", "organisational", "psd"]);

function retainedPolicyRecord(evidence) {
  for (const candidate of [
    evidence?.source_record?.raw,
    evidence?.source_record?.value,
  ]) {
    if (typeof candidate === "string" && candidate.trim()) return candidate;
  }
  const raw = Array.isArray(evidence?.raw_records)
    ? evidence.raw_records
      .flatMap((record) => [record?.raw, record?.value])
      .find((candidate) => typeof candidate === "string" && candidate.trim())
    : null;
  return raw || null;
}

function withCanonicalEvidenceState(state, canonicalEvidenceState, evidence) {
  const projected = {
    ...state,
    canonical_evidence_state: canonicalEvidenceState,
    policy_source_kind: evidence?.policy_source_kind ?? "unknown",
    policy_completeness: evidence?.policy_completeness ?? "unavailable",
    // Carry all completeness axes so an incomplete/unavailable summary can name
    // the ACTUAL failing axis instead of generically blaming the policy lookup.
    organisational_domain_completeness: evidence?.organisational_domain_completeness ?? null,
    existence_completeness: evidence?.existence_completeness ?? null,
    rua_authorisation_completeness: evidence?.rua_authorisation_completeness ?? null,
    core_completeness: evidence?.core_completeness ?? null,
    provider_state: evidence?.provider_state ?? null,
    observation_state: evidence?.observation_state ?? null,
    receiver_enforcement_observed: false,
  };
  return {
    ...projected,
    canonical_summary: canonicalDmarcAssessmentSummary(projected),
  };
}

// Name the actual failing completeness axis, in observation order, so the
// customer reason is specific ("the aggregate-report destination authorisation
// could not be completed") rather than a generic "policy lookup unavailable".
// Returns null when nothing identifiable failed (caller falls back to generic).
function failingDmarcAxisReason(state) {
  if (state?.provider_state && state.provider_state !== "available") {
    return "the DMARC provider could not be corroborated, so no policy or absence conclusion was made.";
  }
  if (state?.observation_state === "incomplete_oversized") {
    return "the DMARC record set was incomplete or oversized, so no policy or absence conclusion was made.";
  }
  if (state?.policy_completeness && !["complete", "not_applicable"].includes(state.policy_completeness)) {
    return "the DMARC policy record could not be fully resolved, so no policy or absence conclusion was made.";
  }
  if (state?.organisational_domain_completeness && !["complete", "not_applicable"].includes(state.organisational_domain_completeness)) {
    return "the organisational-domain tree-walk could not be completed, so no policy or absence conclusion was made.";
  }
  if (state?.existence_completeness && !["complete", "not_applicable"].includes(state.existence_completeness)) {
    return "domain existence could not be confirmed, so no policy or absence conclusion was made.";
  }
  if (state?.rua_authorisation_completeness && !["complete", "not_applicable"].includes(state.rua_authorisation_completeness)) {
    return "the aggregate-report (rua) destination authorisation could not be completed, so no policy or absence conclusion was made.";
  }
  return null;
}

/**
 * Project the immutable DMARCbis protocol evidence through the existing ADR-003
 * state resolver. This is the shared bridge used by scan-time compatibility,
 * report summaries and the technical presentation.
 *
 * Precedence is deliberate: a retained, valid policy conclusion is stronger
 * than a stale provider/core/monitoring marker. The function never changes the
 * evidence object and never treats ambiguity as healthy.
 */
export function deriveDmarcStateFromPolicyEvidence(evidence) {
  if (!evidence || typeof evidence !== "object") {
    return withCanonicalEvidenceState(
      deriveDmarcState({ assessed: false }),
      "not_assessed",
      null,
    );
  }

  const policy = normalizePolicy(evidence.effective_requested_policy);
  const raw = retainedPolicyRecord(evidence);
  const validPolicy =
    VALID_POLICY_OBSERVATIONS.has(evidence.observation_state) &&
    VALID_POLICY_RECORDS.has(evidence.record_validity) &&
    POLICY_SOURCE_KINDS.has(evidence.policy_source_kind) &&
    evidence.policy_completeness === "complete" &&
    VALID_POLICIES.has(policy) &&
    raw != null;

  // Strong positive policy evidence wins before any weaker core/provider marker.
  if (validPolicy) {
    return withCanonicalEvidenceState(
      deriveDmarcState({
        assessed: true,
        evidence_status: "observed",
        dmarc: {
          raw,
          valid: true,
          record_count: 1,
          policy,
          percentage: 100,
          subdomain_policy: null,
          has_reporting: Array.isArray(evidence.rua_destinations) &&
            evidence.rua_destinations.length > 0,
        },
        policy_source: "observed_dns",
        last_observed: evidence.observed_at ?? null,
      }),
      "observed_policy",
      evidence,
    );
  }

  // A malformed/multiple observation remains a real observation. It is never
  // converted into absence and never promoted to a usable policy.
  if (["present_invalid", "multiple"].includes(evidence.observation_state)) {
    const recordCount = evidence.observation_state === "multiple"
      ? Math.max(2, Array.isArray(evidence.raw_records)
        ? evidence.raw_records.length
        : 2)
      : Math.max(1, Array.isArray(evidence.raw_records)
        ? evidence.raw_records.length
        : 1);
    return withCanonicalEvidenceState(
      deriveDmarcState({
        assessed: true,
        evidence_status: "observed",
        dmarc: {
          raw,
          valid: false,
          record_count: recordCount,
          policy: null,
          percentage: null,
          subdomain_policy: null,
          tags: {},
        },
        policy_source: "observed_dns",
        last_observed: evidence.observed_at ?? null,
      }),
      "malformed",
      evidence,
    );
  }

  // Absence is sayable only after a complete policy walk concluded that no
  // exact, organisational or public-suffix policy applies.
  if (evidence.observation_state === "absent" &&
      evidence.policy_source_kind === "none" &&
      evidence.policy_completeness === "complete") {
    return withCanonicalEvidenceState(
      deriveDmarcState({
        assessed: true,
        evidence_status: "observed",
        dmarc: { raw: null, valid: false, record_count: 0 },
        policy_source: "observed_dns",
        last_observed: evidence.observed_at ?? null,
      }),
      "absent",
      evidence,
    );
  }

  // An axis valued "unavailable" is not an INCOMPLETE marker: unavailable means
  // the observation could not happen at all and must classify as "unavailable",
  // never be re-labelled a partial result. Widening this predicate over
  // unavailable values collapsed the two canonical evidence states into one
  // (DMARC-PARITY-UNAVAILABLE-DISTINCT).
  const axisIncomplete = (value) => value != null && !["complete", "not_applicable", "unavailable"].includes(value);
  // When the observation itself was unavailable, every derived completeness
  // axis is an echo of that same failed lookup. Classifying the echoes as
  // "incomplete" would re-label a failed lookup as a partial result — the
  // exact false-reason class the axis work exists to eliminate.
  const incomplete =
    evidence.observation_state !== "unavailable" && (
    evidence.observation_state === "incomplete_oversized" ||
    axisIncomplete(evidence.policy_completeness) ||
    axisIncomplete(evidence.core_completeness) ||
    axisIncomplete(evidence.organisational_domain_completeness) ||
    axisIncomplete(evidence.existence_completeness) ||
    axisIncomplete(evidence.rua_authorisation_completeness));
  return withCanonicalEvidenceState(
    deriveDmarcState({
      assessed: true,
      evidence_status: "unavailable",
      last_observed: evidence.observed_at ?? null,
    }),
    incomplete ? "incomplete" : "unavailable",
    evidence,
  );
}

export function canonicalDmarcAssessmentSummary(state) {
  switch (state?.canonical_evidence_state) {
    case "observed_policy":
      if (state.policy === "none") {
        return "A valid DMARC no-action policy (p=none) was observed. It requests monitoring only, not quarantine or rejection.";
      }
      if (state.policy === "quarantine") {
        return "A valid DMARC policy requests quarantine for alignment failures. Receiver handling is not observed.";
      }
      return "A valid DMARC policy requests rejection for alignment failures. Receiver handling is not observed.";
    case "absent":
      return "The completed DMARC policy lookup found no applicable DMARC policy.";
    case "malformed":
      return "DMARC-looking evidence was observed, but it was malformed or ambiguous and no valid policy was established.";
    case "incomplete": {
      const axis = failingDmarcAxisReason(state);
      return axis
        ? `DMARC evidence was incomplete: ${axis}`
        : "DMARC policy evidence was incomplete, so no policy or absence conclusion was made.";
    }
    case "unavailable": {
      const axis = failingDmarcAxisReason(state);
      return axis
        ? `DMARC evidence was insufficient: ${axis}`
        : "The DMARC policy lookup was unavailable, so no policy or absence conclusion was made.";
    }
    case "not_assessed":
    default:
      return "DMARC was not assessed in this snapshot.";
  }
}

/** Clone-only scan-report projection; raw R2 evidence remains untouched. */
export function projectDmarcReportForCustomer(report, policyEvidence) {
  if (!report || typeof report !== "object" || !policyEvidence) return report;
  const modules = report.modules && typeof report.modules === "object"
    ? report.modules
    : {};
  const email = modules.email_security &&
    typeof modules.email_security === "object"
    ? modules.email_security
    : {};
  return {
    ...report,
    modules: {
      ...modules,
      email_security: {
        ...email,
        dmarc_state: deriveDmarcStateFromPolicyEvidence(policyEvidence),
      },
    },
  };
}

const ISSUE_LEVELS = new Set([
  "no_record",
  "invalid_record",
  "monitoring",
  "partial_quarantine",
  "quarantine_enforced",
  "partial_reject",
]);

/**
 * Read-time customer projection for immutable snapshots. Only the separate
 * customer view changes; checksum-scoped snapshot/raw bytes remain verbatim.
 */
export function projectDmarcSnapshotForCustomer(snapshot, policyEvidence) {
  if (!snapshot || typeof snapshot !== "object" || !policyEvidence) return snapshot;
  const assessment = deriveDmarcStateFromPolicyEvidence(policyEvidence);
  const summary = canonicalDmarcAssessmentSummary(assessment);
  let changed = false;
  const domains = (Array.isArray(snapshot.domains) ? snapshot.domains : [])
    .map((domain) => {
      if (domain?.domain_key !== "email_protection") return domain;
      const next = {
        ...domain,
        canonical_dmarc_assessment: assessment,
      };
      if (ISSUE_LEVELS.has(assessment.enforcement_level)) {
        // Preserve an existing issue summary because it may describe unrelated
        // SPF/DKIM findings. The corrective only replaces a weaker domain state.
        if (domain.state !== "issue_detected") {
          next.state = "issue_detected";
          next.coverage = domain.coverage === "complete" ? "complete" : "partial";
          next.highest_severity = domain.highest_severity || "medium";
          next.summary = summary;
          next.state_reason = summary;
        }
      } else if (assessment.enforcement_level === "not_observed" &&
          domain.state !== "issue_detected") {
        next.state = "evidence_insufficient";
        next.coverage = "degraded";
        next.summary = summary;
        next.state_reason = summary;
      } else if (assessment.enforcement_level === "not_yet_assessed" &&
          !["issue_detected", "evidence_insufficient"].includes(domain.state)) {
        next.state = "not_yet_assessed";
        next.summary = summary;
        next.state_reason = summary;
      } else if (assessment.enforcement_level === "reject_enforced" &&
          /DMARC.*(?:could not|unavailable|lookup did not complete)/i.test(
            String(domain.summary || ""),
          )) {
        next.state = domain.coverage === "complete"
          ? "assessed_healthy"
          : "provisional";
        next.summary = summary;
        next.state_reason = summary;
      }
      changed = true;
      return next;
    });
  if (!changed) return snapshot;
  const counts = domains.reduce((all, domain) => {
    all[domain.state] = (all[domain.state] || 0) + 1;
    return all;
  }, {});
  const healthy = counts.assessed_healthy || 0;
  const issues = counts.issue_detected || 0;
  const attention = domains.length - healthy - issues;
  const notFullyAssessed = domains
    .filter((domain) =>
      !["assessed_healthy", "issue_detected"].includes(domain.state))
    .map((domain) => ({
      domain_key: domain.domain_key,
      state: domain.state,
      reason: domain.state_reason || domain.summary,
      evidence_grade: domain.evidence_grade,
    }));
  return {
    ...snapshot,
    domains,
    overall: {
      ...(snapshot.overall || {}),
      summary:
        `Across the eight Cyber MOT domains: ${healthy} assessed healthy, ` +
        `${issues} with issues detected, and ${attention} needing further ` +
        "evidence, customer input or monitoring.",
      not_fully_assessed: notFullyAssessed,
    },
  };
}
