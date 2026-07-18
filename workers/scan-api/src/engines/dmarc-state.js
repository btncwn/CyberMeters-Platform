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
      confidence: "high",
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
      confidence: "high",
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
    confidence: parsed?.has_reporting ? "high" : "medium",
    last_observed: lastObserved,
  });
}
