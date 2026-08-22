// ── Canonical serviceability / conclusion-eligibility authority ─────────────────
//
// THE RECONCILIATION, NOT AN INVENTION. `fetch-observation.js` already contradicts
// itself: "Rule A" maps ANY origin status — including 503 — to `origin_response`
// with completeness `observed`, while `classifyServerErrorStatus` in the same file
// states that a genuine origin 5xx "must never confirm absence or health". The
// right answer was already written down; this module makes it the single authority
// and gives every consumer one place to ask.
//
// THE MISSING AXIS. Rule A is literally true — any origin status proves transport —
// but one field was carrying two different questions:
//
//     transport_observed  — did bytes come back from the customer's origin?  (503 => TRUE)
//     serviceable         — did the origin SERVE THE SITE?                   (503 => FALSE)
//
// Every unguarded producer in the I11A-ACC-P2-01 inventory needed the second and was
// handed the first. The discriminating datum (`origin_status`, recorded on
// `http_redirect_chain.hop_observations[]`) already exists; nothing new is probed.
//
// THE CLASS IS BIDIRECTIONAL. The same non-serviceable response currently produces a
// false ISSUE (a scored "no HTTP redirect" against an all-503 origin) AND a false
// FIXED (a takeover surface "claimed" during a provider outage; a managed
// verification "complete" off a 503). Both directions are pinned separately below.
//
// CANONICAL AUTHORITY, cited at its true type: Governance RULINGS seq 42
// (F48-F51-CLASSIFICATION), seq 63 (F48-REMEDIATION-ACCEPTANCE) and seq 262
// (I11A-ACC-P2-01-BAR-CONFLICT — FINAL, authorizes this succession). seq 260 is an
// Executive SUBMISSION and seq 263 an Executive MEASUREMENT: context, not rulings.
// Plan: EXECUTIVE-EPISODE-PLAN-P1-ERROR-CLASS-001.

import { FETCH_OBSERVATION_STATES } from "./fetch-observation.js";

export const SERVICEABILITY_CONTRACT_VERSION = "cybermeters.serviceability/v1";

export const CONCLUSION_CLASSES = Object.freeze({
  CONCLUSIVE:            "conclusive",
  EVIDENCE_INSUFFICIENT: "evidence_insufficient",
});

// Reasons are stable snake_case tokens. `origin_error_no_serviceable_response` is
// deliberately the SAME token headers-scan.js already emits, so the vocabulary does
// not fork.
export const SERVICEABILITY_REASONS = Object.freeze({
  ORIGIN_SERVED:            "origin_served",
  ORIGIN_NEGATIVE_ANSWER:   "origin_negative_answer",
  ORIGIN_ERROR:             "origin_error_no_serviceable_response",
  ACCESS_RESTRICTED:        "origin_access_restricted",
  INFORMATIONAL_ONLY:       "origin_informational_only",
  EDGE_ERROR:               "cloudflare_edge_error",
  TRANSPORT_UNAVAILABLE:    "transport_unavailable",
  NOT_ASSESSED:             "not_assessed",
  UNKNOWN_SHAPE:            "unknown_observation_shape",
});

// 4xx BOUNDARY — DECIDED EXPLICITLY (Ruling 2 forbids letting it fall through a
// default). A 404 is a SERVICEABLE origin returning a definitive negative answer:
// the origin served us, and "this resource is not here" is a real observation, which
// is a different question from a 503 (the origin could not serve at all).
//
// EXCEPTION, tested: 401/403/429 describe the REQUESTER'S ACCESS, not the origin's
// service. Bot protection answering 403 tells us nothing about what a browser would
// receive, and treating it as a definitive answer is how a false ISSUE is born for
// enterprise-edge domains. These are evidence-insufficient.
export const ACCESS_RESTRICTED_STATUSES = Object.freeze([401, 403, 429]);

// The admissible HTTP status range. A value outside it is a malformed observation,
// NOT an origin that answered with an unusual code.
export const MIN_HTTP_STATUS = 100;
export const MAX_HTTP_STATUS = 599;

const isPlainRecord = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);

function unknown(reason) {
  return Object.freeze({
    serviceable:      null,
    conclusion_class: CONCLUSION_CLASSES.EVIDENCE_INSUFFICIENT,
    reason,
    origin_status:    null,
    contract_version: SERVICEABILITY_CONTRACT_VERSION,
  });
}

function decided(serviceable, conclusionClass, reason, originStatus) {
  return Object.freeze({
    serviceable,
    conclusion_class: conclusionClass,
    reason,
    origin_status:    typeof originStatus === "number" && Number.isFinite(originStatus)
      ? originStatus
      : null,
    contract_version: SERVICEABILITY_CONTRACT_VERSION,
  });
}

/**
 * classifyServiceability(observation)
 *
 * `observation` is a record produced by `classifyFetchObservation(...)`. Pure; no I/O.
 *
 * FAIL-CLOSED: anything unrecognised yields `serviceable: null` +
 * `evidence_insufficient`, and every decision helper below returns false. `null` must
 * NEVER be read as "not serviceable, therefore report a defect" — that inversion is
 * exactly how a false ISSUE is produced from absent evidence.
 *
 * Type admission happens BEFORE any value normalisation: a non-record, or a
 * non-string state, is rejected without coercion.
 */
export function classifyServiceability(observation) {
  if (!isPlainRecord(observation)) return unknown(SERVICEABILITY_REASONS.UNKNOWN_SHAPE);

  const state = observation.state;
  if (typeof state !== "string") return unknown(SERVICEABILITY_REASONS.UNKNOWN_SHAPE);

  if (state === FETCH_OBSERVATION_STATES.NOT_ASSESSED) {
    return unknown(SERVICEABILITY_REASONS.NOT_ASSESSED);
  }
  if (state === FETCH_OBSERVATION_STATES.TRANSPORT_UNAVAILABLE) {
    return decided(false, CONCLUSION_CLASSES.EVIDENCE_INSUFFICIENT,
      SERVICEABILITY_REASONS.TRANSPORT_UNAVAILABLE, null);
  }
  if (state === FETCH_OBSERVATION_STATES.CLOUDFLARE_EDGE_ERROR) {
    // The edge wrote this, not the customer's origin. Nothing here is attributable.
    return decided(false, CONCLUSION_CLASSES.EVIDENCE_INSUFFICIENT,
      SERVICEABILITY_REASONS.EDGE_ERROR, null);
  }
  if (state !== FETCH_OBSERVATION_STATES.ORIGIN_RESPONSE) {
    return unknown(SERVICEABILITY_REASONS.UNKNOWN_SHAPE);
  }

  // ADMISSION IS A TYPE **AND VALUE** CONTRACT (P11-LV-01). Guarding `typeof` alone
  // let every finite number through to the range ladder below, so `200.5` reached
  // `>= 200` and grounded a conclusion, while `600`/`99`/`0`/`-1` were DECIDED
  // non-serviceable — i.e. reported as if a real origin had answered badly.
  //
  // An out-of-range or fractional status is not a worse origin; it is a MALFORMED
  // OBSERVATION. Conflating the two would let a corrupt record masquerade as a 5xx
  // and produce an "evidence insufficient because the origin errored" story about an
  // origin that never said any such thing. Malformed input therefore fails closed to
  // UNKNOWN — `null` — and never to a decided verdict in either direction.
  //
  // Admissible == an INTEGER in [100, 599]. Checked BEFORE any range decision.
  const status = observation.origin_status;
  if (typeof status !== "number" || !Number.isInteger(status)
      || status < MIN_HTTP_STATUS || status > MAX_HTTP_STATUS) {
    return unknown(SERVICEABILITY_REASONS.UNKNOWN_SHAPE);
  }

  if (status >= 500) {
    return decided(false, CONCLUSION_CLASSES.EVIDENCE_INSUFFICIENT,
      SERVICEABILITY_REASONS.ORIGIN_ERROR, status);
  }
  if (ACCESS_RESTRICTED_STATUSES.includes(status)) {
    return decided(false, CONCLUSION_CLASSES.EVIDENCE_INSUFFICIENT,
      SERVICEABILITY_REASONS.ACCESS_RESTRICTED, status);
  }
  if (status >= 400) {
    return decided(true, CONCLUSION_CLASSES.CONCLUSIVE,
      SERVICEABILITY_REASONS.ORIGIN_NEGATIVE_ANSWER, status);
  }
  if (status >= 200) {
    return decided(true, CONCLUSION_CLASSES.CONCLUSIVE,
      SERVICEABILITY_REASONS.ORIGIN_SERVED, status);
  }
  // 1xx: informational, no final answer was delivered.
  return decided(false, CONCLUSION_CLASSES.EVIDENCE_INSUFFICIENT,
    SERVICEABILITY_REASONS.INFORMATIONAL_ONLY, status);
}

// ── The three decision helpers ────────────────────────────────────────────────
//
// Deliberately THREE, not one. The class is bidirectional, so a single `isUsable()`
// would let a repair in one direction silently re-open the other, and would give the
// mutation pair no distinct named assertion to die on. They share one gate today;
// they are separate so a future divergence (a 4xx that may ground absence but not
// health, say) does not require re-plumbing every consumer.

const eligible = (record) =>
  isPlainRecord(record)
  && record.serviceable === true
  && record.conclusion_class === CONCLUSION_CLASSES.CONCLUSIVE;

/** May this evidence ground a customer-visible DEFECT (finding / scored issue / alert)? */
export function maySupportDefectConclusion(record) { return eligible(record); }

/** May this evidence ground HEALTHY / verified-fixed / "no surface" / remediation-complete? */
export function maySupportHealthyConclusion(record) { return eligible(record); }

/** May "we did not observe X" be published as "X is absent"? */
export function mayGroundAbsence(record) { return eligible(record); }

/**
 * Redirect absence is admissible only when the redirect chain carries the
 * canonical observation state.  Historical rows without hop observations are
 * readable, but deliberately non-comparable: their legacy boolean cannot
 * certify absence (and in particular an all-503 shape must not do so).
 */
export function mayGroundRedirectAbsence(chain) {
  if (!isPlainRecord(chain) || typeof chain.observation_state !== "string") return false;
  const hops = Array.isArray(chain.hop_observations) ? chain.hop_observations : [];
  const last = hops.length ? hops[hops.length - 1] : null;
  return mayGroundAbsence(classifyServiceability({
    state: chain.observation_state,
    origin_status: last?.origin_status ?? chain.origin_status ?? null,
  }));
}

/** Convenience: classify then ask, for call sites holding a raw fetch observation. */
export function serviceabilityOf(observation) { return classifyServiceability(observation); }
