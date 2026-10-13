// ── Item 9 P5 certificate customer-surface projection ──────────────────────
//
// Presentation only. P1-P4's certificate-signal-completeness model remains the
// source of truth; this module never re-runs certificate, lifecycle or trust
// derivation. It maps the frozen canonical evidence onto one additive contract
// shared by APIs, immutable snapshots, Executive Reports and PDFs.
//
// Historical law: a snapshot without this P5 block is not upgraded in place and
// no missing security fact is invented. Readers return a notice-only
// `not_recorded` projection whose signals explicitly say the historical snapshot
// did not record them.
import {
  CERTIFICATE_SIGNAL_KEYS,
  CERTIFICATE_SIGNAL_COMPLETENESS_VERSION,
} from "./certificate-signal-completeness.js";

export const CERTIFICATE_CUSTOMER_PRESENTATION_SCHEMA =
  "certificate-customer-presentation-v2";
// Snapshots frozen under an earlier schema are returned exactly as recorded.
const RECORDED_PRESENTATION_SCHEMAS = new Set([
  "certificate-customer-presentation-v1",
  CERTIFICATE_CUSTOMER_PRESENTATION_SCHEMA,
]);

export const CERTIFICATE_CUSTOMER_STATES = Object.freeze([
  "observed",
  "not_observed",
  "unknown",
  "unavailable",
  "incomplete",
]);

const SIGNAL_META = Object.freeze({
  leaf: ["Live TLS leaf certificate", "external_tls_validation"],
  chain: ["Presented certificate chain", "external_tls_validation"],
  san: ["Certificate hostnames (SAN)", "external_tls_validation"],
  issuer: ["Certificate issuer", "external_tls_validation"],
  expiry: ["Certificate validity end", "external_tls_validation"],
  wildcard: ["Wildcard certificate identifier", "external_tls_validation"],
  parallel_certificate_set: ["Simultaneous live certificate set", "external_tls_validation"],
  active_service: ["Active HTTPS service", "active_service_observation"],
  caa: ["CAA issuance policy", "issuance_policy"],
  hostname_match: ["Live hostname match", "external_tls_validation"],
  intermediate_validity: ["Presented intermediate validity", "external_tls_validation"],
  certificate_algorithm: ["Certificate algorithms", "external_tls_validation"],
  trust_store_validation: ["Declared trust-store validation", "external_tls_validation"],
  revocation_assurance: ["OCSP / revocation assurance", "revocation_assurance"],
});

const STATE_LABELS = Object.freeze({
  observed: "Observed",
  not_observed: "Not observed",
  unknown: "Unknown",
  unavailable: "Unavailable",
  incomplete: "Incomplete",
});

function asObject(value) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value
    : null;
}

function parseJson(value, fallback = null) {
  if (value && typeof value === "object") return value;
  try { return value ? JSON.parse(value) : fallback; } catch { return fallback; }
}

function signalState(signal, presentInModel) {
  if (!presentInModel) return "not_observed";
  const completeness = String(signal?.completeness_state || "evidence_incomplete");
  const observation = String(signal?.observation || "unknown");
  if (completeness === "signal_unavailable") return "unavailable";
  if (completeness === "evidence_incomplete") return "incomplete";
  if (observation === "unknown") return "unknown";
  if (observation === "present") return "observed";
  // A degraded negative cannot support absence. Keep a complete negative
  // distinct from missing evidence without presenting it as a pass/healthy.
  if (observation === "absent") {
    return completeness === "monitoring_healthy"
      ? "not_observed"
      : "incomplete";
  }
  return "unknown";
}

// Customer name for a declared trust store. The exact store identity (runtime
// bundle name, version and fingerprint) stays in the evidence; customers read
// which root store it is, not which runtime shipped it.
export function customerTrustStoreName(context) {
  if (!context?.name || !context?.version) return null;
  return /mozilla ca roots/i.test(String(context.name))
    ? "the Mozilla CA root store"
    : `${context.name} ${context.version}`;
}

function trustStoreName(value) {
  return customerTrustStoreName(asObject(value)?.trust_store_context);
}

// Name match, expiry and trust-store validation are separate checks on the
// captured leaf. Each reads as passed or failed only when that check ran on a
// certificate the live endpoint presented; otherwise it is "not checked", never a
// pass. The outcome is the backend's, so no screen derives a certificate verdict.
const CHECK_SIGNAL_KEYS = new Set(["hostname_match", "expiry", "trust_store_validation"]);
const NOT_CHECKED = Object.freeze({ outcome: "not_checked", label: "Not checked" });

function isoDay(ms) {
  return new Date(ms).toISOString().slice(0, 10);
}

function expiryTiming(signal) {
  const notAfter = Date.parse(typeof signal?.value === "string" ? signal.value : "");
  const observedAt = Date.parse(String(asObject(signal?.provenance)?.observed_at || ""));
  if (!Number.isFinite(notAfter) || !Number.isFinite(observedAt)) return null;
  return { notAfter, observedAt, expired: notAfter <= observedAt };
}

function checkOutcome(key, signal, state) {
  if (state !== "observed") return NOT_CHECKED;
  const value = asObject(signal?.value);
  if (key === "hostname_match") {
    const name = typeof value?.reference_hostname === "string" && value.reference_hostname.trim()
      ? value.reference_hostname.trim().slice(0, 253)
      : null;
    if (value?.result === "matched") return { outcome: "passed", label: name ? `Covers ${name}` : "Covers the checked name" };
    if (value?.result === "mismatched") return { outcome: "failed", label: name ? `Does not cover ${name}` : "Does not cover the checked name" };
    return NOT_CHECKED;
  }
  if (key === "trust_store_validation") {
    const store = customerTrustStoreName(asObject(value?.trust_store_context)) || "the recorded trust store";
    if (value?.validation_result === "valid") return { outcome: "passed", label: `Trusted by ${store}` };
    if (value?.validation_result === "invalid") return { outcome: "failed", label: `Not trusted by ${store}` };
    return NOT_CHECKED;
  }
  const timing = expiryTiming(signal);
  if (!timing) return NOT_CHECKED;
  if (timing.expired) return { outcome: "failed", label: `Expired on ${isoDay(timing.notAfter)}` };
  const days = Math.floor((timing.notAfter - timing.observedAt) / 86_400_000);
  return {
    outcome: "passed",
    label: `In date until ${isoDay(timing.notAfter)} (${days} day${days === 1 ? "" : "s"} left when checked)`,
  };
}

function observedMessage(key, signal) {
  const value = signal?.value;
  if (key === "leaf") {
    return "A leaf certificate was observed from a live TLS endpoint. This alone does not establish hostname match, chain validity, revocation status or trust-store acceptance.";
  }
  if (key === "active_service") {
    return "An HTTPS service response was observed. The HTTP response does not identify or validate the certificate presented during the TLS handshake.";
  }
  if (key === "chain") {
    const state = asObject(value)?.presentation_state;
    return state === "presented_complete"
      ? "The presented certificate chain was collected completely. Trust-store acceptance and revocation remain separate signals."
      : state === "presented_incomplete"
        ? "The live endpoint presented an incomplete certificate chain."
        : "Presented-chain evidence was observed; its structured state is retained below.";
  }
  if (key === "hostname_match") {
    return asObject(value)?.result === "mismatched"
      ? "The live-presented certificate identifiers did not match the protected hostname."
      : "The live-presented certificate identifiers matched the protected hostname. This is not an overall trust conclusion.";
  }
  if (key === "intermediate_validity") {
    return asObject(value)?.status === "expired"
      ? "At least one presented intermediate certificate was observed outside its validity period."
      : "No expired intermediate was observed in the completely collected presented chain.";
  }
  if (key === "certificate_algorithm") {
    return asObject(value)?.status === "weak"
      ? "A certificate algorithm or key-size weakness predicate was observed."
      : "No listed weak-algorithm predicate was observed in the collected certificate metadata; this is not blanket standards conformance.";
  }
  if (key === "trust_store_validation") {
    const context = trustStoreName(value);
    return asObject(value)?.validation_result === "invalid"
      ? `Certificate-path validation failed for the declared trust-store context${context ? ` (${context})` : ""}.`
      : `Certificate-path validation succeeded for the declared trust-store context${context ? ` (${context})` : ""}. This result does not establish universal client trust.`;
  }
  if (key === "revocation_assurance") {
    const status = asObject(value)?.status;
    if (status === "revoked") return "A validated OCSP response reported the checked certificate as revoked.";
    if (status === "good") return "A validated OCSP response reported good status for the checked certificate at the recorded time.";
    return "A validated OCSP response returned an unknown status for the checked certificate.";
  }
  if (key === "caa") {
    return "CAA DNS policy evidence was observed. CAA controls issuance authorization; it is not a live certificate trust result.";
  }
  if (key === "parallel_certificate_set") {
    return "Multiple non-identical certificates were observed simultaneously for the protected hostname across recorded live endpoint contexts. Multiplicity alone is not a fault or maliciousness conclusion.";
  }
  if (key === "expiry") {
    return expiryTiming(signal)?.expired === true
      ? "The certificate the live site presented had passed its validity end when it was checked."
      : "A certificate validity end was observed on the certificate the live site presented. An in-date certificate alone does not establish verified trust.";
  }
  return `${SIGNAL_META[key]?.[0] || key} evidence was observed in the declared scope.`;
}

function absentMessage(key) {
  if (key === "caa") {
    return "The completed CAA lookup did not observe a CAA record. This is an issuance-policy observation, not a live trust result.";
  }
  if (key === "wildcard") {
    return "No wildcard identifier was observed in the completely assessed certificate evidence scope.";
  }
  if (key === "parallel_certificate_set") {
    return "The complete simultaneous endpoint observation did not show multiple non-identical live certificates.";
  }
  if (key === "active_service") {
    return "The completed active-service probe did not observe an HTTPS service. This does not prove that no TLS service exists outside the checked context.";
  }
  return `${SIGNAL_META[key]?.[0] || key} was not observed in the completely assessed evidence scope.`;
}

function customerMessage(key, signal, state, presentInModel, absenceReason) {
  if (!presentInModel) {
    return absenceReason ||
      "This signal was not recorded in the historical snapshot. No current value is inferred.";
  }
  if (state === "unavailable") {
    return `${SIGNAL_META[key]?.[0] || key} evidence was unavailable. This is not an absent or favourable result.`;
  }
  if (state === "incomplete") {
    return `${SIGNAL_META[key]?.[0] || key} evidence was incomplete. No negative or favourable conclusion is inferred.`;
  }
  if (state === "unknown") {
    return `${SIGNAL_META[key]?.[0] || key} could not be determined from the recorded evidence.`;
  }
  if (state === "observed") return observedMessage(key, signal);
  return absentMessage(key);
}

function presentSignal(key, signal, {
  presentInModel,
  absenceReason = null,
} = {}) {
  const [label, family] = SIGNAL_META[key] || [key, null];
  const raw = asObject(signal);
  const state = signalState(raw, presentInModel);
  const gradeContract = asObject(raw?.grade_contract);
  const authorities = Array.isArray(raw?.authorities)
    ? raw.authorities.map((authority) => ({ ...authority }))
    : [];
  return {
    signal_key: key,
    label,
    assurance_family: raw?.assurance_family || family,
    state,
    state_label: STATE_LABELS[state],
    customer_message: customerMessage(
      key,
      raw,
      state,
      presentInModel,
      absenceReason,
    ),
    observation: raw?.observation || "unknown",
    completeness_state: raw?.completeness_state || "evidence_incomplete",
    observation_scope: raw?.observation_scope || "unobserved",
    value: raw?.value ?? null,
    publishable: raw?.publishable === true,
    evidence_grade: {
      achieved: raw?.achieved_grade || "L0",
      observable_ceiling: gradeContract?.observable_ceiling || null,
      beta_target: gradeContract?.beta_target || null,
      minimum_publishable: gradeContract?.minimum_publishable || null,
      degrade_behavior: gradeContract?.degrade_behavior || null,
    },
    source_type: raw?.source_type || null,
    provenance: raw?.provenance || null,
    required_corroboration: Array.isArray(gradeContract?.required_corroboration)
      ? [...gradeContract.required_corroboration]
      : [],
    corroboration_status: raw?.corroboration_status || "none",
    repeat_confirmed: raw?.repeat_confirmed === true,
    cited_authorities: authorities,
    reasons: Array.isArray(raw?.reasons) ? [...raw.reasons] : [],
    limitations: Array.isArray(raw?.limitations) ? [...raw.limitations] : [],
    ...(CHECK_SIGNAL_KEYS.has(key) ? { check: checkOutcome(key, raw, state) } : {}),
  };
}

function leafIdentity(signalCompleteness) {
  const value = signalCompleteness?.signals?.leaf?.value;
  if (typeof value === "string") return value || null;
  return value?.certificate_identity || value?.fingerprint_sha256 || null;
}

function parallelIdentities(signalCompleteness) {
  const signal = signalCompleteness?.signals?.parallel_certificate_set;
  if (
    signal?.observation !== "present" ||
    signal?.observation_scope !== "live_tls_endpoint_set"
  ) return [];
  return [...new Set(
    (signal?.value?.observations || [])
      .map((entry) => String(entry?.certificate_identity || "").trim())
      .filter(Boolean),
  )].sort();
}

export function buildCertificateRelationshipPresentation({
  lifecycle = null,
  currentSignalCompleteness = null,
  previousSignalCompleteness = null,
} = {}) {
  const replacementObserved = Boolean(
    lifecycle?.replacement_detected_at ||
    lifecycle?.relation === "replaced",
  );
  const parallel = parallelIdentities(currentSignalCompleteness);
  const parallelObserved = parallel.length > 1;
  const previousIdentity = leafIdentity(previousSignalCompleteness);
  const currentIdentity =
    leafIdentity(currentSignalCompleteness) ||
    lifecycle?.certificate_identity ||
    null;
  const samePair = Boolean(
    replacementObserved &&
    parallelObserved &&
    previousIdentity &&
    currentIdentity &&
    parallel.includes(previousIdentity) &&
    parallel.includes(currentIdentity),
  );

  if (replacementObserved && parallelObserved) {
    return {
      state: "observed",
      relationship: samePair
        ? "replacement_with_parallel_transition_context"
        : "replacement_with_separate_parallel_context",
      primary_context: "replacement_lifecycle",
      customer_message: samePair
        ? "A certificate replacement was observed over time, and the same certificate identities were also observed simultaneously across live endpoint contexts during the recorded window. This is one transition-context explanation, not two contradictory findings."
        : "A certificate replacement was observed over time. A separate simultaneous live endpoint certificate set was also observed, but the recorded identities do not establish that it is the same replacement pair.",
      replacement_observed: true,
      parallel_live_set_observed: true,
      same_certificate_pair: samePair,
      previous_certificate_identity: previousIdentity,
      current_certificate_identity: currentIdentity,
      parallel_certificate_identities: parallel,
      raw_evidence_preserved: true,
    };
  }
  if (replacementObserved) {
    return {
      state: "observed",
      relationship: "replacement_lifecycle",
      primary_context: "replacement_lifecycle",
      customer_message:
        "A distinct certificate replacement was observed over time. This temporal lifecycle result does not imply simultaneous serving.",
      replacement_observed: true,
      parallel_live_set_observed: false,
      same_certificate_pair: false,
      previous_certificate_identity: previousIdentity,
      current_certificate_identity: currentIdentity,
      parallel_certificate_identities: [],
      raw_evidence_preserved: true,
    };
  }
  if (parallelObserved) {
    return {
      state: "observed",
      relationship: "parallel_live_certificate_set",
      primary_context: "live_tls_endpoint_set",
      customer_message:
        "Multiple non-identical certificates were observed simultaneously across live endpoint contexts. This does not establish a renewal, replacement, fault or maliciousness.",
      replacement_observed: false,
      parallel_live_set_observed: true,
      same_certificate_pair: false,
      previous_certificate_identity: previousIdentity,
      current_certificate_identity: currentIdentity,
      parallel_certificate_identities: parallel,
      raw_evidence_preserved: true,
    };
  }
  return {
    state: "not_observed",
    relationship: "none_observed",
    primary_context: null,
    customer_message:
      "No replacement or simultaneous live certificate-set relationship was recorded in this evidence.",
    replacement_observed: false,
    parallel_live_set_observed: false,
    same_certificate_pair: false,
    previous_certificate_identity: previousIdentity,
    current_certificate_identity: currentIdentity,
    parallel_certificate_identities: [],
    raw_evidence_preserved: true,
  };
}

function summaryFor(signals) {
  const liveLeaf = signals.leaf;
  const trust = signals.trust_store_validation;
  const revocation = signals.revocation_assurance;
  return {
    live_tls_certificate: {
      state: liveLeaf.state,
      message: liveLeaf.customer_message,
    },
    trust_store_validation: {
      state: trust.state,
      message: trust.customer_message,
    },
    revocation_assurance: {
      state: revocation.state,
      message: revocation.customer_message,
    },
    trust_ceiling:
      "An unexpired certificate alone does not establish hostname correctness, complete chain validity, revocation status, declared trust-store acceptance, private-key security, internal keystore health or complete internal certificate inventory.",
  };
}

export function buildCertificateCustomerPresentation({
  signalCompleteness = null,
  lifecycle = null,
  previousSignalCompleteness = null,
  absenceReason = null,
} = {}) {
  const canonical = asObject(signalCompleteness);
  const signalsInput = asObject(canonical?.signals);
  const presentInModel = Boolean(signalsInput);
  const signals = {};
  for (const key of CERTIFICATE_SIGNAL_KEYS) {
    signals[key] = presentSignal(key, signalsInput?.[key], {
      presentInModel: presentInModel &&
        Object.prototype.hasOwnProperty.call(signalsInput, key),
      absenceReason,
    });
  }
  const status = presentInModel ? "current" : "not_recorded";
  return {
    schema: CERTIFICATE_CUSTOMER_PRESENTATION_SCHEMA,
    status,
    model_version: canonical?.model_version || null,
    signal_order: [...CERTIFICATE_SIGNAL_KEYS],
    signals,
    summary: summaryFor(signals),
    relationship: buildCertificateRelationshipPresentation({
      lifecycle,
      currentSignalCompleteness: canonical,
      previousSignalCompleteness,
    }),
    internal_key_assurance: {
      state: "not_observed",
      private_key_security: "unknown",
      internal_keystore_health: "unknown",
      complete_internal_certificate_inventory: "unknown",
      absence_of_key_compromise: "unknown",
      customer_message:
        "External TLS and DNS evidence does not assess private-key security, internal keystore health, complete internal inventory or absence of key compromise.",
    },
    historical_notice: presentInModel
      ? null
      : (absenceReason ||
        "Per-signal certificate assurance was not recorded in this historical snapshot. Missing fields are not interpreted as favourable results."),
    scope_note:
      "Certificate evidence is reported per signal and per observation scope. Active HTTPS, the live-presented certificate, hostname match, trust-store validation and revocation assurance are separate facts.",
  };
}

export function buildCertificateLifecycleAssurance(row) {
  const currentEvidence = parseJson(
    row?.current_observation_evidence_json ??
      row?.current_evidence_json ??
      row?.current_observation_evidence,
    {},
  ) || {};
  const previousEvidence = parseJson(
    row?.previous_observation_evidence_json ??
      row?.previous_evidence_json ??
      row?.previous_observation_evidence,
    {},
  ) || {};
  return buildCertificateCustomerPresentation({
    signalCompleteness: currentEvidence.signal_completeness || null,
    previousSignalCompleteness:
      previousEvidence.signal_completeness || null,
    lifecycle: row,
    absenceReason:
      "Per-signal evidence was not recorded for this lifecycle observation. No favourable state is inferred.",
  });
}

export function certificateAssuranceFromSnapshot(snapshot) {
  const recorded = snapshot?.certificate_assurance;
  if (
    RECORDED_PRESENTATION_SCHEMAS.has(recorded?.schema) &&
    recorded?.signals
  ) {
    return recorded;
  }
  const reason = recorded
    ? "This snapshot contains an unsupported certificate-assurance presentation schema. It is unavailable to this reader and is not interpreted."
    : "Per-signal certificate assurance was not recorded in this historical snapshot. Missing fields are not interpreted as favourable results.";
  return buildCertificateCustomerPresentation({ absenceReason: reason });
}

export function certificateAssuranceApiProjection(snapshot) {
  return {
    certificate_assurance: certificateAssuranceFromSnapshot(snapshot),
  };
}

// Drift guard for callers that need to confirm the projection was built from
// the current canonical P1-P4 model without re-deriving it.
export function certificatePresentationModelCompatible(presentation) {
  return presentation?.status !== "current" ||
    presentation?.model_version === CERTIFICATE_SIGNAL_COMPLETENESS_VERSION;
}
