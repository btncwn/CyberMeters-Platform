// ── Item 9 Certificates & Trust per-signal evidence contract ────────────────
//
// Pure model only (P1): no probes, persistence, scoring, alerts, cases, reports or
// production caller. The production integration is intentionally deferred to P2.
//
// Completeness reuses the ONE canonical monitoring-state vocabulary. Observation
// is a separate axis so unavailable/incomplete evidence can never collapse to
// "absent", and a degraded positive observation can remain visible without being
// presented as healthy.
import { SIGNAL_MONITORING_STATES } from "./signal-monitoring-state.js";

export const CERTIFICATE_SIGNAL_COMPLETENESS_VERSION =
  "certificate-signal-completeness-v1";
export const MAX_PARALLEL_OBSERVATION_WINDOW_MS = 9_000;

export const CERTIFICATE_SIGNAL_KEYS = Object.freeze([
  "leaf",
  "chain",
  "san",
  "issuer",
  "expiry",
  "certificate_transparency",
  "wildcard",
  "parallel_certificate_set",
  "active_service",
]);

export const CERTIFICATE_OBSERVATION_STATES = Object.freeze({
  PRESENT: "present",
  ABSENT: "absent",
  UNKNOWN: "unknown",
});

export const CERTIFICATE_OBSERVATION_SCOPES = Object.freeze([
  "live_tls",
  "live_tls_endpoint_set",
  "ct_issuance",
  "dns_policy",
  "historical_observation",
  "live_http_service",
  "unobserved",
]);

export const CERTIFICATE_CORROBORATION_STATUSES = Object.freeze([
  "none",
  "repeated",
  "independent-path",
  "independent-source",
  "controlled-ground-truth",
]);

const EVIDENCE_GRADES = Object.freeze(["L0", "L1", "L2", "L3", "L4", "L5"]);
const GRADE_RANK = Object.freeze(
  Object.fromEntries(EVIDENCE_GRADES.map((grade, rank) => [grade, rank]))
);
const SOURCE_TYPES = new Set([
  "normative_protocol",
  "configuration_baseline",
  "assurance_scheme",
  "management_framework",
  "customer_attestation",
  "product_policy",
]);
const COMPLETENESS_STATES = new Set(Object.values(SIGNAL_MONITORING_STATES));
const OBSERVATION_STATES = new Set(Object.values(CERTIFICATE_OBSERVATION_STATES));
const OBSERVATION_SCOPES = new Set(CERTIFICATE_OBSERVATION_SCOPES);
const CORROBORATION_STATUSES = new Set(CERTIFICATE_CORROBORATION_STATUSES);

function authority({
  standard_id,
  standard_version,
  section,
  requirement_type,
  source_type = "normative_protocol",
  interpretation,
  url,
  accessed_at = null,
}) {
  return Object.freeze({
    standard_id,
    standard_version,
    section,
    requirement_type,
    source_type,
    interpretation,
    url,
    accessed_at,
  });
}

const RFC_5280_LEAF = authority({
  standard_id: "RFC 5280",
  standard_version: "May 2008",
  section: "§4.1",
  requirement_type: "protocol_profile",
  interpretation: "Defines the X.509 certificate and TBSCertificate field profile.",
  url: "https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1",
});
const RFC_5280_CHAIN = authority({
  standard_id: "RFC 5280",
  standard_version: "May 2008",
  section: "§6",
  requirement_type: "protocol_profile",
  interpretation: "Defines certification-path validation.",
  url: "https://www.rfc-editor.org/rfc/rfc5280.html#section-6",
});
const RFC_5280_ISSUER = authority({
  standard_id: "RFC 5280",
  standard_version: "May 2008",
  section: "§4.1.2.4",
  requirement_type: "protocol_profile",
  interpretation: "Defines the certificate issuer field.",
  url: "https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.4",
});
const RFC_5280_VALIDITY = authority({
  standard_id: "RFC 5280",
  standard_version: "May 2008",
  section: "§4.1.2.5",
  requirement_type: "protocol_profile",
  interpretation: "Defines the certificate validity period.",
  url: "https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.5",
});
const RFC_5280_SAN = authority({
  standard_id: "RFC 5280",
  standard_version: "May 2008",
  section: "§4.2.1.6",
  requirement_type: "protocol_profile",
  interpretation:
    "Defines subjectAltName; it explicitly does not define wildcard matching semantics.",
  url: "https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.6",
});
const RFC_8446_CERTIFICATE = authority({
  standard_id: "RFC 8446",
  standard_version: "August 2018",
  section: "§4.4.2",
  requirement_type: "protocol_requirement",
  interpretation: "Defines certificate presentation in a TLS 1.3 handshake.",
  url: "https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.2",
});
const RFC_9525_IDENTITY = authority({
  standard_id: "RFC 9525",
  standard_version: "November 2023",
  section: "§6.3",
  requirement_type: "protocol_requirement",
  interpretation: "Defines DNS service-identity matching against presented identifiers.",
  url: "https://www.rfc-editor.org/rfc/rfc9525.html#section-6.3",
});
const RFC_9525_WILDCARD = authority({
  standard_id: "RFC 9525",
  standard_version: "November 2023",
  section: "§7.1",
  requirement_type: "protocol_requirement",
  interpretation:
    "Constrains wildcard identifiers; wildcard presence alone is not a trust verdict.",
  url: "https://www.rfc-editor.org/rfc/rfc9525.html#section-7.1",
});
const RFC_9162_CT = authority({
  standard_id: "RFC 9162",
  standard_version: "December 2021",
  section: "§§3–4",
  requirement_type: "protocol_definition",
  interpretation:
    "Defines CT certificate/precertificate logging; a log entry does not prove live service presentation.",
  url: "https://www.rfc-editor.org/rfc/rfc9162.html",
});
const RFC_6962_CT_LEGACY = authority({
  standard_id: "RFC 6962",
  standard_version: "June 2013",
  section: "§3.1",
  requirement_type: "obsolete_protocol_definition",
  interpretation:
    "Legacy CT v1 definition, obsoleted by RFC 9162; retained because provider data can include v1 log entries.",
  url: "https://www.rfc-editor.org/rfc/rfc6962.html#section-3.1",
});
const CABF_TLS_BR = authority({
  standard_id: "CA/Browser Forum TLS Baseline Requirements",
  standard_version: "2.2.8 (16 June 2026)",
  section: "certificate issuance and management requirements",
  requirement_type: "industry_baseline",
  source_type: "configuration_baseline",
  interpretation:
    "Applies to issuance and management of publicly trusted TLS server certificates; it is not a live-service verdict by itself.",
  url: "https://cabforum.org/working-groups/server/baseline-requirements/requirements/",
  accessed_at: "2026-07-26",
});
const PARALLEL_PRODUCT_POLICY = authority({
  standard_id: "CyberMeters Certificate Parallelism Policy",
  standard_version: "item9-p1",
  section: "simultaneous endpoint observation interpretation",
  requirement_type: "product_policy",
  source_type: "product_policy",
  interpretation:
    "Multiple simultaneous, non-identical certificate observations for one protected hostname are reported without inferring misconfiguration or maliciousness from multiplicity.",
  url: "docs/ITEM-9-CERTIFICATES-TRUST-DEPTH-DESIGN.md",
});
const ACTIVE_SERVICE_PRODUCT_POLICY = authority({
  standard_id: "CyberMeters Active Service Observation Policy",
  standard_version: "item9-p1",
  section: "live HTTP service observation",
  requirement_type: "product_policy",
  source_type: "product_policy",
  interpretation:
    "An HTTP response over TLS establishes a reachable service observation, not the identity or trust state of the served certificate.",
  url: "docs/ITEM-9-CERTIFICATES-TRUST-DEPTH-DESIGN.md",
});

function contract({
  observable_ceiling,
  beta_target,
  minimum_publishable,
  degrade_behavior,
  required_corroboration,
  source_type,
  observation_scope,
  authorities,
  limitations,
  assurance_family,
}) {
  return Object.freeze({
    observable_ceiling,
    beta_target,
    minimum_publishable,
    degrade_behavior,
    required_corroboration: Object.freeze([...required_corroboration]),
    source_type,
    observation_scope,
    authorities: Object.freeze([...authorities]),
    limitations: Object.freeze([...limitations]),
    assurance_family,
  });
}

export const CERTIFICATE_SIGNAL_CONTRACTS = Object.freeze({
  leaf: contract({
    observable_ceiling: "L5",
    beta_target: "L4",
    minimum_publishable: "L2",
    degrade_behavior: "show_unknown_never_substitute_ct",
    required_corroboration: ["independent-source"],
    source_type: "normative_protocol",
    observation_scope: "live_tls",
    authorities: [RFC_5280_LEAF, RFC_8446_CERTIFICATE, CABF_TLS_BR],
    limitations: [
      "A CT entry is issuance evidence and cannot identify the leaf certificate currently served.",
      "Leaf observation does not by itself prove chain validity, root trust, revocation status or private-key security.",
    ],
    assurance_family: "external_tls_validation",
  }),
  chain: contract({
    observable_ceiling: "L5",
    beta_target: "L4",
    minimum_publishable: "L3",
    degrade_behavior: "show_unknown_trust_path",
    required_corroboration: ["independent-path"],
    source_type: "normative_protocol",
    observation_scope: "live_tls",
    authorities: [RFC_5280_CHAIN, RFC_8446_CERTIFICATE, CABF_TLS_BR],
    limitations: [
      "An unexpired leaf certificate does not establish a complete or trusted certification path.",
      "Root trust depends on an explicit trust store and validation policy; it is never inferred from issuer text.",
    ],
    assurance_family: "external_tls_validation",
  }),
  san: contract({
    observable_ceiling: "L5",
    beta_target: "L4",
    minimum_publishable: "L2",
    degrade_behavior: "retain_scoped_positive_never_infer_absence",
    required_corroboration: ["independent-source"],
    source_type: "normative_protocol",
    observation_scope: "ct_issuance",
    authorities: [RFC_5280_SAN, RFC_9525_IDENTITY, CABF_TLS_BR],
    limitations: [
      "CT SANs describe a logged issuance unless separately observed on the live service.",
      "SAN presence alone does not establish hostname match, intended ownership or safe service configuration.",
    ],
    assurance_family: "external_tls_validation",
  }),
  issuer: contract({
    observable_ceiling: "L5",
    beta_target: "L4",
    minimum_publishable: "L2",
    degrade_behavior: "retain_scoped_positive_never_infer_trust",
    required_corroboration: ["independent-source"],
    source_type: "normative_protocol",
    observation_scope: "ct_issuance",
    authorities: [RFC_5280_ISSUER, CABF_TLS_BR],
    limitations: [
      "Issuer text is an observed certificate field, not proof of a valid path to a trusted root.",
      "A new issuer is a change signal and is not proof of compromise or malicious issuance.",
    ],
    assurance_family: "external_tls_validation",
  }),
  expiry: contract({
    observable_ceiling: "L5",
    beta_target: "L4",
    minimum_publishable: "L2",
    degrade_behavior: "retain_scoped_date_never_infer_live_deployment",
    required_corroboration: ["independent-source"],
    source_type: "normative_protocol",
    observation_scope: "ct_issuance",
    authorities: [RFC_5280_VALIDITY, CABF_TLS_BR],
    limitations: [
      "A CT notAfter value describes the logged certificate and does not prove that certificate is currently served.",
      "An in-date certificate does not establish chain validity, root trust, OCSP, revocation or private-key security.",
    ],
    assurance_family: "external_tls_validation",
  }),
  certificate_transparency: contract({
    observable_ceiling: "L5",
    beta_target: "L2",
    minimum_publishable: "L1",
    degrade_behavior: "show_provider_degraded_or_unavailable",
    required_corroboration: ["independent-path"],
    source_type: "normative_protocol",
    observation_scope: "ct_issuance",
    authorities: [RFC_9162_CT, RFC_6962_CT_LEGACY],
    limitations: [
      "CT records certificate or precertificate logging and does not prove live service presentation.",
      "crt.sh and CertSpotter are aggregation paths; disagreement is surfaced and never averaged into a healthy result.",
    ],
    assurance_family: "certificate_transparency",
  }),
  wildcard: contract({
    observable_ceiling: "L5",
    beta_target: "L4",
    minimum_publishable: "L2",
    degrade_behavior: "retain_scoped_positive_never_infer_live_use",
    required_corroboration: ["independent-source"],
    source_type: "normative_protocol",
    observation_scope: "ct_issuance",
    authorities: [RFC_5280_SAN, RFC_9525_WILDCARD, CABF_TLS_BR],
    limitations: [
      "RFC 5280 defines subjectAltName but does not define wildcard matching semantics.",
      "A wildcard in CT is issuance evidence and does not prove that the certificate is served or unsafe.",
    ],
    assurance_family: "external_tls_validation",
  }),
  parallel_certificate_set: contract({
    observable_ceiling: "L5",
    beta_target: "L3",
    minimum_publishable: "L2",
    degrade_behavior: "show_unknown_until_simultaneous_endpoint_set_is_complete",
    required_corroboration: ["independent-source"],
    source_type: "product_policy",
    observation_scope: "live_tls_endpoint_set",
    authorities: [RFC_5280_LEAF, RFC_8446_CERTIFICATE, PARALLEL_PRODUCT_POLICY],
    limitations: [
      "Historical observations and multiple CT issuances cannot establish simultaneous serving.",
      "Multiplicity alone is not a misconfiguration, attack, compromise or maliciousness verdict.",
    ],
    assurance_family: "external_tls_validation",
  }),
  active_service: contract({
    observable_ceiling: "L5",
    beta_target: "L3",
    minimum_publishable: "L1",
    degrade_behavior: "show_unknown_when_live_probe_did_not_execute",
    required_corroboration: ["repeated"],
    source_type: "product_policy",
    observation_scope: "live_http_service",
    authorities: [RFC_8446_CERTIFICATE, ACTIVE_SERVICE_PRODUCT_POLICY],
    limitations: [
      "An HTTP response over TLS does not identify or validate the certificate served in the handshake.",
      "A failed or unexecuted HTTP probe is not proof that no TLS service exists.",
    ],
    assurance_family: "active_service_observation",
  }),
});

function cleanString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function uniqueStrings(values) {
  return [...new Set(
    (Array.isArray(values) ? values : [values])
      .map((value) => cleanString(value))
      .filter(Boolean)
  )];
}

function normalizeCompletenessState(value) {
  return COMPLETENESS_STATES.has(value)
    ? value
    : SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE;
}

function normalizeObservation(value) {
  return OBSERVATION_STATES.has(value)
    ? value
    : CERTIFICATE_OBSERVATION_STATES.UNKNOWN;
}

function normalizeScope(value, fallback) {
  if (OBSERVATION_SCOPES.has(value)) return value;
  if (OBSERVATION_SCOPES.has(fallback)) return fallback;
  return "unobserved";
}

function normalizeCorroboration(value) {
  return CORROBORATION_STATUSES.has(value) ? value : "none";
}

function clampGrade(grade, ceiling) {
  const safe = Object.prototype.hasOwnProperty.call(GRADE_RANK, grade) ? grade : "L0";
  const cap = Object.prototype.hasOwnProperty.call(GRADE_RANK, ceiling) ? ceiling : "L0";
  return GRADE_RANK[safe] <= GRADE_RANK[cap] ? safe : cap;
}

function provenanceFor(input, {
  observedAt,
  engineVersion,
  observationScope,
}) {
  const raw = input?.provenance || {};
  return {
    source: cleanString(raw.source || input?.source) || null,
    method: cleanString(raw.method || input?.method) || null,
    observed_at: cleanString(raw.observed_at || input?.observed_at || observedAt) || null,
    engine_version:
      cleanString(raw.engine_version || input?.engine_version || engineVersion) || null,
    observation_scope: observationScope,
    time_anchor: cleanString(raw.time_anchor || input?.time_anchor) ||
      "application_timestamp",
    provider: cleanString(raw.provider || input?.provider) || null,
    evidence_ref: cleanString(raw.evidence_ref || input?.evidence_ref) || null,
  };
}

function provenanceComplete(provenance) {
  return Boolean(
    provenance?.source &&
    provenance?.method &&
    provenance?.observed_at &&
    provenance?.engine_version
  );
}

function hasDeclaredTrustStoreContext(value) {
  const context = value?.trust_store_context;
  return Boolean(
    context &&
    typeof context === "object" &&
    cleanString(context.name) &&
    cleanString(context.version)
  );
}

function chainClaimsTrustValidation(value) {
  const result = cleanString(value?.validation_result).toLowerCase();
  return result && result !== "not_performed" && result !== "unknown";
}

function validateParallelCertificateSet(value, completenessState) {
  if (!value || typeof value !== "object") {
    return "A parallel certificate set requires structured simultaneous endpoint evidence.";
  }

  const protectedHostname = cleanString(value.protected_hostname).toLowerCase();
  const observations = Array.isArray(value.observations) ? value.observations : [];
  if (!protectedHostname || observations.length < 2) {
    return "A parallel certificate set requires one protected hostname and at least two observations.";
  }

  const identities = new Set();
  for (const observation of observations) {
    const hostname = cleanString(observation?.protected_hostname).toLowerCase();
    const source = cleanString(observation?.source);
    const endpointContext = cleanString(observation?.endpoint_context);
    const certificateIdentity = cleanString(observation?.certificate_identity);
    const observedAt = cleanString(observation?.observed_at);
    const childCompleteness = observation?.completeness_state;
    if (
      hostname !== protectedHostname ||
      !source ||
      !endpointContext ||
      !certificateIdentity ||
      !observedAt ||
      !COMPLETENESS_STATES.has(childCompleteness)
    ) {
      return "Each simultaneous observation must carry the same protected hostname, source, endpoint/context, certificate identity, time and completeness.";
    }
    if (
      completenessState === SIGNAL_MONITORING_STATES.MONITORING_HEALTHY &&
      childCompleteness !== SIGNAL_MONITORING_STATES.MONITORING_HEALTHY
    ) {
      return "A complete parallel certificate set requires complete member observations.";
    }
    identities.add(certificateIdentity);
  }

  if (identities.size < 2) {
    return "Parallel certificate set members must contain at least two non-identical certificate identities.";
  }

  const windowStart = Date.parse(value?.observation_window?.started_at);
  const windowEnd = Date.parse(value?.observation_window?.ended_at);
  if (
    !Number.isFinite(windowStart) ||
    !Number.isFinite(windowEnd) ||
    windowEnd < windowStart ||
    windowEnd - windowStart > MAX_PARALLEL_OBSERVATION_WINDOW_MS
  ) {
    return "A parallel certificate set requires a valid observation window no longer than the 9-second SSL module cap.";
  }

  const allInsideWindow = observations.every((observation) => {
    const observedAt = Date.parse(observation.observed_at);
    return Number.isFinite(observedAt) && observedAt >= windowStart && observedAt <= windowEnd;
  });
  if (!allInsideWindow) {
    return "Every parallel certificate observation must fall within the declared simultaneous window.";
  }

  return null;
}

function resolveOneSignal(signal, rawInput, {
  observedAt,
  engineVersion,
}) {
  const contractDefinition = CERTIFICATE_SIGNAL_CONTRACTS[signal];
  const input = rawInput && typeof rawInput === "object" ? rawInput : {};
  let completenessState = normalizeCompletenessState(
    input.completeness_state ?? input.state
  );
  let observation = normalizeObservation(input.observation);
  let value = input.value ?? null;
  const observationScope = normalizeScope(
    input.observation_scope,
    contractDefinition.observation_scope
  );
  const provenance = provenanceFor(input, {
    observedAt,
    engineVersion,
    observationScope,
  });
  const reasons = uniqueStrings(input.reasons);

  // A negative conclusion requires complete evidence. Degraded evidence may retain
  // a positive observation from the available path, but it cannot establish absence.
  if (
    completenessState === SIGNAL_MONITORING_STATES.SIGNAL_UNAVAILABLE ||
    completenessState === SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE
  ) {
    observation = CERTIFICATE_OBSERVATION_STATES.UNKNOWN;
    value = null;
  } else if (
    completenessState === SIGNAL_MONITORING_STATES.MONITORING_DEGRADED &&
    observation !== CERTIFICATE_OBSERVATION_STATES.PRESENT
  ) {
    observation = CERTIFICATE_OBSERVATION_STATES.UNKNOWN;
    value = null;
    reasons.push("Degraded evidence cannot establish absence.");
  }

  // "Complete but unknown" and "present without a value" are contradictory. Missing
  // provenance is equally fail-closed: every customer-facing signal needs its source,
  // method, timestamp and engine version.
  if (
    (
      completenessState === SIGNAL_MONITORING_STATES.MONITORING_HEALTHY &&
      (
        observation === CERTIFICATE_OBSERVATION_STATES.UNKNOWN ||
        (observation === CERTIFICATE_OBSERVATION_STATES.PRESENT && value == null)
      )
    ) ||
    (
      observation !== CERTIFICATE_OBSERVATION_STATES.UNKNOWN &&
      !provenanceComplete(provenance)
    )
  ) {
    completenessState = SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE;
    observation = CERTIFICATE_OBSERVATION_STATES.UNKNOWN;
    value = null;
    reasons.push("A complete signal requires a decisive observation and full provenance.");
  }

  if (
    signal === "chain" &&
    observation === CERTIFICATE_OBSERVATION_STATES.PRESENT &&
    chainClaimsTrustValidation(value) &&
    !hasDeclaredTrustStoreContext(value)
  ) {
    completenessState = SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE;
    observation = CERTIFICATE_OBSERVATION_STATES.UNKNOWN;
    value = null;
    reasons.push(
      "A chain trust-validation result requires a declared trust-store name and version."
    );
  }

  if (
    signal === "parallel_certificate_set" &&
    observation === CERTIFICATE_OBSERVATION_STATES.PRESENT
  ) {
    const parallelError = validateParallelCertificateSet(value, completenessState);
    if (parallelError) {
      completenessState = SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE;
      observation = CERTIFICATE_OBSERVATION_STATES.UNKNOWN;
      value = null;
      reasons.push(parallelError);
    }
  }

  if (observation === CERTIFICATE_OBSERVATION_STATES.ABSENT) {
    value = false;
  }

  let achievedGrade = clampGrade(
    input.achieved_grade,
    contractDefinition.observable_ceiling
  );
  if (
    completenessState === SIGNAL_MONITORING_STATES.SIGNAL_UNAVAILABLE ||
    completenessState === SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE ||
    observation === CERTIFICATE_OBSERVATION_STATES.UNKNOWN
  ) {
    achievedGrade = "L0";
  }

  const sourceType = SOURCE_TYPES.has(input.source_type)
    ? input.source_type
    : contractDefinition.source_type;
  const corroborationStatus = normalizeCorroboration(input.corroboration_status);
  const publishable =
    observation !== CERTIFICATE_OBSERVATION_STATES.UNKNOWN &&
    completenessState !== SIGNAL_MONITORING_STATES.SIGNAL_UNAVAILABLE &&
    completenessState !== SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE &&
    GRADE_RANK[achievedGrade] >= GRADE_RANK[contractDefinition.minimum_publishable];

  const limitations = uniqueStrings([
    ...contractDefinition.limitations,
    ...(Array.isArray(input.limitations) ? input.limitations : []),
    ...(GRADE_RANK[achievedGrade] < GRADE_RANK[contractDefinition.beta_target]
      ? [`Delivered below the declared beta target ${contractDefinition.beta_target}; achieved ${achievedGrade}.`]
      : []),
  ]);

  return {
    signal,
    assurance_family: contractDefinition.assurance_family,
    completeness_state: completenessState,
    complete: completenessState === SIGNAL_MONITORING_STATES.MONITORING_HEALTHY,
    observation,
    value,
    observation_scope: observationScope,
    achieved_grade: achievedGrade,
    publishable,
    grade_contract: {
      observable_ceiling: contractDefinition.observable_ceiling,
      beta_target: contractDefinition.beta_target,
      minimum_publishable: contractDefinition.minimum_publishable,
      degrade_behavior: contractDefinition.degrade_behavior,
      required_corroboration: [...contractDefinition.required_corroboration],
    },
    source_type: sourceType,
    corroboration_status: corroborationStatus,
    repeat_confirmed: input.repeat_confirmed === true,
    provenance,
    authorities: contractDefinition.authorities.map((entry) => ({ ...entry })),
    reasons: uniqueStrings(reasons),
    limitations,
  };
}

export function deriveCertificateSignalCompleteness({
  evidenceBySignal = {},
  observedAt = null,
  engineVersion = null,
} = {}) {
  const signals = {};
  for (const signal of CERTIFICATE_SIGNAL_KEYS) {
    signals[signal] = resolveOneSignal(signal, evidenceBySignal?.[signal], {
      observedAt,
      engineVersion,
    });
  }

  const entries = Object.values(signals);
  const matching = (state) =>
    entries.filter((entry) => entry.completeness_state === state).map((entry) => entry.signal);

  return {
    model_version: CERTIFICATE_SIGNAL_COMPLETENESS_VERSION,
    signals,
    assurance_families: {
      external_tls_validation: {
        model_supported: true,
        signal_keys: CERTIFICATE_SIGNAL_KEYS.filter(
          (signal) =>
            CERTIFICATE_SIGNAL_CONTRACTS[signal].assurance_family ===
            "external_tls_validation"
        ),
        limitation:
          "External TLS evidence is scoped to the presented certificate/service context and does not establish internal key assurance.",
      },
      internal_key_assurance: {
        supported: false,
        completeness_state: SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE,
        private_key_security: CERTIFICATE_OBSERVATION_STATES.UNKNOWN,
        internal_keystore_health: CERTIFICATE_OBSERVATION_STATES.UNKNOWN,
        internal_certificate_inventory: CERTIFICATE_OBSERVATION_STATES.UNKNOWN,
        absence_of_key_compromise: CERTIFICATE_OBSERVATION_STATES.UNKNOWN,
        limitation:
          "External handshakes, CT records and expiry data cannot establish internal private-key, keystore or inventory assurance.",
      },
      revocation_assurance: {
        supported: false,
        completeness_state: SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE,
        stapled_ocsp: CERTIFICATE_OBSERVATION_STATES.UNKNOWN,
        revocation_status: CERTIFICATE_OBSERVATION_STATES.UNKNOWN,
        limitation:
          "Missing OCSP or revocation evidence affects this family only and never erases independently reliable certificate signals.",
      },
    },
    summary: {
      complete_signals: matching(SIGNAL_MONITORING_STATES.MONITORING_HEALTHY),
      degraded_signals: matching(SIGNAL_MONITORING_STATES.MONITORING_DEGRADED),
      unavailable_signals: matching(SIGNAL_MONITORING_STATES.SIGNAL_UNAVAILABLE),
      incomplete_signals: matching(SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE),
      publishable_signals: entries.filter((entry) => entry.publishable).map((entry) => entry.signal),
      live_leaf_observed:
        signals.leaf.observation_scope === "live_tls" &&
        signals.leaf.observation === CERTIFICATE_OBSERVATION_STATES.PRESENT,
      live_chain_assessed:
        signals.chain.observation_scope === "live_tls" &&
        signals.chain.observation !== CERTIFICATE_OBSERVATION_STATES.UNKNOWN,
    },
  };
}

function providerStateFromHealth(providerHealth = {}) {
  const outcomes = ["crt_sh", "certspotter"].map(
    (provider) => providerHealth?.[provider]?.outcome ?? null
  );
  const available = outcomes.filter((value) => value === "available").length;
  const unavailable = outcomes.filter((value) => value === "unavailable").length;
  if (available === 2) return SIGNAL_MONITORING_STATES.MONITORING_HEALTHY;
  if (available > 0 && unavailable > 0) return SIGNAL_MONITORING_STATES.MONITORING_DEGRADED;
  if (available === 0 && unavailable > 0) return SIGNAL_MONITORING_STATES.SIGNAL_UNAVAILABLE;
  return SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE;
}

function providerStateFromModules(modules = {}) {
  const subSources = modules?.subdomains?.sources || {};
  const sslSources = modules?.ssl?.ct_sources || {};
  const statuses = ["crt_sh", "certspotter"].map((provider) => {
    const row = subSources?.[provider] ?? sslSources?.[provider] ?? null;
    if (!row) return null;
    return cleanString(row.error) ? "unavailable" : "available";
  });
  const available = statuses.filter((value) => value === "available").length;
  const unavailable = statuses.filter((value) => value === "unavailable").length;
  if (available === 2) return SIGNAL_MONITORING_STATES.MONITORING_HEALTHY;
  if (available > 0 && unavailable > 0) return SIGNAL_MONITORING_STATES.MONITORING_DEGRADED;
  if (available === 0 && unavailable > 0) return SIGNAL_MONITORING_STATES.SIGNAL_UNAVAILABLE;
  return SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE;
}

function currentCtState({ monitoringStates, providerHealth, modules }) {
  const canonical = monitoringStates?.signals?.certificate_transparency?.state;
  if (COMPLETENESS_STATES.has(canonical)) return canonical;
  const health = providerStateFromHealth(providerHealth);
  if (health !== SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE) return health;
  return providerStateFromModules(modules);
}

function evidence({
  completeness_state,
  observation,
  value = null,
  observation_scope,
  achieved_grade,
  source_type,
  source,
  method,
  corroboration_status = "none",
  reasons = [],
  limitations = [],
  provider = null,
}) {
  return {
    completeness_state,
    observation,
    value,
    observation_scope,
    achieved_grade,
    source_type,
    source,
    method,
    corroboration_status,
    reasons,
    limitations,
    provider,
  };
}

// Pure compatibility adapter for deterministic tests and the later P2 caller.
// Current production modules contain CT issuance fields and HTTP reachability, but
// no live TLS leaf/chain capture. The adapter therefore refuses to manufacture live
// evidence from those CT fields.
export function deriveCertificateSignalCompletenessFromModules({
  modules = {},
  monitoringStates = null,
  providerHealth = null,
  observedAt = null,
  engineVersion = null,
} = {}) {
  const ssl = modules?.ssl || {};
  const ctState = currentCtState({ monitoringStates, providerHealth, modules });
  const selectedCtCertificate = Boolean(
    cleanString(ssl.cert_not_after) ||
    cleanString(ssl.cert_issuer) ||
    cleanString(ssl.cert_subject)
  );
  const ctPositiveState = selectedCtCertificate
    ? ctState
    : SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE;
  const ctSource = "shared_ct_provider_cache";
  const ctMethod = "logged_issuance_projection";
  const evidenceBySignal = {
    leaf: evidence({
      completeness_state: SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE,
      observation: CERTIFICATE_OBSERVATION_STATES.UNKNOWN,
      observation_scope: "live_tls",
      achieved_grade: "L0",
      source_type: "normative_protocol",
      source: "not_collected",
      method: "live_tls_leaf_not_implemented",
      reasons: ["The current scan modules did not capture the leaf certificate served in a TLS handshake."],
    }),
    chain: evidence({
      completeness_state: SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE,
      observation: CERTIFICATE_OBSERVATION_STATES.UNKNOWN,
      observation_scope: "live_tls",
      achieved_grade: "L0",
      source_type: "normative_protocol",
      source: "not_collected",
      method: "live_tls_chain_not_implemented",
      reasons: ["The current scan modules did not capture or validate a live certification path."],
    }),
    san: evidence({
      completeness_state: Array.isArray(ssl.cert_san_names)
        ? ctPositiveState
        : SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE,
      observation: Array.isArray(ssl.cert_san_names) && selectedCtCertificate
        ? CERTIFICATE_OBSERVATION_STATES.PRESENT
        : CERTIFICATE_OBSERVATION_STATES.UNKNOWN,
      value: Array.isArray(ssl.cert_san_names) ? [...ssl.cert_san_names] : null,
      observation_scope: "ct_issuance",
      achieved_grade: "L1",
      source_type: "normative_protocol",
      source: ctSource,
      method: `${ctMethod}_san`,
    }),
    issuer: evidence({
      completeness_state: cleanString(ssl.cert_issuer)
        ? ctPositiveState
        : SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE,
      observation: cleanString(ssl.cert_issuer)
        ? CERTIFICATE_OBSERVATION_STATES.PRESENT
        : CERTIFICATE_OBSERVATION_STATES.UNKNOWN,
      value: cleanString(ssl.cert_issuer) || null,
      observation_scope: "ct_issuance",
      achieved_grade: "L1",
      source_type: "normative_protocol",
      source: ctSource,
      method: `${ctMethod}_issuer`,
    }),
    expiry: evidence({
      completeness_state: cleanString(ssl.cert_not_after)
        ? ctPositiveState
        : SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE,
      observation: cleanString(ssl.cert_not_after)
        ? CERTIFICATE_OBSERVATION_STATES.PRESENT
        : CERTIFICATE_OBSERVATION_STATES.UNKNOWN,
      value: cleanString(ssl.cert_not_after) || null,
      observation_scope: "ct_issuance",
      achieved_grade: "L1",
      source_type: "normative_protocol",
      source: ctSource,
      method: `${ctMethod}_validity`,
    }),
    certificate_transparency: evidence({
      completeness_state: ctState,
      observation: ctState === SIGNAL_MONITORING_STATES.SIGNAL_UNAVAILABLE ||
        ctState === SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE
        ? CERTIFICATE_OBSERVATION_STATES.UNKNOWN
        : CERTIFICATE_OBSERVATION_STATES.PRESENT,
      value: {
        crt_sh: providerHealth?.crt_sh?.outcome ??
          (cleanString(modules?.subdomains?.sources?.crt_sh?.error) ? "unavailable" : "available"),
        certspotter: providerHealth?.certspotter?.outcome ??
          (cleanString(modules?.subdomains?.sources?.certspotter?.error) ? "unavailable" : "available"),
      },
      observation_scope: "ct_issuance",
      achieved_grade: "L1",
      source_type: "normative_protocol",
      source: ctSource,
      method: "shared_provider_query",
      corroboration_status:
        ctState === SIGNAL_MONITORING_STATES.MONITORING_HEALTHY
          ? "independent-path"
          : "none",
    }),
    wildcard: evidence({
      completeness_state:
        Number.isFinite(ssl.cert_wildcard_san_count) &&
        ssl.cert_wildcard_san_count > 0
        ? ctPositiveState
        : SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE,
      observation:
        Number.isFinite(ssl.cert_wildcard_san_count) &&
        ssl.cert_wildcard_san_count > 0 &&
        selectedCtCertificate
        ? CERTIFICATE_OBSERVATION_STATES.PRESENT
        : CERTIFICATE_OBSERVATION_STATES.UNKNOWN,
      value:
        Number.isFinite(ssl.cert_wildcard_san_count) &&
        ssl.cert_wildcard_san_count > 0
        ? true
        : null,
      observation_scope: "ct_issuance",
      achieved_grade: "L1",
      source_type: "normative_protocol",
      source: ctSource,
      method: `${ctMethod}_wildcard_san`,
    }),
    parallel_certificate_set: evidence({
      completeness_state: SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE,
      observation: CERTIFICATE_OBSERVATION_STATES.UNKNOWN,
      value: null,
      observation_scope: "live_tls_endpoint_set",
      achieved_grade: "L0",
      source_type: "product_policy",
      source: "not_collected",
      method: "simultaneous_endpoint_certificate_set_not_implemented",
      reasons: [
        "Current modules do not contain simultaneous endpoint/context observations for multiple non-identical certificates.",
      ],
      limitations: [
        "CT issuance multiplicity and historical observations cannot complete this signal.",
      ],
    }),
    active_service: evidence({
      completeness_state:
        ssl.https_probe_executed === true && typeof ssl.https_available === "boolean"
          ? SIGNAL_MONITORING_STATES.MONITORING_HEALTHY
          : SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE,
      observation:
        ssl.https_probe_executed === true && typeof ssl.https_available === "boolean"
          ? (ssl.https_available
            ? CERTIFICATE_OBSERVATION_STATES.PRESENT
            : CERTIFICATE_OBSERVATION_STATES.ABSENT)
          : CERTIFICATE_OBSERVATION_STATES.UNKNOWN,
      value:
        ssl.https_probe_executed === true && typeof ssl.https_available === "boolean"
          ? ssl.https_available
          : null,
      observation_scope: "live_http_service",
      achieved_grade: "L1",
      source_type: "product_policy",
      source: "ssl_https_head_probe",
      method: "http_response_over_tls",
    }),
  };

  return deriveCertificateSignalCompleteness({
    evidenceBySignal,
    observedAt,
    engineVersion,
  });
}
