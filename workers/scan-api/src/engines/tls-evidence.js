import { mayGroundRedirectAbsence } from "../lib/serviceability.js";

// ── Canonical active-TLS evidence state ─────────────────────────────────────
//
// A Workers fetch can prove that TLS transport was present when an origin
// answered. It cannot prove TLS absence from a timeout, refusal, exception,
// Cloudflare edge response, missing probe, incomplete execution or a bare
// historical boolean. Every runtime and customer-read consumer must resolve
// those inputs here instead of interpreting https_available independently.

export const TLS_RUNTIME_STATES = Object.freeze({
  OBSERVED_PRESENT: "observed_present",
  POSITIVELY_ABSENT: "positively_absent",
  UNAVAILABLE: "unavailable",
});

export const TLS_POSITIVE_ABSENCE_SOURCE_TYPE = "approved_active_tls_collector";
export const TLS_POSITIVE_ABSENCE_GRADE = "positive_absence";

// Positive-absence evidence may not be older than this relative to the carrier's
// own reference observation. The bound's existence is contractual; its exact
// value is a founder-acceptance item recorded for the (currently inert) future
// collector path.
export const TLS_POSITIVE_ABSENCE_MAX_AGE_MS = 15 * 60 * 1000;

export const TLS_INSTALL_TITLES = new Set([
  "Enable HTTPS with a valid certificate",
  "Install a TLS Certificate",
]);

const nonEmpty = (value) => typeof value === "string" && value.trim().length > 0;
// Exact canonical UTC round trip: merely parseable forms (offset, missing
// milliseconds, lowercase, hour 24) are NOT canonical and fail closed.
const validObservedAt = (value) => {
  if (!nonEmpty(value)) return false;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return false;
  try {
    return new Date(parsed).toISOString() === value;
  } catch {
    return false;
  }
};

function activeServiceEvidence(ssl) {
  return ssl?.certificate_evidence?.active_service ?? null;
}

/**
 * The future positive-absence contract is intentionally strict and inert:
 * no current producer emits it. A future collector must carry all of this
 * source-bound evidence before any existing actionable path can be enabled.
 */
export function isApprovedPositiveTlsAbsenceEvidence(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (value.state !== TLS_RUNTIME_STATES.POSITIVELY_ABSENT) return false;
  if (value.execution !== "completed") return false;
  if (value.source_type !== TLS_POSITIVE_ABSENCE_SOURCE_TYPE) return false;
  if (value.evidence_grade !== TLS_POSITIVE_ABSENCE_GRADE) return false;
  if (!nonEmpty(value.collector) || !nonEmpty(value.collector_version)) return false;
  if (!nonEmpty(value.endpoint) || !validObservedAt(value.observed_at)) return false;
  if (!nonEmpty(value.absence_outcome)) return false;
  // The evidence must name the domain it asserts absence FOR, and the probed
  // endpoint must be that exact host. HTTPS syntax alone is not target identity.
  if (!nonEmpty(value.assessed_domain)) return false;
  try {
    const endpoint = new URL(value.endpoint);
    if (endpoint.protocol !== "https:") return false;
    if (endpoint.hostname !== value.assessed_domain) return false;
  } catch {
    return false;
  }
  return true;
}

/**
 * Any contradictory state anywhere on the trusted probe carrier disqualifies
 * positive absence: a failed, unexecuted, deadline-hit or incomplete probe can
 * never prove that TLS is absent, no matter how well-formed its envelope is.
 */
function contradictedCarrier(ssl) {
  if (!ssl || typeof ssl !== "object") return true;
  if (ssl.executed === false) return true;
  if (ssl.outcome === "deadline_exceeded") return true;
  if (ssl.error) return true;
  if (ssl.incomplete === true) return true;
  if (nonEmpty(ssl.incomplete_reason)) return true;
  return false;
}

/**
 * Positive absence must be timely relative to the carrier's own reference
 * observation. A missing or non-canonical reference fails closed: evidence
 * that cannot be located in time cannot prove absence.
 */
function timelyPositiveAbsence(ssl, absence) {
  const reference = ssl?.certificate_evidence?.observed_at;
  if (!validObservedAt(reference)) return false;
  const observed = Date.parse(absence.observed_at);
  const anchor = Date.parse(reference);
  if (observed > anchor) return false;
  if (anchor - observed > TLS_POSITIVE_ABSENCE_MAX_AGE_MS) return false;
  return true;
}

/**
 * The envelope's assessed_domain must match the carrier's recorded probe
 * domain where the carrier exposes one, and the caller-supplied assessed
 * domain where the call site has it in scope. Mismatch resolves unavailable.
 */
function boundToAssessedDomain(ssl, absence, context) {
  const carrierDomain = ssl?.assessed_domain ?? ssl?.domain ?? null;
  if (carrierDomain != null && carrierDomain !== absence.assessed_domain) return false;
  const contextDomain = context?.assessedDomain ?? null;
  if (contextDomain != null && contextDomain !== absence.assessed_domain) return false;
  return true;
}

function positiveAbsenceEvidence(ssl) {
  return ssl?.tls_positive_absence_evidence
    ?? activeServiceEvidence(ssl)?.positive_absence_evidence
    ?? null;
}

function presentObservation(ssl) {
  const active = activeServiceEvidence(ssl);
  const state = ssl?.https_observation_state ?? active?.observation_state ?? null;
  const status = ssl?.https_origin_status ?? active?.origin_status ?? null;
  if (ssl?.https_available !== true || ssl?.executed === false || ssl?.error) return false;
  if (state == null) {
    // Backward-compatible positive carrier. The historical producer emitted true
    // only after a successful HTTPS Response; unlike legacy false, this is direct
    // positive evidence and does not infer absence from a failed request.
    return ssl?.https_probe_executed !== false;
  }
  return ssl?.https_probe_executed === true
    && state === "origin_response"
    && Number.isInteger(status)
    && status >= 100
    && status <= 599;
}

function unavailableReason(ssl) {
  if (!ssl || typeof ssl !== "object") return "tls_module_missing";
  if (ssl.executed === false || ssl.outcome === "deadline_exceeded") return "tls_probe_not_executed";
  if (ssl.error) return "tls_probe_error";
  if (ssl.tls_state === TLS_RUNTIME_STATES.POSITIVELY_ABSENT) {
    return "positive_absence_provenance_invalid";
  }
  if (ssl.https_available === false) return "legacy_or_unproven_false";
  return ssl.https_observation_reason
    ?? activeServiceEvidence(ssl)?.observation_reason
    ?? ssl.incomplete_reason
    ?? "tls_evidence_unavailable";
}

/**
 * Resolve exactly one of observed_present | positively_absent | unavailable.
 * Returned evidence is a reference to the input's frozen/read-only provenance;
 * callers must not mutate it.
 */
export function resolveTlsRuntimeState(ssl, context = {}) {
  const absence = positiveAbsenceEvidence(ssl);
  if (ssl?.tls_state === TLS_RUNTIME_STATES.POSITIVELY_ABSENT
      && ssl?.https_available === false
      && !contradictedCarrier(ssl)
      && isApprovedPositiveTlsAbsenceEvidence(absence)
      && timelyPositiveAbsence(ssl, absence)
      && boundToAssessedDomain(ssl, absence, context)) {
    return {
      state: TLS_RUNTIME_STATES.POSITIVELY_ABSENT,
      reason: "approved_active_tls_positive_absence",
      actionable: true,
      evidence: absence,
      confidence: 90,
    };
  }

  if ((ssl?.tls_state == null || ssl?.tls_state === TLS_RUNTIME_STATES.OBSERVED_PRESENT)
      && presentObservation(ssl)) {
    return {
      state: TLS_RUNTIME_STATES.OBSERVED_PRESENT,
      reason: "origin_response_over_tls",
      actionable: true,
      evidence: {
        source_type: "cloudflare_workers_fetch",
        endpoint: activeServiceEvidence(ssl)?.endpoint_context ?? null,
        observed_at: ssl?.certificate_evidence?.observed_at ?? null,
        origin_status: ssl?.https_origin_status ?? activeServiceEvidence(ssl)?.origin_status ?? null,
      },
      confidence: null,
    };
  }

  return {
    state: TLS_RUNTIME_STATES.UNAVAILABLE,
    reason: unavailableReason(ssl),
    actionable: false,
    evidence: null,
    confidence: null,
  };
}

export function isTlsPositivelyAbsent(ssl, context = {}) {
  return resolveTlsRuntimeState(ssl, context).state === TLS_RUNTIME_STATES.POSITIVELY_ABSENT;
}

export function isTlsObservedPresent(ssl, context = {}) {
  return resolveTlsRuntimeState(ssl, context).state === TLS_RUNTIME_STATES.OBSERVED_PRESENT;
}

export function isHttpRedirectPositivelyAbsent(ssl) {
  const chain = ssl?.http_redirect_chain;
  return ssl?.http_redirects_to_https === false
    && chain?.http_redirect_validated === true
    && mayGroundRedirectAbsence(chain);
}

export function findingHasApprovedTlsAbsence(finding) {
  return isApprovedPositiveTlsAbsenceEvidence(
    finding?.evidence?.tls_positive_absence_evidence,
  );
}

export function projectTlsFindingsForCustomer(findings, modules = {}) {
  const values = Array.isArray(findings) ? findings : [];
  if (isTlsPositivelyAbsent(modules?.ssl)) return [...values];
  return values.filter((finding) =>
    String(finding?.id ?? finding?.finding_id ?? finding?.finding_type ?? "") !== "ssl_not_available"
  );
}

export function projectTlsRecommendationsForCustomer(recommendations, modules = {}) {
  const values = Array.isArray(recommendations) ? recommendations : [];
  if (isTlsPositivelyAbsent(modules?.ssl)) return [...values];
  return values.filter((recommendation) => !(
    recommendation?.remediation_id === "cert.tls.install"
    || TLS_INSTALL_TITLES.has(recommendation?.title)
  ));
}

function unknownOwnership(ownership) {
  return {
    ...(ownership && typeof ownership === "object" ? ownership : {}),
    status: "unknown",
    assessment_state: "not_assessed",
    assessment_reason: "active_tls_unavailable",
    confidence: null,
    customer_owned: null,
    shared_san_count: null,
    evidence_signals: [],
  };
}

function projectedCertificateRisk(signals, certificateIntelligence) {
  if (signals.some((signal) => signal?.severity === "critical")) return "critical";
  if (signals.some((signal) => signal?.severity === "high")) return "high";
  if (signals.some((signal) => signal?.severity === "medium")) return "medium";
  const hasCertificateDetail = certificateIntelligence?.issuer != null
    || certificateIntelligence?.expires_at != null
    || certificateIntelligence?.days_until_expiry != null;
  return hasCertificateDetail ? "low" : "unknown";
}

/** Add the canonical state to module projections without mutating stored R2. */
export function projectTlsModulesForCustomer(modules = {}) {
  const ssl = modules?.ssl && typeof modules.ssl === "object" ? modules.ssl : {};
  const resolved = resolveTlsRuntimeState(ssl);
  const active = activeServiceEvidence(ssl);
  const projectedSsl = {
    ...ssl,
    tls_state: resolved.state,
    tls_state_reason: resolved.reason,
    https_available:
      resolved.state === TLS_RUNTIME_STATES.OBSERVED_PRESENT
        ? true
        : resolved.state === TLS_RUNTIME_STATES.POSITIVELY_ABSENT
          ? false
          : null,
    ...(resolved.state === TLS_RUNTIME_STATES.UNAVAILABLE
      ? {
          incomplete: true,
          incomplete_reason: "active_tls_evidence_unavailable",
        }
      : {}),
    ...(ssl.certificate_evidence && typeof ssl.certificate_evidence === "object"
      ? {
          certificate_evidence: {
            ...ssl.certificate_evidence,
            active_service: {
              ...(active ?? {}),
              tls_state: resolved.state,
              tls_state_reason: resolved.reason,
              https_available:
                resolved.state === TLS_RUNTIME_STATES.OBSERVED_PRESENT
                  ? true
                  : resolved.state === TLS_RUNTIME_STATES.POSITIVELY_ABSENT
                    ? false
                    : null,
            },
          },
        }
      : {}),
  };

  const projected = { ...modules, ssl: projectedSsl };
  const ci = modules?.certificate_intelligence;
  if (resolved.state === TLS_RUNTIME_STATES.UNAVAILABLE && ci && typeof ci === "object") {
    const signals = (Array.isArray(ci.suspicious_certificate_signals)
      ? ci.suspicious_certificate_signals
      : []).filter((signal) => signal?.signal !== "no_https");
    const completeness = ci.signal_completeness;
    projected.certificate_intelligence = {
      ...ci,
      certificate_status: "unknown",
      ownership: unknownOwnership(ci.ownership),
      shared_san_count: null,
      suspicious_certificate_signals: signals,
      certificate_risk_level: projectedCertificateRisk(signals, ci),
      ...(completeness && typeof completeness === "object"
        ? {
            signal_completeness: {
              ...completeness,
              signals: {
                ...(completeness.signals ?? {}),
                active_service: {
                  ...(completeness.signals?.active_service ?? {}),
                  completeness_state: "evidence_incomplete",
                  observation: "unknown",
                  value: null,
                },
              },
            },
          }
        : {}),
    };
  }
  return projected;
}

function projectSnapshotDomain(domain, keptFindings, removedTlsFinding) {
  if (!removedTlsFinding || domain?.domain_key !== "website_security") return domain;
  const remaining = keptFindings.filter((finding) =>
    Array.isArray(finding?.domain_keys) && finding.domain_keys.includes("website_security")
  );
  if (remaining.length > 0) {
    const rank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const highest = remaining
      .map((finding) => String(finding?.severity || "").toLowerCase())
      .sort((a, b) => (rank[b] ?? 0) - (rank[a] ?? 0))[0] ?? null;
    return {
      ...domain,
      finding_count: remaining.length,
      finding_ids: remaining.map((finding) => finding.finding_id).filter(Boolean).sort(),
      highest_severity: highest,
    };
  }
  return {
    ...domain,
    state: "evidence_insufficient",
    coverage: "degraded",
    summary: "HTTPS/TLS availability could not be established from the recorded evidence.",
    state_reason: "HTTPS/TLS availability could not be established from the recorded evidence.",
    finding_count: 0,
    finding_ids: [],
    highest_severity: null,
    recommendation_count: 0,
  };
}

/** Read-time customer view; immutable snapshot bytes/checksum remain untouched. */
export function projectTlsSnapshotForCustomer(snapshot, modules = {}) {
  if (!snapshot || typeof snapshot !== "object" || isTlsPositivelyAbsent(modules?.ssl)) return snapshot;
  const sourceFindings = Array.isArray(snapshot.observed_findings) ? snapshot.observed_findings : [];
  const keptFindings = sourceFindings.filter((finding) => finding?.finding_id !== "ssl_not_available");
  const removedTlsFinding = keptFindings.length !== sourceFindings.length;
  if (!removedTlsFinding) return snapshot;
  const keptIds = new Set(keptFindings.map((finding) => finding?.finding_id).filter(Boolean));
  const actions = (Array.isArray(snapshot.remediation_actions) ? snapshot.remediation_actions : [])
    .map((action) => {
      const findingIds = (Array.isArray(action?.finding_ids) ? action.finding_ids : [])
        .filter((id) => id !== "ssl_not_available" && keptIds.has(id));
      return { ...action, finding_ids: findingIds };
    })
    .filter((action) => !(action.remediation_id === "cert.tls.install" && action.finding_ids.length === 0));
  const overall = snapshot.overall ?? {};
  const bri = overall.business_risk_indicator ?? {};
  return {
    ...snapshot,
    domains: (Array.isArray(snapshot.domains) ? snapshot.domains : [])
      .map((domain) => projectSnapshotDomain(domain, keptFindings, removedTlsFinding)),
    observed_findings: keptFindings,
    remediation_actions: actions,
    overall: {
      ...overall,
      cyber_metrics_score: null,
      score_band: null,
      summary: null,
      assessment: {
        ...(overall.assessment ?? {}),
        status: "evidence_insufficient",
        quality: "partial",
        message: "Historical HTTPS/TLS absence was not supported by approved positive-absence evidence.",
      },
      business_risk_indicator: {
        ...bri,
        band: null,
        explanation: null,
        provisional: true,
        internal_metrics: { ...(bri.internal_metrics ?? {}), score: null },
      },
      evidence_completeness: {
        ...(overall.evidence_completeness ?? {}),
        scan_quality: "partial",
        assessment_quality: "partial",
        tls_state: TLS_RUNTIME_STATES.UNAVAILABLE,
      },
      not_fully_assessed: [
        ...new Set([
          ...(Array.isArray(overall.not_fully_assessed) ? overall.not_fully_assessed : []),
          "ssl",
        ]),
      ],
    },
  };
}

export function projectTlsReportForCustomer(report = {}) {
  const modules = projectTlsModulesForCustomer(report?.modules ?? {});
  return {
    ...report,
    modules,
    findings: projectTlsFindingsForCustomer(report?.findings, modules),
    recommendations: projectTlsRecommendationsForCustomer(report?.recommendations, modules),
  };
}
