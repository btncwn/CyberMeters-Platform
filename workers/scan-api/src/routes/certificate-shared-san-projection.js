// Candidate A (R1 + R3) — additive customer projection for the one historical
// cert_shared_san_count ambiguity. This module is imported only by scans.js so
// it remains outside the email-ingest Worker closure.
//
// Stored SSL/certificate-intelligence bytes are immutable. The projection
// clones the certificate-intelligence object, appends one presentation field,
// and never writes, backfills, or uses time/deployment/application versions.
import { buildCertificateOwnershipAssessment } from "../engines/cert-intel.js";

const POST_CUTOVER_SCHEMA_VERSION = 3;
const SCHEMA_VERSION_PATTERN = /^external-certificate-observation-v([1-9]\d*)$/;

const MEASURED_ZERO = "measured_zero";
const MEASURED_POSITIVE = "measured_positive";
const LEGACY_AMBIGUOUS_ZERO = "legacy_ambiguous_zero";
const LEGACY_MEASURED_POSITIVE = "legacy_measured_positive";
const UNMEASURED = "unmeasured";

function notAssessed(measurementState) {
  return {
    measurement_state: measurementState,
    assessment_state: "not_assessed",
    shared_san_count: null,
    ownership_status: null,
    customer_owned: null,
    confidence: null,
  };
}

function assessed(measurementState, ownership) {
  return {
    measurement_state: measurementState,
    assessment_state: "assessed",
    shared_san_count: ownership.shared_san_count,
    ownership_status: ownership.status,
    customer_owned: ownership.customer_owned,
    confidence: ownership.confidence,
  };
}

export function projectCertificateSharedSanForCustomer({
  ssl = null,
  certificateIntelligence = null,
  domain = null,
} = {}) {
  const rawCertificateIntelligence =
    certificateIntelligence && typeof certificateIntelligence === "object" &&
    !Array.isArray(certificateIntelligence)
      ? certificateIntelligence
      : {};
  const schemaVersion = ssl?.certificate_evidence?.schema_version;
  const versionMatch = typeof schemaVersion === "string"
    ? schemaVersion.match(SCHEMA_VERSION_PATTERN)
    : null;
  const schemaVersionIsMissing = schemaVersion == null;
  const schemaVersionIsValid = schemaVersionIsMissing || versionMatch != null;
  const postCutover = versionMatch != null &&
    Number(versionMatch[1]) >= POST_CUTOVER_SCHEMA_VERSION;
  const rawSharedSanCount = ssl?.cert_shared_san_count;
  const crtShSource = ssl?.ct_sources?.crt_sh;
  const fivePredicatesHold = Boolean(
    crtShSource &&
    crtShSource.error == null &&
    Number.isInteger(crtShSource.count) &&
    crtShSource.count > 0 &&
    Number.isInteger(rawSharedSanCount) &&
    rawSharedSanCount >= 0
  );
  const evidenceComplete = rawCertificateIntelligence.incomplete !== true;

  let sharedSanAssessment;
  if (!schemaVersionIsValid) {
    sharedSanAssessment = notAssessed(UNMEASURED);
  } else if (!postCutover && rawSharedSanCount === 0) {
    // Every pre-cutover/unversioned zero is irreducibly ambiguous, including a
    // genuinely measured old zero. Stored ownership/confidence remain visible
    // under their existing raw keys but cannot become canonical healthy proof.
    sharedSanAssessment = notAssessed(LEGACY_AMBIGUOUS_ZERO);
  } else if (postCutover && fivePredicatesHold && evidenceComplete && rawSharedSanCount === 0) {
    sharedSanAssessment = assessed(
      MEASURED_ZERO,
      buildCertificateOwnershipAssessment(ssl, domain),
    );
  } else if (postCutover && fivePredicatesHold && evidenceComplete && rawSharedSanCount > 0) {
    sharedSanAssessment = assessed(
      MEASURED_POSITIVE,
      buildCertificateOwnershipAssessment(ssl, domain),
    );
  } else if (!postCutover && fivePredicatesHold && evidenceComplete && rawSharedSanCount > 0) {
    sharedSanAssessment = assessed(
      LEGACY_MEASURED_POSITIVE,
      buildCertificateOwnershipAssessment(ssl, domain),
    );
  } else {
    sharedSanAssessment = notAssessed(UNMEASURED);
  }

  return {
    ...rawCertificateIntelligence,
    shared_san_assessment: sharedSanAssessment,
  };
}
