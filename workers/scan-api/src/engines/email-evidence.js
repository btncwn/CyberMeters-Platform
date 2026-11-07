// Pure email probe coverage contracts. Keep this module dependency-free: the
// domain resolver is also read by the remediation registry, so importing the
// email-analysis builders from that resolver would create an initialisation cycle.

// ── Email probe evidence-status (A1) ─────────────────────────────────────────
// Shared, dependency-free classifier used by BOTH the SPF and DKIM truth
// consumers (scoring + email-intel) to tell "we could not observe this probe"
// apart from "we observed it and there is no record". The observation status
// itself is produced at the probe boundary (email-scan.js) reusing the DMARC
// observation-status pattern; this leaf helper only answers "is it unobserved?".
// unavailable = probe/DNS failure; not_yet_assessed = probe never executed.
// Both are score-neutral and must never become a missing/failed conclusion.
export function isEmailProbeUnobserved(status) {
  return status === "unavailable" || status === "not_yet_assessed";
}

// Presence is an evidence contract: only booleans can establish presence or
// absence. New module results persist null when a probe did not conclude; the
// non-enumerable live status does not survive JSON. Known legacy booleans keep
// their meaning when no status is available.
export function isEmailProbeEvidenceUnknown(present, status) {
  return typeof present !== "boolean" || isEmailProbeUnobserved(status);
}

// Before nullable SPF presence, email-scan.js wrote false when its root TXT
// lookup failed. Its root-probe failure branch also persisted no root record,
// zero records and an explicit authorisation temperror. That combination is
// enough to recover unknown evidence after JSON drops the live probe status.
// A generic temperror alone is not this marker; an observed root SPF record can
// have an include/redirect resolution error and must remain usable. Do not
// require unrelated nullable lookup counters to recognise the root failure.
export function isSpfEvidenceUnknown(spf, status) {
  return isEmailProbeEvidenceUnknown(spf?.present, status) ||
    (spf?.present === false && spf.record === null && spf.record_count === 0 &&
      spf.resolution_status === "temperror");
}

// SPF is required primary Email Protection evidence. A module object alone
// cannot establish coverage when its root TXT probe did not conclude. Read the
// same tri-state/status contract as scoring; null also survives report JSON.
// Keep this separate from the module's publishability: an independent observed
// DMARC issue and its remediation remain usable while SPF coverage is partial.
export function isEmailSpfEvidenceIncomplete(email) {
  return isSpfEvidenceUnknown(email?.spf, email?.spf_evidence_status);
}
