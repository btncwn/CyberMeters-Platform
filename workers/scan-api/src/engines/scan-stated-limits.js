// Stated limits: module gaps that are disclosed to the customer but are NOT a
// gap in CyberMeters' own assessment, so they never make a scan partial and
// never degrade monitoring. One predicate, read by buildScanQuality
// (scan-engine.js) and by moduleEvidenceState (signal-monitoring-state.js), so
// the two can never disagree about the same evidence (22 Oct 2026: they did,
// and a complete scan read "Attack-surface checks did not complete").
// The module record itself stays incomplete, so it can never verify a case it
// did not fully re-check (asm-cases.js moduleCompletionGate).

// A takeover candidate whose provider answered the confirming probe with its
// access-restricted page: reported as a hedged finding, so coverage is stated.
// Only when that is the module's SOLE reason and EVERY unconfirmed row is
// origin_access_restricted; truncation, lookup or fetch failures still count.
export function takeoverWithheldOnly(value) {
  const reasons = Array.isArray(value?.incomplete_reasons) ? value.incomplete_reasons : [value?.incomplete_reason];
  const rows = Array.isArray(value?.unconfirmed) ? value.unconfirmed : [];
  return !value?.error && reasons.length === 1 && reasons[0] === "host_probe_unconfirmed" &&
    rows.length > 0 && rows.every((row) => row?.reason === "origin_access_restricted" && row.host && row.cname);
}

// Remote-admin exposure (S3-0) and DANE (S3-C) are supplementary: their gaps
// (address cap, deadline, lookup or probe unavailable) are stated.
// Technology detection the site itself withheld is stated, not ours.
export function isStatedAccessLimit(name, value) {
  return value?.incomplete === true && (
    name === "remote_admin_exposure" || name === "dane" ||
    (name === "technology_detection" && value?.incomplete_reason === "origin_access_restricted") ||
    (name === "subdomain_takeover" && takeoverWithheldOnly(value)));
}
