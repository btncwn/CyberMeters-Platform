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

// A host where NO web port answered at all (every HTTP/HTTPS attempt timed
// out: an SSH-only server, or 80/443 filtered) has no web service to assess.
// That is stated per host, never an evidence gap for the whole domain
// (22 Oct 2026: one SSH-only test host made cybermeters.com partial and hid
// its score). Only when probe_timeout is the module's reason AND every
// not-assessed asset is such a host; a server error, a budget cut, a DNS gap
// or a host that answered and then stalled still counts.
const ASSET_NOT_ASSESSED = new Set(["not_executed", "timed_out", "server_error"]);
export function webServiceNeverAnsweredHosts(value) {
  const assets = Array.isArray(value?.assets) ? value.assets : [];
  const notAssessed = assets.filter((asset) => ASSET_NOT_ASSESSED.has(asset?.probe_status));
  const silent = (asset) => asset?.probe_status === "timed_out" && Array.isArray(asset.attempts) &&
    asset.attempts.length > 0 && asset.attempts.every((attempt) => attempt?.outcome === "timeout");
  return notAssessed.length > 0 && notAssessed.every(silent) ? notAssessed.map((asset) => asset.host || asset.hostname).filter(Boolean) : [];
}

// Remote-admin exposure (S3-0) and DANE (S3-C) are supplementary: their gaps
// (address cap, deadline, lookup or probe unavailable) are stated.
// Technology detection the site itself withheld is stated, not ours.
export function isStatedAccessLimit(name, value) {
  return value?.incomplete === true && (
    name === "remote_admin_exposure" || name === "dane" ||
    (name === "technology_detection" && value?.incomplete_reason === "origin_access_restricted") ||
    (name === "asset_exposure" && !value?.error && value?.incomplete_reason === "probe_timeout" &&
      webServiceNeverAnsweredHosts(value).length > 0) ||
    (name === "subdomain_takeover" && takeoverWithheldOnly(value)));
}
