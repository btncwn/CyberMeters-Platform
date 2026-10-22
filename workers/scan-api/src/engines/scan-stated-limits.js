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

// The customer sentence for a stated limit. Every surface (scan page, PDF,
// monitoring copy) shows this text, never the reason key. Worded as what
// happened in THIS scan, never a stronger claim.
const REMOTE_ADMIN_LIMIT = Object.freeze({
  address_cap: "Remote-administration ports were checked on the first eight of this domain's own addresses only.",
  ports_not_all_checked: "Some remote-administration port checks did not complete in this scan.",
  address_unreachable: "Nothing on one of this domain's addresses answered, so CyberMeters could not tell whether its ports are filtered or the host was unreachable.",
  address_lookup_failed: "Some of this domain's addresses could not be looked up, so remote-administration ports may not have been checked on every address.",
  probe_unavailable: "The remote-administration port check was unavailable in this scan.",
  module_deadline: "The remote-administration port check did not finish within its time limit in this scan.",
});
export function statedLimitMessage(name, value) {
  if (name === "asset_exposure") {
    const hosts = webServiceNeverAnsweredHosts(value);
    return `No web service observed on ${hosts.join(", ")} (ports 80/443 did not answer during this scan); ${hosts.length > 1 ? "these hosts are" : "the host is"} still recorded in your inventory.`;
  }
  if (name === "subdomain_takeover") {
    return "A DNS record points at an external service that withheld the page needed to confirm whether it is claimed; CyberMeters could not confirm either way.";
  }
  if (name === "technology_detection") {
    return "The website withheld its pages from technology detection (for example a challenge or a closed store), so technologies were not identified in this scan.";
  }
  if (name === "remote_admin_exposure") {
    return REMOTE_ADMIN_LIMIT[value?.incomplete_reason] || "Remote-administration port checks were limited in this scan.";
  }
  if (name === "dane") {
    return value?.incomplete_reason === "module_deadline"
      ? "The DANE (TLSA) check did not finish within its time limit in this scan."
      : "A DANE (TLSA) lookup failed, so DANE status is not known for every mail server or the website in this scan.";
  }
  return "A check in this scan was limited; this is stated, not treated as a finding.";
}
