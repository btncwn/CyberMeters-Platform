// Customer words for the authorised TLS special checks (Heartbleed, ROBOT, CCS):
// ONE mapping, read by the scan page (frontend LiveTlsEvidence) and the PDF
// report (scan-api), so the two can never word a result differently. The
// recorded vulnerability status decides; a bare engine state ("Accepted",
// "Rejected") is never the customer's result for these checks (Executive
// 24 Oct 2026, F1 headline wording).

export const TLS_SPECIAL_CHECKS = Object.freeze(["heartbleed", "robot", "ccs"]);

export const TLS_SPECIAL_CHECK_NAMES = Object.freeze({
  heartbleed: "Heartbleed",
  robot: "ROBOT",
  ccs: "CCS injection",
});

export const TLS_VULNERABILITY_STATUS_WORDS = Object.freeze({
  confirmed: "Confirmed by the recorded test",
  not_observed: "Not observed in this test",
  unknown: "Unknown",
});

export function isTlsSpecialCheck(control) {
  return TLS_SPECIAL_CHECKS.includes(control);
}

/** The vulnerability status in words, or null when the row records none. */
export function tlsVulnerabilityWords(row) {
  const status = row?.evidence?.vulnerability?.status;
  return typeof status === "string" && Object.prototype.hasOwnProperty.call(TLS_VULNERABILITY_STATUS_WORDS, status)
    ? TLS_VULNERABILITY_STATUS_WORDS[status]
    : null;
}

export const TLS_HEARTBEAT_NOT_APPLICABLE =
  "Not applicable — this server did not offer the TLS heartbeat extension that Heartbleed relies on.";

/**
 * One special-check row's result in customer words, for a check that was run
 * (or attempted) on an authorised host. The vulnerability status decides;
 * otherwise the recorded reason; never the engine's Accepted/Rejected.
 */
export function tlsSpecialCheckResult(row) {
  const vulnerability = tlsVulnerabilityWords(row);
  if (vulnerability) return vulnerability;
  if (row?.reason === "heartbeat_unavailable") return TLS_HEARTBEAT_NOT_APPLICABLE;
  if (row?.reason === "provider_infrastructure_not_tested") return "Not tested — shared provider infrastructure";
  if (row?.reason === "slice_failed" || row?.state === "uncertain" || row?.state === "unexecutable") return "Could not complete";
  return "Unknown";
}

// Reasons that mean the check was NOT run on this scan (no authorisation,
// engine withheld, scheduled scan, unverified address): not an "authorised
// active check" result.
const TLS_SPECIAL_NOT_RUN_REASONS = new Set([
  "requires_customer_authorisation", "authorised_engine_not_released",
  "scheduled_or_unknown_origin", "authorised_runs_on_started_check", "address_not_verified_not_tested",
]);

/**
 * The authorised active checks a scan ran, from its TLS assessment
 * (modules.tls_assessment / readTlsAssessmentForScan): one row per
 * host:port and check, with its result words and observation time.
 * Empty when none ran.
 */
export function authorisedActiveCheckRows(assessment) {
  const endpoints = Array.isArray(assessment?.endpoints) ? assessment.endpoints : [];
  const rows = [];
  for (const endpoint of endpoints) {
    for (const row of Array.isArray(endpoint?.checks) ? endpoint.checks : []) {
      if (!isTlsSpecialCheck(row?.control)) continue;
      if (row.state === "not_authorized" || row.state === "pending" || TLS_SPECIAL_NOT_RUN_REASONS.has(row.reason)) continue;
      rows.push({
        host: typeof endpoint.hostname === "string" ? endpoint.hostname : null,
        port: Number.isInteger(endpoint.port) ? endpoint.port : null,
        check: TLS_SPECIAL_CHECK_NAMES[row.control],
        result: tlsSpecialCheckResult(row),
        observed_at: typeof row.observed_at === "string" ? row.observed_at : null,
      });
    }
  }
  return rows;
}
