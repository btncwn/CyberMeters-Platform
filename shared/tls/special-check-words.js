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

// Recorded TLS control reasons in plain words (Seat 3's held reasons, the
// engine's heartbeat limit, scan-api's repeated-failure record). The scan page
// and the PDF read these same strings.
export const TLS_CONTROL_REASON_WORDS = Object.freeze({
  requires_customer_authorisation: "Not tested — requires your authorisation",
  authorised_engine_not_released: "Authorised — not yet available",
  address_not_verified_not_tested: "Not tested — this address is not verified as yours",
  // The producer's reason (catalog.js TLS_AUTHORISED_ON_DEMAND_REASON); the older key stays as an alias.
  scheduled_or_unknown_origin: "Not tested — authorised checks run only on scans you start yourself, never on scheduled scans.",
  authorised_runs_on_started_check: "Not tested — authorised checks run only on scans you start yourself, never on scheduled scans.",
  heartbeat_unavailable: TLS_HEARTBEAT_NOT_APPLICABLE,
  slice_failed: "Could not complete — this check did not finish on this server after repeated attempts. The other checks were not affected.",
});

/** A provider-edge refusal names the host and, when known, the provider, and says what to do. */
export function tlsProviderNotTestedWords(row, endpoint = null) {
  const host = typeof endpoint?.hostname === "string" && endpoint.hostname ? endpoint.hostname : "This host";
  const provider = row?.provider_name || endpoint?.provider_name || endpoint?.provider || null;
  return `Not tested — ${host} is served by shared provider infrastructure${provider ? ` (${provider})` : ""}. Add your own servers to test them.`;
}

/** A check scan-api gave up on, with the attempts it recorded (null when it recorded none). */
export function tlsSliceFailedWords(row) {
  const n = row?.failure_attempts;
  if (!(Number.isSafeInteger(n) && n > 0)) return null;
  return `Could not complete — this check did not finish on this server after ${n} attempt${n === 1 ? "" : "s"}. The other checks were not affected.`;
}

/**
 * One special-check row's result in customer words — the ONE string both the
 * scan page and the PDF print. Order: provider edge, recorded failure attempts,
 * the vulnerability status, the recorded reason; never the engine's
 * Accepted/Rejected.
 */
export function tlsSpecialCheckResult(row, endpoint = null) {
  if (row?.reason === "provider_infrastructure_not_tested") return tlsProviderNotTestedWords(row, endpoint);
  const failed = row?.reason === "slice_failed" ? tlsSliceFailedWords(row) : null;
  if (failed) return failed;
  const vulnerability = tlsVulnerabilityWords(row);
  if (vulnerability) return vulnerability;
  if (row?.reason && TLS_CONTROL_REASON_WORDS[row.reason]) return TLS_CONTROL_REASON_WORDS[row.reason];
  if (row?.state === "uncertain") return "Uncertain — the test did not reach a result.";
  if (row?.state === "unexecutable") return "Could not complete";
  if (row?.state === "not_authorized") return TLS_CONTROL_REASON_WORDS.requires_customer_authorisation;
  return "Unknown";
}

// Reasons that mean the check was NOT run on this scan (no authorisation,
// engine withheld, scheduled scan, unverified address, shared provider edge):
// not an "authorised active check" result.
const TLS_SPECIAL_NOT_RUN_REASONS = new Set([
  "requires_customer_authorisation", "authorised_engine_not_released",
  "scheduled_or_unknown_origin", "authorised_runs_on_started_check", "address_not_verified_not_tested",
  // A shared provider edge is refused before anything runs (tls-planner emits it
  // only when the address is not authorised): nothing ran, so no section.
  "provider_infrastructure_not_tested",
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
        result: tlsSpecialCheckResult(row, endpoint),
        observed_at: typeof row.observed_at === "string" ? row.observed_at : null,
      });
    }
  }
  return rows;
}
