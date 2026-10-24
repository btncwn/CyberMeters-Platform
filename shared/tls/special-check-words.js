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
