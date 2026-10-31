// Customer words for the scan's MTA-STS and TLS-RPT observations: ONE mapping,
// read by the mail transport card (frontend) and the PDF report (scan-api), so
// the two can never word the same evidence differently. Both read the details
// buildEmailTransportDetails recorded (email-analysis.js). A check that did not
// conclude is never "absent", and a TLS-RPT record in DNS is never a received
// TLS report.

export function mtaStsWords(detail) {
  if (detail?.policy_found === true) {
    const mode = ["enforce", "testing", "none"].includes(detail.mode) ? detail.mode : null;
    return `${mode ? `${mode} policy observed` : "policy observed, mode not recorded"}; DNS activation not separately checked`;
  }
  if (detail?.policy_found === false) return "enforcement not confirmed; no policy file was confirmed";
  if (detail) return "enforcement not confirmed; the check did not conclude";
  return "enforcement not confirmed; not recorded for this check";
}

export function tlsRptWords(detail) {
  if (detail?.record_found === true) return "reporting record observed in DNS; this does not show that TLS reports were received";
  if (detail?.record_found === false) {
    return detail.observation_state === "definitive_absent"
      ? "reporting record not found"
      : "reporting record not confirmed";
  }
  if (detail) return "reporting record not confirmed; the lookup did not conclude";
  return "reporting record not confirmed; not recorded for this check";
}
