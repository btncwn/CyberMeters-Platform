// ── Canonical scorecard domain-state → customer wording behaviour (B) ────────
// ONE source of truth mapping a canonical Cyber MOT domain state (or the A3 admin
// evidence_status) to the four customer-facing scorecard behaviours, so the
// executive_summary (scorecard.js) and the sections[] (buildScorecardSections) can
// never disagree, and unavailable / not_assessed evidence can never render as a
// reassuring healthy / "none detected" / "looks normal" conclusion.
//
// The four customer-facing behaviours: healthy | issue | unavailable | not_assessed.

export function scorecardBehaviour(state) {
  switch (state) {
    case "assessed_healthy":     return "healthy";
    case "issue_detected":
    case "degraded":             return "issue";
    case "evidence_insufficient":
    case "unavailable":
    case "provisional":          return "unavailable";
    default:                     return "not_assessed"; // not_yet_assessed / not_configured / monitoring_only / customer_input_required / null / unknown
  }
}

// Only assessed_healthy may produce reassuring positive wording.
export function canSayHealthy(state) {
  return scorecardBehaviour(state) === "healthy";
}

// Look up a canonical domain state from the scorecard's cyber_mot_domains array.
export function domainState(cyberMotDomains, key) {
  return (Array.isArray(cyberMotDomains) ? cyberMotDomains : [])
    .find((d) => d?.domain_key === key)?.state ?? null;
}

// Neutral, non-reassuring one-liner for a non-healthy, non-issue domain.
export function neutralSummary(state, subject) {
  return scorecardBehaviour(state) === "unavailable"
    ? `${subject} could not be assessed in the latest scan — evidence was unavailable.`
    : `${subject} has not been assessed yet.`;
}

// Section status ('ok'|'warning'|'critical'|'unknown') gated on canonical state.
// The caller supplies the issue-severity status (warning vs critical). unavailable /
// not_assessed → 'unknown' (neutral, never 'ok'/healthy).
export function sectionStatus(state, issueStatus = "warning") {
  const b = scorecardBehaviour(state);
  if (b === "healthy") return "ok";
  if (b === "issue")   return issueStatus;
  return "unknown";
}
