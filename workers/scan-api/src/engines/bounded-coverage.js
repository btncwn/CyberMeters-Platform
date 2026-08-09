// ── Closed bounded-coverage vocabulary ──────────────────────────────────────
// This dimension records whether a declared cap limited an otherwise successful
// execution. It is deliberately separate from incomplete/unavailable/error and
// can never change top-level scan quality by itself.

export const BOUNDED_COVERAGE_STATES = Object.freeze([
  "bounded",
  "complete",
  "not_recorded",
]);

const BOUNDED_COVERAGE_STATE_SET = new Set(BOUNDED_COVERAGE_STATES);

export function normalizeBoundedCoverageState(value) {
  return BOUNDED_COVERAGE_STATE_SET.has(value) ? value : "not_recorded";
}

export function coverageStateFromTruncation(truncated) {
  return truncated === true ? "bounded" : "complete";
}
