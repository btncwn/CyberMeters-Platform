// ── Cyber Essentials Readiness — questionnaire + merge logic ─────────────────
// Cyber Essentials readiness = PARTIALLY-verified, transparently-labelled.
// HONEST BOUNDARY: we can corroborate answers ONLY for controls with an
// externally-observable footprint (boundary/secure-config/patch — partial).
// Internal controls (access control / MFA, endpoint malware protection) have
// NO external footprint → they stay pure self-attestation, clearly labelled as
// such. We never call self-attested answers "verified". Where an external scan
// contradicts an optimistic answer on an observable control, we flag it — that
// contradiction, plus honest per-control evidence labelling, is the edge over
// pure-questionnaire and pure-scanner tools. Readiness/gap only, not certification.
//
// ── THE QUESTIONS THEMSELVES LIVE IN shared/cyber-essentials-questions.js ────
// They are re-exported here so every existing Worker import path keeps working, and so the
// PUBLIC self-check page and this authenticated set are provably the same 20 questions.
// They used to be two independently-maintained copies and had drifted: 14 of 20 questions
// carried a different KEY on each side, and 4 of the 6 shared keys had different wording.
// A visitor who answered the public check and then subscribed was answering a different
// questionnaire. scripts/validate-ce-question-drift.js now blocks that in CI.
//
// The set is CyberMeters-authored readiness, NOT the official IASME application form.
// control_key mirrors cyberEssentialsCategory() in ce-readiness.js.

export {
  CE_QUESTIONS,
  CE_QUESTION_SET_VERSION,
  CE_QUESTION_SET_PROVENANCE,
  CE_QUESTION_KEYS,
} from "../../../../shared/cyber-essentials-questions.js";
import { CE_QUESTIONS } from "../../../../shared/cyber-essentials-questions.js";

const OPTIMISTIC = new Set(["yes"]);
const GAP_ANSWERS = new Set(["no", "partial"]);

/**
 * Merge measured external signal with self-attestation answers into a readiness
 * view. Measured wins on contradiction.
 * @param {Array<{control_key:string, measured_score:number, measured_gaps:string[]}>} measured
 *        one entry per control (measured_score 0-100; measured_gaps = observed problems)
 * @param {Record<string, Record<string,string>>} answers
 *        { [control_key]: { [question_key]: 'yes'|'partial'|'no'|'unknown' } }
 * @returns {Array<object>} per-control readiness with contradictions flagged
 */
export function mergeReadiness(measured, answers = {}) {
  const measuredByKey = new Map((measured || []).map((m) => [m.control_key, m]));
  return CE_QUESTIONS.map((ctrl) => {
    const m = measuredByKey.get(ctrl.control_key) || { measured_score: null, measured_gaps: [] };
    const ans = answers[ctrl.control_key] || {};
    const answered = ctrl.questions.filter((q) => ans[q.key] && ans[q.key] !== "unknown");
    const selfGaps = ctrl.questions.filter((q) => GAP_ANSWERS.has(ans[q.key]));
    const allOptimistic = ctrl.questions.length > 0 && ctrl.questions.every((q) => OPTIMISTIC.has(ans[q.key]));
    const measuredGaps = Array.isArray(m.measured_gaps) ? m.measured_gaps : [];
    const measuredHasGap = measuredGaps.length > 0 || (typeof m.measured_score === "number" && m.measured_score < 70);

    // The killer feature: claimed OK but observed otherwise.
    const contradiction = allOptimistic && measuredHasGap;

    let readiness;
    if (measuredHasGap) readiness = "gaps";                 // measured wins — not ready
    else if (selfGaps.length > 0) readiness = "gaps";       // self-declared gaps
    else if (answered.length < ctrl.questions.length) readiness = "incomplete";
    else readiness = "ready";

    const externalCoverage = ctrl.external_coverage || "none";
    // Honest evidence status — never label self-attestation as "verified".
    let evidence;
    if (externalCoverage === "none") evidence = "self_attested_only";
    else if (contradiction) evidence = "contradicted_by_scan";
    else if (measuredHasGap) evidence = "externally_confirmed_gap";
    else evidence = "externally_corroborated";

    return {
      control_key: ctrl.control_key,
      label: ctrl.label,
      external_coverage: externalCoverage,
      evidence,
      readiness,
      measured_score: m.measured_score ?? null,
      measured_gaps: measuredGaps,
      self_attestation: { answered: answered.length, total: ctrl.questions.length, gaps: selfGaps.map((q) => q.key) },
      contradiction: contradiction
        ? { message: "Self-assessment says this control is met, but external checks observed a gap. External evidence takes precedence.", measured_gaps: measuredGaps }
        : null,
    };
  });
}
