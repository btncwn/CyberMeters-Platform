// Score honesty — PRESENTATION ONLY.
//
// The backend decides whether a Cyber Metrics Score is established or withheld
// (assessment.provisional / display_rating / scan_quality). This module only
// turns that decision into one presentation rule used everywhere a scan score
// appears: a withheld or provisional score is never shown as a number.

export const WITHHELD_SCORE_EXPLANATION =
  'Assessment incomplete: some checks did not complete, so there is no score yet. What was measured is shown, and what was not is listed.'
export const SCORE_PENDING_LABEL = 'Score available after a complete scan'

const PARTIAL = new Set(['partial', 'degraded'])
// assessment-presentation.js ASSESSMENT_MESSAGES.partial / .degraded.
const PROVISIONAL_NUMBER_MESSAGE = /This score is provisional\.?$/

/**
 * scoreHeadline({ score, rating, provisional, message, scanQuality })
 *   → { mode: 'established' | 'withheld' | 'none', score, rating, explanation }
 * 'withheld' whenever the backend marks the assessment provisional, withholds
 * the band while publishing a number, or records the scan as partial.
 */
export function scoreHeadline({ score = null, rating = null, provisional = null, message = null, scanQuality = null } = {}) {
  const value = Number.isFinite(score) ? score : null
  const text = typeof message === 'string' && message.trim() ? message.trim() : null
  const partial = PARTIAL.has(String(scanQuality || '').toLowerCase())
  if (provisional === true || (value !== null && rating == null) || partial) {
    // The backend's generic quality message speaks about the number this rule
    // hides ("... This score is provisional.") and would contradict the screen,
    // so the withheld explanation replaces it. Any other message is a specific
    // reason (e.g. which area did not complete) and is shown as written.
    const aboutHiddenNumber = text !== null && PROVISIONAL_NUMBER_MESSAGE.test(text)
    return { mode: 'withheld', score: null, rating: null, explanation: text && !aboutHiddenNumber ? text : WITHHELD_SCORE_EXPLANATION }
  }
  if (value === null) return { mode: 'none', score: null, rating: null, explanation: text }
  return { mode: 'established', score: value, rating, explanation: null }
}

// The backend words a provisional scan notification as
// "Score: 100 (provisional) · <disclosure>". Retain the disclosure, not the number.
const PROVISIONAL_MESSAGE = /^Score:\s*(\d{1,3})\s*\(provisional\)\s*·\s*(.+)$/s

export function presentNotificationMessage(message) {
  if (typeof message !== 'string') return message
  const m = PROVISIONAL_MESSAGE.exec(message.trim())
  if (!m) return message
  return `${m[2].trim()} · ${SCORE_PENDING_LABEL}`
}

// The Business Risk Indicator sentence is frozen when the scan finishes and says
// "No major gaps detected" without regard to coverage. The PDF bounds it by the
// snapshot's own coverage facts (engines/pdf.js); the scan page says the same.
const COVERAGE_LIMIT = 'Coverage is incomplete: some checks did not run or still need customer input, so this provisional indicator is not confirmation that no other material gaps exist.'

// A report that could not be read has not confirmed coverage, so it is incomplete.
export function coverageIsIncomplete(report) {
  const coverage = report?.evidence_completeness
  if (!coverage) return true
  return (coverage.scan_quality && coverage.scan_quality !== 'complete')
    || (coverage.assessment_quality && coverage.assessment_quality !== 'complete')
    || (coverage.monitoring_state && coverage.monitoring_state !== 'monitoring_healthy')
    || (Array.isArray(coverage.modules_skipped) && coverage.modules_skipped.length > 0)
    || (Array.isArray(report.executive_summary?.not_fully_assessed) && report.executive_summary.not_fully_assessed.length > 0)
}

export function businessRiskNarrative(explanation, report) {
  if (!explanation || !coverageIsIncomplete(report)) return explanation
  if (/No major gaps detected/.test(explanation)) {
    return `No major gaps were identified in the evidence available. ${COVERAGE_LIMIT}`
  }
  return `${explanation} ${COVERAGE_LIMIT}`
}
