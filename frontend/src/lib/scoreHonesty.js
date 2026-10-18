// Score honesty — PRESENTATION ONLY.
//
// The backend decides whether a Cyber Metrics Score is established or withheld
// (assessment.provisional / display_rating / scan_quality). This module only
// turns that decision into one presentation rule used everywhere a scan score
// appears: a withheld or provisional score is never shown as a number.

export const WITHHELD_SCORE_EXPLANATION =
  'Score withheld: some checks did not complete. See what was not assessed.'
export const SCORE_PENDING_LABEL = 'Score available after a complete scan'

const PARTIAL = new Set(['partial', 'degraded'])

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
    return { mode: 'withheld', score: null, rating: null, explanation: text || WITHHELD_SCORE_EXPLANATION }
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
