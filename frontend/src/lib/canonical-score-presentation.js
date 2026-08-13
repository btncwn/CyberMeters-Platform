export const NOT_ESTABLISHED_SCORE_MESSAGE = 'Current posture not yet established.'

/**
 * Validates the additive backend assessment envelope for rendering. This is not
 * a verdict resolver: it accepts only self-consistent explicit backend state and
 * fails every missing, malformed or future shape to not-established.
 */
export function canonicalScoreView(assessment) {
  const state = assessment?.state
  const score = Number.isFinite(assessment?.display_score)
    ? assessment.display_score
    : null
  const reason = typeof assessment?.message === 'string' && assessment.message.trim()
    ? assessment.message.trim()
    : NOT_ESTABLISHED_SCORE_MESSAGE
  const provisional = state === 'provisional' && score != null &&
    assessment?.provisional === true && assessment?.authoritative === false
  const established = state === 'established' && score != null &&
    assessment?.provisional === false && assessment?.authoritative === true

  if (provisional) {
    return { state: 'provisional', score, rating: null, reason }
  }
  if (established) {
    return {
      state: 'established',
      score,
      rating: assessment.display_rating ?? null,
      reason: null,
    }
  }
  return { state: 'not_established', score: null, rating: null, reason }
}
