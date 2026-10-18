import { scoreHeadline, presentNotificationMessage, WITHHELD_SCORE_EXPLANATION, SCORE_PENDING_LABEL } from '../scoreHonesty'

// The backend decides; this only forbids a withheld score from being a headline.

describe('scoreHeadline', () => {
  it('establishes only a rated, non-provisional, complete score', () => {
    expect(scoreHeadline({ score: 85, rating: 'good', provisional: false, scanQuality: 'complete' }))
      .toEqual({ mode: 'established', score: 85, rating: 'good', explanation: null })
  })
  it('withholds a provisional score, a score without a band, and a partial scan, with the explanation first', () => {
    expect(scoreHeadline({ score: 100, rating: null, provisional: true, message: 'Attack surface did not complete.' }))
      .toEqual({ mode: 'withheld', score: null, rating: null, explanation: 'Attack surface did not complete.' })
    expect(scoreHeadline({ score: 100, rating: null, provisional: false }).mode).toBe('withheld')
    expect(scoreHeadline({ score: 100, rating: 'excellent', provisional: false, scanQuality: 'partial' }).mode).toBe('withheld')
    expect(scoreHeadline({ score: 100, rating: null }).explanation).toBe(WITHHELD_SCORE_EXPLANATION)
  })
  it('publishes no number without a score', () => {
    expect(scoreHeadline({ score: null, message: 'Posture not yet established.' })).toEqual({ mode: 'none', score: null, rating: null, explanation: 'Posture not yet established.' })
    expect(scoreHeadline({}).mode).toBe('none')
  })
})

it('uses a nonnumeric placeholder for incomplete scans', () => {
  expect(SCORE_PENDING_LABEL).toBe('Score available after a complete scan')
  expect(scoreHeadline({ score: 100, rating: 'excellent', scanQuality: 'partial' }).score).toBeNull()
  expect(scoreHeadline({ score: null, rating: null, scanQuality: 'partial' }).mode).toBe('withheld')
})

describe('presentNotificationMessage', () => {
  it('moves the backend disclosure before the provisional number', () => {
    expect(presentNotificationMessage('Score: 100 (provisional) · Attack surface did not complete, so the score is provisional.'))
      .toBe('Attack surface did not complete, so the score is provisional. · Score available after a complete scan')
  })
  it('leaves established and other messages untouched', () => {
    expect(presentNotificationMessage('Score: 82 · low risk')).toBe('Score: 82 · low risk')
    expect(presentNotificationMessage('3 new hostnames.')).toBe('3 new hostnames.')
    expect(presentNotificationMessage(null)).toBeNull()
  })
})
