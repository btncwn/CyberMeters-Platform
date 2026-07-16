import { describe, it, expect } from 'vitest'
import {
  TONE_CLASS, SCORE_BAND_META, SCORE_STATE_META,
  scoreBandMeta, scoreStateMeta, toneClass, hasRenderableScore, scoreOutOfHundred,
} from '../portfolioScoreDisplay'

// The backend owns the verdict. This module may only translate it into pixels, and the
// thing it must never do is invent one — a `?? healthy` or a re-derived threshold here
// would resurrect the defect this file was written to bury: a null portfolio score that
// fell through `>= 75 / >= 55 / >= 35` and rendered as "Serious ... null/100".
describe('portfolioScoreDisplay — absent evidence never becomes a verdict', () => {
  it('contains no thresholds of its own (band logic lives in the backend)', () => {
    // Guards against someone re-adding a ladder here "just for the badge". If a number
    // appears in a comparison in this module, the frontend has started deriving verdicts.
    const src = scoreBandMeta.toString() + scoreStateMeta.toString() + toneClass.toString()
    expect(src).not.toMatch(/>=\s*\d/)
    expect(src).not.toMatch(/[<>]\s*\d/)
  })

  describe('scoreBandMeta — a band exists only when the backend says so', () => {
    it.each([
      ['healthy', 'Healthy'],
      ['moderate', 'Moderate'],
      ['elevated', 'Elevated'],
      ['serious', 'Serious'],
    ])('maps %s to a label with a real tone', (band, label) => {
      const meta = scoreBandMeta(band)
      expect(meta.label).toBe(label)
      expect(TONE_CLASS[meta.tone]).toBeTruthy()
      expect(SCORE_BAND_META[band]).toEqual(meta)
    })

    it('is case-insensitive', () => {
      expect(scoreBandMeta('HEALTHY').label).toBe('Healthy')
    })

    // The heart of it. Every one of these once produced "Serious".
    it.each([null, undefined, '', NaN, 0, false, 'nonsense', 'unknown'])(
      'returns null for %p rather than substituting a band', (input) => {
        expect(scoreBandMeta(input)).toBeNull()
      })

    it('never returns a band that would render as healthy for absent input', () => {
      for (const input of [null, undefined, '', NaN]) {
        const meta = scoreBandMeta(input)
        expect(meta).toBeNull()
        expect(meta?.tone).not.toBe('healthy')
      }
    })
  })

  describe('scoreStateMeta — unknown states degrade to unknown, never to benign', () => {
    it.each([
      ['available', true],
      ['partial', true],
      ['evidence_insufficient', false],
      ['no_workspaces', false],
    ])('%s declares whether a score may be shown', (state, showsScore) => {
      const meta = scoreStateMeta(state)
      expect(meta.showsScore).toBe(showsScore)
      expect(TONE_CLASS[meta.tone]).toBeTruthy()
      expect(SCORE_STATE_META[state]).toEqual(meta)
    })

    it('the two no-evidence states carry the unknown tone — not green, not red', () => {
      for (const s of ['evidence_insufficient', 'no_workspaces']) {
        expect(scoreStateMeta(s).tone).toBe('unknown')
      }
    })

    // A state the frontend has not learned yet must read as "we do not know", which is
    // true, rather than as "fine", which would be a guess.
    it.each([null, undefined, '', 'state_from_the_future', 42])(
      'falls back to unknown for %p', (input) => {
        const meta = scoreStateMeta(input)
        expect(meta.tone).toBe('unknown')
        expect(meta.showsScore).toBe(false)
      })
  })

  describe('toneClass', () => {
    it('resolves every declared tone', () => {
      for (const tone of Object.keys(TONE_CLASS)) expect(toneClass(tone)).toBe(TONE_CLASS[tone])
    })
    it('falls back to the unknown tone, never to a risk colour', () => {
      for (const bad of [null, undefined, 'chartreuse', '']) {
        expect(toneClass(bad)).toBe(TONE_CLASS.unknown)
      }
    })
    it('the unknown tone is visually neutral (slate), not green or red', () => {
      expect(TONE_CLASS.unknown).toMatch(/slate/)
      expect(TONE_CLASS.unknown).not.toMatch(/brand|green|red|amber|orange/)
    })
  })

  describe('hasRenderableScore — `!= null` was not enough', () => {
    it.each([0, 1, 35, 55, 75, 100, 59.5, -3, 120])('accepts the finite number %p', (n) => {
      expect(hasRenderableScore(n)).toBe(true)
    })
    // NaN != null is true, and NaN fails every `>=`, which is exactly how a non-finite
    // score landed in the final `else` and painted the page red.
    it.each([null, undefined, NaN, Infinity, -Infinity, '60', '', {}, []])(
      'rejects %p', (bad) => {
        expect(hasRenderableScore(bad)).toBe(false)
      })
  })

  describe('scoreOutOfHundred — no denominator without a numerator', () => {
    it('formats a real score', () => {
      expect(scoreOutOfHundred(60)).toBe('60/100')
      expect(scoreOutOfHundred(0)).toBe('0/100')
      expect(scoreOutOfHundred(100)).toBe('100/100')
    })
    // The page rendered `{score ?? '—'}` beside an unconditional `/100`, giving "—/100".
    it.each([null, undefined, NaN])('returns null for %p — the caller omits the element', (bad) => {
      expect(scoreOutOfHundred(bad)).toBeNull()
    })
    it('never produces null/100, undefined/100 or NaN/100', () => {
      for (const bad of [null, undefined, NaN]) {
        expect(String(scoreOutOfHundred(bad))).not.toMatch(/null\/100|undefined\/100|NaN\/100/)
      }
    })
  })
})
