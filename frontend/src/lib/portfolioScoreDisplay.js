/**
 * Portfolio score presentation — labels and tones for a BACKEND-OWNED verdict.
 *
 * This file deliberately contains no thresholds. `PortfolioRiskPage` carried its own
 * `>= 75 / >= 55 / >= 35` ladder — byte-identical to one in the risk engine — plus a
 * second copy inside `scoreColor()`. Duplicated band logic is how a page ends up
 * disagreeing with the API that feeds it, and it had already drifted: the frontend
 * partitioned at 75/55/35 while `portfolioRiskBand()` partitioned at 25/50/75, so the
 * same workspace could be 'medium' in one field and "Elevated" in the badge beside it.
 *
 * The backend now publishes `portfolio_score_band` and `portfolio_score_state`. This
 * module maps those strings to presentation and nothing else — the same shape as
 * `identityExposureDisplay.js` and `caseDisplay.js`, which key off backend states and
 * are the surfaces in this codebase that already get absence right.
 *
 * The rule this exists to enforce: a score that does not exist has no band, and no
 * band renders in a risk colour. An unknown must LOOK unknown.
 */

/** Tone → Tailwind classes. Slate is the "we do not know" tone: never green, never red. */
export const TONE_CLASS = Object.freeze({
  healthy:  'bg-brand-50 text-brand-700 border border-brand-100',
  moderate: 'bg-amber-50 text-amber-700 border border-amber-100',
  elevated: 'bg-orange-50 text-orange-700 border border-orange-100',
  serious:  'bg-red-50 text-red-700 border border-red-100',
  unknown:  'bg-slate-100 text-slate-600 border border-slate-200',
});

/**
 * Bands the backend may publish in `portfolio_score_band`. A band is only ever
 * present when a finite score exists; absence is expressed by `null`, never by a
 * fallback word.
 */
export const SCORE_BAND_META = Object.freeze({
  healthy:  { label: 'Healthy',  tone: 'healthy'  },
  moderate: { label: 'Moderate', tone: 'moderate' },
  elevated: { label: 'Elevated', tone: 'elevated' },
  serious:  { label: 'Serious',  tone: 'serious'  },
});

/**
 * States the backend may publish in `portfolio_score_state`.
 *
 * `partial` is the subtle one. The score is real, so it keeps its band and colour —
 * but it speaks for only some of the portfolio, and the page must say so. Missing
 * customers must not quietly flatter the number.
 */
export const SCORE_STATE_META = Object.freeze({
  available:             { label: 'All environments assessed', tone: 'healthy', showsScore: true  },
  partial:               { label: 'Partial coverage',          tone: 'moderate', showsScore: true  },
  evidence_insufficient: { label: 'Insufficient evidence',     tone: 'unknown', showsScore: false },
  no_workspaces:         { label: 'Nothing monitored',         tone: 'unknown', showsScore: false },
});

/**
 * scoreBandMeta(band) → { label, tone } | null
 *
 * Returns null for null/undefined/unrecognised. Callers MUST render nothing (or an
 * explicit unknown) rather than substituting a default — a `?? SCORE_BAND_META.healthy`
 * here would reintroduce exactly the bug this module exists to prevent.
 */
export function scoreBandMeta(band) {
  if (!band || typeof band !== 'string') return null;
  return SCORE_BAND_META[band.toLowerCase()] ?? null;
}

/**
 * scoreStateMeta(state) → { label, tone, showsScore }
 *
 * Unrecognised states fall back to the UNKNOWN presentation, never to a benign one.
 * If the backend grows a state this file has not learned yet, the page says "we do not
 * know" — which is true — instead of guessing "fine".
 */
export function scoreStateMeta(state) {
  if (!state || typeof state !== 'string') return { label: 'Unknown', tone: 'unknown', showsScore: false };
  return SCORE_STATE_META[state.toLowerCase()] ?? { label: 'Unknown', tone: 'unknown', showsScore: false };
}

/** toneClass(tone) → classes. Unrecognised tone → the unknown tone, not a risk colour. */
export function toneClass(tone) {
  return TONE_CLASS[tone] ?? TONE_CLASS.unknown;
}

/**
 * hasRenderableScore(score) → boolean
 *
 * The single guard for "may this number be drawn?". `!= null` is not enough: NaN is
 * not null, and NaN survives every `>=` comparison to land in the last else — which is
 * how a non-finite score rendered as "Serious" in red. Rings, bars and `/100` labels
 * all gate on this.
 */
export function hasRenderableScore(score) {
  return Number.isFinite(score);
}

/**
 * scoreOutOfHundred(score) → 'NN/100' | null
 *
 * Returns null when there is no score, so callers omit the whole element. The page
 * previously rendered `{score ?? '—'}` next to an unconditional `/100`, producing
 * "—/100" — a denominator for a numerator that does not exist.
 */
export function scoreOutOfHundred(score) {
  return hasRenderableScore(score) ? `${score}/100` : null;
}
