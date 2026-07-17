// ── Canonical score presentation (M5.e) ──
// The ONE place the frontend maps a Cyber Metrics Score or its band to labels,
// thresholds and tones. Pages must consume this module — a local `score >= N`
// ternary anywhere else is the drift class M5.e closed.
//
// MIRROR CONTRACT: SCORE_BANDS mirrors CYBER_METRICS_SCORE_BANDS in
// workers/scan-api/src/engines/scoring.js. There is deliberately no cross-build
// import (the worker module must not enter the browser bundle); the two are
// held value-identical by scripts/validate-band-ladder-contract.js, which fails
// CI if either side changes without the other.
//
// Honesty rules baked in:
//   • a null/undefined/non-finite score has NO band — never a color, never green;
//   • an unrecognised band name renders as unknown (neutral), never as healthy.

export const SCORE_BANDS = Object.freeze({
  excellent: 90,
  good: 75,
  moderate: 50,
  high: 25,
  // below `high` → critical
});

export function scoreBand(score) {
  // null/undefined are ABSENT, not zero — Number(null) would be 0/critical.
  if (score == null || score === '') return null;
  const n = Number(score);
  if (!Number.isFinite(n)) return null;
  const b = SCORE_BANDS;
  return n >= b.excellent ? 'excellent' :
    n >= b.good ? 'good' :
    n >= b.moderate ? 'moderate' :
    n >= b.high ? 'high' : 'critical';
}

// Presentation metadata per canonical band. `unknown` is the fail-closed
// default for absent scores and unrecognised band strings.
export const BAND_META = Object.freeze({
  excellent: { label: 'Excellent',       tone: 'brand',  text: 'text-brand-600',  pill: 'bg-brand-50 text-brand-700 border-brand-100',   color: '#00876A' },
  good:      { label: 'Good',            tone: 'brand',  text: 'text-brand-600',  pill: 'bg-brand-50 text-brand-700 border-brand-100',   color: '#00876A' },
  moderate:  { label: 'Moderate',        tone: 'amber',  text: 'text-amber-500',  pill: 'bg-amber-50 text-amber-700 border-amber-100',   color: '#F59E0B' },
  high:      { label: 'Needs Attention', tone: 'orange', text: 'text-orange-500', pill: 'bg-orange-50 text-orange-700 border-orange-100', color: '#F97316' },
  critical:  { label: 'Critical',        tone: 'red',    text: 'text-red-500',    pill: 'bg-red-50 text-red-700 border-red-100',          color: '#EF4444' },
  unknown:   { label: 'Not assessed',    tone: 'slate',  text: 'text-gray-400',   pill: 'bg-gray-100 text-gray-500 border-gray-200',      color: '#D1D5DB' },
});

export function bandMeta(band) {
  return BAND_META[band] ?? BAND_META.unknown;
}

export function metaForScore(score) {
  const band = scoreBand(score);
  return band ? BAND_META[band] : BAND_META.unknown;
}
