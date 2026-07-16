// ── MSP Portfolio per-domain display contract — PRESENTATION ONLY ─────────────
// Maps the backend's canonical vocabulary to labels and tones. It derives NO state,
// NO trend and NO priority: every one of those is a decision the API already made, and
// a second opinion here is how the page and the API start disagreeing about the same
// customer.
//
// The rule this module exists to enforce, learned the expensive way in #117: a `??`
// fallback to a benign value is not a default, it is a fabrication. RiskBadge fell back
// to `badge-low`, so the backend's honest `unknown` rendered in low-risk blue on 15
// surfaces — a customer we knew nothing about looked identical to one verified fine.
// Every fallback below therefore resolves to UNKNOWN (slate), never to a safe-looking
// tone, and unrecognised input keeps its raw name rather than being smoothed away.

// Tones. Slate is the "we do not know" tone: never green, never red. Amber means "we
// looked and could not finish", which is a different thing from both.
export const DOMAIN_TONE = Object.freeze({
  healthy:  'bg-emerald-50 text-emerald-700 border-emerald-200',
  issue:    'bg-red-50 text-red-700 border-red-200',
  caution:  'bg-amber-50 text-amber-700 border-amber-200',
  info:     'bg-blue-50 text-blue-700 border-blue-200',
  unknown:  'bg-slate-100 text-slate-600 border-slate-200',
})

export const DOMAIN_STATE_META = Object.freeze({
  assessed_healthy:        { label: 'Healthy',               tone: 'healthy' },
  issue_detected:          { label: 'Issue detected',        tone: 'issue' },
  provisional:             { label: 'Provisional',           tone: 'caution' },
  degraded:                { label: 'Degraded',              tone: 'caution' },
  evidence_insufficient:   { label: 'Evidence insufficient', tone: 'caution' },
  customer_input_required: { label: 'Input required',        tone: 'info' },
  monitoring_only:         { label: 'Monitoring',            tone: 'info' },
  not_yet_assessed:        { label: 'Not assessed',          tone: 'unknown' },
  unavailable:             { label: 'Unavailable',           tone: 'unknown' },
  not_configured:          { label: 'Not configured',        tone: 'unknown' },
})

// Trend. Note there is no "flat" arrow: `stable` is a CLAIM (we compared two comparable
// assessments and they matched) and `insufficient_history` / `not_comparable` are the
// absence of one. Rendering both as a neutral dash would erase exactly the distinction
// the trend contract exists to preserve, so they get different words and different
// tones, and neither gets an arrow.
export const TREND_META = Object.freeze({
  improving:            { label: 'Improving',  symbol: '↑', tone: 'healthy', srLabel: 'improving' },
  recovered:            { label: 'Recovered',  symbol: '↑', tone: 'healthy', srLabel: 'recovered' },
  stable:               { label: 'Stable',     symbol: '→', tone: 'info',    srLabel: 'stable' },
  worsening:            { label: 'Worsening',  symbol: '↓', tone: 'issue',   srLabel: 'worsening' },
  new_risk:             { label: 'New risk',   symbol: '↓', tone: 'issue',   srLabel: 'new risk' },
  insufficient_history: { label: 'No history', symbol: '·', tone: 'unknown', srLabel: 'not enough history for a trend' },
  not_comparable:       { label: 'Not comparable', symbol: '·', tone: 'unknown', srLabel: 'not comparable' },
})

export const PRIORITY_META = Object.freeze({
  critical: { label: 'Critical', tone: 'issue' },
  high:     { label: 'High',     tone: 'issue' },
  medium:   { label: 'Medium',   tone: 'caution' },
  unknown:  { label: 'Unknown',  tone: 'unknown' },
  low:      { label: 'Low',      tone: 'healthy' },
})

export const FRESHNESS_META = Object.freeze({
  current: { label: 'Current', tone: 'healthy' },
  aging:   { label: 'Ageing',  tone: 'caution' },
  stale:   { label: 'Stale',   tone: 'issue' },
  none:    { label: 'Never assessed', tone: 'unknown' },
})

// Unrecognised → unknown, always. Never a benign default, and the raw value is kept as
// the label so an unmapped backend state is visible rather than silently smoothed into
// something reassuring.
const lookup = (map, key, fallbackLabel) => {
  const k = String(key ?? '').toLowerCase()
  return map[k] ?? { label: fallbackLabel ?? (key ? String(key) : 'Unknown'), tone: 'unknown', symbol: '·', srLabel: 'unknown' }
}

export const domainStateMeta = (s) => lookup(DOMAIN_STATE_META, s)
export const trendMeta       = (t) => lookup(TREND_META, t)
export const priorityMeta    = (p) => lookup(PRIORITY_META, p)
export const freshnessMeta   = (f) => lookup(FRESHNESS_META, f)
export const toneClass       = (t) => DOMAIN_TONE[t] ?? DOMAIN_TONE.unknown

// A score is renderable only if it is a real number. `!= null` passes NaN, which then
// passes every `>=` comparison and lands in the final else — that is #117's NaN leak.
export const hasScore = (s) => Number.isFinite(s)
