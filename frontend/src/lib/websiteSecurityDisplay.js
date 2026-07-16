// Shared presentation for the Website Security managed lifecycle (migration 089).
//
// The frontend NEVER decides a condition's state. It maps the server-owned vocabulary to
// a label and a tone, and where the server says it could not tell, this says so too.
//
// The distinction this file exists to protect: `no_longer_observed` and `unknown` are NOT
// the same thing, and the difference is the whole product. The first means the condition
// is gone AND the module that detects it provably ran on a complete scan. The second
// means CyberMeters did not look, or could not tell — and rendering that as green would
// tell a customer they fixed something when what actually happened is that we stopped
// being able to see it.

export const MONITORING_META = {
  observed:           { label: 'Observed',        tone: 'red',   hint: 'Currently observed on this site.' },
  no_longer_observed: { label: 'No longer seen',  tone: 'green', hint: 'Absent on a complete scan, and the check that detects it did run.' },
  // Deliberately NOT green, and deliberately not red either: it is neither good news nor
  // a finding. It is the absence of evidence, and it says so.
  unknown:            { label: 'Not determined',  tone: 'slate', hint: 'CyberMeters could not tell this time. This is not a fix.' },
  baseline:           { label: 'Pre-existing',    tone: 'slate', hint: 'Already present when monitoring began, so it was never announced as new.' },
}

// Why we could not tell. Server-owned (mig 089 `unknown_reason`).
export const UNKNOWN_REASON_META = {
  module_not_assessed: 'The check that detects this did not run on the latest scan.',
  scan_partial:        'The latest scan was partial, so absence is not evidence of a fix.',
  evidence_uncertain:  'The evidence weakened rather than clearing — we can no longer confirm it either way.',
}

export const SEVERITY_META = {
  critical: { label: 'Critical', tone: 'red'   },
  high:     { label: 'High',     tone: 'red'   },
  medium:   { label: 'Medium',   tone: 'amber' },
  low:      { label: 'Low',      tone: 'slate' },
  info:     { label: 'Info',     tone: 'slate' },
}

// Scan quality the condition was last graded on. Anything but `complete` means the state
// is provisional, and the UI must not present it as settled.
export const SCAN_QUALITY_META = {
  complete: { label: 'Complete evidence', tone: 'green' },
  partial:  { label: 'Partial evidence',  tone: 'amber' },
  degraded: { label: 'Degraded evidence', tone: 'amber' },
  unknown:  { label: 'Evidence unknown',  tone: 'slate' },
}

export const TONE_CLASS = {
  green: 'bg-emerald-50 text-emerald-700 border-emerald-100',
  amber: 'bg-amber-50 text-amber-700 border-amber-100',
  red:   'bg-red-50 text-red-700 border-red-100',
  blue:  'bg-blue-50 text-blue-700 border-blue-100',
  slate: 'bg-gray-100 text-gray-600 border-gray-200',
}
export const toneClass = (tone) => TONE_CLASS[tone] || TONE_CLASS.slate

// Unknown server values fall back to a NEUTRAL label, never a reassuring one: a state
// this build does not recognise is not evidence that nothing is wrong.
export const monitoringMeta = (s) => MONITORING_META[s] || { label: s || 'Unknown', tone: 'slate', hint: 'State not recognised by this version.' }
export const severityMeta   = (s) => SEVERITY_META[s]   || { label: s || 'Unrated', tone: 'slate' }
export const scanQualityMeta = (q) => SCAN_QUALITY_META[q] || { label: 'Evidence unknown', tone: 'slate' }
export const unknownReasonText = (r) => UNKNOWN_REASON_META[r] || (r ? String(r).replace(/_/g, ' ') : null)

// A condition is only settled when it is gone AND the evidence was complete. Used to
// decide whether the row may look calm — nothing else in the UI gets to make that call.
export const isSettled = (item) =>
  item?.monitoring_status === 'no_longer_observed' && item?.last_scan_quality === 'complete'

// A condition_key is a canonical slug (header_missing_strict_transport_security). The
// server sends a human title; this is the fallback when an older row has none.
export const conditionLabel = (item) =>
  item?.title || String(item?.condition_key || '').replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase())
