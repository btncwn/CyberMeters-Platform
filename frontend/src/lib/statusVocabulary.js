// Common status vocabulary — PRESENTATION ONLY.
//
// Every customer surface that shows "where does this area / this case stand"
// uses these words and no others. The frontend never decides a state: the
// eight-domain state comes from the backend resolver (cyber-mot-domains.js),
// freshness from the backend (evidence_freshness on the same payload), the
// case phase from the case API (canonical_phase) and how a case may be
// concluded from the case API (verification_support). This file only maps
// those backend values to one of the words below.
//
// Founder vocabulary (App Experience PR 2): Loading, Error, Not assessed,
// Evidence insufficient, Provisional, Established, Stale, Action required,
// In progress, Ready to verify, Verified, Recurring / reopened.
//
// Three further words exist because docs/verification-vocabulary.md is
// binding: a case that reached `verified` on the customer's word is shown as
// an attestation and never as "Verified"; one that needs an independent third
// party is neither; and a case in a terminal phase is "Closed" (PR 4 column).
//
// "Established" means what it means elsewhere in the product: an
// authoritative assessment exists for the area. It is not "healthy" — the
// backend summary next to the chip says what was concluded.

import { ATTESTED_LABEL, EXTERNAL_EVIDENCE_LABEL } from './caseDisplay'

export const STATUS_VOCABULARY = Object.freeze({
  loading:               { label: 'Loading',               tone: 'gray' },
  error:                 { label: 'Error',                 tone: 'red' },
  not_assessed:          { label: 'Not assessed',          tone: 'gray' },
  evidence_insufficient: { label: 'Evidence insufficient', tone: 'amber' },
  provisional:           { label: 'Provisional',           tone: 'amber' },
  established:           { label: 'Established',           tone: 'blue' },
  stale:                 { label: 'Stale',                  tone: 'amber' },
  action_required:       { label: 'Action required',       tone: 'red' },
  in_progress:           { label: 'In progress',           tone: 'amber' },
  ready_to_verify:       { label: 'Ready to verify',       tone: 'indigo' },
  verified:              { label: 'Verified',              tone: 'green' },
  recurring:             { label: 'Recurring / reopened',  tone: 'red' },
  attested:              { label: ATTESTED_LABEL,          tone: 'blue' },
  external:              { label: EXTERNAL_EVIDENCE_LABEL, tone: 'blue' },
  closed:                { label: 'Closed',                tone: 'gray' },
})

export const STATUS_KEYS = Object.freeze(Object.keys(STATUS_VOCABULARY))

export const STATUS_TONE_CLASS = Object.freeze({
  gray:   'bg-gray-50 text-gray-600 border-gray-200',
  red:    'bg-red-50 text-red-700 border-red-200',
  amber:  'bg-amber-50 text-amber-800 border-amber-200',
  blue:   'bg-blue-50 text-blue-700 border-blue-200',
  indigo: 'bg-indigo-50 text-indigo-700 border-indigo-200',
  green:  'bg-emerald-50 text-emerald-700 border-emerald-200',
})

export function statusMeta(key) {
  return STATUS_VOCABULARY[key] || STATUS_VOCABULARY.error
}

// ── Eight-domain state → vocabulary ──────────────────────────────────────────
// Backend CYBER_MOT_STATES → word. Anything the map does not know is shown as
// "Evidence insufficient": the honest floor is the weaker claim, never a
// settled one.
const DOMAIN_STATE_WORD = Object.freeze({
  not_yet_assessed:        'not_assessed',
  not_configured:          'not_assessed',
  evidence_insufficient:   'evidence_insufficient',
  unavailable:             'evidence_insufficient',
  provisional:             'provisional',
  degraded:                'provisional',
  assessed_healthy:        'established',
  monitoring_only:         'established',
  issue_detected:          'action_required',
  customer_input_required: 'action_required',
})

// Words that mean "something stands"; backend-stale evidence overrides them.
// An issue that needs action still needs it when the evidence is old.
const STALE_OVERRIDES = new Set(['established', 'provisional'])

/**
 * domainStatus(entry, request)
 *   entry   — one backend cyber_mot_domains row (or null/undefined)
 *   request — 'loading' | 'error' | 'ok' (how the request itself went)
 */
export function domainStatus(entry, request = 'ok') {
  if (request === 'loading') return 'loading'
  if (request === 'error') return 'error'
  if (!entry || typeof entry !== 'object' || typeof entry.state !== 'string') return 'error'
  let word = DOMAIN_STATE_WORD[entry.state] || 'evidence_insufficient'
  if (word === 'established' && entry.state === 'monitoring_only' && entry.coverage && entry.coverage !== 'complete') word = 'provisional'
  if (entry.evidence_freshness === 'stale' && STALE_OVERRIDES.has(word)) word = 'stale'
  return word
}

// ── Managed case phase → vocabulary ──────────────────────────────────────────
const OPEN_PHASES = Object.freeze({
  detected:              'action_required',
  triaged:               'action_required',
  assigned:              'action_required',
  approved:              'action_required',
  action_in_progress:    'in_progress',
  awaiting_verification: 'ready_to_verify',
  reopened:              'recurring',
})
const CONCLUDED_PHASES = new Set(['verified', 'monitoring'])
const TERMINAL_PHASES = new Set(['rejected', 'accepted_risk', 'false_positive', 'closed_no_action', 'superseded'])

export function caseStatus(caseRecord) {
  const phase = caseRecord?.canonical_phase || caseRecord?.status || null
  if (!phase) return 'error'
  if (OPEN_PHASES[phase]) return OPEN_PHASES[phase]
  if (CONCLUDED_PHASES.has(phase)) {
    // Fail closed, exactly as caseDisplay.phaseMeta: silence is an attestation.
    const support = caseRecord?.verification_support
    if (support === 'automated') return 'verified'
    if (support === 'external') return 'external'
    return 'attested'
  }
  if (TERMINAL_PHASES.has(phase)) return 'closed'
  // An unrecognised phase on a real case is a case someone must look at.
  return 'action_required'
}

export const OPEN_CASE_WORDS = new Set(['action_required', 'in_progress', 'ready_to_verify', 'recurring'])

/** Counts per vocabulary word plus the verification-support split, for one list of cases. */
export function summariseCases(cases) {
  const list = Array.isArray(cases) ? cases : []
  const byWord = {}
  const support = { automated: 0, manual: 0, external: 0, unsupported: 0 }
  let open = 0
  for (const c of list) {
    const word = caseStatus(c)
    byWord[word] = (byWord[word] || 0) + 1
    if (OPEN_CASE_WORDS.has(word)) open += 1
    const s = c?.verification_support
    if (s === 'automated' || s === 'manual' || s === 'external') support[s] += 1
    else support.unsupported += 1
  }
  return { total: list.length, open, byWord, support }
}
