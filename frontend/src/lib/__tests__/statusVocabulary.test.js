import { describe, it, expect } from 'vitest'
import {
  STATUS_VOCABULARY, STATUS_KEYS, domainStatus, caseStatus, summariseCases, statusMeta,
} from '../statusVocabulary'
import { ATTESTED_LABEL } from '../caseDisplay'

// The common status vocabulary: the words every surface may use, and the ONLY
// mapping from backend values to them. Nothing here reads evidence.

const FOUNDER_WORDS = [
  'Loading', 'Error', 'Not assessed', 'Evidence insufficient', 'Provisional', 'Established',
  'Stale', 'Action required', 'In progress', 'Ready to verify', 'Verified', 'Recurring / reopened',
]

describe('vocabulary', () => {
  it('carries the twelve founder words plus the three the verification vocabulary requires', () => {
    const labels = STATUS_KEYS.map((k) => STATUS_VOCABULARY[k].label)
    for (const w of FOUNDER_WORDS) expect(labels).toContain(w)
    expect(labels).toContain(ATTESTED_LABEL)
    expect(labels).toContain('Closed')
    expect(STATUS_KEYS).toHaveLength(16)
  })

  it('an unknown word is shown as Error, never as a settled state', () => {
    expect(statusMeta('healthy').label).toBe('Error')
    expect(statusMeta(undefined).label).toBe('Error')
  })

  it('no vocabulary word is "Healthy", "Protected", "Connected" or "Resolved"', () => {
    const labels = STATUS_KEYS.map((k) => STATUS_VOCABULARY[k].label.toLowerCase())
    for (const banned of ['healthy', 'protected', 'connected', 'resolved', 'confirmed']) {
      expect(labels.some((l) => l.includes(banned))).toBe(false)
    }
  })
})

describe('domainStatus — backend eight-domain state → word', () => {
  const e = (state, extra = {}) => ({ domain_key: 'email_protection', state, ...extra })

  it('request states come first', () => {
    expect(domainStatus(e('assessed_healthy'), 'loading')).toBe('loading')
    expect(domainStatus(e('assessed_healthy'), 'error')).toBe('error')
  })

  it('a missing or malformed row is an error, never a state', () => {
    expect(domainStatus(null)).toBe('error')
    expect(domainStatus(undefined)).toBe('error')
    expect(domainStatus({ domain_key: 'email_protection' })).toBe('error')
    expect(domainStatus('assessed_healthy')).toBe('error')
  })

  it('maps every canonical resolver state', () => {
    expect(domainStatus(e('not_yet_assessed'))).toBe('not_assessed')
    expect(domainStatus(e('not_configured'))).toBe('not_assessed')
    expect(domainStatus(e('evidence_insufficient'))).toBe('evidence_insufficient')
    expect(domainStatus(e('unavailable'))).toBe('evidence_insufficient')
    expect(domainStatus(e('provisional'))).toBe('provisional')
    expect(domainStatus(e('degraded'))).toBe('provisional')
    expect(domainStatus(e('assessed_healthy'))).toBe('established')
    expect(domainStatus(e('issue_detected'))).toBe('action_required')
    expect(domainStatus(e('customer_input_required'))).toBe('customer_input')
    expect(statusMeta('customer_input').tone).toBe('hollow')
  })

  it('monitoring-only is established only on complete coverage', () => {
    expect(domainStatus(e('monitoring_only', { coverage: 'complete' }))).toBe('established')
    expect(domainStatus(e('monitoring_only', { coverage: 'degraded' }))).toBe('provisional')
    expect(domainStatus(e('monitoring_only', { coverage: 'partial' }))).toBe('provisional')
  })

  it('an unknown backend state falls to Evidence insufficient, never Established', () => {
    expect(domainStatus(e('all_good'))).toBe('evidence_insufficient')
    expect(domainStatus(e('healthy'))).toBe('evidence_insufficient')
  })

  it('backend-stale evidence overrides a standing conclusion but not a required action', () => {
    expect(domainStatus(e('assessed_healthy', { evidence_freshness: 'stale' }))).toBe('stale')
    expect(domainStatus(e('provisional', { evidence_freshness: 'stale' }))).toBe('stale')
    expect(domainStatus(e('issue_detected', { evidence_freshness: 'stale' }))).toBe('action_required')
    expect(domainStatus(e('not_yet_assessed', { evidence_freshness: 'stale' }))).toBe('not_assessed')
    // Only the backend's own word counts; age is never computed here.
    expect(domainStatus(e('assessed_healthy', { last_assessed_at: '2020-01-01T00:00:00Z' }))).toBe('established')
    expect(domainStatus(e('assessed_healthy', { evidence_freshness: 'aging' }))).toBe('established')
  })
})

describe('caseStatus — case phase + verification support → word', () => {
  it('open phases', () => {
    for (const p of ['detected', 'triaged', 'assigned', 'approved']) expect(caseStatus({ canonical_phase: p })).toBe('action_required')
    expect(caseStatus({ canonical_phase: 'action_in_progress' })).toBe('in_progress')
    expect(caseStatus({ canonical_phase: 'awaiting_verification' })).toBe('ready_to_verify')
    expect(caseStatus({ canonical_phase: 'reopened' })).toBe('recurring')
  })

  it('"Verified" only when CyberMeters re-observed the fix; silence is an attestation', () => {
    expect(caseStatus({ canonical_phase: 'verified', verification_support: 'automated' })).toBe('verified')
    expect(caseStatus({ canonical_phase: 'monitoring', verification_support: 'automated' })).toBe('verified')
    expect(caseStatus({ canonical_phase: 'verified', verification_support: 'manual' })).toBe('attested')
    expect(caseStatus({ canonical_phase: 'verified' })).toBe('attested')
    expect(caseStatus({ canonical_phase: 'verified', verification_support: 'unsupported' })).toBe('attested')
    expect(caseStatus({ canonical_phase: 'verified', verification_support: 'external' })).toBe('external')
    expect(STATUS_VOCABULARY.attested.label).toBe(ATTESTED_LABEL)
    expect(STATUS_VOCABULARY.attested.tone).not.toBe('filled')
  })

  it('terminal phases are Closed; falls back to status; unknown phase needs a look', () => {
    for (const p of ['rejected', 'accepted_risk', 'false_positive', 'closed_no_action', 'superseded']) expect(caseStatus({ canonical_phase: p })).toBe('closed')
    expect(caseStatus({ status: 'triaged' })).toBe('action_required')
    expect(caseStatus({ canonical_phase: 'something_new' })).toBe('action_required')
    expect(caseStatus(null)).toBe('error')
    expect(caseStatus({})).toBe('error')
  })
})

describe('summariseCases', () => {
  it('counts words, open cases and the verification-support split', () => {
    const s = summariseCases([
      { canonical_phase: 'triaged', verification_support: 'automated' },
      { canonical_phase: 'awaiting_verification', verification_support: 'manual' },
      { canonical_phase: 'verified', verification_support: 'automated' },
      { canonical_phase: 'verified', verification_support: 'manual' },
      { canonical_phase: 'reopened', verification_support: 'external' },
      { canonical_phase: 'rejected' },
    ])
    expect(s.total).toBe(6)
    expect(s.open).toBe(3)
    expect(s.byWord).toEqual({ action_required: 1, ready_to_verify: 1, verified: 1, attested: 1, recurring: 1, closed: 1 })
    expect(s.support).toEqual({ automated: 2, manual: 2, external: 1, unsupported: 1 })
  })

  it('tolerates garbage', () => {
    expect(summariseCases(null)).toEqual({ total: 0, open: 0, byWord: {}, support: { automated: 0, manual: 0, external: 0, unsupported: 0 } })
    expect(summariseCases([null, 'x']).total).toBe(2)
  })
})
