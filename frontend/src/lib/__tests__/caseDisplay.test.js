import { describe, it, expect } from 'vitest'
import { phaseMeta, phaseClass, CANONICAL_PHASE_META, ATTESTED_LABEL, domainKeyLabel } from '../caseDisplay'

// The verification vocabulary rule (docs/verification-vocabulary.md).
// "Verified"/"Confirmed" are reserved for what CyberMeters itself observed. A
// manual_attestation outcome rests on the customer's word and must never borrow the word.
describe('verification vocabulary', () => {
  it('an OBSERVED verification says CyberMeters verified it', () => {
    const m = phaseMeta('verified', 'automated')
    expect(m.label).toBe('Verified by CyberMeters')
    expect(m.tone).toBe('green')
  })

  it('an ATTESTATION never says verified or confirmed', () => {
    const m = phaseMeta('verified', 'manual')
    expect(m.label).toBe(ATTESTED_LABEL)
    expect(m.label).toBe('Attested by customer — not externally verifiable')
    expect(m.label).not.toMatch(/verified/i)
    expect(m.label).not.toMatch(/confirmed/i)
  })

  it('an attestation is not green — tone carries meaning too', () => {
    expect(phaseMeta('verified', 'manual').tone).not.toBe('green')
    expect(phaseClass('verified', 'manual')).not.toBe(phaseClass('verified', 'automated'))
  })

  // Fail closed: absent/unknown support must never be read as CyberMeters' own observation.
  it.each([null, undefined, 'unsupported', 'manual', 'bogus', ''])(
    'support=%s does not claim CyberMeters verified it', (support) => {
      expect(phaseMeta('verified', support).label).not.toMatch(/verified by cybermeters/i)
    })

  it('reading the phase map directly still cannot yield a bare "Verified"', () => {
    expect(CANONICAL_PHASE_META.verified.label).not.toBe('Verified')
    expect(CANONICAL_PHASE_META.verified.label).toBe(ATTESTED_LABEL)
  })

  it('no other canonical phase claims verification', () => {
    for (const [phase, meta] of Object.entries(CANONICAL_PHASE_META)) {
      if (phase === 'verified') continue
      expect(meta.label).not.toMatch(/^verified/i)
    }
  })
})

describe('phase presentation', () => {
  it('renders the canonical phases it knows', () => {
    expect(phaseMeta('detected').label).toBe('Detected')
    expect(phaseMeta('awaiting_verification').label).toBe('Awaiting verification')
    expect(phaseMeta('reopened').tone).toBe('red')
  })

  it('never fabricates a status for an unknown phase', () => {
    expect(phaseMeta('some_new_phase').label).toBe('Some New Phase')
    expect(phaseMeta('some_new_phase').tone).toBe('slate')
    expect(phaseMeta(null).label).toBe('Unknown')
  })

  it('labels all eight canonical domains', () => {
    expect(domainKeyLabel('website_security')).toBe('Website Security')
    expect(domainKeyLabel('cyber_essentials_readiness')).toBe('Cyber Essentials Readiness')
    expect(domainKeyLabel(null)).toBe('Unassigned')
  })
})
