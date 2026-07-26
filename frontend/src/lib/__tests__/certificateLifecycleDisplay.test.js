import { describe, it, expect } from 'vitest'
import {
  READINESS_META, COVERAGE_META, OWNERSHIP_META, VERIFICATION_META, TONE_CLASS,
  readinessMeta, coverageMeta, ownershipMeta, verificationMeta, toneClass,
  daysRemainingLabel, isAwaitingVerification, certificateRelationshipMessage,
  CERT_LIFECYCLE_SCOPE_NOTE,
} from '../certificateLifecycleDisplay'

describe('certificateLifecycleDisplay — canonical presentation of server-owned certificate states', () => {
  it('maps the renewal readiness bands to labels + tones', () => {
    for (const s of ['monitoring', 'planning', 'preparation', 'high', 'critical', 'expired', 'unknown']) {
      const meta = readinessMeta(s)
      expect(meta.label).toBeTruthy()
      expect(TONE_CLASS[meta.tone]).toBeTruthy()
      expect(READINESS_META[s]).toEqual(meta)
    }
  })

  it('maps the five coverage statuses (expected vs observed) to labels + tones', () => {
    for (const s of ['complete', 'partial', 'missing', 'unexpected', 'unknown']) {
      const meta = coverageMeta(s)
      expect(meta.label).toBeTruthy()
      expect(TONE_CLASS[meta.tone]).toBeTruthy()
      expect(COVERAGE_META[s]).toEqual(meta)
    }
  })

  it('maps the three server-derived ownership statuses', () => {
    for (const s of ['known', 'partial', 'missing']) {
      const meta = ownershipMeta(s)
      expect(meta.label).toBeTruthy()
      expect(TONE_CLASS[meta.tone]).toBeTruthy()
      expect(OWNERSHIP_META[s]).toEqual(meta)
    }
  })

  it('maps verification states, and only verified_replaced reads as green/verified', () => {
    expect(verificationMeta('verified_replaced')).toEqual(VERIFICATION_META.verified_replaced)
    expect(verificationMeta('verified_replaced').tone).toBe('green')
    expect(verificationMeta('not_verified').tone).toBe('slate')
    expect(verificationMeta('failed').tone).toBe('red')
    expect(verificationMeta('inconclusive').tone).toBe('amber')
  })

  it('falls back to a humanized label (never invents a state) for unknown values', () => {
    expect(readinessMeta('some_future_band')).toEqual({ label: 'Some Future Band', tone: 'slate' })
    expect(coverageMeta('novel')).toEqual({ label: 'Novel', tone: 'slate' })
    expect(verificationMeta(null).label).toBe('—')
    expect(ownershipMeta(undefined).label).toBe('—')
  })

  it('toneClass resolves known tones and defaults to slate', () => {
    for (const t of ['green', 'red', 'amber', 'blue', 'slate']) expect(toneClass(t)).toBe(TONE_CLASS[t])
    expect(toneClass('nonexistent')).toBe(TONE_CLASS.slate)
  })

  it('daysRemainingLabel never claims safety it cannot see', () => {
    expect(daysRemainingLabel(null)).toBe('Expiry unknown')
    expect(daysRemainingLabel(-3)).toBe('Expired 3d ago')
    expect(daysRemainingLabel(0)).toBe('Expires today')
    expect(daysRemainingLabel(42)).toBe('42d remaining')
  })

  it('isAwaitingVerification is true only for a recorded-but-unverified replacement', () => {
    expect(isAwaitingVerification({ renewal_status: 'awaiting_verification', verification_status: 'not_verified' })).toBe(true)
    expect(isAwaitingVerification({ renewal_status: 'awaiting_verification', verification_status: 'verified_replaced' })).toBe(false)
    expect(isAwaitingVerification({ renewal_status: 'monitoring', verification_status: 'not_verified' })).toBe(false)
    expect(isAwaitingVerification(null)).toBe(false)
  })

  it('renders only the backend-owned replacement/parallel relationship wording', () => {
    expect(certificateRelationshipMessage({
      certificate_assurance: {
        relationship: {
          customer_message: 'One canonical transition-context explanation.',
        },
      },
    })).toBe('One canonical transition-context explanation.')
    expect(certificateRelationshipMessage({ replacement_detected_at: '2026-07-26' })).toBeNull()
  })

  it('carries the honest external-scope note (unknown chain/root/OCSP, recorded != verified)', () => {
    expect(CERT_LIFECYCLE_SCOPE_NOTE).toMatch(/externally observed/i)
    expect(CERT_LIFECYCLE_SCOPE_NOTE).toMatch(/chain, root acceptance, ocsp/i)
    expect(CERT_LIFECYCLE_SCOPE_NOTE).toMatch(/not verified until/i)
  })
})
