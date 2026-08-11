import { describe, it, expect } from 'vitest'
import {
  CLASSIFICATION_META, RISK_META, OWNERSHIP_META, VERIFICATION_META, SURFACE_META, TONE_CLASS,
  classificationMeta, riskMeta, ownershipMeta, verificationMeta, surfaceLabel, toneClass,
  isAwaitingVerification, IDENTITY_SCOPE_NOTE,
} from '../identityExposureDisplay'

describe('identityExposureDisplay — canonical presentation of server-owned identity states', () => {
  it('maps the six customer classifications to labels + tones', () => {
    for (const c of ['unreviewed', 'expected', 'unexpected', 'investigate', 'exception', 'retired']) {
      const meta = classificationMeta(c)
      expect(meta.label).toBeTruthy()
      expect(TONE_CLASS[meta.tone]).toBeTruthy()
      expect(CLASSIFICATION_META[c]).toEqual(meta)
    }
    expect(Object.keys(CLASSIFICATION_META)).toHaveLength(6)
  })

  it('maps the five risk bands (explainable, not alarmist)', () => {
    for (const s of ['ok', 'low', 'attention', 'elevated', 'high']) {
      const meta = riskMeta(s)
      expect(meta.label).toBeTruthy()
      expect(TONE_CLASS[meta.tone]).toBeTruthy()
      expect(RISK_META[s]).toEqual(meta)
    }
    expect(riskMeta('ok').tone).toBe('green')
    expect(riskMeta('high').tone).toBe('red')
  })

  it('maps the three server-derived ownership statuses', () => {
    for (const s of ['known', 'partial', 'missing']) {
      const meta = ownershipMeta(s)
      expect(meta.label).toBeTruthy()
      expect(TONE_CLASS[meta.tone]).toBeTruthy()
      expect(OWNERSHIP_META[s]).toEqual(meta)
    }
  })

  it('maps verification states, and only verified reads green', () => {
    expect(verificationMeta('verified')).toEqual(VERIFICATION_META.verified)
    expect(verificationMeta('verified').tone).toBe('green')
    expect(verificationMeta('not_verified').tone).toBe('slate')
    expect(verificationMeta('failed').tone).toBe('red')
    expect(verificationMeta('inconclusive').tone).toBe('amber')
    expect(verificationMeta('unsupported').tone).toBe('slate')
    expect(verificationMeta('pending').tone).toBe('slate')
  })

  it('labels surface types and falls back to a humanized label', () => {
    expect(surfaceLabel('admin_login')).toBe(SURFACE_META.admin_login.label)
    expect(surfaceLabel('identity_provider')).toBe('Identity provider')
    expect(surfaceLabel('some_new_surface')).toBe('Some New Surface')
  })

  it('never invents a state — humanized fallback for unknown values', () => {
    expect(classificationMeta('future_state')).toEqual({ label: 'Future State', tone: 'slate' })
    expect(riskMeta('novel')).toEqual({ label: 'Novel', tone: 'slate' })
    expect(verificationMeta(null).label).toBe('—')
    expect(ownershipMeta(undefined).label).toBe('—')
  })

  it('toneClass resolves known tones and defaults to slate', () => {
    for (const t of ['green', 'red', 'amber', 'blue', 'slate']) expect(toneClass(t)).toBe(TONE_CLASS[t])
    expect(toneClass('nonexistent')).toBe(TONE_CLASS.slate)
  })

  it('isAwaitingVerification is true only for a recorded-but-unverified action', () => {
    expect(isAwaitingVerification({ remediation_status: 'customer_actioned', verification_status: 'not_verified' })).toBe(true)
    expect(isAwaitingVerification({ remediation_status: 'customer_actioned', verification_status: 'verified' })).toBe(false)
    expect(isAwaitingVerification({ remediation_status: 'in_progress', verification_status: 'not_verified' })).toBe(false)
    expect(isAwaitingVerification(null)).toBe(false)
  })

  it('carries the honest external-scope note (candidate is not reachability; no MFA/breach; classification != verification)', () => {
    expect(IDENTITY_SCOPE_NOTE).toMatch(/does not measure endpoint reachability/i)
    expect(IDENTITY_SCOPE_NOTE).toMatch(/leaked or breached credentials|dark-web/i)
    expect(IDENTITY_SCOPE_NOTE).toMatch(/classification is a decision, not a CyberMeters verification/i)
  })
})
