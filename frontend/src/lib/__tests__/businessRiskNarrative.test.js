import { describe, expect, it } from 'vitest'
import { businessRiskNarrative, coverageIsIncomplete } from '../scoreHonesty'

const LOW = 'Business risk is low. No major gaps detected across email security, website trust, operational continuity, attack surface, or brand protection.'
const HIGH = 'Business risk is high. The top risks are: Domain can be spoofed and Website certificate expired.'
const complete = { scan_quality: 'complete', assessment_quality: 'complete', monitoring_state: 'monitoring_healthy', modules_skipped: [] }
const fullReport = { evidence_completeness: complete, executive_summary: { not_fully_assessed: [] } }
const liveShape = { evidence_completeness: complete, executive_summary: { not_fully_assessed: [{ domain_key: 'identity_exposure' }] } }

describe('businessRiskNarrative', () => {
  it('bounds the no-gaps sentence when an area is not fully assessed, even on a complete scan', () => {
    const text = businessRiskNarrative(LOW, liveShape)
    expect(text).not.toContain('No major gaps detected')
    expect(text).toContain('No major gaps were identified in the evidence available')
    expect(text).toContain('Coverage is incomplete')
  })

  it('never turns named risks into a no-gaps sentence', () => {
    const text = businessRiskNarrative(HIGH, liveShape)
    expect(text).toContain('Domain can be spoofed')
    expect(text).not.toContain('No major gaps')
    expect(text).toContain('Coverage is incomplete')
  })

  it('keeps the frozen sentence verbatim when coverage is complete', () => {
    expect(businessRiskNarrative(LOW, fullReport)).toBe(LOW)
    expect(businessRiskNarrative(HIGH, fullReport)).toBe(HIGH)
  })

  it('treats an unread report as unconfirmed coverage', () => {
    expect(coverageIsIncomplete(null)).toBe(true)
    expect(businessRiskNarrative(LOW, null)).not.toContain('No major gaps detected')
  })

  it.each([
    ['scan_quality', { scan_quality: 'partial' }],
    ['assessment_quality', { assessment_quality: 'partial' }],
    ['monitoring_state', { monitoring_state: 'monitoring_degraded' }],
    ['modules_skipped', { modules_skipped: ['asset_exposure'] }],
  ])('counts %s as incomplete', (_name, change) => {
    expect(coverageIsIncomplete({ evidence_completeness: { ...complete, ...change } })).toBe(true)
  })
})
