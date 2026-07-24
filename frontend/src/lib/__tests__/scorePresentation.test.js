import { describe, expect, it } from 'vitest'
import { assessmentBandLabel } from '../score-presentation'

describe('assessment band completeness label', () => {
  it('qualifies a canonical provisional assessment', () => {
    expect(assessmentBandLabel({
      assessment: { provisional: true },
      scanQuality: 'complete',
    })).toBe('Provisional assessment band')
  })

  it('uses partial scan quality as a legacy/loading fallback', () => {
    expect(assessmentBandLabel({
      assessment: null,
      scanQuality: 'partial',
    })).toBe('Provisional assessment band')
  })

  it('keeps the product-policy label for an authoritative assessment', () => {
    expect(assessmentBandLabel({
      assessment: { provisional: false },
      scanQuality: 'complete',
    })).toBe('CyberMeters assessment band')
  })
})
