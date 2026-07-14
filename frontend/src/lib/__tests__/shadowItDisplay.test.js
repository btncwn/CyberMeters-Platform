import { describe, it, expect } from 'vitest'
import {
  CLASSIFICATION_META, MONITORING_META, OWNERSHIP_META, TONE_CLASS,
  classificationMeta, monitoringMeta, ownershipMeta, toneClass, SHADOW_IT_SCOPE_NOTE,
} from '../shadowItDisplay'

describe('shadowItDisplay — canonical presentation of server-owned states', () => {
  it('maps the five backend classifications to labels + tones', () => {
    for (const c of ['unreviewed', 'approved', 'rejected', 'exception', 'retired']) {
      const meta = classificationMeta(c)
      expect(meta.label).toBeTruthy()
      expect(TONE_CLASS[meta.tone]).toBeTruthy()
      expect(CLASSIFICATION_META[c]).toEqual(meta)
    }
    expect(Object.keys(CLASSIFICATION_META)).toHaveLength(5)
  })

  it('maps the three server-derived ownership statuses (separate from classification)', () => {
    for (const s of ['known', 'partial', 'missing']) {
      const meta = ownershipMeta(s)
      expect(meta.label).toBeTruthy()
      expect(TONE_CLASS[meta.tone]).toBeTruthy()
      expect(OWNERSHIP_META[s]).toEqual(meta)
    }
    expect(ownershipMeta('other').tone).toBe('slate')
  })

  it('maps the three monitoring states to labels + tones', () => {
    for (const s of ['observed', 'no_longer_observed', 'reappeared']) {
      const meta = monitoringMeta(s)
      expect(meta.label).toBeTruthy()
      expect(TONE_CLASS[meta.tone]).toBeTruthy()
      expect(MONITORING_META[s]).toEqual(meta)
    }
  })

  it('falls back to a humanized label (never invents a state) for unknown values', () => {
    expect(classificationMeta('some_future_state')).toEqual({ label: 'Some Future State', tone: 'slate' })
    expect(monitoringMeta('brand_new')).toEqual({ label: 'Brand New', tone: 'slate' })
    expect(classificationMeta(null).label).toBe('—')
    expect(monitoringMeta(undefined).label).toBe('—')
  })

  it('toneClass resolves known tones and defaults to slate', () => {
    expect(toneClass('green')).toBe(TONE_CLASS.green)
    expect(toneClass('red')).toBe(TONE_CLASS.red)
    expect(toneClass('amber')).toBe(TONE_CLASS.amber)
    expect(toneClass('blue')).toBe(TONE_CLASS.blue)
    expect(toneClass('slate')).toBe(TONE_CLASS.slate)
    expect(toneClass('nonexistent')).toBe(TONE_CLASS.slate)
  })

  it('carries the honest external-scope note', () => {
    expect(SHADOW_IT_SCOPE_NOTE).toMatch(/externally observed/i)
    expect(SHADOW_IT_SCOPE_NOTE).toMatch(/not a security guarantee/i)
    expect(SHADOW_IT_SCOPE_NOTE).toMatch(/rejected is not removal/i)
  })
})
