import { describe, it, expect } from 'vitest'
import {
  CLASSIFICATION_META, MONITORING_META, OWNERSHIP_META, TONE_CLASS,
  ONBOARDING_META, REMOVAL_META,
  REMOVAL_VERIFIED_DECLARED_DOMAIN, REMOVAL_VERIFIED_CONTRADICTED,
  REMOVAL_VERIFIED_NORMALIZED_TO_NULL, REMOVAL_VERIFIED_PASSES_THROUGH,
  classificationMeta, monitoringMeta, ownershipMeta, toneClass, SHADOW_IT_SCOPE_NOTE,
  onboardingMeta, removalMeta,
} from '../shadowItDisplay'

// ── F-47 — managed lifecycle presentation ───────────────────────────────────
// These states became customer-visible when F-47 added the onboarding/removal
// controls. The removal wording is the evidence-honesty boundary.
//
// CORRECTION (F-54). An earlier revision of this file asserted that the backend
// vocabulary was ONLY `contradicted | unverified | null`. That was FALSE:
// migration 084 declares four values including `verified`, the column is an
// unconstrained `TEXT` with no CHECK and no cleanup migration, and a NON-EMPTY
// stored value reaches this module unchanged. Independent verification
// reproduced a schema-valid `verified` reaching the serializer.
//
// The old suite therefore tested the CLAIM rather than the DOMAIN: it never
// exercised a `verified` input at all. These tests now drive the real
// legacy-capable domain — including `verified` and a value outside the declared
// set — and assert the fail-closed presentation contract holds for every one of
// them. Whether such a row exists in production is NOT MEASURED.
//
// SECOND CORRECTION (F-54 successor-2). The previous revision then overshot in
// the other direction, characterising the empty string as reaching this module
// unmodified. It does not: the serializer expression `row.removal_verified ||
// null` normalizes it to `null`. The reachability list below is now exactly the
// set demonstrated at that boundary by execution, and `''` is asserted only as
// defence in depth. Read the ACTUAL expression — not the narrowest or the
// widest reading of it.
describe('shadowItDisplay — managed lifecycle (F-47)', () => {
  it('maps the two backend onboarding statuses and nothing else', () => {
    for (const s of ['in_progress', 'onboarded']) {
      const meta = onboardingMeta(s)
      expect(meta.label).toBeTruthy()
      expect(TONE_CLASS[meta.tone]).toBeTruthy()
      expect(ONBOARDING_META[s]).toEqual(meta)
    }
    expect(Object.keys(ONBOARDING_META)).toHaveLength(2)
    expect(onboardingMeta(null)).toBeNull()
    expect(onboardingMeta(undefined)).toBeNull()
  })

  it('returns null when there is no removal state', () => {
    expect(removalMeta(null, null)).toBeNull()
    expect(removalMeta(undefined, 'unverified')).toBeNull()
  })

  it('never presents a customer-asserted removal as verified', () => {
    const meta = removalMeta('removed', 'unverified')
    expect(meta.label).toMatch(/your assertion, not verified by CyberMeters/i)
    expect(meta.label).not.toMatch(/\bverified removal\b|\bconfirmed\b/i)
    expect(meta.tone).toBe('amber')
  })

  it('treats a bare removed status with no verification signal as unverified too', () => {
    // Absence of a verification signal is NOT evidence of removal.
    expect(removalMeta('removed', null).label).toMatch(/not verified by CyberMeters/i)
  })

  it('escalates a contradicted removal above the customer assertion', () => {
    const meta = removalMeta('removed', 'contradicted')
    expect(meta.label).toMatch(/still observed, contradicts the assertion/i)
    expect(meta.tone).toBe('red')
  })

  it('renders removal in progress plainly, with no verification claim', () => {
    const meta = removalMeta('in_progress', null)
    expect(meta.label).toBe(REMOVAL_META.in_progress.label)
    expect(meta.label).not.toMatch(/verif/i)
  })

  it('surfaces a contradiction even while removal is only in progress', () => {
    expect(removalMeta('in_progress', 'contradicted').tone).toBe('red')
  })

  it('has no "verified" vocabulary anywhere in the removal base labels', () => {
    // About the presentation labels only — NOT a claim about the stored domain.
    for (const meta of Object.values(REMOVAL_META)) {
      expect(meta.label).not.toMatch(/verif|confirm/i)
    }
  })

  // ── F-54 — the real legacy-capable persisted domain ───────────────────────
  // The exact copy the customer must see for any non-contradicted value when the
  // customer has asserted removal. Asserted by equality, not by pattern: a
  // regex like /not verified/ would also pass for "verified removal — not
  // verified", which is the kind of near-miss this finding is about.
  const ASSERTION_COPY = 'Marked removed — your assertion, not verified by CyberMeters'

  it('declares the persisted domain migration 084 actually declares', () => {
    expect(REMOVAL_VERIFIED_DECLARED_DOMAIN).toEqual([null, 'verified', 'contradicted', 'unverified'])
    expect(REMOVAL_VERIFIED_DECLARED_DOMAIN).toContain('verified')
    expect(REMOVAL_VERIFIED_CONTRADICTED).toBe('contradicted')
  })

  it('renders a REAL legacy `verified` row as the customer assertion, never as confirmation', () => {
    // The exact input independent verification reproduced through the live list
    // serializer: schema-valid, unconstrained column, no cleanup migration.
    const meta = removalMeta('removed', 'verified')
    expect(meta.label).toBe(ASSERTION_COPY)
    expect(meta.tone).toBe('amber')
    expect(meta.tone).not.toBe('green')
    // The lookbehind matters: the honest copy legitimately CONTAINS "verified by
    // CyberMeters", negated by "not". A bare /verified by CyberMeters/ would
    // fail on correct output — the same near-miss this test exists to catch.
    expect(meta.label).not.toMatch(/\bverified removal\b|\bconfirmed\b|(?<!not )verified by CyberMeters/i)
  })

  it('renders an UNKNOWN non-contradicted value exactly like the known ones', () => {
    // Values outside the declared set. The column is unconstrained AND each of
    // these is demonstrated at the serializer boundary to arrive unchanged (see
    // REMOVAL_VERIFIED_PASSES_THROUGH), so they are genuinely reachable here.
    // The empty string is deliberately NOT in this list — it is normalized to
    // null upstream and never arrives as ''. It is covered separately below as
    // defence in depth, not as a reachability claim.
    for (const unknown of ['verification_grade_a', 'CONFIRMED', 'true']) {
      const meta = removalMeta('removed', unknown)
      expect(meta.label, `unknown value ${JSON.stringify(unknown)}`).toBe(ASSERTION_COPY)
      expect(meta.tone).toBe('amber')
    }
  })

  it('states the measured serializer boundary, and keeps the two sides disjoint', () => {
    // The empty string is normalized upstream; the non-empty values are not.
    expect(REMOVAL_VERIFIED_NORMALIZED_TO_NULL).toContain('')
    expect(REMOVAL_VERIFIED_PASSES_THROUGH).not.toContain('')
    // Nothing may appear on both sides, and nothing falsy may be claimed as
    // passing through — that was exactly the too-wide error this corrects.
    for (const v of REMOVAL_VERIFIED_PASSES_THROUGH) {
      expect(v, `pass-through value ${JSON.stringify(v)} must be non-empty`).toBeTruthy()
      expect(REMOVAL_VERIFIED_NORMALIZED_TO_NULL).not.toContain(v)
    }
    // The declared legacy value is among the demonstrated pass-through values.
    expect(REMOVAL_VERIFIED_PASSES_THROUGH).toContain('verified')
  })

  it('renders every DEMONSTRATED pass-through value fail-closed', () => {
    for (const v of REMOVAL_VERIFIED_PASSES_THROUGH.filter((x) => x !== 'contradicted')) {
      expect(removalMeta('removed', v).label, `pass-through ${JSON.stringify(v)}`).toBe(ASSERTION_COPY)
    }
  })

  it('renders the post-normalization value (null) for a stored empty string', () => {
    // What a stored '' actually becomes by the time it reaches this module.
    expect(removalMeta('removed', null).label).toBe(ASSERTION_COPY)
  })

  it('still fails closed on a raw empty string — defence in depth, not reachability', () => {
    // '' cannot arrive through the measured serializer. Asserted anyway so a
    // future direct caller or a changed boundary cannot produce a promotion.
    expect(removalMeta('removed', '').label).toBe(ASSERTION_COPY)
  })

  it('gives every declared non-contradicted value the identical customer copy', () => {
    for (const v of REMOVAL_VERIFIED_DECLARED_DOMAIN.filter((x) => x !== 'contradicted')) {
      expect(removalMeta('removed', v).label, `declared value ${JSON.stringify(v)}`).toBe(ASSERTION_COPY)
    }
  })

  it('keeps `contradicted` the ONLY value that renders the loud contradiction', () => {
    const loud = (v) => /contradicts the assertion/.test(removalMeta('removed', v)?.label || '')
    expect(loud('contradicted')).toBe(true)
    for (const v of [null, 'verified', 'unverified', 'verification_grade_a', 'CONTRADICTED']) {
      expect(loud(v), `value ${JSON.stringify(v)} must not be loud`).toBe(false)
    }
  })

  it('does not let a legacy `verified` claim confirmation while removal is in progress', () => {
    const meta = removalMeta('in_progress', 'verified')
    expect(meta.label).toBe(REMOVAL_META.in_progress.label)
    expect(meta.label).not.toMatch(/verif|confirm/i)
  })

  it('lets a contradiction outrank a stored `verified`', () => {
    // Observation beats the stored grade, in that order and never the reverse.
    expect(removalMeta('removed', 'contradicted').label).toMatch(/contradicts the assertion/)
    expect(removalMeta('removed', 'contradicted').tone).toBe('red')
  })
})

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
