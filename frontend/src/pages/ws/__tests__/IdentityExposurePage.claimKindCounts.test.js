import { describe, expect, it } from 'vitest'
import { allChipLabel, identitySummaryFigures } from '../IdentityExposurePage'

// #942 (Executive 19:55): the claim-kind figures read the backend's workspace-wide
// counts.by_claim_kind — exact when complete, "N+" past its bound, "Not available"
// when it could not count; a page count never stands in for them.
const values = (f) => Object.fromEntries(f.map((x) => [x.id, x.value]))
const item = (kind) => ({ identity_claim: { claim_kind: kind } })

describe('Identity figures from counts.by_claim_kind', () => {
  it('complete counts are exact, even when the loaded page is full', () => {
    const counts = { unreviewed: 4, by_claim_kind: { provider_relationship: 12, surface_candidate: 700, measured_identity_surface: 3, complete: true, counted: 715 } }
    expect(values(identitySummaryFigures({ status: 'ok', items: [item('surface_candidate')], counts, atLimit: true }))).toEqual({
      'identity-providers-observed': 12, 'identity-hostnames-possible': 700, 'identity-measured': 3, 'identity-unreviewed': 4,
    })
    expect(allChipLabel({ status: 'ok', items: [], counts, atLimit: true })).toBe('All (715)')
  })
  it('past the backend bound the counts read "N+"', () => {
    const counts = { unreviewed: 9, by_claim_kind: { provider_relationship: 20, surface_candidate: 4970, measured_identity_surface: 10, complete: false, counted: 5000 } }
    const f = values(identitySummaryFigures({ status: 'ok', items: [], counts }))
    expect(f['identity-hostnames-possible']).toBe('4970+')
    expect(f['identity-unreviewed']).toBe(9)
    expect(allChipLabel({ status: 'ok', items: [], counts })).toBe('All (5000+)')
  })
  it('a count without complete: true is never presented as exact', () => {
    const counts = { unreviewed: 0, by_claim_kind: { provider_relationship: 2, surface_candidate: 3, measured_identity_surface: 1, counted: 6 } }
    expect(values(identitySummaryFigures({ status: 'ok', items: [], counts }))['identity-providers-observed']).toBe('2+')
    expect(allChipLabel({ status: 'ok', items: [], counts })).toBe('All (6+)')
  })
  it('by_claim_kind null (the backend could not count) → "Not available", never a page count', () => {
    const f = values(identitySummaryFigures({ status: 'ok', items: [item('provider_relationship')], counts: { unreviewed: 1, by_claim_kind: null } }))
    expect(f['identity-providers-observed']).toBe('Not available')
    expect(f['identity-measured']).toBe('Not available')
    expect(f['identity-unreviewed']).toBe(1)
  })
  it('an older response without the field keeps the page-count rule', () => {
    expect(values(identitySummaryFigures({ status: 'ok', items: [item('provider_relationship')], counts: { unreviewed: 0 }, atLimit: true }))['identity-providers-observed']).toBe('1+')
  })
})
