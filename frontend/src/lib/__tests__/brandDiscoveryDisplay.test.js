import { describe, it, expect } from 'vitest'
import { brandDiscoveryOutcome, BRAND_DISCOVERY_BOUNDARY } from '../brandDiscoveryDisplay'

describe('brandDiscoveryOutcome', () => {
  it('reports new candidates and asks for a refresh', () => {
    const o = brandDiscoveryOutcome({ status: 200, body: { inserted: 2, updated: 1, merged: 0 } })
    expect(o.title).toBe('2 new lookalike candidates found.')
    expect(o.detail).toMatch(/1 existing candidate was refreshed/)
    expect(o.tone).toBe('success')
    expect(o.refresh).toBe(true)
  })

  it('says nothing new was found without implying the brand is safe', () => {
    const o = brandDiscoveryOutcome({ status: 200, body: { inserted: 0, updated: 0 } })
    expect(o.title).toBe('No new lookalike candidates found.')
    expect(`${o.title} ${o.detail || ''}`).not.toMatch(/safe|protected|no threats|secure/i)
  })

  it('a partial run is a warning, never a clean success', () => {
    const o = brandDiscoveryOutcome({ status: 200, body: { inserted: 0, partial: true } })
    expect(o.tone).toBe('warning')
    expect(o.detail).toMatch(/partial/)
  })

  it('explains each refusal without a raw code', () => {
    const cases = [
      [{ status: 409, body: { error: 'brand_profile_required' } }, /brand profile first/],
      [{ status: 403, body: { error: 'domain_verification_required' } }, /Verify your primary domain/],
      [{ status: 403, body: { error: 'Forbidden' } }, /permission/],
      [{ status: 429, body: { code: 'rate_limit_exceeded' } }, /run recently/],
      [{ status: 502, body: { error: 'brand_discovery_upstream_unavailable' } }, /could not be reached/],
      [{ status: 500, body: {} }, /could not be completed/],
    ]
    for (const [result, re] of cases) {
      const o = brandDiscoveryOutcome(result)
      expect(o.title).toMatch(re)
      expect(o.refresh).toBe(false)
      expect(`${o.title} ${o.detail || ''}`).not.toMatch(/_required|rate_limit|upstream_unavailable/)
    }
  })

  it('the rate limit is never framed as a plan upgrade', () => {
    const o = brandDiscoveryOutcome({ status: 429, body: { upgrade_message: 'Upgrade your plan for higher scan limits.' } })
    expect(`${o.title} ${o.detail}`).not.toMatch(/upgrade|plan/i)
  })

  it('boundary wording does not overclaim', () => {
    expect(BRAND_DISCOVERY_BOUNDARY).toMatch(/not proof of abuse/)
    expect(BRAND_DISCOVERY_BOUNDARY).not.toMatch(/attack|phishing|compromise|scan the internet/i)
  })
})
