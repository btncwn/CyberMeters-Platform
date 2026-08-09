import { describe, expect, it } from 'vitest'
import {
  ASSET_LIFECYCLE_SUPPORT_PROJECTION_VERSION,
  assetLifecycleClaimDisplay,
  projectedCountDisplay,
} from '../assetLifecycleClaimDisplay'

describe('asset lifecycle claim display', () => {
  it('fails missing and unknown projection versions to not evaluated', () => {
    for (const lifecycle_claim_support of [undefined, { version: 'future-v2', state: 'supported' }]) {
      const result = assetLifecycleClaimDisplay({
        event_type: 'asset_no_longer_seen',
        title: 'Confirmed removed',
        description: 'Removed',
        lifecycle_claim_support,
      })
      expect(result.evaluated).toBe(false)
      expect(result.title).toContain('support not evaluated')
      expect(result.description).not.toContain('Removed')
    }
  })

  it('renders only recognised backend support states', () => {
    const result = assetLifecycleClaimDisplay({
      event_type: 'asset_reappeared',
      title: 'Externally observed again',
      description: 'Qualified backend wording',
      lifecycle_claim_support: {
        version: ASSET_LIFECYCLE_SUPPORT_PROJECTION_VERSION,
        state: 'unsupported',
      },
    })
    expect(result.title).toBe('Externally observed again')
    expect(result.supportLabel).toBe('Evidence not supported')
  })

  it('never turns missing projection counts into zero', () => {
    expect(projectedCountDisplay(0, null)).toEqual({ value: null, label: 'Not evaluated' })
    expect(projectedCountDisplay(0, {
      version: ASSET_LIFECYCLE_SUPPORT_PROJECTION_VERSION,
      coverage: 'complete',
    })).toEqual({ value: 0, label: '0' })
  })
})
