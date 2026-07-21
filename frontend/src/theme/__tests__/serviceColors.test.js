import { describe, it, expect } from 'vitest'
import { SERVICE_COLORS, SERVICE_KEYS } from '../serviceColors'

// This suite guards the exact failure class that broke CI once: the shared
// glacier palette drifting apart between the launcher, dashboard and sidebar.
// Everything reads from SERVICE_COLORS, so these checks anchor the whole system.
describe('SERVICE_COLORS — glacier palette single source of truth', () => {
  it('defines exactly the eight canonical domain presentation keys', () => {
    expect(SERVICE_KEYS.sort()).toEqual([
      'brand',
      'certs',
      'cyber_essentials',
      'email',
      'identity',
      'shadow_it',
      'surface',
      'website',
    ])
  })

  it('gives every domain a complete, valid-hex colour set', () => {
    const hex = /^#[0-9A-Fa-f]{6}$/
    for (const key of SERVICE_KEYS) {
      const c = SERVICE_COLORS[key]
      for (const field of ['icon', 'text', 'chip', 'card', 'ring', 'tint']) {
        expect(c[field], `${key}.${field}`).toMatch(hex)
      }
    }
  })

  it('keeps tint an alias of card (the sidebar hover state)', () => {
    for (const key of SERVICE_KEYS) {
      expect(SERVICE_COLORS[key].tint).toBe(SERVICE_COLORS[key].card)
    }
  })

  it('pins the domain identity icon colours so a silent change is caught', () => {
    // If these are intentionally re-themed, update this test in the same commit
    // — that is the point: the colour is a product decision, not an accident.
    expect(SERVICE_COLORS.email.icon).toBe('#1E5FDB')   // glacier blue
    expect(SERVICE_COLORS.brand.icon).toBe('#D6488E')   // rose (founder re-theme 21 Jul)
    expect(SERVICE_COLORS.surface.icon).toBe('#12938C') // glacier teal
    expect(SERVICE_COLORS.certs.icon).toBe('#1685C9')   // azure
    expect(SERVICE_COLORS.cyber_essentials.icon).toBe('#0F9F6E') // mint
    expect(SERVICE_COLORS.website.icon).toBe('#C77C16')          // gold
    expect(SERVICE_COLORS.identity.icon).toBe('#5B6EE1')         // periwinkle
    expect(SERVICE_COLORS.shadow_it.icon).toBe('#8A5CCB')        // violet
  })

  it('keeps the domain identity colours visually distinct from each other', () => {
    const icons = SERVICE_KEYS.map(k => SERVICE_COLORS[k].icon)
    expect(new Set(icons).size).toBe(SERVICE_KEYS.length)
  })
})
