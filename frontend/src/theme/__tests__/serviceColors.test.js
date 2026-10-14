import { describe, it, expect } from 'vitest'
import { SERVICE_COLORS, SERVICE_KEYS } from '../serviceColors'

// This suite guards the exact failure class that broke CI once: the shared
// sea-glass palette drifting apart between the launcher, dashboard and sidebar.
// Everything reads from SERVICE_COLORS, so these checks anchor the whole system.
describe('SERVICE_COLORS — sea-glass palette single source of truth', () => {
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
    // Sea-glass palette (founder, 14 Oct 2026): the ink is the identity.
    expect(SERVICE_COLORS.email.text).toBe('#2C5878')            // powder blue
    expect(SERVICE_COLORS.brand.text).toBe('#6E3C5C')            // lilac rose
    expect(SERVICE_COLORS.surface.text).toBe('#246656')          // sea glass
    expect(SERVICE_COLORS.certs.text).toBe('#2F5E72')            // harbour
    expect(SERVICE_COLORS.cyber_essentials.text).toBe('#3B6232') // mint
    expect(SERVICE_COLORS.website.text).toBe('#5E5232')          // sand
    expect(SERVICE_COLORS.identity.text).toBe('#48447E')         // lavender
    expect(SERVICE_COLORS.shadow_it.text).toBe('#4B5566')        // slate mist
  })

  it('keeps the domain identity colours visually distinct from each other', () => {
    const icons = SERVICE_KEYS.map(k => SERVICE_COLORS[k].icon)
    expect(new Set(icons).size).toBe(SERVICE_KEYS.length)
  })
})
