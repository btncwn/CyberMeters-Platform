import { describe, expect, it } from 'vitest'
import { affectedLabel, conditionKeyLabel, isOpaqueId, keyLabel, keysInText } from '../keyLabel'

// Founder P1 (23 Oct 2026) and Codex C-45 R01–R26: no snake_case key reaches customer text.
describe('keyLabel', () => {
  it('reads enums as sentences; empty is null', () => {
    expect(keyLabel('awaiting_verification')).toBe('Awaiting verification')
    expect(keyLabel('retired_surface_reappeared')).toBe('Retired surface reappeared')
    expect(keyLabel('CERT_HAS_EXPIRED')).toBe('Cert has expired')
    expect(keyLabel('')).toBeNull()
    expect(keyLabel(null)).toBeNull()
  })
})

describe('conditionKeyLabel and affectedLabel (R01)', () => {
  it('names headers by their name', () => {
    expect(conditionKeyLabel('header_missing_strict_transport_security')).toBe('HSTS header missing')
    expect(conditionKeyLabel('header_malformed_content_security_policy')).toBe('Content-Security-Policy header malformed')
    expect(conditionKeyLabel('header_weak_hsts')).toBe('HSTS header weak')
  })
  it('the founder\'s case: "sheshire.co.uk — HSTS header missing", never the raw key', () => {
    expect(affectedLabel({ asset_ref: 'sheshire.co.uk:header_missing_strict_transport_security' })).toBe('sheshire.co.uk — HSTS header missing')
    expect(affectedLabel({ resource: 'https://www.example.org/login' })).toBe('https://www.example.org/login')
    expect(affectedLabel({ domain: 'example.org' })).toBe('example.org')
    expect(affectedLabel({})).toBeNull()
  })
})

describe('keysInText and isOpaqueId', () => {
  it('turns stray keys in prose into words, leaving domains, URLs and DNS labels alone', () => {
    expect(keysInText('Case moved to awaiting_verification for example.org')).toBe('Case moved to awaiting verification for example.org')
    expect(keysInText('Publish _dmarc.example.org at https://example.org/a_b')).toBe('Publish _dmarc.example.org at https://example.org/a_b')
  })
  it('recognises internal ids', () => {
    expect(isOpaqueId('usr_8f2c1a9b77')).toBe(true)
    expect(isOpaqueId('3f2b1c4d-1111-2222-3333-444455556666')).toBe(true)
    expect(isOpaqueId('Taylor Owner')).toBe(false)
  })
})
