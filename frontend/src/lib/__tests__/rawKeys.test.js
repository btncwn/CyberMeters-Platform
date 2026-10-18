import { findRawKeys, RAW_KEY_PATTERN } from '../rawKeys'

// The shared detector for raw internal keys on screen (PR-C area pages, PR-D mapping table).

describe('findRawKeys', () => {
  it('finds snake_case backend keys and returns each once', () => {
    expect(findRawKeys('Status: plan_feature_required · email_missing_spf · email_missing_spf')).toEqual(['plan_feature_required', 'email_missing_spf'])
    expect(findRawKeys('shadow_it_unmanaged_technology needs review')).toEqual(['shadow_it_unmanaged_technology'])
  })
  it('ignores ordinary customer text, DNS names and hyphenated words', () => {
    expect(findRawKeys('Add Strict-Transport-Security to example.co.uk; check _dmarc.example.co.uk and selector1._domainkey.')).toEqual([])
    expect(findRawKeys('Not yet classified · 6 items · last seen 2026-10-16')).toEqual([])
  })
  it('exposes a global pattern for callers that scan in bulk', () => {
    expect(RAW_KEY_PATTERN.flags).toContain('g')
  })
})
