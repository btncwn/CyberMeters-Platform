import { describe, expect, it } from 'vitest'
import { assetSourceLabel } from '../assetSourceLabel'

describe('assetSourceLabel', () => {
  it('names every discovery source in customer words', () => {
    expect(assetSourceLabel('certificate_transparency')).toBe('Certificate Transparency')
    expect(assetSourceLabel('dns_bruteforce')).toBe('DNS lookup')
    expect(assetSourceLabel('dns_mx')).toBe('Mail (MX) record')
    expect(assetSourceLabel('dns_srv')).toBe('Service (SRV) record')
    expect(assetSourceLabel('html_link')).toBe('Linked from your website')
    expect(assetSourceLabel('exposure_probe')).toBe('Web exposure check')
    expect(assetSourceLabel('scan_root')).toBe('Scanned domain')
  })

  it('shows an unrecognised code as-is and an absent one as a dash', () => {
    expect(assetSourceLabel('future_source')).toBe('future_source')
    expect(assetSourceLabel('toString')).toBe('toString')
    expect(assetSourceLabel('')).toBe('—')
    expect(assetSourceLabel(null)).toBe('—')
  })
})
