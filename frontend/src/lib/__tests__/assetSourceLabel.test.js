import { describe, expect, it } from 'vitest'
import { assetSourceLabel } from '../assetSourceLabel'

describe('assetSourceLabel', () => {
  it('names every discovery source in customer words', () => {
    expect(assetSourceLabel('dns_discovery')).toBe('DNS discovery')
    expect(assetSourceLabel('dns_bruteforce')).toBe('DNS lookup')
    expect(assetSourceLabel('dns_mx')).toBe('Mail (MX) record')
    expect(assetSourceLabel('dns_srv')).toBe('Service (SRV) record')
    expect(assetSourceLabel('html_link')).toBe('Linked from your website')
    expect(assetSourceLabel('exposure_probe')).toBe('Web exposure check')
    expect(assetSourceLabel('scan_root')).toBe('Scanned domain')
    expect(assetSourceLabel('certificate_transparency')).toBe('Certificate log (historical)')
  })

  it('names every configuration reference confirmed by DNS', () => {
    expect(assetSourceLabel('tls_certificate_name')).toBe('Named in your website certificate')
    expect(assetSourceLabel('mx_target')).toBe('Your mail server (MX)')
    expect(assetSourceLabel('ns_target')).toBe('Your name server (NS)')
    expect(assetSourceLabel('spf_reference')).toBe('Named in your SPF record')
    expect(assetSourceLabel('dmarc_reference')).toBe('Named in your DMARC record')
    expect(assetSourceLabel('redirect_reference')).toBe('Reached by a website redirect')
    expect(assetSourceLabel('csp_reference')).toBe('Named in your Content-Security-Policy')
    expect(assetSourceLabel('link_header_reference')).toBe('Named in a website Link header')
    expect(assetSourceLabel('cors_reference')).toBe('Allowed by your website CORS policy')
  })

  it('shows an unrecognised code as-is and an absent one as a dash', () => {
    expect(assetSourceLabel('future_source')).toBe('future_source')
    expect(assetSourceLabel('toString')).toBe('toString')
    expect(assetSourceLabel('')).toBe('—')
    expect(assetSourceLabel(null)).toBe('—')
  })
})
