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
    expect(assetSourceLabel('bimi_reference')).toBe('Named in your BIMI record')
    expect(assetSourceLabel('redirect_reference')).toBe('Reached by a website redirect')
    expect(assetSourceLabel('csp_reference')).toBe('Named in your Content-Security-Policy')
    expect(assetSourceLabel('link_header_reference')).toBe('Named in a website Link header')
    expect(assetSourceLabel('cors_reference')).toBe('Allowed by your website CORS policy')
  })

  it('names every deeper DNS discovery source', () => {
    expect(assetSourceLabel('dns_wordlist')).toBe('DNS lookup (extended name list)')
    expect(assetSourceLabel('dns_name_variant')).toBe('Name pattern check')
    expect(assetSourceLabel('dnssec_nsec')).toBe('Listed in your DNSSEC zone records')
  })

  it('names hostnames the customer listed', () => {
    expect(assetSourceLabel('customer_list')).toBe('Listed by you')
  })

  it('names hostnames the site\'s own files name', () => {
    expect(assetSourceLabel('robots_reference')).toBe('Named in your robots.txt')
    expect(assetSourceLabel('sitemap_reference')).toBe('Listed in your sitemap')
    expect(assetSourceLabel('script_reference')).toBe("Named in your website's scripts")
  })

  it('shows an unrecognised code as-is and an absent one as a dash', () => {
    expect(assetSourceLabel('future_source')).toBe('future_source')
    expect(assetSourceLabel('toString')).toBe('toString')
    expect(assetSourceLabel('')).toBe('—')
    expect(assetSourceLabel(null)).toBe('—')
  })
})
