import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { durationSeconds, HeadersPanel } from '../ScanDetail'
import { customerEvidenceText } from '../../lib/evidenceStrengthDisplay'

// Executive, 21 Oct 2026 (sheshire.co.uk first scan): raw module keys on the
// report, a 61-minute duration for a one-minute scan, and HSTS/CSP "Missing"
// where the finding said "Validation Uncertain".

describe('scan duration', () => {
  it('reads D1 zone-less timestamps as UTC, so a 1m 22s scan never shows an extra hour', () => {
    expect(durationSeconds('2026-10-21 19:30:00', '2026-10-21T19:31:22.000Z')).toBe('1m 22s')
  })
})

describe('scan coverage reads as sentences, never machine codes', () => {
  const RAW = /\b[a-z][a-z0-9]*_[a-z0-9_]+\b/
  it.each([
    'Module incomplete: tls_assessment',
    'Module incomplete: subdomain_takeover',
    'Module skipped (subrequest budget): technology_detection',
    'subdomain_takeover: ran, but evidence was insufficient — host_probe_unconfirmed',
    'tls_assessment: ran, but evidence was insufficient — tls_endpoints_unobserved',
    'technology_detection: did not complete within the scan budget — not assessed',
  ])('%s', (raw) => {
    const text = customerEvidenceText(raw)
    expect(text).not.toMatch(RAW)
    expect(text).not.toMatch(/^Module /)
  })
  it('says which check did not finish, in words', () => {
    expect(customerEvidenceText('Module incomplete: tls_assessment')).toBe('Deep TLS checks did not finish.')
    expect(customerEvidenceText('subdomain_takeover: ran, but evidence was insufficient — host_probe_unconfirmed'))
      .toBe('subdomain takeover checks: ran, but evidence was insufficient — some hosts gave an answer that could not be confirmed')
  })
})

describe('headers table uses the finding’s word when a protection layer answered', () => {
  const headers = { accessible: true, present: ['x-content-type-options'], values: { 'x-content-type-options': 'nosniff' } }
  it('says "Validation uncertain", never "Missing", when the response may be from a protection layer', () => {
    render(<HeadersPanel headers={{ ...headers, validation_uncertain: true }} httpsAvailable />)
    expect(screen.queryByText('Missing')).toBeNull()
    expect(screen.getAllByText('Validation uncertain').length).toBeGreaterThan(0)
    expect(screen.getByTestId('headers-validation-uncertain')).toHaveTextContent('bot-protection or caching layer')
  })
  it('still says "Missing" when the website itself answered without the header', () => {
    render(<HeadersPanel headers={headers} httpsAvailable />)
    expect(screen.getAllByText('Missing').length).toBeGreaterThan(0)
    expect(screen.queryByText('Validation uncertain')).toBeNull()
  })
})
