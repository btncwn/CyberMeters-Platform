import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { TlsAssessmentEvidence, endpointNotTestedReason } from '../LiveTlsEvidence'

// Founder live run (24 Oct 2026): an endpoint with no checks said "Assessed Not
// recorded / No controls recorded". It now says why, from the planner's own
// scope deferrals (assessment.scope_deferrals), in plain words.
const ep = { hostname: 'www.example.com', address: '203.0.113.20', port: 443, application_protocol: 'https', checks: [] }

describe('an endpoint that was not tested', () => {
  it.each([
    ['representative_address_scope', { endpoints: [{ hostname: 'www.example.com', port: 443, address: '203.0.113.20', reason: 'representative_address_scope' }] },
      'Not tested in this scan — CyberMeters tests one address per host and port, and another address for www.example.com:443 was tested.'],
    ['tls_plan_budget', { hosts: [{ hostname: 'www.example.com', port: 443, reason: 'tls_plan_budget' }] },
      'Not tested in this scan — the scan’s TLS check limit was reached before this service. It is not counted as passed.'],
    ['https_service_not_observed', { hosts: [{ hostname: 'www.example.com', port: 443, reason: 'https_service_not_observed' }] },
      'Not tested in this scan — no HTTPS service was observed on this host in this scan.'],
    ['non_https_service', { hosts: [{ hostname: 'www.example.com', port: 443, reason: 'non_https_service' }] },
      'Not tested in this scan — these checks test HTTPS services, and this service is not HTTPS.'],
  ])('%s reads in words', (_reason, deferrals, text) => {
    expect(endpointNotTestedReason(ep, deferrals)).toBe(text)
  })
  it('a deferral for another address or port does not apply', () => {
    expect(endpointNotTestedReason(ep, { endpoints: [{ hostname: 'www.example.com', port: 443, address: '203.0.113.99', reason: 'representative_address_scope' }],
      hosts: [{ hostname: 'www.example.com', port: 8443, reason: 'tls_plan_budget' }] }))
      .toBe('Not tested in this scan — no TLS checks were planned for this address. Its TLS status remains unknown.')
  })
  it('the card says why and "Assessed: Not tested in this scan", never "Not recorded"', () => {
    render(<TlsAssessmentEvidence assessment={{ source: 'tls_assessment', quality: 'complete', coverage: {}, endpoints: [ep],
      scope_deferrals: { endpoints: [{ hostname: 'www.example.com', port: 443, address: '203.0.113.20', reason: 'representative_address_scope' }], hosts: [] } }} />)
    expect(screen.getByTestId('tls-endpoint-not-tested')).toHaveTextContent('another address for www.example.com:443 was tested')
    expect(document.body.textContent).toContain('Assessed Not tested in this scan')
    expect(document.body.textContent).not.toContain('No controls recorded')
  })
  // F1 (24 Oct 2026): a special whose run kept failing is recorded by scan-api
  // as unexecutable / slice_failed. It reads as a finite "Could not complete",
  // never as "budget exhausted".
  it('a ROBOT check that could not complete says so in words', () => {
    render(<TlsAssessmentEvidence assessment={{ source: 'tls_assessment', quality: 'complete', coverage: {}, endpoints: [{ ...ep,
      checks: [{ control: 'protocol', protocol: 'tls1_2', state: 'accepted', observed_at: '2026-10-24T14:15:00Z' },
        { control: 'robot', protocol: 'tls1_2', state: 'unexecutable', reason: 'slice_failed', observed_at: '2026-10-24T14:16:00Z' }] }] }} />)
    expect(document.body.textContent).toContain('Could not complete — this check did not finish on this server after two attempts.')
    expect(document.body.textContent.toLowerCase()).not.toContain('budget exhausted')
  })
  it('a tested endpoint shows when its checks were observed', () => {
    render(<TlsAssessmentEvidence assessment={{ source: 'tls_assessment', quality: 'complete', coverage: {}, endpoints: [{ ...ep,
      checks: [{ control: 'protocol', protocol: 'tls1_2', state: 'accepted', observed_at: '2026-10-24T09:59:30Z' }] }] }} />)
    expect(document.body.textContent).toMatch(/Assessed 24 Oct 2026, 09:59 UTC/)
  })
})
