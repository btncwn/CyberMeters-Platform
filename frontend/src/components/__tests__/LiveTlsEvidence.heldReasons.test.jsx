import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { TlsAssessmentEvidence } from '../LiveTlsEvidence'

// TLS specials go-live (Executive 23:00): Seat 3's three held reasons read in
// plain words, never "Could not execute".
const assessmentWith = (reason, state = 'unexecutable') => ({
  source: 'tls_assessment', quality: 'complete', phase_state: 'complete',
  coverage: { planned: 1, completed: 0, uncertain: 0, unexecutable: 1, not_authorized: 0, not_applicable: 0 },
  endpoints: [{ hostname: 'example.com', address: '81.2.69.160', port: 443, application_protocol: 'https', checks: [
    { control: 'heartbleed', protocol: 'tls1_2', state, reason },
  ] }],
})

describe('LiveTlsEvidence held reasons', () => {
  it.each([
    ['address_not_verified_not_tested', 'Not tested — this address is not verified as yours'],
    ['authorised_runs_on_started_check', 'Not tested on this scan — authorised checks run only on scans you start yourself'],
  ])('%s', (reason, text) => {
    render(<TlsAssessmentEvidence assessment={assessmentWith(reason)} />)
    expect(screen.getAllByText(new RegExp(text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))).length).toBeGreaterThan(0)
    // The check's own line names the reason (the coverage counter above is separate).
    expect(document.body.textContent).not.toContain('heartbleed · tls1_2 — Could not execute')
  })
})

// Founder, 23 Oct 2026: a provider-infrastructure refusal names the host (and the
// provider when known) and links to where the customer adds their own servers.
describe('provider infrastructure', () => {
  it('names the host and says what to do, with the settings link', () => {
    render(<TlsAssessmentEvidence assessment={assessmentWith('provider_infrastructure_not_tested')} />)
    expect(document.body.textContent).toContain('Not tested — example.com is served by shared provider infrastructure. Add your own servers to test them.')
    expect(screen.getByRole('link', { name: 'Add your own servers' })).toHaveAttribute('href', '/ws/certificates?tab=settings#additional-tls-services')
  })
  it('names the provider when the evidence carries it', () => {
    const a = assessmentWith('provider_infrastructure_not_tested')
    a.endpoints[0].checks[0].provider_name = 'Cloudflare'
    render(<TlsAssessmentEvidence assessment={a} />)
    expect(document.body.textContent).toContain('example.com is served by shared provider infrastructure (Cloudflare).')
  })
})
