import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { TlsAssessmentEvidence } from '../LiveTlsEvidence'

// S3-B (22 Oct 2026): an intrusive TLS check the customer has not authorised
// reads "Not tested — requires your authorisation", never a failure.
describe('LiveTlsEvidence intrusive-check wording', () => {
  it('states an unauthorised intrusive check plainly', () => {
    const assessment = {
      source: 'tls_assessment', quality: 'complete', phase_state: 'complete',
      coverage: { planned: 2, completed: 1, uncertain: 0, unexecutable: 0, not_authorized: 1, not_applicable: 0 },
      endpoints: [{ hostname: 'example.com', address: '81.2.69.160', port: 443, application_protocol: 'https', checks: [
        { control: 'protocol', protocol: 'tls1_2', state: 'accepted' },
        { control: 'heartbleed', protocol: 'tls1_2', state: 'not_authorized', reason: 'requires_customer_authorisation' },
      ] }],
    }
    render(<TlsAssessmentEvidence assessment={assessment} />)
    expect(screen.getAllByText(/Not tested — requires your authorisation/).length).toBeGreaterThan(0)
  })
})
