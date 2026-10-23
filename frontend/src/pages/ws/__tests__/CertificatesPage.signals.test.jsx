import { render, screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { CertificateSignalSection } from '../CertificatesPage'

// S1-SHELL-V2b (Certificates): Hostname match and Issuance policy (CAA) are their
// own sections, in the presentation engine's own words; nothing derived here.

const cert = (domain, signals) => ({ domain, certificate_assurance: { signals } })

describe('CertificateSignalSection', () => {
  it('hostname match shows the backend check verdict and its sentence, per domain', () => {
    render(<CertificateSignalSection id="cert-hostname-match" title="Hostname match" signalKey="hostname_match" certs={[
      cert('example.co.uk', { hostname_match: { state: 'observed', state_label: 'Observed', check: { outcome: 'passed', label: 'Covers example.co.uk' }, customer_message: 'The live certificate covers the connected name.' } }),
      cert('shop.example.co.uk', { hostname_match: { state: 'observed', state_label: 'Observed', check: { outcome: 'failed', label: 'Does not cover shop.example.co.uk' }, customer_message: 'The live certificate does not cover this name.' } }),
    ]} />)
    const section = screen.getByTestId('cert-hostname-match')
    expect(section).toHaveAttribute('id', 'cert-hostname-match')
    expect(within(section).getByText('Covers example.co.uk')).toBeInTheDocument()
    expect(within(section).getByText('Does not cover shop.example.co.uk')).toBeInTheDocument()
    expect(within(section).getByText('The live certificate does not cover this name.')).toBeInTheDocument()
  })
  it('CAA shows its state label and sentence; an unread signal says Unknown, never a pass', () => {
    render(<CertificateSignalSection id="cert-caa" title="Issuance policy (CAA)" signalKey="caa" certs={[
      cert('example.co.uk', { caa: { state: 'not_observed', state_label: 'Not observed', customer_message: 'The completed CAA lookup did not observe a CAA record.' } }),
      cert('other.example', {}),
    ]} />)
    const section = screen.getByTestId('cert-caa')
    expect(within(section).getByText('Not observed')).toBeInTheDocument()
    expect(within(section).getByText(/did not observe a CAA record/)).toBeInTheDocument()
    expect(within(section).getByText('Unknown')).toBeInTheDocument()
  })
  it('before any certificate is read it says so (the section still exists for the sidebar)', () => {
    render(<CertificateSignalSection id="cert-caa" title="Issuance policy (CAA)" signalKey="caa" certs={[]} />)
    expect(screen.getByTestId('cert-caa')).toHaveTextContent('No certificate has been read yet')
  })
  it('while loading it says Loading', () => {
    render(<CertificateSignalSection id="cert-caa" title="Issuance policy (CAA)" signalKey="caa" certs={[]} loading />)
    expect(screen.getByTestId('cert-caa')).toHaveTextContent('Loading…')
  })
})
