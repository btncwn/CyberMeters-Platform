import React from 'react'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import AboutPage from '../AboutPage'
import TrustPage from '../TrustPage'
import PrivacyPage from '../PrivacyPage'
import TermsPage from '../TermsPage'
import DpaPage from '../DpaPage'
const mount = Page => render(<MemoryRouter><Page /></MemoryRouter>)
describe('Founder and public assurance pages', () => {
  it('identifies the actual founder/operator and openly distinguishes AI assistance from independent testing', () => {
    mount(AboutPage)
    expect(screen.getByRole('heading', { name: 'Built and operated by Turhan Acar' })).toBeInTheDocument()
    expect(screen.getByText(/trading as a sole trader/)).toBeInTheDocument()
    expect(screen.getByText(/AI-generated code and reviews still need verification/)).toHaveTextContent('not independent third-party penetration tests')
    expect(screen.getByRole('link', { name: /See our own-domain check/ })).toHaveAttribute('href', '/trust')
    expect(document.body.textContent).not.toMatch(/Scotist|100\/100|years of experience/i)
  })
  it('keeps the real dated own-domain observation provisional and separate from the illustrative landing score', () => {
    mount(TrustPage)
    expect(screen.getByText('cybermeters.com', { exact: true })).toBeInTheDocument()
    expect(screen.getByText('9 October 2026 at 02:15:48 UTC')).toHaveAttribute('dateTime', '2026-10-09T02:15:48Z')
    expect(screen.getByText('90 — provisional')).toBeInTheDocument()
    expect(screen.getByText('16 scan modules recorded')).toBeInTheDocument(); expect(screen.getByText('4 endpoints')).toBeInTheDocument()
    expect(screen.getByText('Partial', { exact: true })).toBeInTheDocument()
    expect(screen.getByText(/crt.sh source did not complete/)).toHaveTextContent('CertSpotter returned results')
    expect(screen.getByText(/example.com scorecard/)).toHaveTextContent('separate, clearly labelled illustration')
    expect(document.body.textContent).not.toContain('100/100')
  })
  it('retains exact TLS and independent-assurance limitations beside the evidence', () => {
    mount(TrustPage)
    expect(screen.getByText(/recorded runtime trust store/)).toHaveTextContent('exact wire chain, OCSP and revocation status were not measured')
    expect(screen.getByText(/runtime-observed issuer chain/)).toHaveTextContent('not proof of the exact chain sent on the wire')
    expect(screen.getByText(/We do not claim a completed independent third-party penetration test/)).toHaveTextContent('SOC 2 attestation or ISO 27001 certification')
    expect(screen.getByText(/controlled Cloudflare recovery exercise/)).toHaveTextContent('does not establish an off-provider backup or guarantee a recovery time')
    expect(screen.queryByText(/planned before commercial general availability/)).not.toBeInTheDocument()
  })
  it('keeps optional breach lookup scope and privacy links consistent with existing provider flow', () => {
    mount(TrustPage)
    expect(screen.getByText(/Optional known-address breach checks use LeakCheck/)).toHaveTextContent('pseudonymous, not anonymous')
    expect(screen.getByRole('link', { name: 'Privacy Policy' })).toHaveAttribute('href', '/privacy')
    expect(screen.getByRole('link', { name: 'Data Processing Addendum' })).toHaveAttribute('href', '/dpa')
  })
  it.each([[PrivacyPage, 'Privacy Policy'], [TermsPage, 'Terms of Service'], [DpaPage, 'Data Processing Addendum']])('identifies the sole-trader operator on %s', (Page, heading) => {
    mount(Page); expect(screen.getByRole('heading', { level: 1, name: heading })).toBeInTheDocument()
    expect(screen.getByText(/Turhan Acar, a sole trader trading as CyberMeters/)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/Scotist|currently in public beta/i)
  })
})
