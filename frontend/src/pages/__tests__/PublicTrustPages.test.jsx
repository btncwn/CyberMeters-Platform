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
    expect(document.body.textContent).not.toMatch(/small businesses, startups|digital agencies|small teams/i)
  })
  it('keeps the real dated own-domain observation provisional and separate from the illustrative landing score', () => {
    mount(TrustPage)
    expect(screen.getByText('cybermeters.com', { exact: true })).toBeInTheDocument()
    expect(screen.getByText('14 October 2026 at 11:16:05 UTC')).toHaveAttribute('dateTime', '2026-10-14T11:16:05.640Z')
    expect(screen.getByText('Score available after a complete scan')).toBeInTheDocument()
    expect(screen.queryByText(/100\/100/)).not.toBeInTheDocument()
    expect(screen.getByText('4 Cloudflare edge endpoints')).toBeInTheDocument()
    expect(screen.getByText('Partial', { exact: true })).toBeInTheDocument()
    expect(screen.getByText(/The TLS assessment completed 162/)).toHaveTextContent('346 were uncertain')
    expect(screen.getByText(/The separately permitted Heartbleed/)).toHaveTextContent('Heartbleed remained inconclusive')
    expect(screen.getByText(/example.co.uk sample on our home page/)).toHaveTextContent('separate, clearly labelled illustration')
  })
  it('retains exact TLS and independent-assurance limitations beside the evidence', () => {
    mount(TrustPage)
    expect(screen.getByText(/endpoint assessment records offered certificate-chain/)).toHaveTextContent('no external revocation lookup was performed')
    expect(screen.getByText(/endpoint assessment records offered certificate-chain/)).toHaveTextContent('do not assess QUIC or the origin behind Cloudflare')
    expect(screen.getByText(/We do not claim a completed independent third-party penetration test/)).toHaveTextContent('SOC 2 attestation or ISO 27001 certification')
    expect(screen.getByText(/controlled Cloudflare recovery exercise/)).toHaveTextContent('does not establish an off-provider backup or guarantee a recovery time')
    expect(screen.queryByText(/planned before commercial general availability/)).not.toBeInTheDocument()
  })
  it('keeps privacy links without advertising the disconnected provider', () => {
    mount(TrustPage)
    expect(screen.queryByText(/LeakCheck/)).not.toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/small businesses, startups|digital agencies|small teams/i)
    expect(screen.getByRole('link', { name: 'Privacy Policy' })).toHaveAttribute('href', '/privacy')
    expect(screen.getByRole('link', { name: 'Data Processing Addendum' })).toHaveAttribute('href', '/dpa')
  })
  it('discloses anonymous preview counters and their actual cleanup window', () => {
    mount(PrivacyPage)
    expect(screen.getByText(/Public API and anonymous free checks/).closest('p')).toHaveTextContent('five-minute API-wide rate-limit counters based on the requesting IP address')
    expect(screen.getByText(/Public API and anonymous free checks/).closest('p')).toHaveTextContent('one-hour counters based on the IP address and submitted domain')
    expect(screen.getByText(/Public API and free-check rate-limit counters/).closest('li')).toHaveTextContent('a daily cleanup deletes these records more than 24 hours after their counting window ends')
  })
  it.each([[PrivacyPage, 'Privacy Policy'], [TermsPage, 'Terms of Service'], [DpaPage, 'Data Processing Addendum']])('identifies the sole-trader operator on %s', (Page, heading) => {
    mount(Page); expect(screen.getByRole('heading', { level: 1, name: heading })).toBeInTheDocument()
    expect(screen.getByText(/Turhan Acar, a sole trader trading as CyberMeters/)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/Scotist|currently in public beta/i)
  })
})
