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
  it('About has its own headline and a short founder section, with no legal-entity wording (founder, 19 Oct 2026)', () => {
    mount(AboutPage)
    const h1 = screen.getByRole('heading', { level: 1 })
    expect(h1).toHaveTextContent('Built to show what anyone can see of your business from the outside.')
    expect(h1).not.toHaveTextContent('Know where your business is exposed')
    expect(screen.getByRole('heading', { name: 'The founder: Turhan Acar' })).toBeInTheDocument()
    expect(screen.getByText(/holds CompTIA Security\+ and CySA\+/)).toHaveTextContent('airport security on document and fraud checks')
    expect(screen.getByText(/built CyberMeters to show small businesses and MSPs/)).toHaveTextContent('with the evidence behind every finding')
    // The legal entity is the founder's decision for Terms and the footer, not About.
    expect(document.body.textContent).not.toMatch(/sole trader|trading as|Ltd|limited company/i)
    expect(document.body.textContent).not.toMatch(/AI assistance|AI-generated/i)
    expect(screen.getByRole('link', { name: /See our own-domain check/ })).toHaveAttribute('href', '/trust')
    expect(document.body.textContent).not.toMatch(/Scotist|100\/100|years of experience/i)
    expect(document.body.textContent).not.toMatch(/small businesses, startups|digital agencies|small teams/i)
  })
  it('shows the latest complete own-domain assessment, dated, separate from the illustrative landing score', () => {
    mount(TrustPage)
    expect(screen.getByText('cybermeters.com', { exact: true })).toBeInTheDocument()
    expect(screen.getByText('27 October 2026 at 11:13 UTC')).toHaveAttribute('dateTime', '2026-10-27T11:13:42.000Z')
    expect(screen.queryByText('21 October 2026 at 18:45 UTC')).not.toBeInTheDocument()
    expect(screen.getByText('100 out of 100')).toBeInTheDocument()
    expect(screen.getByText(/^Complete — every planned check/)).toBeInTheDocument()
    // Tonight's containment: intrusive checks are not run until customer-authorised Active Checks ship.
    expect(screen.getByText(/Intrusive checks that send test traffic/)).toHaveTextContent('are not run against any domain, including ours')
    expect(document.body.textContent).not.toMatch(/\bsecure\b/i)
    expect(screen.getByText(/example.co.uk sample on our home page/)).toHaveTextContent('separate, clearly labelled illustration')
  })
  it('names the hosting provider, never the blueprint, and keeps every honest limit', () => {
    mount(TrustPage)
    expect(screen.getByText(/Hosted on Cloudflare.s network/)).toHaveTextContent('No agent is installed on your systems. Checks run from our infrastructure against what is publicly visible.')
    expect(document.body.textContent).not.toMatch(/Workers|Containers|\bD1\b|\bR2\b|edge endpoints|planned check outcomes|Heartbleed|ROBOT/)
    expect(screen.getByText(/A missing revocation staple/)).toHaveTextContent('no external revocation lookup was performed')
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
