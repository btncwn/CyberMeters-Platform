import { describe, it, expect } from 'vitest'
import { render, screen, within, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import PublicLandingPage from '../PublicLandingPage'
import { SERVICE_COLORS } from '../../theme/serviceColors'
import { EXAMPLE_FINDINGS, paintIris } from '../../components/landing/IrisGlobe'

function renderLanding() {
  return render(<MemoryRouter><PublicLandingPage /></MemoryRouter>)
}

const CANONICAL = ['Identity Exposure', 'Attack Surface', 'Email Protection', 'Website Security', 'Shadow IT & Unmanaged Technology', 'Certificates & Trust', 'Brand Protection', 'Cyber Essentials Readiness']

describe('PublicLandingPage', () => {
  it('presents the eight canonical domains by name, in canonical order', () => {
    renderLanding()
    expect(screen.getAllByRole('heading', { level: 3 })
      .map(heading => heading.textContent).filter(name => CANONICAL.includes(name))).toEqual(CANONICAL)
  })

  it('keeps the Cyber Essentials legal disclaimer verbatim (trust requirement)', () => {
    // CyberMeters must never imply it issues Cyber Essentials certification.
    renderLanding()
    expect(screen.getByText(/does not provide Cyber Essentials certification/i)).toBeInTheDocument()
    expect(screen.getByText(/IASME and approved Certification Bodies/i)).toBeInTheDocument()
  })

  it('leads with the exposure headline', () => {
    renderLanding()
    expect(screen.getByRole('heading', { level: 1, name: 'Know where your business is exposed and what to do next.' })).toBeInTheDocument()
  })

  it('sends every free-check call to action to the free scan, with the domain when typed', () => {
    const { container } = renderLanding()
    expect(screen.getByRole('link', { name: 'Run a free check' })).toHaveAttribute('href', '/free-scan')
    const forms = [...container.querySelectorAll('form')]
    expect(forms).toHaveLength(2) // hero + closing call to action
    for (const form of forms) {
      expect(form).toHaveAttribute('action', '/free-scan')
      expect(form).toHaveAttribute('method', 'get')
      expect(within(form).getByLabelText('Your domain')).toHaveAttribute('name', 'domain')
      expect(within(form).getByRole('button', { name: 'Run a free check' })).toHaveAttribute('type', 'submit')
    }
  })

  it('describes the free check as a bounded one-off snapshot, with full access only after verification', () => {
    renderLanding()
    expect(screen.getByText(/one-off snapshot of public evidence: nothing is stored or monitored until you create an account/i)).toBeInTheDocument()
    expect(screen.getByText(/Full findings, fix steps, PDF reports and monitoring unlock once you verify that you own the domain/i)).toBeInTheDocument()
    expect(screen.getByText(/Scheduled checks, alerts and PDF reports come with paid plans and the 14-day trial/i)).toBeInTheDocument()
    expect(screen.getByText(/bounded, non-persistent external snapshot/i)).toBeInTheDocument()
    expect(screen.getAllByText(/what could not be assessed/i).length).toBeGreaterThan(0)
    expect(screen.getByText(/Nothing is marked as passed on silence/i)).toBeInTheDocument()
    expect(screen.queryByText(/two minutes/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/fully protected|guarantee/i)).not.toBeInTheDocument()
  })

  it('keeps the animated eye decorative, out of the reading order', () => {
    const { container } = renderLanding()
    const eyes = [...container.querySelectorAll('.cm-eye')]
    expect(eyes.length).toBeGreaterThan(0)
    for (const eye of eyes) expect(eye).toHaveAttribute('aria-hidden', 'true')
  })

  it('labels the report panel as a sample in the product coverage vocabulary, with no score', () => {
    renderLanding()
    const sample = screen.getByRole('figure', { name: 'Sample report layout' })
    expect(within(sample).getByText('Sample')).toBeInTheDocument()
    expect(within(sample).getByText(/not a live result/i)).toBeInTheDocument()
    expect(within(sample).getAllByText('Evidence insufficient').length).toBeGreaterThan(0)
    expect(within(sample).getAllByText('Customer input required').length).toBeGreaterThan(0)
    expect(within(sample).queryByText(/\b\d{2,3}\s*\/\s*100\b|score/i)).not.toBeInTheDocument()
  })

  it('colours each area question with its identity from the shared palette', () => {
    renderLanding()
    expect(screen.getByText('Can attackers send email as me?')).toHaveStyle({ color: SERVICE_COLORS.email.text })
    expect(screen.getByText('Is anyone impersonating my brand?')).toHaveStyle({ color: SERVICE_COLORS.brand.text })
  })

  it('never narrows the audience or counts areas in its pitch', () => {
    renderLanding()
    expect(screen.queryByText(/small businesses, startups|digital agencies|small teams/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/across (all )?(eight|8) areas/i)).not.toBeInTheDocument()
  })

  it('does not advertise the MSP portfolio view, which is not customer-accepted', () => {
    renderLanding()
    expect(screen.queryByText(/portfolio/i)).not.toBeInTheDocument()
  })

  it('links to the founder story and trust page without putting biography into the pitch', () => {
    renderLanding()
    for (const link of screen.getAllByRole('link', { name: 'About' })) expect(link).toHaveAttribute('href', '/about')
    for (const link of screen.getAllByRole('link', { name: 'Trust & Security' })) expect(link).toHaveAttribute('href', '/trust')
    expect(screen.queryByText(/Designed and developed by Turhan Acar/i)).not.toBeInTheDocument()
  })
})

describe('PublicLandingPage product story', () => {
  it('shows the product right after the first screen, with a direct link to it', () => {
    renderLanding()
    expect(screen.getByRole('link', { name: 'See a sample result first' })).toHaveAttribute('href', '#product')
    const product = document.getElementById('product')
    expect(product).not.toBeNull()
    expect(within(product).getByRole('figure', { name: 'Sample report layout' })).toBeInTheDocument()
    // The product view comes before the walkthrough and the eight areas.
    const order = ['product', 'tour', 'areas', 'how', 'trust', 'start', 'faq'].map(id => document.getElementById(id))
    for (let i = 1; i < order.length; i++) {
      expect(order[i - 1].compareDocumentPosition(order[i]) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    }
  })

  it('keeps every area scannable and opens its details on request', () => {
    renderLanding()
    const toggles = screen.getAllByRole('button', { name: 'What it checks' })
    expect(toggles).toHaveLength(8)
    const email = toggles[2]
    expect(email).toHaveAttribute('aria-expanded', 'false')
    expect(document.getElementById('area-email')).not.toBeVisible()
    fireEvent.click(email)
    expect(email).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByText(/Review SPF, DKIM and DMARC in plain English/)).toBeVisible()
  })

  it('keeps the free check, the trial and paid plans apart, with honest labels', () => {
    renderLanding()
    expect(screen.getByRole('link', { name: 'Check a domain now' })).toHaveAttribute('href', '/free-scan')
    expect(screen.getByRole('link', { name: 'Start my 14-day trial' })).toHaveAttribute('href', 'https://app.cybermeters.com/signup')
    for (const link of screen.getAllByRole('link', { name: 'See pricing' })) expect(link).toHaveAttribute('href', '/pricing')
  })

  it('answers the questions that stop people starting, without promising fixes', () => {
    renderLanding()
    expect(screen.getByText('Will CyberMeters change my DNS or fix things for me?')).toBeInTheDocument()
    expect(screen.getByText(/Your DNS, email or IT provider makes the change/)).toBeInTheDocument()
  })

  it('opens the main navigation on small screens', () => {
    renderLanding()
    const toggle = screen.getByRole('button', { name: 'Menu' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(toggle)
    expect(screen.getByRole('button', { name: 'Close' })).toHaveAttribute('aria-expanded', 'true')
    expect(document.getElementById('site-menu')).toBeInTheDocument()
  })
})

describe('IrisGlobe illustration', () => {
  it('only uses canonical area names for its example findings', () => {
    for (const f of EXAMPLE_FINDINGS) expect(CANONICAL).toContain(f.area)
  })

  it('draws nothing when the browser has no 2D canvas', () => {
    expect(paintIris(document.createElement('canvas'), 400)).toBe(false)
  })
})
