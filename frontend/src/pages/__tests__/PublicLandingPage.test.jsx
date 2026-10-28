import { describe, it, expect } from 'vitest'
import { render, screen, within, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import PublicLandingPage from '../PublicLandingPage'
import { SERVICE_COLORS } from '../../theme/serviceColors'
import IrisGlobe, { EXAMPLE_FINDINGS, GLOBE, HERO_GLOBE_MAX, heroGlobe, paintIris } from '../../components/landing/IrisGlobe'

function renderLanding() {
  return render(<MemoryRouter><PublicLandingPage /></MemoryRouter>)
}

// The one canonical area order used across the app and the site (shared/areas.js).
const CANONICAL = ['Email Protection', 'Attack Surface', 'Website Security', 'Identity Exposure', 'Shadow IT & Unmanaged Technology', 'Certificates & Trust', 'Brand Protection', 'Cyber Essentials Readiness']

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
    expect(screen.getByText(/official Cyber Essentials scheme and its approved Certification Bodies/i)).toBeInTheDocument()
    // No other organisation is named in public copy (founder rule).
    expect(document.body.textContent).not.toMatch(/IASME/i)
  })

  it('leads with the exposure headline', () => {
    renderLanding()
    expect(screen.getByRole('heading', { level: 1, name: 'Know where your business is exposed and what to do next.' })).toBeInTheDocument()
  })

  it('sends every free-check call to action to the free scan, with the domain when typed', () => {
    const { container } = renderLanding()
    // One label for the one action: every free-check link reads "Run a free check".
    for (const link of screen.getAllByRole('link', { name: 'Run a free check' })) expect(link).toHaveAttribute('href', '/free-scan')
    expect(screen.queryByRole('link', { name: 'Check a domain now' })).toBeNull()
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
    expect(screen.getByText(/A one-off snapshot of public evidence. No scan report or monitoring history is saved/)).toBeInTheDocument()
    expect(screen.getByText(/An eligible trial or paid plan provides findings, fix steps, PDF reports and monitoring for domains you verify/i)).toBeInTheDocument()
    expect(screen.getByText(/Scheduled checks, alerts and PDF reports come with paid plans and the 14-day trial/i)).toBeInTheDocument()
    expect(screen.getByText(/An account and verified domain control are needed to keep reports and monitor changes/i)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/bounded, (non-persistent|honest)/i)
    expect(screen.getAllByText(/what could not be assessed/i).length).toBeGreaterThan(0)
    expect(screen.getByText(/Nothing is marked as passed on silence/i)).toBeInTheDocument()
    expect(screen.queryByText(/two minutes/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/fully protected|guarantee/i)).not.toBeInTheDocument()
  })

  it('keeps the animated eye decorative, out of the reading order', async () => {
    const { container } = renderLanding()
    await waitFor(() => expect(container.querySelectorAll('.cm-eye').length).toBeGreaterThan(0))
    for (const eye of container.querySelectorAll('.cm-eye')) expect(eye).toHaveAttribute('aria-hidden', 'true')
  })

  it('paints the heading before the eye, holding the eye\'s place at its size so nothing moves', async () => {
    const { container } = renderLanding()
    // First render: the heading is there, the globe's drawing code is not yet.
    expect(screen.getByRole('heading', { level: 1 })).toBeInTheDocument()
    expect(container.querySelector('.cm-eye')).toBeNull()
    const eye = await waitFor(() => {
      const found = container.querySelector('.cm-eye')
      expect(found).not.toBeNull()
      return found
    })
    expect(eye.style.width).toBe(eye.style.height)
    expect(parseInt(eye.style.width, 10)).toBeGreaterThan(0)
  })

  it('reserves the eye\'s exact box while it loads', () => {
    const { container } = renderLanding()
    const slot = container.querySelector('section .relative.mx-auto > div[aria-hidden="true"]')
    expect(slot).not.toBeNull()
    expect(slot.style.width).toBe(slot.style.height)
    expect(parseInt(slot.style.width, 10)).toBeGreaterThan(0)
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
    expect(screen.getByText('Are there lookalikes of my domain?')).toHaveStyle({ color: SERVICE_COLORS.brand.text })
  })

  it('never narrows the audience or counts areas in its pitch', () => {
    renderLanding()
    expect(screen.queryByText(/small businesses, startups|digital agencies|small teams/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/across (all )?(eight|8) areas/i)).not.toBeInTheDocument()
  })

  it('limits the free-check storage promise to reports and monitoring history', () => {
    renderLanding()
    expect(screen.getByText(/No scan report or monitoring history is saved/)).toHaveTextContent('Usage records and operational counts are kept to limit misuse and run the service.')
    expect(document.body.textContent).not.toContain('nothing is stored')
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
    const email = toggles[0] // Email Protection leads the canonical order
    expect(email).toHaveAttribute('aria-expanded', 'false')
    expect(document.getElementById('area-email')).not.toBeVisible()
    fireEvent.click(email)
    expect(email).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByText(/Review SPF, DKIM and DMARC in plain English/)).toBeVisible()
  })

  it('keeps the free check, the trial and paid plans apart, with honest labels', () => {
    renderLanding()
    expect(screen.getAllByRole('link', { name: 'Run a free check' }).every((l) => l.getAttribute('href') === '/free-scan')).toBe(true)
    expect(screen.getByRole('link', { name: 'Start my 14-day trial' })).toHaveAttribute('href', 'https://app.cybermeters.com/signup')
    for (const link of screen.getAllByRole('link', { name: 'See pricing' })) expect(link).toHaveAttribute('href', '/pricing')
  })

  it('answers the questions that stop people starting, without promising fixes', () => {
    renderLanding()
    expect(screen.getByText('Will CyberMeters change my DNS or fix things for me?')).toBeInTheDocument()
    expect(screen.getByText(/Your DNS, email or IT provider normally makes the change/)).toBeInTheDocument()
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

  it('keeps its full size in a narrow row, so the iris turns about its own centre', () => {
    const { container } = render(<IrisGlobe size={448} />)
    const eye = container.querySelector('.cm-eye')
    expect(eye).toHaveStyle({ width: '448px', height: '448px', flexShrink: '0' })
  })

  it('draws nothing when the browser has no 2D canvas', () => {
    expect(paintIris(document.createElement('canvas'), 400)).toBe(false)
    expect(paintIris(document.createElement('canvas'), 1000, HERO_GLOBE_MAX)).toBe(false)
  })

  it('gives wide screens a bigger world and keeps the standard size up to 1200px', () => {
    expect(heroGlobe(800)).toBe(GLOBE)
    expect(heroGlobe(1024)).toBe(GLOBE)
    expect(heroGlobe(1200)).toBe(GLOBE)
    const mid = heroGlobe(1250)
    expect(mid).toBeGreaterThan(GLOBE)
    expect(mid).toBeLessThan(HERO_GLOBE_MAX)
    expect(heroGlobe(1300)).toBe(HERO_GLOBE_MAX)
    expect(heroGlobe(2560)).toBe(HERO_GLOBE_MAX)
  })
})

describe('first-customer journey (founder, 20 Oct 2026)', () => {
  it('the Cyber Essentials area links to the readiness page', () => {
    renderLanding()
    const toggle = screen.getAllByRole('button', { name: 'What it checks' }).at(-1)
    fireEvent.click(toggle)
    expect(screen.getByRole('link', { name: 'How the readiness check works' })).toHaveAttribute('href', '/cyber-essentials-readiness')
  })
})

describe('Cyber Essentials readiness page', () => {
  it('names the two partly external controls and never counts email security', async () => {
    const { default: CyberEssentialsReadinessPage } = await import('../CyberEssentialsReadinessPage')
    render(<MemoryRouter><CyberEssentialsReadinessPage /></MemoryRouter>)
    const text = document.body.textContent
    expect(text).toMatch(/partly check two of the five control areas: boundary protection/)
    expect(text).toMatch(/Email security results are not counted towards Cyber Essentials/)
    expect(text).not.toMatch(/such as website security, TLS, DNS and email protection/)
  })
})

describe('public site audit (21 Oct 2026)', () => {
  it('says "read-only", never "beta", about AI assistant access', () => {
    renderLanding()
    expect(screen.getByText('Read-only AI assistant access (MCP)')).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/\bbeta\b/i)
  })

  it('asks every area question in the owner\'s voice', () => {
    renderLanding()
    expect(screen.getByText('What is visible about my business identities?')).toBeInTheDocument()
    expect(screen.queryByText(/our business identities/)).toBeNull()
  })

  it('does not mention live prices where no price is shown', () => {
    renderLanding()
    expect(document.body.textContent).not.toMatch(/live prices from our billing system/i)
  })
})
