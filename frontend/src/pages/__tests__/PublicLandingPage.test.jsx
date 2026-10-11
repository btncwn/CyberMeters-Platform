import { describe, it, expect } from 'vitest'
import { render, screen, within } from '@testing-library/react'
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

  it('captions the animated eye as an illustration with example findings', () => {
    renderLanding()
    expect(screen.getByText(/illustration with example findings, not a live result/i)).toBeInTheDocument()
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

describe('IrisGlobe illustration', () => {
  it('only uses canonical area names for its example findings', () => {
    for (const f of EXAMPLE_FINDINGS) expect(CANONICAL).toContain(f.area)
  })

  it('draws nothing when the browser has no 2D canvas', () => {
    expect(paintIris(document.createElement('canvas'), 400)).toBe(false)
  })
})
