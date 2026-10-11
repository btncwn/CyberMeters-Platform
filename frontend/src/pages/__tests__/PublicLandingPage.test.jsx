import { describe, it, expect } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import PublicLandingPage from '../PublicLandingPage'
import { SERVICE_COLORS } from '../../theme/serviceColors'

function renderLanding() {
  return render(<MemoryRouter><PublicLandingPage /></MemoryRouter>)
}

describe('PublicLandingPage', () => {
  it('presents the eight canonical domains by name, in canonical order', () => {
    renderLanding()
    const names = ['Identity Exposure', 'Attack Surface', 'Email Protection', 'Website Security', 'Shadow IT & Unmanaged Technology', 'Certificates & Trust', 'Brand Protection', 'Cyber Essentials Readiness']
    expect(screen.getAllByRole('heading', { level: 3 })
      .map(heading => heading.textContent).filter(name => names.includes(name))).toEqual(names)
  })

  it('keeps the Cyber Essentials legal disclaimer verbatim (trust requirement)', () => {
    // CyberMeters must never imply it issues Cyber Essentials certification.
    // This note is a compliance requirement — the test guards it against being
    // dropped in a future redesign.
    renderLanding()
    expect(
      screen.getByText(/does not provide Cyber Essentials certification/i)
    ).toBeInTheDocument()
    expect(screen.getByText(/IASME and approved Certification Bodies/i)).toBeInTheDocument()
  })

  it('sends every free-check call to action to the free scan, with the domain when typed', () => {
    const { container } = renderLanding()
    expect(screen.getByRole('link', { name: 'Run a free check' })).toHaveAttribute('href', '/free-scan')
    const forms = [...container.querySelectorAll('form')]
    expect(forms).toHaveLength(2) // hero + final call to action
    for (const form of forms) {
      expect(form).toHaveAttribute('action', '/free-scan')
      expect(form).toHaveAttribute('method', 'get')
      expect(within(form).getByLabelText('Your domain')).toHaveAttribute('name', 'domain')
      expect(within(form).getByRole('button', { name: 'Run a free check' })).toHaveAttribute('type', 'submit')
    }
  })

  it('describes the free check as a one-off snapshot, with full access only after verification', () => {
    renderLanding()
    expect(screen.getByText(/one-off snapshot of public evidence: nothing is stored or monitored until you create an account/i)).toBeInTheDocument()
    expect(screen.getByText(/Full findings, fix steps, PDF reports and monitoring unlock once you verify that you own the domain/i)).toBeInTheDocument()
    expect(screen.getByText(/what could not be assessed/i)).toBeInTheDocument()
    expect(screen.getByText(/never marked as passed on silence/i)).toBeInTheDocument()
    expect(screen.getByText(/Scheduled checks, alerts and PDF reports come with paid plans and the 14-day trial/i)).toBeInTheDocument()
    expect(screen.queryByText(/two minutes/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/fully protected|guarantee/i)).not.toBeInTheDocument()
  })

  it('leads with the Cyber MOT headline', () => {
    renderLanding()
    expect(screen.getByRole('heading', { level: 1, name: 'Put your business through a Cyber MOT.' })).toBeInTheDocument()
  })

  it('colours each area question with its identity from the shared palette', () => {
    renderLanding()
    expect(screen.getByText('Can someone send email pretending to be you?')).toHaveStyle({ color: SERVICE_COLORS.email.text })
    expect(screen.getByText('Is someone registering lookalikes of your domain?')).toHaveStyle({ color: SERVICE_COLORS.brand.text })
  })

  it('labels the hero report as a sample, never a live result, and shows a not-tested state', () => {
    renderLanding()
    const sheet = screen.getByRole('figure', { name: 'Sample Cyber MOT report' })
    expect(within(sheet).getByText('Sample')).toBeInTheDocument()
    expect(within(sheet).getByText('example.co.uk')).toBeInTheDocument()
    expect(within(sheet).getByText(/Sample report to show the layout, not a live result/i)).toBeInTheDocument()
    expect(within(sheet).getByText('Not tested')).toBeInTheDocument()
    expect(within(sheet).queryByText(/\b\d{2,3}\s*\/\s*100\b/)).not.toBeInTheDocument()
  })

  it('does not advertise the MSP portfolio view, which is not customer-accepted', () => {
    renderLanding()
    expect(screen.queryByText(/portfolio/i)).not.toBeInTheDocument()
  })

  it('links to the founder story without putting biography into the product pitch', () => {
    renderLanding()
    expect(screen.getByRole('link', { name: 'About' })).toHaveAttribute('href', '/about')
    expect(screen.queryByText(/Designed and developed by Turhan Acar/i)).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Trust & Security' })).toHaveAttribute('href', '/trust')
  })
})
