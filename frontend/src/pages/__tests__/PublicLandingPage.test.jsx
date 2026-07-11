import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import PublicLandingPage from '../PublicLandingPage'
import { SERVICE_COLORS } from '../../theme/serviceColors'

function renderLanding() {
  return render(<MemoryRouter><PublicLandingPage /></MemoryRouter>)
}

describe('PublicLandingPage', () => {
  it('presents the four core services by name', () => {
    renderLanding()
    for (const name of ['Email Protection', 'Brand Protection', 'Attack Surface', 'Certificates & Trust']) {
      expect(screen.getAllByText(name).length).toBeGreaterThan(0)
    }
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

  it('routes every primary call-to-action to the free Cyber MOT', () => {
    renderLanding()
    const ctas = screen.getAllByRole('link', { name: /Cyber MOT/i })
      .filter(a => a.getAttribute('href') === '/free-scan')
    expect(ctas.length).toBeGreaterThanOrEqual(2) // nav + hero + final CTA
  })

  it('leads with the exposure headline', () => {
    renderLanding()
    expect(screen.getByRole('heading', { name: /Know where your business is/i })).toBeInTheDocument()
  })

  it('colours each service card with its glacier identity from the shared palette', () => {
    renderLanding()
    // The Email service question is styled with the shared email text colour.
    const emailQuestion = screen.getByText(/Can attackers send email as me/i)
    expect(emailQuestion).toHaveStyle({ color: SERVICE_COLORS.email.text })
    const brandQuestion = screen.getByText(/Is anyone impersonating my brand/i)
    expect(brandQuestion).toHaveStyle({ color: SERVICE_COLORS.brand.text })
  })

  it('shows the live Cyber MOT result card with a posture readout', () => {
    renderLanding()
    expect(screen.getByText(/Cyber MOT · Result/i)).toBeInTheDocument()
    expect(screen.getByText('Posture')).toBeInTheDocument() // exact: the gauge label, not the "Live posture" eyebrow
    expect(screen.getByText(/Overall verdict/i)).toBeInTheDocument()
  })
})
