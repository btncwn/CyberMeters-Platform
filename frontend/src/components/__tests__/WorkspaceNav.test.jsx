import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import WorkspaceNav from '../WorkspaceNav'
import { SERVICE_COLORS } from '../../theme/serviceColors'

// Small helper: jsdom reports colours as rgb(), so compare hex → rgb.
function hexToRgb(hex) {
  const n = parseInt(hex.slice(1), 16)
  return `rgb(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255})`
}

// Keep the test hermetic: hovering/clicking nav entries must not actually
// dynamic-import route modules.
vi.mock('../../utils/preload', () => ({ preloadComponent: vi.fn() }))
vi.mock('../../utils/preloadMap', () => ({ routePreloadMap: {} }))

function renderNav(path = '/ws/email-protection') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <WorkspaceNav wsName="Deneme" />
    </MemoryRouter>,
  )
}

describe('WorkspaceNav (eight-domain sidebar)', () => {
  it('opens mobile navigation and closes it after changing route or pressing Escape', () => {
    renderNav()
    const toggle = screen.getByRole('button', { name: 'Workspace navigation' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(toggle)
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    fireEvent.click(screen.getByText('Brand Protection'))
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(toggle)
    fireEvent.keyDown(toggle, { key: 'Escape' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
  })
  it('shows the eight canonical domains in order', () => {
    renderNav()
    // Founder order (14 Oct 2026): strongest evidence first, readiness last.
    const names = ['Email Protection', 'Attack Surface', 'Website Security', 'Identity Exposure', 'Shadow IT & Unmanaged Technology', 'Certificates & Trust', 'Brand Protection', 'Cyber Essentials Readiness']
    const elements = names.map(name => screen.getByText(name))
    for (let i = 1; i < elements.length; i++) {
      expect(elements[i - 1].compareDocumentPosition(elements[i]) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    }
  })

  it('expands only the active domain — no cross-domain sub-item mixing', () => {
    renderNav('/ws/email-protection')
    expect(screen.getByText('DMARC Setup')).toBeInTheDocument()
    // Brand's sub-items must not leak into an Email context.
    expect(screen.queryByText('Typosquat Candidates')).not.toBeInTheDocument()
  })

  it('the area name is a link and the chevron is a separate expand/collapse button', () => {
    renderNav('/ws/email-protection')
    const link = screen.getByRole('link', { name: 'Email Protection' })
    expect(link).toHaveAttribute('href', '/ws/email-protection')
    const toggle = screen.getByRole('button', { name: 'Collapse Email Protection' })
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByText('DMARC Setup')).toBeInTheDocument()
    // Clicking the name does NOT collapse anything: it only navigates.
    fireEvent.click(link)
    expect(screen.getByText('DMARC Setup')).toBeInTheDocument()
    // The chevron collapses, then reopens.
    fireEvent.click(toggle)
    expect(screen.queryByText('DMARC Setup')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Expand Email Protection' }))
    expect(screen.getByText('DMARC Setup')).toBeInTheDocument()
  })

  it('switching domain moves the accordion: Brand opens, Email closes', () => {
    renderNav('/ws/email-protection')
    fireEvent.click(screen.getByRole('link', { name: 'Brand Protection' }))
    expect(screen.getByText('Typosquat Candidates')).toBeInTheDocument()
    expect(screen.queryByText('DMARC Setup')).not.toBeInTheDocument()
  })

  it('no two visible controls in one navigation group share a destination', () => {
    // Every service's sub-items (plus its Operations entry) and the
    // Workspace tools are each one group; one destination appears once.
    for (const path of ['/assets', '/ws/email-protection', '/ws/certificates', '/ws/brand-monitoring', '/ws/shadow-it']) {
      const { unmount } = renderNav(path)
      const hrefs = screen.getAllByRole('link').map(a => a.getAttribute('href'))
      const seen = new Map()
      for (const h of hrefs) seen.set(h, (seen.get(h) || 0) + 1)
      const dupes = [...seen].filter(([, n]) => n > 1).map(([h]) => h)
      expect(dupes).toEqual([])
      unmount()
    }
  })

  it('sub-items inherit their parent service colour', () => {
    renderNav('/ws/email-protection')
    // Derives from the shared palette, so re-theming Email can never silently
    // desync this assertion from the sidebar again.
    expect(screen.getByText('DMARC Setup')).toHaveStyle({ color: hexToRgb(SERVICE_COLORS.email.text) })
  })
})

// ── Domain identity wash (Layout content-column tint) ─────────────────────────
import { detectServiceKey } from '../WorkspaceNav'

describe('detectServiceKey → domain surface wash', () => {
  it('maps every canonical domain route to its palette entry', () => {
    const expectations = {
      '/ws/email-protection':  'email',
      '/ws/brand-monitoring':  'brand',
      '/assets':               'surface',
      '/scans/new':            'surface',
      '/ws/certificates/lifecycle': 'certs',
      '/ws/cyber-essentials':  'cyber_essentials',
      '/ws/website-security':  'website',
      '/ws/identity-exposure': 'identity',
      '/ws/shadow-it':         'shadow_it',
      '/ws/saas-exposure':     'shadow_it',
    }
    for (const [path, key] of Object.entries(expectations)) {
      expect(detectServiceKey(path), path).toBe(key)
      expect(SERVICE_COLORS[key].surface, `${key}.surface`).toMatch(/^#[0-9A-F]{6}$/i)
    }
  })

  it('non-domain routes stay neutral — no identity wash on shared surfaces', () => {
    for (const path of ['/ws/dashboard', '/ws/cases', '/ws/members', '/settings', '/ws/reports']) {
      expect(detectServiceKey(path), path).toBeNull()
    }
  })

  it('every palette entry ships a surface wash lighter than its card tint', () => {
    // Large-area washes must stay fainter than card tints so white cards pop
    // and severity colours remain unambiguous. Luminance(surface) > luminance(card).
    const lum = (hex) => {
      const n = parseInt(hex.slice(1), 16)
      return ((n >> 16) & 255) + ((n >> 8) & 255) + (n & 255)
    }
    for (const [key, c] of Object.entries(SERVICE_COLORS)) {
      expect(c.surface, `${key}.surface`).toBeTruthy()
      expect(lum(c.surface), `${key}: surface must be lighter than card`).toBeGreaterThan(lum(c.card))
    }
  })
})


it.each([
  ['/ws/identity-exposure', 'identity_exposure'], ['/assets', 'attack_surface'],
  ['/ws/email-protection', 'email_protection'], ['/ws/website-security', 'website_security'],
  ['/ws/shadow-it', 'shadow_it_unmanaged_technology'], ['/ws/certificates', 'certificates_trust'],
  ['/ws/brand-monitoring', 'brand_protection'], ['/ws/cyber-essentials', 'cyber_essentials_readiness'],
])('links %s to its existing operations queue', (path, domain) => {
  renderNav(path)
  expect(screen.getByRole('link', { name: 'Operations' })).toHaveAttribute('href', `/ws/cases?domain_key=${domain}`)
})
