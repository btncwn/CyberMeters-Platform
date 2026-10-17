import { render, screen, fireEvent, within } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import WorkspaceNav, { SERVICES, detectServiceKey, subpagesForDomainKey, MODULE_SUBPAGES } from '../WorkspaceNav'
import { SERVICE_COLORS } from '../../theme/serviceColors'
import { MODULES } from '../../lib/moduleRegistry'
import { api } from '../../api'

// The 72px module rail: eight icons in founder order, a dark tooltip, the
// active area on its light ground, and the workspace button with its popover.

function hexToRgb(hex) {
  const n = parseInt(hex.slice(1), 16)
  return `rgb(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255})`
}

vi.mock('../../api', () => ({ api: { getWorkspaces: vi.fn() } }))
vi.mock('../../utils/preload', () => ({ preloadComponent: vi.fn() }))
vi.mock('../../utils/preloadMap', () => ({ routePreloadMap: {} }))

function renderNav(path = '/ws/email-protection', { wsId = 'ws1', wsName = 'Deneme' } = {}) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="*" element={<WorkspaceNav wsId={wsId} wsName={wsName} />} />
      </Routes>
    </MemoryRouter>,
  )
}

const railLinks = () => within(screen.getByRole('navigation', { name: 'Modules' })).getAllByRole('link')

beforeEach(() => {
  vi.clearAllMocks()
  api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws1', name: 'Deneme' }, { id: 'ws2', name: 'Other' }] })
})

describe('WorkspaceNav (module rail)', () => {
  it('shows the eight canonical domains in order', () => {
    renderNav()
    const names = railLinks().map(a => a.getAttribute('aria-label'))
    expect(names).toEqual([
      'Email Protection', 'Attack Surface', 'Website Security', 'Identity Exposure',
      'Shadow IT & Unmanaged Technology', 'Certificates & Trust', 'Brand Protection', 'Cyber Essentials Readiness',
    ])
    // The rail and the module registry agree on order and destinations.
    expect(SERVICES.map(s => [s.title, s.to])).toEqual(MODULES.map(m => [m.title, m.to]))
  })

  it('each icon links to its area and carries a tooltip with the area name', () => {
    renderNav()
    for (const [i, a] of railLinks().entries()) {
      expect(a).toHaveAttribute('href', SERVICES[i].to)
      expect(a.querySelector('.cm-tip')).toHaveTextContent(SERVICES[i].title)
      expect(a.querySelector('.cm-tip')).toHaveAttribute('aria-hidden', 'true')
    }
  })

  it('marks the active area with aria-current and its own light ground', () => {
    renderNav('/ws/brand-monitoring')
    const active = railLinks().filter(a => a.getAttribute('aria-current') === 'page')
    expect(active.map(a => a.getAttribute('aria-label'))).toEqual(['Brand Protection'])
    expect(active[0]).toHaveStyle({ backgroundColor: hexToRgb(SERVICE_COLORS.brand.chip), color: hexToRgb(SERVICE_COLORS.brand.text) })
    const idle = railLinks().find(a => a.getAttribute('aria-label') === 'Email Protection')
    expect(idle).not.toHaveAttribute('aria-current')
    expect(idle).toHaveStyle({ color: hexToRgb(SERVICE_COLORS.email.icon) })
  })

  it('maps every canonical domain route to its palette entry; non-domain routes stay neutral', () => {
    for (const svc of SERVICES) expect(SERVICE_COLORS[detectServiceKey(svc.to)]).toBeTruthy()
    expect(detectServiceKey('/scans')).toBe('surface')
    expect(detectServiceKey('/ws/saas-exposure')).toBe('shadow_it')
    expect(detectServiceKey('/dashboard')).toBeNull()
    expect(detectServiceKey('/ws/cases')).toBeNull()
  })

  it('exposes each area’s sub-pages as absolute tiles (anchors resolve against the area page)', () => {
    expect(subpagesForDomainKey('email_protection').map(t => t.to)).toEqual([
      '/ws/email-protection#dmarc-setup', '/ws/email-protection#sender-inventory', '/ws/email-protection#auth-detail',
    ])
    expect(subpagesForDomainKey('attack_surface')[0]).toEqual({ label: 'Timeline', desc: 'What appeared, changed or disappeared', to: '/exposure', anchor: false })
    // The scan intelligence page is reachable from the Attack Surface area (16 Oct 2026).
    expect(subpagesForDomainKey('attack_surface').at(-1)).toEqual({ label: 'Intelligence', desc: 'Score history, changes between scans and the remediation plan', to: '/intelligence', anchor: false })
    expect(detectServiceKey('/intelligence')).toBe('surface')
    expect(detectServiceKey('/ws/identity-assets')).toBe('identity')
    expect(subpagesForDomainKey('identity_exposure').map(t => t.to)).toEqual([
      '/ws/identity-assets', '/ws/identity-assets#workforce-response', '/ws/identity-assets#public-sources',
    ])
    expect(detectServiceKey('/ws/vendors')).toBe('shadow_it')
    expect(detectServiceKey('/ws/supply-chain')).toBe('shadow_it')
    expect(subpagesForDomainKey('shadow_it_unmanaged_technology').slice(-2).map(t => t.to)).toEqual(['/ws/vendors', '/ws/supply-chain'])
    // A summary block that lives on Overview is reached with the tab stated.
    expect(subpagesForDomainKey('brand_protection').find((t) => t.label === 'Brand Findings').to).toBe('/ws/brand-monitoring?tab=overview#brand-summary')
    expect(subpagesForDomainKey('certificates_trust').find((t) => t.label === 'Expiry Risk').to).toBe('/ws/certificates?tab=overview#cert-expiry')
    expect(subpagesForDomainKey('certificates_trust').find((t) => t.label === 'Inventory').to).toBe('/ws/certificates#cert-inventory')
    expect(subpagesForDomainKey('website_security')).toEqual([])
    expect(subpagesForDomainKey('nope')).toEqual([])
    expect(Object.keys(MODULE_SUBPAGES)).toEqual(MODULES.map(m => m.domainKey))
  })

  it('every palette entry ships a surface wash lighter than its card tint', () => {
    const lum = (hex) => { const n = parseInt(hex.slice(1), 16); return ((n >> 16) & 255) + ((n >> 8) & 255) + (n & 255) }
    for (const c of Object.values(SERVICE_COLORS)) expect(lum(c.surface)).toBeGreaterThan(lum(c.card))
  })
})

describe('WorkspaceNav — workspace button and popover', () => {
  it('names the active workspace, lists workspaces on open, and offers Manage workspaces and Members & roles only', async () => {
    renderNav()
    const b = screen.getByRole('button', { name: 'Workspace: Deneme' })
    expect(b).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(b)
    expect(b).toHaveAttribute('aria-expanded', 'true')
    const menu = screen.getByRole('menu', { name: 'Workspace' })
    expect(within(menu).getByTestId('active-workspace-name')).toHaveTextContent('Deneme')
    expect(await within(menu).findByRole('menuitem', { name: /Other/ })).toBeInTheDocument()
    expect(within(menu).getByRole('menuitem', { name: /Deneme/ })).toHaveAttribute('aria-current', 'true')
    expect(within(menu).getByRole('menuitem', { name: 'Manage workspaces' })).toHaveAttribute('href', '/workspaces')
    expect(within(menu).getByRole('menuitem', { name: 'Members & roles' })).toHaveAttribute('href', '/ws/members')
    // Founder, 16 Oct 2026: nothing else lives here — no Clear selection, no workspace tools.
    expect(within(menu).queryByRole('menuitem', { name: 'Clear selection' })).not.toBeInTheDocument()
    for (const gone of ['Administration', 'Scorecard', 'Executive dashboard', 'Operations', 'Related changes', 'Audit log', 'Alert channels', 'Usage & retention', 'Settings']) {
      expect(within(menu).queryByRole('menuitem', { name: gone })).not.toBeInTheDocument()
    }
    expect(within(menu).getAllByRole('menuitem').map(i => i.textContent)).toEqual(['Deneme', 'Other', 'Manage workspaces', 'Members & roles'])
    expect(api.getWorkspaces).toHaveBeenCalledTimes(1)
    // No two visible links in the popover share a destination.
    const hrefs = within(menu).getAllByRole('menuitem').map(i => i.getAttribute('href')).filter(Boolean)
    expect(new Set(hrefs).size).toBe(hrefs.length)
  })

  it('without a workspace the button says so and still offers Manage workspaces', () => {
    renderNav('/dashboard', { wsId: null, wsName: '' })
    const b = screen.getByRole('button', { name: 'Select a workspace' })
    fireEvent.click(b)
    const menu = screen.getByRole('menu', { name: 'Workspace' })
    expect(within(menu).getByTestId('active-workspace-name')).toHaveTextContent('No workspace selected')
    expect(within(menu).getByRole('menuitem', { name: 'Manage workspaces' })).toBeInTheDocument()
    expect(within(menu).getByRole('menuitem', { name: 'Members & roles' })).toBeInTheDocument()
  })

  it('switching writes the workspace; Escape returns focus to the button', async () => {
    localStorage.clear()
    renderNav()
    const b = screen.getByRole('button', { name: 'Workspace: Deneme' })
    fireEvent.click(b)
    fireEvent.click(await screen.findByRole('menuitem', { name: /Other/ }))
    expect(localStorage.getItem('cybermeters_workspace_id')).toBe('ws2')
    expect(screen.queryByRole('menu', { name: 'Workspace' })).not.toBeInTheDocument()
    expect(document.activeElement).toBe(b)

    fireEvent.click(b)
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('menu', { name: 'Workspace' })).not.toBeInTheDocument()
    expect(document.activeElement).toBe(b)
    expect(localStorage.getItem('cybermeters_workspace_id')).toBe('ws2')
  })
})
