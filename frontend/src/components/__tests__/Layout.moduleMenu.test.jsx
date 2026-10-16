import { render, screen, within, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import Layout, { DIRECT_NAV, MSP_NAV, MODULE_MENU_ID } from '../Layout'
import { MODULES } from '../../lib/moduleRegistry'
import { api } from '../../api'
import { useAuth } from '../../context/AuthContext'

// Founder shell decision (16 Oct 2026): the brand is the module menu, the
// workspace selector leaves the top bar for the sidebar's WORKSPACE section,
// and the sidebar starts with the module list. These tests pin that shell.

vi.mock('../../api', () => ({
  api: { getAccountUsage: vi.fn(), getWorkspaces: vi.fn() },
  logoutWithToken: vi.fn(),
}))
vi.mock('../../context/AuthContext', () => ({ useAuth: vi.fn() }))
vi.mock('../NotificationBell', () => ({ default: () => null }))
vi.mock('../../utils/preload', () => ({ preloadComponent: vi.fn() }))
vi.mock('../../utils/preloadMap', () => ({ routePreloadMap: {} }))

// Founder order, duplicated on purpose so the test fails if the registry drifts.
const FOUNDER_ORDER = [
  ['Email Protection', '/ws/email-protection'],
  ['Attack Surface', '/assets'],
  ['Website Security', '/ws/website-security'],
  ['Identity Exposure', '/ws/identity-exposure'],
  ['Shadow IT & Unmanaged Technology', '/ws/shadow-it'],
  ['Certificates & Trust', '/ws/certificates'],
  ['Brand Protection', '/ws/brand-monitoring'],
  ['Cyber Essentials Readiness', '/ws/cyber-essentials'],
]

function renderLayout({ features = [], workspace = null, path = '/dashboard' } = {}) {
  useAuth.mockReturnValue({ user: { name: 'Owner', email: 'owner@example.co.uk', plan: 'business' }, logout: vi.fn(), isAuthenticated: true, isLoading: false })
  api.getAccountUsage.mockResolvedValue({ plan: 'business', features })
  api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws_a', name: 'Customer A' }, { id: 'ws_b', name: 'Customer B' }] })
  if (workspace) {
    localStorage.setItem('cybermeters_workspace_id', workspace.id)
    localStorage.setItem('cybermeters_workspace_name', workspace.name)
  }
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route element={<Layout />}>
          <Route path="*" element={<div data-testid="page" />} />
        </Route>
      </Routes>
    </MemoryRouter>,
  )
}

const brand = () => screen.getByRole('button', { name: 'CyberMeters modules' })
const header = () => screen.getByRole('banner')
const menu = () => screen.getByRole('menu', { name: 'Modules' })

beforeEach(() => {
  localStorage.clear()
  vi.clearAllMocks()
})

describe('Brand = module menu', () => {
  it('the logo is one button with aria-expanded; it opens the menu and closes it again', () => {
    renderLayout({ workspace: { id: 'ws_a', name: 'Customer A' } })
    const b = brand()
    expect(b).toHaveAttribute('aria-expanded', 'false')
    expect(b).toHaveAttribute('aria-haspopup', 'menu')
    expect(b).toHaveAttribute('aria-controls', MODULE_MENU_ID)
    expect(screen.queryByRole('menu', { name: 'Modules' })).not.toBeInTheDocument()
    // The wordmark sits inside the same button: clicking the text opens the menu too.
    fireEvent.click(within(b).getByText('CyberMeters'))
    expect(b).toHaveAttribute('aria-expanded', 'true')
    expect(menu()).toHaveAttribute('id', MODULE_MENU_ID)
    fireEvent.click(b)
    expect(b).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByRole('menu', { name: 'Modules' })).not.toBeInTheDocument()
  })

  it('lists Security overview first, then the eight modules in founder order, each to its page', () => {
    renderLayout({ workspace: { id: 'ws_a', name: 'Customer A' } })
    fireEvent.click(brand())
    const items = within(menu()).getAllByRole('menuitem')
    expect(items[0]).toHaveTextContent('Security overview')
    expect(items[0]).toHaveAttribute('href', '/dashboard')
    expect(items.slice(1).map(a => [a.textContent, a.getAttribute('href')])).toEqual(FOUNDER_ORDER)
    expect(items).toHaveLength(9)
    // The registry and the menu agree, so the sidebar and the menu can never diverge.
    expect(MODULES.map(m => [m.title, m.to])).toEqual(FOUNDER_ORDER)
    expect(screen.queryByRole('menuitem', { name: 'Select a workspace' })).not.toBeInTheDocument()
  })

  it('with no workspace selected the menu says Select a workspace before the modules', () => {
    renderLayout()
    fireEvent.click(brand())
    const items = within(menu()).getAllByRole('menuitem')
    expect(items[0]).toHaveTextContent('Security overview')
    expect(items[1]).toHaveTextContent('Select a workspace')
    expect(items[1]).toHaveAttribute('href', '/workspaces')
    expect(items.slice(2).map(a => a.textContent)).toEqual(FOUNDER_ORDER.map(([t]) => t))
  })

  it('closes on Escape and returns focus to the logo; closes on an outside click', () => {
    renderLayout({ workspace: { id: 'ws_a', name: 'Customer A' } })
    const b = brand()
    fireEvent.click(b)
    within(menu()).getAllByRole('menuitem')[2].focus()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('menu', { name: 'Modules' })).not.toBeInTheDocument()
    expect(b).toHaveAttribute('aria-expanded', 'false')
    expect(document.activeElement).toBe(b)

    fireEvent.click(b)
    expect(menu()).toBeInTheDocument()
    fireEvent.mouseDown(screen.getByTestId('page'))
    expect(screen.queryByRole('menu', { name: 'Modules' })).not.toBeInTheDocument()
  })

  it('choosing a module navigates, closes the menu and hands focus back to the logo', async () => {
    renderLayout({ workspace: { id: 'ws_a', name: 'Customer A' } })
    fireEvent.click(brand())
    fireEvent.click(within(menu()).getByRole('menuitem', { name: 'Certificates & Trust' }))
    expect(screen.queryByRole('menu', { name: 'Modules' })).not.toBeInTheDocument()
    expect(document.activeElement).toBe(brand())
    // The sidebar now marks Certificates as the active area.
    await waitFor(() => expect(screen.getByRole('link', { name: 'Certificates & Trust' })).toHaveClass('flex-1'))
  })
})

describe('Top bar without a workspace selector', () => {
  it('the header carries no workspace selector or workspace name; one New Scan, one account menu', () => {
    renderLayout({ workspace: { id: 'ws_a', name: 'Customer A' } })
    const h = header()
    expect(within(h).queryByRole('button', { name: /^Workspace$/ })).not.toBeInTheDocument()
    expect(within(h).queryByText('Customer A')).not.toBeInTheDocument()
    expect(within(h).queryByText('Switch workspace')).not.toBeInTheDocument()
    expect(within(h).queryByText('Manage workspaces')).not.toBeInTheDocument()
    expect(within(h).getAllByRole('button', { name: 'New Scan' })).toHaveLength(1)
    expect(within(h).getAllByRole('button', { name: 'Account menu' })).toHaveLength(1)
  })

  it('the main navigation is declared single-line on wide screens with non-wrapping items', async () => {
    renderLayout({ features: ['portfolio_monitoring'] })
    const nav = screen.getByRole('navigation', { name: 'Main navigation' })
    expect(nav.className.split(' ')).toContain('lg:flex-nowrap')
    await waitFor(() => expect(within(nav).getAllByRole('link')).toHaveLength(MSP_NAV.length))
    for (const a of within(nav).getAllByRole('link')) expect(a.className.split(' ')).toContain('whitespace-nowrap')
    expect(DIRECT_NAV.length).toBe(6)
  })
})

describe('Sidebar WORKSPACE section', () => {
  it('the sidebar starts with the module list — no workspace title above it', () => {
    renderLayout({ workspace: { id: 'ws_a', name: 'Customer A' }, path: '/ws/email-protection' })
    const rail = screen.getByRole('complementary')
    const body = rail.querySelector('#workspace-service-navigation')
    expect(body.firstElementChild.tagName).toBe('NAV')
    expect(within(rail).queryByText('All workspaces')).not.toBeInTheDocument()
    // The name appears once, in the WORKSPACE section at the foot (and in the phone toggle).
    expect(within(screen.getByTestId('workspace-section')).getByTestId('active-workspace-name')).toHaveTextContent('Customer A')
  })

  it('the selector options live in the WORKSPACE section: switch list, manage, clear', async () => {
    renderLayout({ workspace: { id: 'ws_a', name: 'Customer A' }, path: '/ws/email-protection' })
    const section = within(screen.getByTestId('workspace-section'))
    const toggle = section.getByRole('button', { name: 'Workspace' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(section.queryByText('Switch workspace')).not.toBeInTheDocument()
    fireEvent.click(toggle)
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    expect(section.getByText('Switch workspace')).toBeInTheDocument()
    expect(await section.findByRole('button', { name: /Customer B/ })).toBeInTheDocument()
    expect(section.getByRole('button', { name: /Customer A/ })).toHaveAttribute('aria-current', 'true')
    expect(section.getByRole('link', { name: 'Manage workspaces' })).toHaveAttribute('href', '/workspaces')
    expect(section.getByRole('button', { name: 'Clear selection' })).toBeInTheDocument()
    expect(section.getByRole('link', { name: 'Administration' })).toHaveAttribute('href', '/ws/dashboard')
    expect(api.getWorkspaces).toHaveBeenCalledTimes(1)
  })

  it('switching selects the workspace and clearing leaves the workspace pages', async () => {
    renderLayout({ workspace: { id: 'ws_a', name: 'Customer A' }, path: '/ws/email-protection' })
    const section = () => within(screen.getByTestId('workspace-section'))
    fireEvent.click(section().getByRole('button', { name: 'Workspace' }))
    fireEvent.click(await section().findByRole('button', { name: /Customer B/ }))
    expect(localStorage.getItem('cybermeters_workspace_id')).toBe('ws_b')
    await waitFor(() => expect(section().getByTestId('active-workspace-name')).toHaveTextContent('Customer B'))

    fireEvent.click(section().getByRole('button', { name: 'Workspace' }))
    fireEvent.click(await section().findByRole('button', { name: 'Clear selection' }))
    expect(localStorage.getItem('cybermeters_workspace_id')).toBeNull()
    await waitFor(() => expect(screen.queryByRole('complementary')).not.toBeInTheDocument())
  })
})
