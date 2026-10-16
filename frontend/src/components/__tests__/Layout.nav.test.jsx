import { render, screen, within, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import Layout, { DIRECT_NAV, MSP_NAV, MSP_NAV_FEATURE, selectNav, roleLabelFor } from '../Layout'
import { api } from '../../api'
import { useAuth } from '../../context/AuthContext'

// The app shell (founder, 16 Oct 2026): a white top bar with the main menu as
// pills, the bell and the account button; Field Guide and Billing in the
// account menu; no scan button in the bar. The menu is chosen from the
// account's ENTITLEMENT, never from how many workspaces or domains it has.

vi.mock('../../api', () => ({
  api: { getAccountUsage: vi.fn(), getWorkspaces: vi.fn() },
  logoutWithToken: vi.fn(),
}))
vi.mock('../../context/AuthContext', () => ({ useAuth: vi.fn() }))
vi.mock('../NotificationBell', () => ({ default: () => <button type="button" aria-label="Notifications" /> }))
vi.mock('../../utils/preload', () => ({ preloadComponent: vi.fn() }))
vi.mock('../../utils/preloadMap', () => ({ routePreloadMap: {} }))

const DIRECT_FEATURES = ['scheduled_scans', 'alerts', 'pdf_reports', 'business_risk_score', 'cyber_essentials']
const PRO_FEATURES = [...DIRECT_FEATURES, 'multi_workspace', 'team_members', 'vendor_risk', 'executive_dashboard', 'audit_logs']
const MSP_FEATURES = [...PRO_FEATURES, 'portfolio_monitoring', 'white_label']

function renderLayout(usage, { user = { name: 'Taylor Owner', email: 'owner@example.co.uk', plan: 'professional' }, path = '/dashboard', workspace = null } = {}) {
  useAuth.mockReturnValue({ user, logout: vi.fn(), isAuthenticated: true, isLoading: false })
  api.getWorkspaces.mockResolvedValue({ workspaces: [] })
  if (usage instanceof Promise) api.getAccountUsage.mockReturnValue(usage)
  else if (usage instanceof Error) api.getAccountUsage.mockRejectedValue(usage)
  else api.getAccountUsage.mockResolvedValue(usage)
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

const topBarLabels = () =>
  within(screen.getByRole('navigation', { name: 'Main navigation' })).getAllByRole('link').map(a => a.textContent)
const header = () => screen.getByRole('banner')

const DIRECT = ['Overview', 'Services', 'Cases', 'Reports']
const MSP = ['Portfolio', 'Customers', 'Operations', 'Reports']

beforeEach(() => {
  localStorage.clear()
  vi.clearAllMocks()
})

describe('selectNav (pure)', () => {
  it('chooses the MSP menu only on the portfolio_monitoring entitlement', () => {
    expect(selectNav(DIRECT_FEATURES)).toBe(DIRECT_NAV)
    expect(selectNav(PRO_FEATURES)).toBe(DIRECT_NAV)
    expect(selectNav(MSP_FEATURES)).toBe(MSP_NAV)
    expect(selectNav(null)).toBe(DIRECT_NAV)
    expect(selectNav(undefined)).toBe(DIRECT_NAV)
    expect(selectNav('portfolio_monitoring')).toBe(DIRECT_NAV)
    expect(MSP_NAV_FEATURE).toBe('portfolio_monitoring')
  })

  it('names the destinations the founder fixed — four pills, Field Guide and Billing elsewhere', () => {
    expect(DIRECT_NAV.map(i => i.label)).toEqual(DIRECT)
    expect(DIRECT_NAV.map(i => i.to)).toEqual(['/dashboard', '/services', '/ws/cases', '/reports'])
    expect(MSP_NAV.map(i => i.label)).toEqual(MSP)
    expect(MSP_NAV.map(i => i.to)).toEqual(['/portfolio', '/workspaces', '/ws/cases', '/reports'])
  })

  it('no two items in one menu share a destination', () => {
    for (const menu of [DIRECT_NAV, MSP_NAV]) expect(new Set(menu.map(i => i.to)).size).toBe(menu.length)
  })

  it('role label comes from the plan the API published', () => {
    expect(roleLabelFor({ plan: 'business' })).toBe('Business plan')
    expect(roleLabelFor({ plan: 'enterprise' })).toBe('MSP plan')
    expect(roleLabelFor({})).toBeNull()
  })
})

describe('Layout top bar — personas', () => {
  it('single-workspace, single-domain direct customer never sees an MSP surface', async () => {
    renderLayout({ plan: 'starter', features: DIRECT_FEATURES, usage: { workspaces: 1, domains: 1 } })
    await waitFor(() => expect(api.getAccountUsage).toHaveBeenCalled())
    expect(topBarLabels()).toEqual(DIRECT)
    for (const label of ['Portfolio', 'Customers', 'Operations']) expect(screen.queryByRole('link', { name: label })).not.toBeInTheDocument()
  })

  it('multi-domain direct customer still gets the direct menu — count is not entitlement', async () => {
    renderLayout({ plan: 'professional', features: PRO_FEATURES, usage: { workspaces: 1, domains: 12 } })
    await waitFor(() => expect(api.getAccountUsage).toHaveBeenCalled())
    expect(topBarLabels()).toEqual(DIRECT)
  })

  it('MSP with the entitlement gets the MSP menu even with a single customer', async () => {
    renderLayout({ plan: 'business', features: MSP_FEATURES, usage: { workspaces: 1, domains: 1 } })
    await waitFor(() => expect(topBarLabels()).toEqual(MSP))
  })

  it('MSP-shaped account WITHOUT the entitlement (many workspaces) gets the direct menu', async () => {
    renderLayout({ plan: 'professional', features: PRO_FEATURES, usage: { workspaces: 9, domains: 40 } })
    await waitFor(() => expect(api.getAccountUsage).toHaveBeenCalled())
    expect(topBarLabels()).toEqual(DIRECT)
  })

  it('until usage loads, the direct menu shows; when usage fails, the direct menu stays', async () => {
    renderLayout(new Promise(() => {}))
    expect(topBarLabels()).toEqual(DIRECT)
    renderLayout(new Error('usage unavailable'))
    await waitFor(() => expect(api.getAccountUsage).toHaveBeenCalledTimes(2))
    expect(screen.getAllByRole('navigation', { name: 'Main navigation' }).every(n => within(n).getAllByRole('link').map(a => a.textContent).join() === DIRECT.join())).toBe(true)
  })

  it('an older API without `features` reads as direct', async () => {
    renderLayout({ plan: 'business', usage: { workspaces: 3 } })
    await waitFor(() => expect(api.getAccountUsage).toHaveBeenCalled())
    expect(topBarLabels()).toEqual(DIRECT)
  })
})

describe('Layout top bar — shape', () => {
  it('the active pill is the one whose route is current', async () => {
    renderLayout({ features: DIRECT_FEATURES }, { path: '/reports' })
    const active = within(screen.getByRole('navigation', { name: 'Main navigation' })).getAllByRole('link').filter(a => a.className.includes('cm-pill-active'))
    expect(active.map(a => a.textContent)).toEqual(['Reports'])
  })

  it('carries no scan button, no workspace selector and no Field Guide or Billing pill', async () => {
    renderLayout({ features: DIRECT_FEATURES }, { workspace: { id: 'ws_a', name: 'Customer A' } })
    const h = header()
    expect(within(h).queryByRole('button', { name: /New Scan/ })).not.toBeInTheDocument()
    expect(within(h).queryByRole('link', { name: 'Field Guide' })).not.toBeInTheDocument()
    expect(within(h).queryByRole('link', { name: 'Billing' })).not.toBeInTheDocument()
    expect(within(h).queryByText('Customer A')).not.toBeInTheDocument()
    expect(within(h).getByRole('link', { name: 'CyberMeters home' })).toHaveAttribute('href', '/dashboard')
    expect(within(h).getByRole('button', { name: 'Notifications' })).toBeInTheDocument()
  })

  it('the account button shows the initial and opens Field Guide, Billing, Account & security and Sign out', async () => {
    renderLayout({ features: DIRECT_FEATURES })
    const b = within(header()).getByRole('button', { name: 'Account menu' })
    expect(b).toHaveTextContent('T')
    expect(b).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(b)
    expect(b).toHaveAttribute('aria-expanded', 'true')
    const menu = screen.getByRole('menu', { name: 'Account' })
    expect(within(menu).getByText('Taylor Owner')).toBeInTheDocument()
    expect(within(menu).getByText('Professional plan')).toBeInTheDocument()
    const items = within(menu).getAllByRole('menuitem')
    expect(items.map(i => i.textContent)).toEqual(['Field Guide', 'Billing', 'Account & security', 'Sign out'])
    expect(items[0]).toHaveAttribute('href', '/guide')
    expect(items[1]).toHaveAttribute('href', '/billing')
    expect(items[2]).toHaveAttribute('href', '/account')
  })

  it('the account menu closes on Escape (focus back on the button) and on an outside click', () => {
    renderLayout({ features: DIRECT_FEATURES })
    const b = within(header()).getByRole('button', { name: 'Account menu' })
    fireEvent.click(b)
    within(screen.getByRole('menu', { name: 'Account' })).getAllByRole('menuitem')[0].focus()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('menu', { name: 'Account' })).not.toBeInTheDocument()
    expect(document.activeElement).toBe(b)
    fireEvent.click(b)
    fireEvent.mouseDown(screen.getByTestId('page'))
    expect(screen.queryByRole('menu', { name: 'Account' })).not.toBeInTheDocument()
  })

  it('signing out clears the session and goes to the login page', async () => {
    const logout = vi.fn()
    useAuth.mockReturnValue({ user: { name: 'Taylor Owner', plan: 'starter' }, logout, isAuthenticated: true, isLoading: false })
    api.getAccountUsage.mockResolvedValue({ features: DIRECT_FEATURES })
    api.getWorkspaces.mockResolvedValue({ workspaces: [] })
    render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <Routes>
          <Route element={<Layout />}><Route path="*" element={<div data-testid="page" />} /></Route>
          <Route path="/login" element={<div data-testid="login" />} />
        </Routes>
      </MemoryRouter>,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Account menu' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Sign out' }))
    expect(logout).toHaveBeenCalled()
    expect(await screen.findByTestId('login')).toBeInTheDocument()
  })

  it('renders the module rail, the globe and a skip link; every top-bar label is at least 15px', () => {
    renderLayout({ features: DIRECT_FEATURES })
    expect(screen.getByRole('navigation', { name: 'Modules' })).toBeInTheDocument()
    expect(screen.getByTestId('shell-globe')).toHaveAttribute('aria-hidden', 'true')
    expect(screen.getByText('Skip to content')).toHaveAttribute('href', '#main')
    expect(screen.getByRole('main')).toHaveAttribute('id', 'main')
    for (const a of within(screen.getByRole('navigation', { name: 'Main navigation' })).getAllByRole('link')) {
      expect(a.className.split(' ')).toContain('cm-pill')
    }
  })
})
