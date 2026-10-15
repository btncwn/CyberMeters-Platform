import { render, screen, within, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import Layout, { DIRECT_NAV, MSP_NAV, MSP_NAV_FEATURE, navColorAt, selectNav } from '../Layout'
import { api } from '../../api'
import { useAuth } from '../../context/AuthContext'

// The top bar chooses its menu from the account's ENTITLEMENT, never from how
// many workspaces or domains the account has. These personas pin that down.

vi.mock('../../api', () => ({
  api: { getAccountUsage: vi.fn(), getWorkspaces: vi.fn() },
  logoutWithToken: vi.fn(),
}))
vi.mock('../../context/AuthContext', () => ({ useAuth: vi.fn() }))
vi.mock('../NotificationBell', () => ({ default: () => null }))
vi.mock('../../utils/preload', () => ({ preloadComponent: vi.fn() }))
vi.mock('../../utils/preloadMap', () => ({ routePreloadMap: {} }))

const DIRECT_FEATURES = ['scheduled_scans', 'alerts', 'pdf_reports', 'business_risk_score', 'cyber_essentials']
const PRO_FEATURES = [...DIRECT_FEATURES, 'multi_workspace', 'team_members', 'vendor_risk', 'executive_dashboard', 'audit_logs']
const MSP_FEATURES = [...PRO_FEATURES, 'portfolio_monitoring', 'white_label']

function hexToRgb(hex) {
  const n = parseInt(hex.slice(1), 16)
  return `rgb(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255})`
}

function renderLayout(usage, { user = { name: 'Owner', email: 'owner@example.co.uk', plan: 'starter' }, path = '/dashboard' } = {}) {
  useAuth.mockReturnValue({ user, logout: vi.fn(), isAuthenticated: true, isLoading: false })
  api.getWorkspaces.mockResolvedValue({ workspaces: [] })
  if (usage instanceof Promise) api.getAccountUsage.mockReturnValue(usage)
  else if (usage instanceof Error) api.getAccountUsage.mockRejectedValue(usage)
  else api.getAccountUsage.mockResolvedValue(usage)
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

const MSP_ONLY = ['Portfolio', 'Customers', 'Operations']
const DIRECT = ['Overview', 'Services', 'Cases', 'Reports', 'Field Guide', 'Billing']
const MSP = ['Portfolio', 'Customers', 'Operations', 'Reports', 'Field Guide']

beforeEach(() => {
  localStorage.clear()
  vi.clearAllMocks()
})

describe('selectNav (pure)', () => {
  it('chooses the MSP menu only on the portfolio_monitoring entitlement', () => {
    expect(MSP_NAV_FEATURE).toBe('portfolio_monitoring')
    expect(selectNav(MSP_FEATURES)).toBe(MSP_NAV)
    expect(selectNav(PRO_FEATURES)).toBe(DIRECT_NAV)
    expect(selectNav(DIRECT_FEATURES)).toBe(DIRECT_NAV)
    expect(selectNav([])).toBe(DIRECT_NAV)
    expect(selectNav(null)).toBe(DIRECT_NAV)
    expect(selectNav(undefined)).toBe(DIRECT_NAV)
    expect(selectNav('portfolio_monitoring')).toBe(DIRECT_NAV)
  })

  it('names the destinations the founder fixed', () => {
    expect(DIRECT_NAV.map(i => i.label)).toEqual(DIRECT)
    expect(MSP_NAV.map(i => i.label)).toEqual(MSP)
    expect(DIRECT_NAV.find(i => i.label === 'Cases').to).toBe('/ws/cases')
    expect(MSP_NAV.find(i => i.label === 'Operations').to).toBe('/ws/cases')
    expect(MSP_NAV.find(i => i.label === 'Portfolio').to).toBe('/portfolio')
    expect(MSP_NAV.find(i => i.label === 'Customers').to).toBe('/workspaces')
    expect(DIRECT_NAV.find(i => i.label === 'Field Guide').to).toBe('/guide')
  })

  it('colours belong to the position: two items per amber step', () => {
    expect([0, 1, 2, 3, 4, 5, 6].map(navColorAt)).toEqual(['#CB6629', '#CB6629', '#D57B2E', '#D57B2E', '#DE8E33', '#DE8E33', '#DE8E33'])
  })

  it('no two items in one menu share a destination', () => {
    for (const menu of [DIRECT_NAV, MSP_NAV]) {
      expect(new Set(menu.map(i => i.to)).size).toBe(menu.length)
    }
  })
})

describe('Layout top bar — personas', () => {
  it('single-workspace, single-domain direct customer never sees an MSP surface', async () => {
    renderLayout({ plan: 'starter', features: DIRECT_FEATURES, usage: { workspaces: 1, domains: 1, users: 1 }, limits: { workspaces: 1, domains: 1 } })
    await waitFor(() => expect(api.getAccountUsage).toHaveBeenCalled())
    expect(topBarLabels()).toEqual(DIRECT)
    for (const label of MSP_ONLY) expect(screen.queryByRole('link', { name: label })).not.toBeInTheDocument()
  })

  it('multi-domain direct customer (professional, many domains) still gets the direct menu — count is not entitlement', async () => {
    renderLayout({ plan: 'professional', features: PRO_FEATURES, usage: { workspaces: 3, domains: 12, users: 6 }, limits: { workspaces: 5, domains: 25 } })
    await waitFor(() => expect(api.getAccountUsage).toHaveBeenCalled())
    expect(topBarLabels()).toEqual(DIRECT)
    for (const label of MSP_ONLY) expect(screen.queryByRole('link', { name: label })).not.toBeInTheDocument()
  })

  it('MSP with the entitlement gets the MSP menu even with a single customer', async () => {
    renderLayout({ plan: 'business', features: MSP_FEATURES, usage: { workspaces: 1, domains: 1, users: 1 }, limits: { workspaces: 25, domains: 100 } })
    await screen.findByRole('link', { name: 'Portfolio' })
    expect(topBarLabels()).toEqual(MSP)
    expect(screen.queryByRole('link', { name: 'Overview' })).not.toBeInTheDocument()
  })

  it('MSP-shaped account WITHOUT the entitlement (many workspaces) gets the direct menu', async () => {
    renderLayout({ plan: 'professional', features: PRO_FEATURES, usage: { workspaces: 9, domains: 40, users: 12 }, limits: { workspaces: 10, domains: 50 } })
    await waitFor(() => expect(api.getAccountUsage).toHaveBeenCalled())
    expect(topBarLabels()).toEqual(DIRECT)
  })

  it('read-only member: the menu follows the account entitlement, not the member role', async () => {
    renderLayout({ plan: 'starter', features: DIRECT_FEATURES, usage: { workspaces: 1, domains: 1, users: 3 } }, { user: { name: 'Viewer', email: 'viewer@example.co.uk', role: 'viewer' } })
    await waitFor(() => expect(api.getAccountUsage).toHaveBeenCalled())
    expect(topBarLabels()).toEqual(DIRECT)
  })

  it('trial on a business plan carries the entitlement the API publishes', async () => {
    renderLayout({ plan: 'business', trial: { active: true }, features: MSP_FEATURES, usage: { workspaces: 1, domains: 1, users: 1 } })
    await screen.findByRole('link', { name: 'Portfolio' })
    expect(topBarLabels()).toEqual(MSP)
  })

  it('expired plan (API resolves to free, no features) falls back to the direct menu', async () => {
    renderLayout({ plan: 'free', features: [], usage: { workspaces: 4, domains: 9, users: 2 } })
    await waitFor(() => expect(api.getAccountUsage).toHaveBeenCalled())
    expect(topBarLabels()).toEqual(DIRECT)
  })

  it('until usage loads, the direct menu shows', () => {
    renderLayout(new Promise(() => {}))
    expect(topBarLabels()).toEqual(DIRECT)
  })

  it('when usage fails, the direct menu shows (never an MSP surface the API would 403)', async () => {
    renderLayout(new Error('network'))
    await waitFor(() => expect(api.getAccountUsage).toHaveBeenCalled())
    expect(topBarLabels()).toEqual(DIRECT)
  })

  it('an older API without `features` reads as direct', async () => {
    renderLayout({ plan: 'business', usage: { workspaces: 6, domains: 30, users: 4 } })
    await waitFor(() => expect(api.getAccountUsage).toHaveBeenCalled())
    expect(topBarLabels()).toEqual(DIRECT)
  })
})

describe('Layout top bar — colour, duplicates, hygiene', () => {
  it('direct menu: two items per amber step, deepest first', async () => {
    renderLayout({ plan: 'starter', features: DIRECT_FEATURES, usage: {} })
    await waitFor(() => expect(api.getAccountUsage).toHaveBeenCalled())
    const links = within(screen.getByRole('navigation', { name: 'Main navigation' })).getAllByRole('link')
    expect(links.map(a => a.style.color)).toEqual(['#CB6629', '#CB6629', '#D57B2E', '#D57B2E', '#DE8E33', '#DE8E33'].map(hexToRgb))
  })

  it('MSP menu: same steps by position', async () => {
    renderLayout({ plan: 'business', features: MSP_FEATURES, usage: {} })
    await screen.findByRole('link', { name: 'Portfolio' })
    const links = within(screen.getByRole('navigation', { name: 'Main navigation' })).getAllByRole('link')
    expect(links.map(a => a.style.color)).toEqual(['#CB6629', '#CB6629', '#D57B2E', '#D57B2E', '#DE8E33'].map(hexToRgb))
  })

  it('the active item is the one whose route is current', async () => {
    renderLayout({ plan: 'starter', features: DIRECT_FEATURES, usage: {} }, { path: '/guide' })
    await waitFor(() => expect(api.getAccountUsage).toHaveBeenCalled())
    const active = within(screen.getByRole('navigation', { name: 'Main navigation' })).getAllByRole('link').filter(a => a.className.includes('cm-topbar-link-active'))
    expect(active.map(a => a.textContent)).toEqual(['Field Guide'])
  })

  it('Field Guide lives in the top bar and nowhere else in the header; Billing never shows twice', async () => {
    renderLayout({ plan: 'starter', features: DIRECT_FEATURES, usage: {} })
    await waitFor(() => expect(api.getAccountUsage).toHaveBeenCalled())
    fireEvent.click(screen.getByRole('button', { name: 'Account menu' }))
    expect(screen.queryByRole('button', { name: 'Field Guide' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Billing' })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Billing' })).toHaveAttribute('href', '/billing')
  })

  it('MSP menu keeps Billing reachable from the account menu, once', async () => {
    renderLayout({ plan: 'business', features: MSP_FEATURES, usage: {} })
    await screen.findByRole('link', { name: 'Portfolio' })
    expect(screen.queryByRole('link', { name: 'Billing' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Account menu' }))
    expect(screen.getAllByRole('button', { name: 'Billing' })).toHaveLength(1)
  })

  it('every top-bar label is at least 21px (type scale)', async () => {
    // The size is set by .cm-topbar-link in CSS; here we pin that no inline
    // size undercuts it and that the links carry the class the CSS keys on.
    renderLayout({ plan: 'starter', features: DIRECT_FEATURES, usage: {} })
    await waitFor(() => expect(api.getAccountUsage).toHaveBeenCalled())
    for (const a of within(screen.getByRole('navigation', { name: 'Main navigation' })).getAllByRole('link')) {
      expect(a.className).toContain('cm-topbar-link')
      expect(a.style.fontSize).toBe('')
    }
  })
})
