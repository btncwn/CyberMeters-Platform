import { render, screen, within, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import Layout, { DIRECT_NAV, MSP_NAV, MSP_NAV_FEATURE, selectNav, roleLabelFor, planLabelFor } from '../Layout'
import { api } from '../../api'
import { useAuth } from '../../context/AuthContext'

// The app shell v2 (founder prototype, 17 Oct 2026): a 68px top bar with ONE
// brand button on the left (it opens the area sheet), the main menu as pills
// and the account initial on the right; no bell, no lone dot, no left rail.
// Field Guide and Billing live in the account menu; no scan button in the bar.
// The menu is chosen from the account's ENTITLEMENT, never from how many
// workspaces or domains it has.

vi.mock('../../api', () => ({
  api: { getAccountUsage: vi.fn(), getWorkspaces: vi.fn(), getCyberMotDomains: vi.fn(), getWorkspaceDomains: vi.fn(), getWorkspaceMembers: vi.fn() },
  logoutWithToken: vi.fn(),
}))
vi.mock('../../context/AuthContext', () => ({ useAuth: vi.fn() }))
vi.mock('../shell/EarthButton', () => ({
  default: () => <button type="button" aria-label="Notifications" data-testid="shell-earth" />,
}))
vi.mock('../../utils/preload', () => ({ preloadComponent: vi.fn() }))
vi.mock('../../utils/preloadMap', () => ({ routePreloadMap: {} }))

const DIRECT_FEATURES = ['scheduled_scans', 'alerts', 'pdf_reports', 'business_risk_score', 'cyber_essentials']
const PRO_FEATURES = [...DIRECT_FEATURES, 'multi_workspace', 'team_members', 'vendor_risk', 'executive_dashboard', 'audit_logs']
const MSP_FEATURES = [...PRO_FEATURES, 'portfolio_monitoring', 'white_label']

// jsdom has no matchMedia: the shell is wide (≥1280px, docks in the gutters)
// unless a test asks for the compact bar.
function mockViewport(wide) {
  window.matchMedia = vi.fn().mockReturnValue({ matches: wide, addEventListener: vi.fn(), removeEventListener: vi.fn() })
}

function renderLayout(usage, { user = { name: 'Taylor Owner', email: 'owner@example.co.uk', plan: 'professional' }, path = '/dashboard', workspace = null, wide = true, domainsFor = null } = {}) {
  mockViewport(wide)
  useAuth.mockReturnValue({ user, logout: vi.fn(), isAuthenticated: true, isLoading: false })
  api.getWorkspaces.mockResolvedValue({ workspaces: [] })
  api.getCyberMotDomains.mockResolvedValue({ cyber_mot_domains: [] })
  api.getWorkspaceDomains.mockImplementation(async (id) => (domainsFor ? domainsFor(id) : { domains: [] }))
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

const DIRECT = ['Overview', 'Operations', 'Reports']
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

  it('names the destinations the founder fixed — three pills, Field Guide and Billing elsewhere', () => {
    expect(DIRECT_NAV.map(i => i.label)).toEqual(DIRECT)
    expect(DIRECT_NAV.map(i => i.to)).toEqual(['/dashboard', '/ws/cases', '/reports'])
    expect(MSP_NAV.map(i => i.label)).toEqual(MSP)
    expect(MSP_NAV.map(i => i.to)).toEqual(['/portfolio', '/workspaces', '/ws/cases', '/reports'])
  })

  it('no two items in one menu share a destination', () => {
    for (const menu of [DIRECT_NAV, MSP_NAV]) expect(new Set(menu.map(i => i.to)).size).toBe(menu.length)
  })

  it('plan line: member vs owner vs no membership (18 Oct 2026)', () => {
    const workspaces = [{ id: 'ws_own', name: 'Own Co', role: 'owner' }, { id: 'ws_bbb', name: 'Black Bull Barbers', role: 'analyst' }]
    // Access through membership: the active workspace is someone else's, no paid plan.
    expect(planLabelFor({ user: { plan: 'free' }, workspaces, activeWsId: 'ws_bbb', ownerName: 'Taylor Owner' })).toBe('Member of Black Bull Barbers · plan managed by Taylor Owner')
    expect(planLabelFor({ user: { plan: 'free' }, workspaces: [workspaces[1]], activeWsId: null })).toBe('Member of Black Bull Barbers · plan managed by the workspace owner')
    // Owner of the active workspace on the free plan.
    expect(planLabelFor({ user: { plan: 'free' }, workspaces, activeWsId: 'ws_own' })).toBe('Free plan')
    // No memberships, no subscription.
    expect(planLabelFor({ user: { plan: 'free' }, workspaces: [], activeWsId: null })).toBe('Free plan')
    // A paid plan names itself, even while viewing a workspace the user only belongs to.
    expect(planLabelFor({ user: { plan: 'professional' }, workspaces, activeWsId: 'ws_bbb', ownerName: 'Taylor Owner' })).toBe('Professional plan')
    expect(planLabelFor({ user: {}, workspaces: [], activeWsId: null })).toBeNull()
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
    for (const label of ['Portfolio', 'Customers', 'Services', 'Cases']) expect(screen.queryByRole('link', { name: label })).not.toBeInTheDocument()
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
    // The brand is ONE button that opens the areas; no bell and no lone dot in the bar.
    const brand = within(h).getByRole('button', { name: 'CyberMeters — open areas' })
    expect(brand).toHaveTextContent('CyberMeters')
    expect(brand).toHaveAttribute('aria-haspopup', 'menu')
    // The globe is the one notifications control in the bar; no bell beside it.
    expect(within(h).getAllByRole('button', { name: /^Notifications/ })).toHaveLength(1)
    // The globe sits immediately before the account initial.
    const slot = within(h).getByTestId('earth-slot')
    expect(slot.compareDocumentPosition(within(h).getByRole('button', { name: 'Account menu' })) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(slot).toHaveClass('mr-3')
    expect(within(h).queryByRole('link', { name: 'CyberMeters home' })).not.toBeInTheDocument()
  })

  it('the account button shows the initial and opens Field Guide, Account, Billing and Sign out — account things only', async () => {
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
    expect(items.map(i => i.textContent)).toEqual(['Field Guide', 'Account', 'Billing', 'Sign out'])
    expect(items[0]).toHaveAttribute('href', '/guide')
    expect(items[1]).toHaveAttribute('href', '/account')
    expect(items[2]).toHaveAttribute('href', '/billing')
  })

  it('with a workspace selected the account menu still carries no workspace things (they live in the workspace menu)', () => {
    renderLayout({ features: DIRECT_FEATURES }, { workspace: { id: 'ws_a', name: 'Customer A' } })
    fireEvent.click(within(header()).getByRole('button', { name: 'Account menu' }))
    const menu = screen.getByRole('menu', { name: 'Account' })
    expect(within(menu).getAllByRole('menuitem').map(i => i.textContent)).toEqual(['Field Guide', 'Account', 'Billing', 'Sign out'])
    for (const gone of ['Administration', 'Alert channels', 'Audit log', 'Usage & retention', 'Settings', 'Scorecard', 'Executive dashboard', 'Operations', 'Related changes']) {
      expect(within(menu).queryByRole('menuitem', { name: gone })).not.toBeInTheDocument()
    }
    expect(screen.queryByTestId('profile-settings-group')).not.toBeInTheDocument()
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

  it('has no rail: the areas show only in the sheet the brand opens; the docks and the skip link are present', () => {
    renderLayout({ features: DIRECT_FEATURES }, { workspace: { id: 'ws_a', name: 'Customer A' } })
    expect(screen.queryByRole('navigation', { name: 'Modules' })).not.toBeInTheDocument()
    expect(screen.queryByTestId('module-rail')).not.toBeInTheDocument()
    expect(screen.queryByText('Email Protection')).not.toBeInTheDocument()
    fireEvent.click(within(header()).getByRole('button', { name: 'CyberMeters — open areas' }))
    const sheet = screen.getByRole('menu', { name: 'Areas' })
    expect(within(sheet).getAllByRole('menuitem')).toHaveLength(8)
    expect(within(sheet).getByText('Email Protection')).toBeInTheDocument()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('menu', { name: 'Areas' })).not.toBeInTheDocument()

    // Workspace card deck bottom-left; the globe lives in the top bar, nothing bottom-right.
    const dock = screen.getByTestId('workspace-dock')
    expect(within(dock).getByRole('button', { name: 'Workspace: Customer A' })).toHaveClass('cm-wsbtn')
    // The deck is a layout column beside the content, not an overlay on it.
    expect(dock.parentElement).toHaveClass('cm-body')
    expect(dock.parentElement).toBe(screen.getByRole('main').parentElement)
    expect(screen.queryByTestId('earth-dock')).not.toBeInTheDocument()
    expect(within(header()).getByTestId('shell-earth')).toBeInTheDocument()
    expect(screen.getByText('Skip to content')).toHaveAttribute('href', '#main')
    expect(screen.getByRole('main')).toHaveAttribute('id', 'main')
    for (const a of within(screen.getByRole('navigation', { name: 'Main navigation' })).getAllByRole('link')) {
      expect(a.className.split(' ')).toContain('cm-pill')
    }
  })

  it('below 1280px no dock is rendered: the 36px workspace card and the same globe sit in the top bar; no bell', async () => {
    renderLayout({ features: DIRECT_FEATURES }, { workspace: { id: 'ws_a', name: 'Customer A' }, wide: false })
    expect(screen.queryByTestId('earth-dock')).not.toBeInTheDocument()
    expect(screen.queryByTestId('workspace-dock')).not.toBeInTheDocument()
    const h = header()
    const mini = within(h).getByRole('button', { name: 'Workspace: Customer A' })
    expect(mini).toHaveClass('cm-wsmini')
    expect(screen.queryByTestId('compact-bell')).not.toBeInTheDocument()
    expect(within(h).getAllByRole('button', { name: /^Notifications/ })).toHaveLength(1)
    fireEvent.click(mini)
    expect(await screen.findByRole('menu', { name: 'Workspace' })).toBeInTheDocument()
  })

  it('the workspace dock opens the existing workspace popover', async () => {
    renderLayout({ features: DIRECT_FEATURES }, { workspace: { id: 'ws_a', name: 'Customer A' } })
    api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws_a', name: 'Customer A' }, { id: 'ws_b', name: 'Customer B' }] })
    fireEvent.click(within(screen.getByTestId('workspace-dock')).getByRole('button', { name: 'Workspace: Customer A' }))
    const menu = screen.getByRole('menu', { name: 'Workspace' })
    expect(await within(menu).findByRole('menuitem', { name: /Customer B/ })).toBeInTheDocument()
    expect(within(menu).getByRole('menuitem', { name: 'Manage workspaces' })).toHaveAttribute('href', '/workspaces')
    expect(within(menu).getByRole('menuitem', { name: 'Members & roles' })).toHaveAttribute('href', '/ws/members')
  })

  it('the workspace card letter is the selected domain\'s initial and follows a workspace switch', async () => {
    const domainsFor = (id) => ({
      domains: id === 'ws_a'
        ? [{ domain: 'pending.example', verification_status: 'pending' }, { domain: 'cybermeters.com', verification_status: 'verified' }]
        : [{ domain: 'blackbullbarbers.co.uk', verification_status: 'verified' }],
    })
    renderLayout({ features: DIRECT_FEATURES }, { workspace: { id: 'ws_a', name: 'Zed Workspace' }, domainsFor })
    const dock = screen.getByTestId('workspace-dock')
    await waitFor(() => expect(within(dock).getByTestId('workspace-initial')).toHaveTextContent('C'))
    expect(within(dock).getByRole('button', { name: 'Workspace: Zed Workspace' })).toHaveAttribute('title', 'Workspace · cybermeters.com')
    localStorage.setItem('cybermeters_workspace_id', 'ws_b')
    localStorage.setItem('cybermeters_workspace_name', 'Black Bull Barbers')
    window.dispatchEvent(new Event('storage'))
    await waitFor(() => expect(within(dock).getByTestId('workspace-initial')).toHaveTextContent('B'))
  })

  it('the account menu shows the member line for a workspace the user only belongs to', async () => {
    renderLayout({ features: DIRECT_FEATURES }, { user: { name: 'Casey Analyst', email: 'casey@example.co.uk', plan: 'free' }, workspace: { id: 'ws_bbb', name: 'Black Bull Barbers' } })
    api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws_bbb', name: 'Black Bull Barbers', role: 'analyst' }] })
    api.getWorkspaceMembers.mockResolvedValue({ members: [{ role: 'owner', name: 'Taylor Owner', email: 'owner@example.co.uk' }, { role: 'analyst', name: 'Casey Analyst' }] })
    // Re-render with the membership data in place.
    window.dispatchEvent(new Event('storage'))
    fireEvent.click(within(header()).getByRole('button', { name: 'Account menu' }))
    const menu = screen.getByRole('menu', { name: 'Account' })
    await waitFor(() => expect(within(menu).getByText('Member of Black Bull Barbers · plan managed by Taylor Owner')).toBeInTheDocument())
    expect(within(menu).queryByText('Free plan')).toBeNull()
    expect(document.body.textContent).not.toContain('owner@example.co.uk')
  })
})
