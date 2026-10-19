import { useState, useEffect } from 'react'
import { Outlet, NavLink, useLocation } from 'react-router-dom'
import { api } from '../api'
import { ACTIVE_WORKSPACE_EVENT, readActiveWorkspace, validateActiveWorkspace } from '../lib/activeWorkspace'
import { useAuth } from '../context/AuthContext'
import { detectServiceKey } from './WorkspaceNav'
import { SERVICE_COLORS } from '../theme/serviceColors'
import SafeBoundary from './SafeBoundary'
import ProfileMenu from './shell/ProfileMenu'
import AreaMenu from './shell/AreaMenu'
import WorkspaceMenu from './shell/WorkspaceMenu'
import EarthButton from './shell/EarthButton'
import UpgradePromptModal from './shell/UpgradePromptModal'

// The app shell v2 (founder prototype, 17 Oct 2026):
//   • a 68px top bar — on the left ONE button: the logo mark, the serif
//     wordmark and a small caret, which opens the area sheet (the eight
//     areas with the state the backend resolved); on the right the main menu
//     as pills (Overview · Services · Cases · Reports) and the account initial.
//     No bell, no lone dot.
//   • no left rail: the content takes the full width. Areas are reached from
//     the sheet (and from the pages); nothing lists the modules until the
//     brand is clicked.
//   • bottom-left: the workspace card deck (WorkspaceMenu) and its popover
//     (Switch, Manage workspaces, Members & roles).
//   • top bar, left of the account initial: the photographic globe — the ONE
//     notifications control at every width (founder, 17 Oct 2026). Same 40px
//     diameter as the initial, 12px apart; the unread counter is a small aqua
//     label on it; the panel opens beneath it, right-aligned. Nothing fixed
//     sits in the bottom-right of the content area, and there is no bell.
//   • the workspace deck sits in a reserved left gutter from 1280px up and is
//     not rendered below that; a 36px workspace card then takes its place in
//     the top bar.
//
// Two menus, chosen by ENTITLEMENT (the `features` list the API publishes on
// /account/usage), never by workspace or domain count. Until usage has loaded
// — or when it cannot — the direct menu shows, so nobody is ever shown an MSP
// surface the API would 403.
export const MSP_NAV_FEATURE = 'portfolio_monitoring'

// Founder, 17 Oct 2026: /services is gone (its setup steps live on Overview
// while setup is incomplete), so the direct menu is Overview · Operations · Reports.
export const DIRECT_NAV = [
  { to: '/dashboard', label: 'Overview'   },
  { to: '/ws/cases',  label: 'Operations' },
  { to: '/reports',   label: 'Reports'    },
]

export const MSP_NAV = [
  { to: '/portfolio',  label: 'Portfolio'  },
  { to: '/workspaces', label: 'Customers'  },
  { to: '/ws/cases',   label: 'Operations' },
  { to: '/reports',    label: 'Reports'    },
]

export function selectNav(features) {
  return Array.isArray(features) && features.includes(MSP_NAV_FEATURE) ? MSP_NAV : DIRECT_NAV
}

// Entitled feature keys for the signed-in account. `null` until the usage call
// resolves; `[]` when it fails — both read as "direct menu".
function useAccountFeatures() {
  const [features, setFeatures] = useState(null)
  useEffect(() => {
    let alive = true
    Promise.resolve()
      .then(() => api.getAccountUsage())
      .then(data => { if (alive) setFeatures(Array.isArray(data?.features) ? data.features : []) })
      .catch(() => { if (alive) setFeatures([]) })
    return () => { alive = false }
  }, [])
  return features
}

// Wide layout (≥1280px): the workspace deck lives in a reserved left gutter
// beside the content column, so no fixed element ever sits on page content
// or a control. Below that, the deck is not rendered at all: a 36px workspace
// card takes its place in the top bar, and the content keeps the full width.
export const WIDE_LAYOUT_QUERY = '(min-width: 1280px)'
function useWideLayout() {
  const query = typeof window !== 'undefined' && typeof window.matchMedia === 'function' ? window.matchMedia(WIDE_LAYOUT_QUERY) : null
  const [wide, setWide] = useState(Boolean(query?.matches))
  useEffect(() => {
    if (!query) return undefined
    const sync = () => setWide(Boolean(query.matches))
    sync()
    query.addEventListener?.('change', sync)
    return () => query.removeEventListener?.('change', sync)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  return wide
}

// The workspace card's letter is the selected domain's initial (founder,
// 17 Oct 2026): the workspace's first verified domain, else its first domain,
// else the workspace name. Re-read whenever the workspace changes, so an MSP
// switching customer sees the letter change at once.
export function primaryDomainOf(domains) {
  const rows = Array.isArray(domains) ? domains : []
  const nameOf = (d) => String(d?.domain || d?.name || '').trim()
  const verified = rows.find((d) => String(d?.verification_status || d?.status || '').toLowerCase() === 'verified' && nameOf(d))
  return nameOf(verified || rows.find(nameOf)) || null
}
function usePrimaryDomain(wsId) {
  const [domain, setDomain] = useState(null)
  useEffect(() => {
    let alive = true
    setDomain(null)
    if (!wsId) return undefined
    Promise.resolve()
      .then(() => api.getWorkspaceDomains(wsId))
      .then((data) => { if (alive) setDomain(primaryDomainOf(data?.domains)) })
      .catch(() => { if (alive) setDomain(null) })
    return () => { alive = false }
  }, [wsId])
  return domain
}

const PLAN_LABELS = { free: 'Free plan', starter: 'Starter plan', professional: 'Professional plan', business: 'Business plan', enterprise: 'MSP plan' }
/**
 * The account menu's plan line (P1, 18 Oct 2026). A paid plan names itself. A
 * user whose access comes from membership — the active workspace is someone
 * else's and they have no paid plan — reads "Member of <workspace> · plan managed
 * by <owner>". "Free plan" stays only for owners on the free plan and for users
 * with no memberships and no subscription.
 */
export function planLabelFor({ user = null, workspaces = [], activeWsId = null, ownerName = null } = {}) {
  const plan = String(user?.plan || '').toLowerCase()
  if (plan && plan !== 'free' && PLAN_LABELS[plan]) return PLAN_LABELS[plan]
  const list = Array.isArray(workspaces) ? workspaces : []
  const active = list.find((w) => w?.id === activeWsId) || null
  const memberOf = active && active.role && active.role !== 'owner'
    ? active
    : (!list.some((w) => w?.role === 'owner') ? list.find((w) => w?.role && w.role !== 'owner') : null)
  if (memberOf) return `Member of ${memberOf.name} · plan managed by ${ownerName || 'the workspace owner'}`
  return plan === 'free' ? 'Free plan' : null
}

// The memberships and the active workspace's owner name, for the plan line.
function useMembershipPlanLabel(user, wsId) {
  const [workspaces, setWorkspaces] = useState([])
  const [ownerName, setOwnerName] = useState(null)
  useEffect(() => {
    let alive = true
    Promise.resolve().then(() => api.getWorkspaces())
      .then((d) => { if (alive) setWorkspaces(Array.isArray(d?.workspaces) ? d.workspaces : []) })
      .catch(() => { if (alive) setWorkspaces([]) })
    return () => { alive = false }
  }, [wsId])
  const active = workspaces.find((w) => w?.id === wsId)
  const needsOwner = Boolean(active && active.role && active.role !== 'owner')
  useEffect(() => {
    let alive = true
    setOwnerName(null)
    if (!needsOwner) return undefined
    Promise.resolve().then(() => api.getWorkspaceMembers(wsId))
      .then((d) => {
        const owner = (d?.members || []).find((m) => m?.role === 'owner')
        if (alive) setOwnerName(owner?.name || null)
      })
      .catch(() => { if (alive) setOwnerName(null) })
    return () => { alive = false }
  }, [needsOwner, wsId])
  return planLabelFor({ user, workspaces, activeWsId: wsId, ownerName })
}

export function roleLabelFor(user) {
  const plan = String(user?.plan || '').toLowerCase()
  return PLAN_LABELS[plan] || null
}

export default function Layout() {
  const { user } = useAuth()
  // Read the active workspace straight from localStorage (the workspace menu
  // writes it and fires a `storage` event) — deliberately NOT the
  // useWorkspace() hook, so Layout never triggers its own workspaces fetch /
  // bootstrap on every route.
  const [wsId, setWsId]     = useState(() => readActiveWorkspace().id)
  const [wsName, setWsName] = useState(() => readActiveWorkspace().name)

  // Domain identity: the active area's accent travels as CSS variables for
  // pages that want a stronger accent on headers or tabs.
  const { pathname } = useLocation()
  const domainColors = SERVICE_COLORS[detectServiceKey(pathname)] || null
  const nav = selectNav(useAccountFeatures())
  const wide = useWideLayout()
  const primaryDomain = usePrimaryDomain(wsId)
  const planLabel = useMembershipPlanLabel(user, wsId)
  useEffect(() => {
    function sync() {
      const active = readActiveWorkspace()
      setWsId(active.id)
      setWsName(active.name)
    }
    window.addEventListener('storage', sync)
    window.addEventListener(ACTIVE_WORKSPACE_EVENT, sync)
    const id = setInterval(sync, 1500)
    return () => {
      window.removeEventListener('storage', sync)
      window.removeEventListener(ACTIVE_WORKSPACE_EVENT, sync)
      clearInterval(id)
    }
  }, [])

  // Once per signed-in account: the stored workspace must be one this account
  // really has (another account's id, a deleted workspace or lost access fall
  // back to a workspace it does have). One request per app load, not per route.
  useEffect(() => {
    if (user?.id) validateActiveWorkspace(api)
  }, [user?.id])

  return (
    <div className="cm-app cm-shell min-h-screen flex flex-col">
      <a href="#main" className="cm-skip-link">Skip to content</a>
      <UpgradePromptModal />

      <header className="cm-top sticky top-0 z-40">
        <div className="cm-top-inner">
          <SafeBoundary>
            <AreaMenu wsId={wsId} />
          </SafeBoundary>
          <nav aria-label="Main navigation" className="cm-pills">
            {nav.map(({ to, label }) => (
              <NavLink key={to} to={to} className={({ isActive }) => `cm-pill${isActive ? ' cm-pill-active' : ''}`}>
                {label}
              </NavLink>
            ))}
          </nav>
          <div className="cm-top-account">
            {!wide && (
              <SafeBoundary>
                <div className="flex items-center mr-3" data-testid="compact-controls">
                  <WorkspaceMenu wsId={wsId} wsName={wsName} domainName={primaryDomain} size="mini" />
                </div>
              </SafeBoundary>
            )}
            {/* The globe: notifications, 40px like the initial, 12px before it. */}
            <SafeBoundary>
              <div className="mr-3 flex items-center" data-testid="earth-slot">
                <EarthButton />
              </div>
            </SafeBoundary>
            <ProfileMenu roleLabel={planLabel} />
          </div>
        </div>
      </header>

      {/* The workspace deck (wide screens only) has a column of its own, so
          it can never sit over content — at any width, any scroll position, or
          when a long evidence line makes the page scroll sideways. It sticks to
          the bottom of the viewport inside that column. Nothing sits bottom-right. */}
      <div className="cm-body">
      {wide && (
        <aside className="cm-dock cm-dock-left" data-testid="workspace-dock" aria-label="Workspace">
          <div className="cm-dock-card">
            <SafeBoundary>
              <WorkspaceMenu wsId={wsId} wsName={wsName} domainName={primaryDomain} />
            </SafeBoundary>
          </div>
        </aside>
      )}
      <main
        id="main"
        className="cm-main flex-1 min-w-0"
        style={domainColors ? {
          '--domain-accent': domainColors.icon,
          '--domain-text':   domainColors.text,
          '--domain-chip':   domainColors.chip,
          '--domain-ring':   domainColors.ring,
        } : undefined}
      >
        <Outlet />
      </main>
      </div>

      <footer className="cm-footer">
        <span>© {new Date().getFullYear()} CyberMeters — External Security Monitoring</span>
        <div className="flex flex-wrap items-center gap-4">
          <NavLink to="/pricing" className="hover:text-gray-700">Pricing</NavLink>
          <NavLink to="/terms"   className="hover:text-gray-700">Terms</NavLink>
          <NavLink to="/privacy" className="hover:text-gray-700">Privacy</NavLink>
          <NavLink to="/dpa"     className="hover:text-gray-700">DPA</NavLink>
          <NavLink to="/cookies" className="hover:text-gray-700">Cookies</NavLink>
          <NavLink to="/support" className="hover:text-gray-700">Support</NavLink>
        </div>
      </footer>

    </div>
  )
}
