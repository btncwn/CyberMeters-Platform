import { useState, useEffect, useRef } from 'react'
import { Outlet, NavLink, Link, useLocation } from 'react-router-dom'
import { api } from '../api'
import { ACTIVE_WORKSPACE_EVENT, readActiveWorkspace, validateActiveWorkspace } from '../lib/activeWorkspace'
import { useAuth } from '../context/AuthContext'
import { SERVICES, detectServiceKey } from './WorkspaceNav'
import { SERVICE_COLORS } from '../theme/serviceColors'
import SafeBoundary from './SafeBoundary'
import ProfileMenu from './shell/ProfileMenu'
import AreaSidebar from './shell/AreaSidebar'
import { AreaShellProvider, useAreaShell } from './shell/AreaShell'
import { MODULE_TABS } from '../lib/areaTabs'
import CyberMetersLogo from './CyberMetersLogo'
import WorkspaceMenu from './shell/WorkspaceMenu'
import EarthButton from './shell/EarthButton'
import UpgradePromptModal from './shell/UpgradePromptModal'
import { trialPlanLabel } from '../lib/trialPlan'
import SomethingWrong from './SomethingWrong'

// S1-SHELL-V2 (founder-approved design, 22 Oct 2026) — supersedes the notes
// below where they differ:
//   • a 320px LEFT SIDEBAR at ≥1024px (AreaSidebar): the logo (→ Overview, no longer
//     a menu), "Your external posture" and the eight areas with their state;
//     the selected area expands into its sub-topics. Below 1024px the same
//     sidebar opens as a drawer from a menu button beside the logo.
//   • the TOP BAR has two rows: row 1 the product menu (Overview · Operations ·
//     Active Checks · Reports, or the MSP menu) and, unchanged, the globe and
//     the account initial (now 44px); row 2, only inside an area, "<Area> ·"
//     and the area's tabs — the page's own tab strip moves up into it.
//   • the workspace card stays bottom-left: at the foot of the sidebar from
//     1024px, a 76px floating card below that.
//
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
// Active Checks links to the Active Checks page that exists today (the
// permission record); a hub page, when it ships, takes this link over.
export const ACTIVE_CHECKS_PATH = '/ws/active-checks/permission'
export const DIRECT_NAV = [
  { to: '/dashboard', label: 'Overview'   },
  { to: '/ws/cases',  label: 'Operations' },
  { to: ACTIVE_CHECKS_PATH, label: 'Active Checks' },
  { to: '/reports',   label: 'Reports'    },
]

export const MSP_NAV = [
  { to: '/portfolio',  label: 'Portfolio'  },
  { to: '/workspaces', label: 'Customers'  },
  { to: '/ws/cases',   label: 'Operations' },
  { to: ACTIVE_CHECKS_PATH, label: 'Active Checks' },
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
// S1-SHELL-V2: the sidebar (and the workspace card at its foot) from 1024px.
export const WIDE_LAYOUT_QUERY = '(min-width: 1024px)'
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


const PLAN_LABELS = { free: 'Free plan', starter: 'Starter plan', professional: 'Professional plan', business: 'Business plan', enterprise: 'MSP plan' }
/**
 * The account menu's plan line (P1, 18 Oct 2026). A paid plan names itself. A
 * user whose access comes from membership — the active workspace is someone
 * else's and they have no paid plan — reads "Member of <workspace> · plan managed
 * by <owner>". "Free plan" stays only for owners on the free plan and for users
 * with no memberships and no subscription.
 */
export function planLabelFor({ user = null, workspaces = [], activeWsId = null, ownerName = null } = {}) {
  // A live trial is a trial, never "<Plan> plan" (zero false claims).
  const trial = trialPlanLabel(user)
  if (trial) return trial
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
  return (
    <AreaShellProvider>
      <ShellFrame />
    </AreaShellProvider>
  )
}

// Row 2 of the top bar, only inside an area: "<Area> ·" and the area's tabs.
// The area page portals its own tablist into the slot; on an area's sub-page
// (no tablist claims the slot) the same tabs show as links to the area page.
function AreaRow({ svc }) {
  const shell = useAreaShell()
  const openCount = shell?.openCases?.[svc.domainKey]
  return (
    <div className="cm-arearow" data-testid="area-row">
      {/* Name and tabs are one strip: on a phone it scrolls as one, so a long
          area name never eats the tab viewport (C-38b S15); on desktop the strip
          takes no box of its own. */}
      <div className="cm-arearow-strip" data-testid="area-row-strip">
        <span className="cm-arearow-name">{svc.title}<span aria-hidden="true" className="cm-arearow-dot">·</span></span>
        <div ref={shell?.setSlot} className="cm-arearow-slot" />
        {!shell?.claimed && (
          <nav aria-label={`${svc.title} sections`} className="cm-tabs">
            {MODULE_TABS.map((t) => (
              <Link key={t.id} to={t.id === 'overview' ? svc.to : `${svc.to}?tab=${t.id}`} className="cm-tab">
                {t.label}
                {t.id === 'cases' && openCount > 0 && <><span className="cm-tab-count" aria-hidden="true">{openCount}</span><span className="sr-only">, {openCount} open</span></>}
              </Link>
            ))}
          </nav>
        )}
      </div>
      {/* The page's tools (filter + actions) sit with the tabs they act on (C-38 S07). */}
      <div ref={shell?.setToolbarSlot} className="cm-arearow-tools" />
    </div>
  )
}

function ShellFrame() {
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
  const areaKey = detectServiceKey(pathname)
  const area = SERVICES.find((svc) => svc.key === areaKey) || null
  const domainColors = SERVICE_COLORS[areaKey] || null
  const nav = selectNav(useAccountFeatures())
  const wide = useWideLayout()
  const planLabel = useMembershipPlanLabel(user, wsId)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const menuButtonRef = useRef(null)
  const drawerRef = useRef(null)
  const headerRef = useRef(null)
  // The sticky header's real height (row 1 + row 2 + border) is the scroll
  // offset for every in-page anchor, so a sub-topic never lands under it (C-38 S08).
  useEffect(() => {
    const el = headerRef.current
    if (!el) return undefined
    const apply = () => document.documentElement.style.setProperty('--cm-header-h', `${Math.ceil(el.getBoundingClientRect().height)}px`)
    apply()
    if (typeof ResizeObserver !== 'function') return undefined
    const observer = new ResizeObserver(apply)
    observer.observe(el)
    return () => observer.disconnect()
  }, [])
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

  // The drawer closes on navigation, on Escape (focus back to the menu
  // button) and whenever the screen widens into the sidebar layout.
  useEffect(() => { setDrawerOpen(false) }, [pathname, wide])
  useEffect(() => {
    if (!drawerOpen) return undefined
    drawerRef.current?.querySelector('a, button')?.focus()
    function onKeyDown(e) { if (e.key === 'Escape') { e.preventDefault(); setDrawerOpen(false); menuButtonRef.current?.focus() } }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [drawerOpen])

  return (
    <div className="cm-app cm-shell min-h-screen">
      <a href="#main" className="cm-skip-link">Skip to content</a>
      <UpgradePromptModal />

      <div className="cm-frame">
        {wide && (
          <aside className="cm-sidebar" data-testid="sidebar">
            <SafeBoundary>
              <AreaSidebar wsId={wsId} />
            </SafeBoundary>
          </aside>
        )}

        <div className="cm-column">
          <header ref={headerRef} className="cm-top sticky top-0 z-40">
            <div className="cm-top-inner">
              {!wide && (
                <div className="cm-top-brand">
                  <button
                    ref={menuButtonRef}
                    type="button"
                    className="cm-menubtn"
                    aria-label="Open areas menu"
                    aria-expanded={drawerOpen}
                    aria-controls="cm-area-drawer"
                    onClick={() => setDrawerOpen((v) => !v)}
                    data-testid="areas-menu-button"
                  >
                    <svg width="18" height="18" viewBox="0 0 18 18" aria-hidden="true"><path d="M3 5h12M3 9h12M3 13h12" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" /></svg>
                  </button>
                  <Link to="/dashboard" className="cm-top-logo" aria-label="CyberMeters — Overview">
                    <CyberMetersLogo size={24} />
                    <span className="cm-side-word">CyberMeters</span>
                  </Link>
                </div>
              )}
              <nav aria-label="Main navigation" className="cm-pills">
                {nav.map(({ to, label }) => (
                  // Whole class names as literals: Tailwind generates an @utility only for a name it can find in the source.
                  <NavLink key={to} to={to} className={({ isActive }) => (isActive ? 'cm-pill cm-pill-active' : 'cm-pill')}>
                    {label}
                  </NavLink>
                ))}
              </nav>
              <div className="cm-top-account">
                {/* The globe: notifications, 12px before the account initial. */}
                <SafeBoundary>
                  <div className="mr-3 flex items-center" data-testid="earth-slot">
                    <EarthButton />
                  </div>
                </SafeBoundary>
                <ProfileMenu roleLabel={planLabel} />
              </div>
            </div>
            {area && <AreaRow svc={area} />}
          </header>

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
            <SomethingWrong surface="app" className="basis-full" />
          </footer>
        </div>
      </div>

      {/* The workspace card floats bottom-left, exactly as before (founder rule):
          from 1024px over the foot of the sidebar (whose list keeps room for it),
          below that at 76px. It is not part of the sidebar. */}
      <div className={wide ? 'cm-wsfloat cm-wsfloat-wide' : 'cm-wsfloat'} data-testid="workspace-dock">
        <SafeBoundary>
          <WorkspaceMenu wsId={wsId} wsName={wsName} size={wide ? 'deck' : 'compact'} />
        </SafeBoundary>
      </div>
      {!wide && drawerOpen && (
        <div className="cm-drawer-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) setDrawerOpen(false) }}>
          <div id="cm-area-drawer" ref={drawerRef} className="cm-drawer" role="dialog" aria-modal="true" aria-label="Areas" data-testid="area-drawer">
            <button type="button" className="cm-drawer-close" aria-label="Close menu" onClick={() => { setDrawerOpen(false); menuButtonRef.current?.focus() }}>
              <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" /></svg>
            </button>
            <SafeBoundary>
              <AreaSidebar wsId={wsId} stacked onNavigate={() => setDrawerOpen(false)} />
            </SafeBoundary>
          </div>
        </div>
      )}
    </div>
  )
}
