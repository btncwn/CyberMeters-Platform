import { parseServerDate } from '../utils/dates'
import { useState, useEffect, useRef } from 'react'
import { Outlet, NavLink, useNavigate, useLocation } from 'react-router-dom'
import { ChevronDown, Check, X } from 'lucide-react'
import CyberMetersLogo from './CyberMetersLogo'
import { api, logoutWithToken } from '../api'
import { TOKEN_KEY } from '../context/authKeys'
import { useAuth } from '../context/AuthContext'
import WorkspaceNav, { detectServiceKey } from './WorkspaceNav'
import { SERVICE_COLORS } from '../theme/serviceColors'
import SafeBoundary from './SafeBoundary'
import NotificationBell from './NotificationBell'

// Top nav is intentionally lean — high-level destinations only. Service-specific
// areas live behind Services and the service sidebars; secondary tools (Scans,
// Schedules) live in the user menu. No routes are removed — everything stays
// reachable (Workspaces through the workspace selector's "Manage workspaces").
// Founder decision (14 Oct 2026): the top bar reads left to right from the
// deepest amber to the lightest, two items per step, and Settings lives only in
// the workspace sidebar (a control never appears in three places).
//
// Two menus, chosen by ENTITLEMENT (the `features` list the API publishes on
// /account/usage), never by workspace or domain count: a direct customer with
// twelve domains is still a direct customer, and an MSP with one customer is
// still an MSP. Until usage has loaded — or when it cannot — the direct menu
// shows, so nobody is ever shown an MSP surface the API would 403.
export const MSP_NAV_FEATURE = 'portfolio_monitoring'

export const DIRECT_NAV = [
  { to: '/dashboard', label: 'Overview'    },
  { to: '/services',  label: 'Services'    },
  { to: '/ws/cases',  label: 'Cases'       },
  { to: '/reports',   label: 'Reports'     },
  { to: '/guide',     label: 'Field Guide' },
  { to: '/billing',   label: 'Billing'     },
]

export const MSP_NAV = [
  { to: '/portfolio',  label: 'Portfolio'   },
  { to: '/workspaces', label: 'Customers'   },
  { to: '/ws/cases',   label: 'Operations'  },
  { to: '/reports',    label: 'Reports'     },
  { to: '/guide',      label: 'Field Guide' },
]

// Colour belongs to the POSITION, not the destination: two items per amber step.
const NAV_STEP_COLORS = ['#CB6629', '#D57B2E', '#DE8E33']
export function navColorAt(index) {
  return NAV_STEP_COLORS[Math.min(Math.floor(index / 2), NAV_STEP_COLORS.length - 1)]
}

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

// Secondary destinations surfaced in the user menu so they stay reachable
// without crowding the primary navigation. Billing joins the list only when
// the top bar does not carry it (the MSP menu), so it never shows twice.
const MORE_LINKS = [
  { to: '/scans',     label: 'Scans'     },
  { to: '/schedules', label: 'Schedules' },
  { to: '/support',   label: 'Support'   },
]

// ── Workspace Selector Dropdown ───────────────────────────────────────────────

function WorkspaceSelector() {
  const navigate = useNavigate()
  const [open, setOpen]             = useState(false)
  const [workspaces, setWorkspaces] = useState([])
  const [loading, setLoading]       = useState(false)
  const [activeId, setActiveId]     = useState(() => localStorage.getItem('cybermeters_workspace_id'))
  const [activeName, setActiveName] = useState(() => localStorage.getItem('cybermeters_workspace_name'))
  const ref = useRef(null)

  // Close on outside click
  useEffect(() => {
    function handleClickOutside(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  // Load workspaces when dropdown opens
  async function handleOpen() {
    setOpen(v => !v)
    if (workspaces.length === 0) {
      setLoading(true)
      try {
        const data = await api.getWorkspaces()
        setWorkspaces(data.workspaces || [])
      } catch { /* silent */ }
      finally { setLoading(false) }
    }
  }

  function selectWorkspace(ws) {
    localStorage.setItem('cybermeters_workspace_id', ws.id)
    localStorage.setItem('cybermeters_workspace_name', ws.name)
    setActiveId(ws.id)
    setActiveName(ws.name)
    setOpen(false)
    navigate('/ws/dashboard')
  }

  function clearWorkspace() {
    localStorage.removeItem('cybermeters_workspace_id')
    localStorage.removeItem('cybermeters_workspace_name')
    setActiveId(null)
    setActiveName(null)
    setOpen(false)
    // The /ws/... pages belong to the workspace just cleared, so leave them.
    navigate('/workspaces')
  }

  return (
    // min-w-0 down the chain so the selector is the control that gives way on a
    // phone: the right-hand cluster then fits 390px and nothing pushes the
    // avatar past the page edge.
    <div className="relative min-w-0" ref={ref}>
      <button
        onClick={handleOpen}
        className="h-11 w-full min-w-0 flex items-center gap-2 px-3 sm:px-4 rounded-[8px] text-[16px] font-semibold text-white border border-white/30 bg-white/10 hover:bg-white/20 transition-colors"
      >
        <span className="min-w-0 max-w-[88px] sm:max-w-[140px] truncate">{activeName || 'Workspace'}</span>
        <ChevronDown className={`w-3.5 h-3.5 text-white transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div className="absolute top-full mt-2 left-0 sm:left-auto sm:right-0 w-56 bg-white rounded-xl shadow-lg border border-gray-100 py-1 z-50">
          <div className="px-3 py-1.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">
            Switch workspace
          </div>

          {loading && (
            <div className="px-3 py-2 text-sm text-gray-400">Loading…</div>
          )}

          {!loading && workspaces.length === 0 && (
            <div className="px-3 py-2 text-sm text-gray-400">No workspaces yet</div>
          )}

          {workspaces.map(ws => (
            <button
              key={ws.id}
              onClick={() => selectWorkspace(ws)}
              className="w-full flex items-center gap-2 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 transition-colors text-left"
            >
              <span className="flex-1 truncate">{ws.name}</span>
              {ws.id === activeId && <Check className="w-3.5 h-3.5 text-brand-600 flex-shrink-0" />}
            </button>
          ))}

          <div className="border-t border-gray-100 mt-1 pt-1">
            <button
              onClick={() => { setOpen(false); navigate('/workspaces') }}
              className="w-full flex items-center gap-2 px-3 py-2 text-sm text-brand-600 hover:bg-brand-50 transition-colors text-left font-medium"
            >
              Manage workspaces
            </button>
            {activeId && (
              <button
                onClick={clearWorkspace}
                className="w-full flex items-center gap-2 px-3 py-2 text-sm text-gray-400 hover:bg-gray-50 transition-colors text-left"
              >
                Clear selection
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// ── User Menu ────────────────────────────────────────────────────────────────

function UserMenu({ extraLinks = [] }) {
  const navigate = useNavigate()
  const { user, logout } = useAuth()
  const [open, setOpen]   = useState(false)
  const ref               = useRef(null)

  useEffect(() => {
    function handler(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const initial = (user?.name || user?.email || 'U')[0].toUpperCase()
  const displayPlan = user?.['plan']

  async function handleLogout() {
    // Snapshot token before clearing. If we awaited api.authLogout() first,
    // in-flight background requests (e.g. NotificationBell 60s poll) could see
    // the old token, receive a 401 after the server session is deleted, and
    // trigger handleUnauthorized() — causing a spurious page reload while the
    // user is already in the middle of a deliberate logout.
    const currentToken = localStorage.getItem(TOKEN_KEY)
    // Clear local auth state immediately — ProtectedRoute redirects to /login.
    logout()
    navigate('/login', { replace: true })
    // Revoke server session in the background (fire-and-forget).
    logoutWithToken(currentToken)
  }

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(v => !v)}
        className="flex items-center gap-1.5 rounded-full hover:bg-white/10 transition-colors"
        aria-label="Account menu"
      >
        <div className="w-11 h-11 rounded-full border-2 border-[#E29535] flex items-center justify-center text-[16px] font-bold text-white">
          {initial}
        </div>
        <ChevronDown className="w-3.5 h-3.5 text-white" />
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-2 w-56 bg-white rounded-xl shadow-lg border border-gray-100 py-1 z-50">
          {/* User info */}
          <div className="px-4 py-3 border-b border-gray-100">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-full bg-brand-600 flex items-center justify-center text-xs font-bold text-white flex-shrink-0">
                {initial}
              </div>
              <div className="min-w-0">
                {user?.name && <p className="text-sm font-semibold text-gray-900 truncate">{user.name}</p>}
                <p className="text-xs text-gray-400 truncate">{user?.email || '—'}</p>
              </div>
            </div>
            {displayPlan && (
              <span className="mt-2 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider bg-brand-50 text-brand-700">
                {displayPlan}
              </span>
            )}
          </div>

          {/* Actions */}
          <button
            onClick={() => { setOpen(false); navigate('/account') }}
            className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-gray-700 hover:bg-gray-50 transition-colors"
          >
            Account settings
          </button>

          {/* Secondary tools — kept reachable out of the lean top nav. */}
          <div className="border-t border-gray-100 mt-1 pt-1">
            <p className="px-4 pt-1 pb-0.5 text-xs font-semibold text-gray-400 uppercase tracking-widest">Tools</p>
            {[...extraLinks, ...MORE_LINKS].map(({ to, label }) => (
              <button
                key={to}
                onClick={() => { setOpen(false); navigate(to) }}
                className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-gray-700 hover:bg-gray-50 transition-colors"
              >
                {label}
              </button>
            ))}
          </div>

          <div className="border-t border-gray-100 mt-1 pt-1">
            <button
              onClick={handleLogout}
              className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-red-600 hover:bg-red-50 transition-colors"
            >
              Sign out
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// Human-readable labels for plan limit resource keys returned by the API.
const RESOURCE_LABELS = {
  scans_per_month:     'monthly scans',
  reports_per_month:   'monthly reports',
  scheduled_scans:     'scheduled scans',
  scans_per_hour:      'scans this hour',
  domains:             'domains',
  workspaces:          'workspaces',
  users:               'team members',
}

function UpgradePromptModal() {
  const navigate = useNavigate()
  const [limit, setLimit] = useState(null)
  // Draggable: offset from the centred position. Re-centres each time it opens.
  const [pos, setPos] = useState({ x: 0, y: 0 })
  const dragRef = useRef(null)
  useEffect(() => { if (limit) setPos({ x: 0, y: 0 }) }, [limit])
  const onDragStart = (e) => {
    dragRef.current = { sx: e.clientX, sy: e.clientY, bx: pos.x, by: pos.y }
    e.currentTarget.setPointerCapture?.(e.pointerId)
  }
  const onDragMove = (e) => {
    if (!dragRef.current) return
    setPos({ x: dragRef.current.bx + (e.clientX - dragRef.current.sx), y: dragRef.current.by + (e.clientY - dragRef.current.sy) })
  }
  const onDragEnd = (e) => {
    dragRef.current = null
    e.currentTarget.releasePointerCapture?.(e.pointerId)
  }

  useEffect(() => {
    function handlePlanLimit(e) {
      setLimit(e.detail || {})
    }
    window.addEventListener('cybermeters:plan-limit', handlePlanLimit)
    return () => window.removeEventListener('cybermeters:plan-limit', handlePlanLimit)
  }, [])

  if (!limit) return null

  // Prefer the upgrade_message already composed by the API (e.g.
  // "You have used 5 of 5 scans this month. Upgrade your plan for more scans.")
  // Fall back to a generic message built from resource/limit fields.
  const resourceKey   = limit.resource || ''
  const resourceLabel = RESOURCE_LABELS[resourceKey] ?? resourceKey.replace(/_/g, ' ')
  const limitVal      = limit.limit >= 999999 ? 'unlimited' : limit.limit
  const body = limit.upgrade_message
    ?? (limitVal != null
      ? `You have used all ${limitVal} ${resourceLabel} included in your current plan.`
      : `You have reached the ${resourceLabel} limit on your current plan.`)

  // Optional reset notice (monthly quotas include reset_at from the API)
  let resetNote = null
  if (limit.reset_at) {
    try {
      const d = parseServerDate(limit.reset_at)
      resetNote = limit.reason === 'trial_daily_allowance' ? `Renews ${d.toLocaleDateString('en-GB', { month: 'short', day: 'numeric', timeZone: 'UTC' })}, 00:00 UTC.` : `Your quota resets on ${d.toLocaleDateString(undefined, { month: 'long', day: 'numeric' })}.`
    } catch { /* ignore */ }
  }

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-gray-900/30 px-4">
      <div
        className="w-full max-w-md rounded-xl bg-white border border-gray-100 shadow-xl p-5"
        style={{ transform: `translate(${pos.x}px, ${pos.y}px)` }}
      >
        <div
          className="flex items-start gap-3 cursor-grab active:cursor-grabbing select-none touch-none"
          onPointerDown={onDragStart}
          onPointerMove={onDragMove}
          onPointerUp={onDragEnd}
          onPointerCancel={onDragEnd}
          title="Drag to move"
        >
          <div className="min-w-0 flex-1">
            <h2 className="text-sm font-bold text-gray-900">{limit.title || "You've reached your plan limit"}</h2>
            <p className="text-sm text-gray-500 mt-1">{body}</p>
            {resetNote && (
              <p className="text-xs text-gray-400 mt-1">{resetNote}</p>
            )}
          </div>
          <button
            type="button"
            onClick={() => setLimit(null)}
            onPointerDown={(e) => e.stopPropagation()}
            className="w-7 h-7 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-50 flex items-center justify-center cursor-pointer"
            aria-label="Close plan limit notice"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="mt-5 flex justify-end gap-2">
          <button
            type="button"
            onClick={() => setLimit(null)}
            className="btn-secondary"
          >
            Not now
          </button>
          <button
            type="button"
            onClick={() => { setLimit(null); navigate('/billing') }}
            className="btn-primary"
          >
            Upgrade plan
          </button>
        </div>
      </div>
    </div>
  )
}

export default function Layout() {
  const navigate = useNavigate()
  // Persistent workspace service rail: read the active workspace straight from
  // localStorage (the same lightweight pattern WorkspaceSelector already uses in
  // this header) — deliberately NOT the useWorkspace() hook, so Layout never
  // triggers its own workspaces fetch / bootstrap on every route.
  const [wsId, setWsId]     = useState(() => localStorage.getItem('cybermeters_workspace_id'))
  const [wsName, setWsName] = useState(() => localStorage.getItem('cybermeters_workspace_name'))

  // Domain identity wash — the routed content column takes the active domain's
  // faint `surface` colour, so each module's pages subtly carry its identity.
  // Identity colour is presentation only: severity/state colours are unchanged
  // and non-domain routes (dashboard, cases, settings…) keep the neutral grey.
  const { pathname } = useLocation()
  const domainColors = SERVICE_COLORS[detectServiceKey(pathname)] || null
  const nav = selectNav(useAccountFeatures())
  const userMenuExtras = nav.some(item => item.to === '/billing') ? [] : [{ to: '/billing', label: 'Billing' }]
  useEffect(() => {
    function sync() {
      setWsId(localStorage.getItem('cybermeters_workspace_id'))
      setWsName(localStorage.getItem('cybermeters_workspace_name') || '')
    }
    window.addEventListener('storage', sync)
    const id = setInterval(sync, 1500)
    return () => { window.removeEventListener('storage', sync); clearInterval(id) }
  }, [])

  return (
    <div className="cm-app min-h-screen bg-gray-50 flex flex-col">
      <UpgradePromptModal />

      {/* Top bar: deep navy, darkest at the brand and lighter towards the
          right; brand and navigation in the amber steps of the wordmark. */}
      <header className="cm-topbar sticky top-0 z-50">
        <div className="w-full px-4 sm:px-6 lg:px-10 min-h-[96px] lg:min-h-[144px] flex flex-wrap items-center gap-x-6 gap-y-2 lg:gap-x-11 py-3 lg:py-0">

          {/* Logo */}
          <button
            onClick={() => navigate('/dashboard')}
            className="flex-shrink-0 group"
            aria-label="CyberMeters security overview"
          >
            <CyberMetersLogo size={44} showWordmark animated darkMode wordmarkColor="#C65B26" wordmarkSize={30} subtitle={false} />
          </button>

          {/* Nav: on wide screens it sits beside the brand; on phones it takes
              its own row under the brand and the account controls. */}
          <nav aria-label="Main navigation" className="order-3 lg:order-none w-full lg:w-auto lg:flex-1 min-w-0 flex flex-wrap items-center gap-x-5 lg:gap-x-8 gap-y-1">
            {nav.map(({ to, label }, index) => (
              <NavLink
                key={to}
                to={to}
                style={{ color: navColorAt(index) }}
                className={({ isActive }) => `cm-topbar-link${isActive ? ' cm-topbar-link-active' : ''}`}
              >
                <span>{label}</span>
              </NavLink>
            ))}
          </nav>

          {/* Right */}
          <div className="ml-auto min-w-0 flex items-center gap-2 sm:gap-3">
            <WorkspaceSelector />

            <NotificationBell />

            <button
              onClick={() => {
                // Reset the New Scan form even when already on the page (React
                // Router won't remount the same route). Harmless off-page.
                navigate('/scans/new')
                window.dispatchEvent(new CustomEvent('cybermeters:new-scan-reset'))
              }}
              className="btn-amber h-11 lg:h-12 px-4 sm:px-6 rounded-[8px] text-[17px] lg:text-[18px] whitespace-nowrap"
              aria-label="New Scan"
            >
              <span>New Scan</span>
            </button>

            <UserMenu extraLinks={userMenuExtras} />
          </div>
        </div>
      </header>

      {/* Content — persistent workspace service rail + routed page */}
      <main className="flex-1">
        <div className="flex flex-col lg:flex-row">
          {wsId && (
            <SafeBoundary>
              <WorkspaceNav wsName={wsName} />
            </SafeBoundary>
          )}
          <div
            className="flex-1 min-w-0 transition-colors duration-300"
            style={domainColors ? {
              backgroundColor: domainColors.surface,
              // Exposed for pages/components that want stronger domain accents
              // (headers, active tabs) without importing the palette themselves.
              '--domain-accent': domainColors.icon,
              '--domain-text':   domainColors.text,
              '--domain-chip':   domainColors.chip,
              '--domain-ring':   domainColors.ring,
            } : undefined}
          >
            <Outlet />
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-100 bg-white">
        <div className="max-w-screen-xl mx-auto px-6 py-3 flex flex-wrap items-center justify-between gap-3">
          <span className="text-xs text-gray-500">© {new Date().getFullYear()} CyberMeters — External Security Monitoring</span>
          <div className="flex flex-wrap items-center gap-4 text-xs text-gray-500">
            <NavLink to="/pricing"  className="hover:text-gray-700">Pricing</NavLink>
            <NavLink to="/terms"    className="hover:text-gray-700">Terms</NavLink>
            <NavLink to="/privacy"  className="hover:text-gray-700">Privacy</NavLink>
            <NavLink to="/dpa"      className="hover:text-gray-700">DPA</NavLink>
            <NavLink to="/cookies"  className="hover:text-gray-700">Cookies</NavLink>
            <NavLink to="/support"  className="hover:text-gray-700">Support</NavLink>
          </div>
        </div>
      </footer>
    </div>
  )
}
