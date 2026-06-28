import { useState, useEffect, useRef } from 'react'
import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard, Server, ScanLine, FileBarChart2,
  Settings, Shield, Plus, ChevronDown, Calendar,
  Briefcase, ChevronRight, Check, LogOut, User,
  AlertTriangle, X, CreditCard, GraduationCap, ShieldAlert,
} from 'lucide-react'
import CyberMetersLogo from './CyberMetersLogo'
import { api, logoutWithToken } from '../api'
import { TOKEN_KEY } from '../context/authKeys'
import { useAuth } from '../context/AuthContext'
import NotificationBell from './NotificationBell'
import FeedbackWidget from './FeedbackWidget'

// Accuracy and Pricing are removed from the main nav:
// - Accuracy is an internal developer tool not intended for beta users.
// - Pricing is a public marketing page already linked in the footer.
const NAV = [
  { to: '/dashboard',      icon: LayoutDashboard, label: 'Dashboard'  },
  { to: '/ws/dashboard',        icon: Shield,      label: 'Security'   },
  { to: '/ws/brand-monitoring', icon: ShieldAlert, label: 'Brand'      },
  { to: '/workspaces',          icon: Briefcase,   label: 'Workspaces' },
  { to: '/assets',         icon: Server,          label: 'Assets'     },
  { to: '/scans',          icon: ScanLine,        label: 'Scans'      },
  { to: '/schedules',      icon: Calendar,        label: 'Schedules'  },
  { to: '/reports',        icon: FileBarChart2,   label: 'Reports'    },
  { to: '/billing',        icon: CreditCard,      label: 'Billing'    },
  { to: '/academy',        icon: GraduationCap,   label: 'Academy'    },
  { to: '/settings',       icon: Settings,        label: 'Settings'   },
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
  }

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={handleOpen}
        className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl text-sm font-medium text-gray-600 hover:text-gray-900 hover:bg-gray-100 transition-colors"
      >
        <Briefcase className="w-3.5 h-3.5 text-gray-400" />
        <span className="max-w-[120px] truncate">{activeName || 'Workspace'}</span>
        <ChevronDown className={`w-3 h-3 text-gray-400 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div className="absolute top-full mt-2 right-0 w-56 bg-white rounded-xl shadow-lg border border-gray-100 py-1 z-50">
          <div className="px-3 py-1.5 text-[10px] font-semibold text-gray-400 uppercase tracking-wider">
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
              <div className="w-5 h-5 rounded-md bg-brand-50 flex items-center justify-center flex-shrink-0">
                <Briefcase className="w-3 h-3 text-brand-600" />
              </div>
              <span className="flex-1 truncate">{ws.name}</span>
              {ws.id === activeId && <Check className="w-3.5 h-3.5 text-brand-600 flex-shrink-0" />}
            </button>
          ))}

          <div className="border-t border-gray-100 mt-1 pt-1">
            <button
              onClick={() => { setOpen(false); navigate('/workspaces') }}
              className="w-full flex items-center gap-2 px-3 py-2 text-sm text-brand-600 hover:bg-brand-50 transition-colors text-left font-medium"
            >
              <Plus className="w-3.5 h-3.5" />
              Manage workspaces
              <ChevronRight className="w-3 h-3 ml-auto" />
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

function UserMenu() {
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
        className="flex items-center gap-1.5 pl-2 pr-2.5 py-1.5 rounded-xl hover:bg-gray-100 transition-colors ml-1"
      >
        <div className="w-7 h-7 rounded-full bg-brand-600 flex items-center justify-center text-xs font-bold text-white">
          {initial}
        </div>
        <ChevronDown className="w-3.5 h-3.5 text-gray-400" />
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
              <span className="mt-2 inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider bg-brand-50 text-brand-700">
                {displayPlan}
              </span>
            )}
          </div>

          {/* Actions */}
          <button
            onClick={() => { setOpen(false); navigate('/account') }}
            className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-gray-700 hover:bg-gray-50 transition-colors"
          >
            <User className="w-4 h-4 text-gray-400" />
            Account settings
          </button>

          <div className="border-t border-gray-100 mt-1 pt-1">
            <button
              onClick={handleLogout}
              className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-red-600 hover:bg-red-50 transition-colors"
            >
              <LogOut className="w-4 h-4" />
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
      const d = new Date(limit.reset_at)
      resetNote = `Your quota resets on ${d.toLocaleDateString(undefined, { month: 'long', day: 'numeric' })}.`
    } catch { /* ignore */ }
  }

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-gray-900/30 px-4">
      <div className="w-full max-w-md rounded-xl bg-white border border-gray-100 shadow-xl p-5">
        <div className="flex items-start gap-3">
          <div className="w-9 h-9 rounded-lg bg-amber-50 flex items-center justify-center flex-shrink-0">
            <AlertTriangle className="w-5 h-5 text-amber-600" />
          </div>
          <div className="min-w-0 flex-1">
            <h2 className="text-sm font-bold text-gray-900">You've reached your plan limit</h2>
            <p className="text-sm text-gray-500 mt-1">{body}</p>
            {resetNote && (
              <p className="text-xs text-gray-400 mt-1">{resetNote}</p>
            )}
          </div>
          <button
            type="button"
            onClick={() => setLimit(null)}
            className="w-7 h-7 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-50 flex items-center justify-center"
            aria-label="Close"
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

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      <UpgradePromptModal />

      {/* Top nav */}
      <header className="bg-white border-b border-gray-100 sticky top-0 z-50">
        <div className="max-w-screen-xl mx-auto px-6 h-16 flex items-center gap-6">

          {/* Logo */}
          <button
            onClick={() => navigate('/dashboard')}
            className="flex-shrink-0 group mr-2"
          >
            <CyberMetersLogo size={36} showWordmark animated />
          </button>

          {/* Nav */}
          <nav className="flex items-center gap-1.5 lg:gap-2.5">
            {NAV.map(({ to, icon: Icon, label }) => (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) => isActive ? 'nav-link-active' : 'nav-link'}
              >
                <Icon className="w-4 h-4" />
                {label}
              </NavLink>
            ))}
          </nav>

          {/* Right */}
          <div className="ml-auto flex items-center gap-2">
            <WorkspaceSelector />

            <NotificationBell />

            <button onClick={() => navigate('/scans/new')} className="btn-primary">
              <Plus className="w-4 h-4" />
              New Scan
            </button>

            <UserMenu />
          </div>
        </div>
      </header>

      {/* Content */}
      <main className="flex-1">
        <Outlet />
      </main>

      {/* Beta feedback entry point */}
      <FeedbackWidget />

      {/* Footer */}
      <footer className="border-t border-gray-100 bg-white">
        <div className="max-w-screen-xl mx-auto px-6 py-3 flex flex-wrap items-center justify-between gap-3">
          <span className="text-xs text-gray-400">© {new Date().getFullYear()} CyberMeters — Attack Surface Management</span>
          <div className="flex items-center gap-4 text-xs text-gray-400">
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
