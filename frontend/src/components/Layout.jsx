import { useState, useEffect } from 'react'
import { Outlet, NavLink, useLocation } from 'react-router-dom'
import { api } from '../api'
import { useAuth } from '../context/AuthContext'
import { detectServiceKey } from './WorkspaceNav'
import { SERVICE_COLORS } from '../theme/serviceColors'
import SafeBoundary from './SafeBoundary'
import ProfileMenu from './shell/ProfileMenu'
import AreaMenu from './shell/AreaMenu'
import WorkspaceMenu from './shell/WorkspaceMenu'
import EarthDock, { EARTH_PHONE_QUERY } from './shell/EarthDock'
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
//   • bottom-left: the workspace card deck (WorkspaceMenu, dock variant) and
//     its popover (Switch, Manage workspaces, Members & roles).
//   • bottom-right: the photographic globe — the notifications control. The
//     unread counter sits on it; the panel grows out of it.
//
// Two menus, chosen by ENTITLEMENT (the `features` list the API publishes on
// /account/usage), never by workspace or domain count. Until usage has loaded
// — or when it cannot — the direct menu shows, so nobody is ever shown an MSP
// surface the API would 403.
export const MSP_NAV_FEATURE = 'portfolio_monitoring'

export const DIRECT_NAV = [
  { to: '/dashboard', label: 'Overview' },
  { to: '/services',  label: 'Services' },
  { to: '/ws/cases',  label: 'Cases'    },
  { to: '/reports',   label: 'Reports'  },
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

// Phone layout flag for the docks (72px workspace card, 110px globe).
function usePhoneLayout() {
  const query = typeof window !== 'undefined' && typeof window.matchMedia === 'function' ? window.matchMedia(EARTH_PHONE_QUERY) : null
  const [phone, setPhone] = useState(Boolean(query?.matches))
  useEffect(() => {
    if (!query) return undefined
    const sync = () => setPhone(Boolean(query.matches))
    sync()
    query.addEventListener?.('change', sync)
    return () => query.removeEventListener?.('change', sync)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  return phone
}

const PLAN_LABELS = { free: 'Free plan', starter: 'Starter plan', professional: 'Professional plan', business: 'Business plan', enterprise: 'MSP plan' }
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
  const [wsId, setWsId]     = useState(() => localStorage.getItem('cybermeters_workspace_id'))
  const [wsName, setWsName] = useState(() => localStorage.getItem('cybermeters_workspace_name'))

  // Domain identity: the active area's accent travels as CSS variables for
  // pages that want a stronger accent on headers or tabs.
  const { pathname } = useLocation()
  const domainColors = SERVICE_COLORS[detectServiceKey(pathname)] || null
  const nav = selectNav(useAccountFeatures())
  const phone = usePhoneLayout()
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
            <ProfileMenu roleLabel={roleLabelFor(user)} workspaceId={wsId} />
          </div>
        </div>
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
      </footer>

      {/* The two docks: fixed, above the content, pointer events only on
          their controls. */}
      <div className="cm-dock cm-dock-left" data-testid="workspace-dock">
        <SafeBoundary>
          <WorkspaceMenu wsId={wsId} wsName={wsName} variant="dock" />
        </SafeBoundary>
      </div>
      <SafeBoundary>
        <EarthDock phone={phone} />
      </SafeBoundary>
    </div>
  )
}
