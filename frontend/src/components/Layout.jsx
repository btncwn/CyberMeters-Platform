import { useState, useEffect } from 'react'
import { Outlet, NavLink, Link, useLocation } from 'react-router-dom'
import CyberMetersLogo from './CyberMetersLogo'
import { api } from '../api'
import { useAuth } from '../context/AuthContext'
import WorkspaceNav, { detectServiceKey } from './WorkspaceNav'
import { SERVICE_COLORS } from '../theme/serviceColors'
import SafeBoundary from './SafeBoundary'
import NotificationBell from './NotificationBell'
import ProfileMenu from './shell/ProfileMenu'
import Globe from './shell/Globe'
import UpgradePromptModal from './shell/UpgradePromptModal'

// The app shell (founder, 16 Oct 2026): a white top bar — logo, serif
// wordmark and the main menu as pills on the left, the bell and the account
// button on the right — a 72px module rail on the left with the workspace
// button at its foot, a white-to-sky canvas, and a small turning globe in the
// bottom-right corner. Field Guide and Billing live in the account menu; the
// scan starts from the home screen, so the top bar carries no scan button.
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

const PLAN_LABELS = { free: 'Free plan', starter: 'Starter plan', professional: 'Professional plan', business: 'Business plan', enterprise: 'MSP plan' }
export function roleLabelFor(user) {
  const plan = String(user?.plan || '').toLowerCase()
  return PLAN_LABELS[plan] || null
}

export default function Layout() {
  const { user } = useAuth()
  // Persistent module rail: read the active workspace straight from
  // localStorage (the workspace menu writes it and fires a `storage` event) —
  // deliberately NOT the useWorkspace() hook, so Layout never triggers its own
  // workspaces fetch / bootstrap on every route.
  const [wsId, setWsId]     = useState(() => localStorage.getItem('cybermeters_workspace_id'))
  const [wsName, setWsName] = useState(() => localStorage.getItem('cybermeters_workspace_name'))

  // Domain identity: the active area's accent travels as CSS variables for
  // pages that want a stronger accent on headers or tabs. The canvas itself
  // stays the shell's white-to-sky gradient.
  const { pathname } = useLocation()
  const domainColors = SERVICE_COLORS[detectServiceKey(pathname)] || null
  const nav = selectNav(useAccountFeatures())
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

      <header className="cm-topbar sticky top-0 z-40">
        <div className="cm-topbar-inner">
          <Link to="/dashboard" aria-label="CyberMeters home" className="cm-brand shrink-0 order-1">
            <CyberMetersLogo size={34} showWordmark animated wordmarkSize={24} subtitle={false} />
          </Link>
          <nav aria-label="Main navigation" className="cm-pills sm:ml-3">
            {nav.map(({ to, label }) => (
              <NavLink key={to} to={to} className={({ isActive }) => `cm-pill${isActive ? ' cm-pill-active' : ''}`}>
                {label}
              </NavLink>
            ))}
          </nav>
          <div className="flex items-center gap-2 sm:gap-3 shrink-0 order-2 sm:order-0 sm:ml-auto">
            <NotificationBell />
            <ProfileMenu roleLabel={roleLabelFor(user)} />
          </div>
        </div>
      </header>

      <div className="cm-shell-body flex-1 flex">
        <SafeBoundary>
          <WorkspaceNav wsId={wsId} wsName={wsName} />
        </SafeBoundary>
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

      <Globe className="hidden lg:block" />

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
