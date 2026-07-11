import { useState, useEffect } from 'react'
import { NavLink, Link, useNavigate, useLocation } from 'react-router-dom'
import {
  LayoutDashboard, Shield, Lock, Tag, Briefcase, ChevronLeft, ChevronDown,
  ChevronRight, BarChart2, ClipboardList, Users, HardDrive, Mail,
  Server, Settings, Bell,
} from 'lucide-react'
import { preloadComponent } from '../utils/preload'
import { routePreloadMap } from '../utils/preloadMap'
import { SERVICE_COLORS } from '../theme/serviceColors'

// ── Glacier palette — from the shared single source of truth ──────────────────
// The sidebar maps the shared per-service colours onto the field names it uses
// (bg = active-item background = the shared `chip`; accent = `icon`). Inline
// styles keep the themes dynamic without touching tailwind.config (no purge risk).
const THEME = Object.fromEntries(
  Object.entries(SERVICE_COLORS).map(([key, c]) => [
    key,
    { icon: c.icon, text: c.text, bg: c.chip, accent: c.icon, tint: c.tint },
  ])
)

// ── The four CyberMeters services — the only primary sections in the sidebar ──
const SERVICES = [
  {
    key: 'email', title: 'Email Protection', icon: Mail, to: '/ws/email-protection',
    match: p => p.startsWith('/ws/email-protection'),
    items: [
      { to: '/ws/email-protection', label: 'Overview', end: true },
      { hash: '#dmarc-setup',       label: 'DMARC Setup' },
      { hash: '#sender-inventory',  label: 'Sender Inventory' },
      { hash: '#auth-detail',       label: 'Authentication Detail' },
      { to: '/ws/reports',          label: 'Reports' },
    ],
  },
  {
    key: 'brand', title: 'Brand Protection', icon: Tag, to: '/ws/brand-monitoring',
    match: p => p.startsWith('/ws/brand-monitoring'),
    items: [
      { to: '/ws/brand-monitoring', label: 'Overview', end: true },
      { hash: '#typosquats',        label: 'Typosquat Candidates' },
      { hash: '#brand-summary',     label: 'Brand Findings' },
      { to: '/ws/reports',          label: 'Reports' },
    ],
  },
  {
    key: 'surface', title: 'Attack Surface', icon: Server, to: '/assets',
    match: p => p.startsWith('/assets') || p.startsWith('/ws/admin-surfaces')
      || p.startsWith('/ws/cloud-assets') || p.startsWith('/ws/saas-exposure')
      || p.startsWith('/ws/third-party') || p.startsWith('/scans') || p.startsWith('/schedules'),
    items: [
      { to: '/assets',            label: 'Overview', end: true },
      { to: '/assets',            label: 'Assets' },
      { to: '/scans',             label: 'Scans' },
      { to: '/schedules',         label: 'Schedules' },
      { to: '/ws/admin-surfaces', label: 'Admin Surfaces' },
      { to: '/ws/cloud-assets',   label: 'Cloud Assets' },
      { to: '/ws/saas-exposure',  label: 'SaaS Exposure' },
      { to: '/ws/third-party',    label: 'Third-Party' },
    ],
  },
  {
    key: 'certs', title: 'Certificates & Trust', icon: Lock, to: '/ws/certificates',
    match: p => p.startsWith('/ws/certificates'),
    items: [
      { to: '/ws/certificates',  label: 'Overview', end: true },
      { hash: '#cert-inventory', label: 'Inventory' },
      { hash: '#cert-expiry',    label: 'Expiry Risk' },
      { hash: '#cert-actions',   label: 'Recommended Actions' },
      { hash: '#cert-trust',     label: 'Trust Posture' },
      { to: '/ws/reports',       label: 'Reports' },
    ],
  },
]

// Secondary workspace/admin links — tucked into a small footer dropdown so they
// never dominate the coloured service suite.
const WORKSPACE_TOOLS = [
  { to: '/ws/dashboard',           icon: LayoutDashboard, label: 'Dashboard'    },
  { to: '/ws/scorecard',           icon: Shield,          label: 'Scorecard'    },
  { to: '/ws/executive-dashboard', icon: BarChart2,       label: 'Executive'    },
  { to: '/ws/audit-log',           icon: ClipboardList,   label: 'Audit Log'    },
  { to: '/ws/members',             icon: Users,           label: 'Team Members' },
  { to: '/ws/alerts',              icon: Bell,            label: 'Alert Channels' },
  { to: '/ws/retention',           icon: HardDrive,       label: 'Retention'    },
  { to: '/settings',               icon: Settings,        label: 'Settings'     },
]

function detectServiceKey(pathname) {
  const s = SERVICES.find(svc => svc.match(pathname))
  return s ? s.key : null
}

export default function WorkspaceNav({ wsName }) {
  const navigate = useNavigate()
  const { pathname } = useLocation()
  const activeKey = detectServiceKey(pathname)
  const [toolsOpen, setToolsOpen] = useState(false)
  const [hoverKey, setHoverKey] = useState(null)
  // Sub-items behave as a manual accordion: the active service opens by default,
  // but a click toggles it closed (and open again) without waiting for a route change.
  const [expandedKey, setExpandedKey] = useState(activeKey)
  useEffect(() => { setExpandedKey(activeKey) }, [activeKey])

  const handlePreload = (to) => {
    const loader = routePreloadMap[to]
    if (loader) preloadComponent(loader)
  }

  const activeTheme = activeKey ? THEME[activeKey] : null

  return (
    <aside className="w-56 lg:w-[20%] lg:max-w-[280px] lg:min-w-[236px] flex-shrink-0 bg-white border-r border-gray-200 sticky top-16 h-[calc(100vh-64px)] overflow-y-auto flex flex-col">

      {/* Workspace identity */}
      <div className="px-4 pt-5 pb-4 border-b border-gray-100">
        <button
          onClick={() => navigate('/workspaces')}
          className="flex items-center gap-1.5 text-xs font-medium text-gray-400 hover:text-gray-600 transition-colors mb-3"
        >
          <ChevronLeft className="w-3.5 h-3.5" />
          All workspaces
        </button>
        <div className="flex items-center gap-2.5">
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ backgroundColor: activeTheme ? activeTheme.icon : '#00876A' }}
          >
            <Briefcase className="w-4 h-4 text-white" />
          </div>
          <span className="text-base font-bold text-gray-900 truncate">{wsName || 'Workspace'}</span>
        </div>
      </div>

      {/* ── Product suite: four coloured services ── */}
      <nav className="flex-1 px-2.5 py-4 space-y-1.5">
        {SERVICES.map(svc => {
          const active = activeKey === svc.key
          const expanded = expandedKey === svc.key
          const hovered = hoverKey === svc.key
          const t = THEME[svc.key]
          const Icon = svc.icon
          return (
            <div key={svc.key}>
              <Link
                to={svc.to}
                onMouseEnter={() => { setHoverKey(svc.key); handlePreload(svc.to) }}
                onMouseLeave={() => setHoverKey(null)}
                onFocus={() => handlePreload(svc.to)}
                onClick={() => setExpandedKey(prev => prev === svc.key ? null : svc.key)}
                style={active
                  ? { backgroundColor: t.bg, borderLeftColor: t.accent }
                  : hovered ? { backgroundColor: t.tint, borderLeftColor: 'transparent' } : { borderLeftColor: 'transparent' }}
                className={`flex items-center gap-3 pl-3 pr-2.5 py-2.5 rounded-xl border-l-[3px] transition-colors ${
                  active ? 'font-semibold' : 'font-medium text-gray-700'
                }`}
              >
                <Icon
                  className="w-[22px] h-[22px] flex-shrink-0 transition-transform"
                  strokeWidth={active ? 2.4 : 2}
                  style={{ color: t.icon, transform: hovered && !active ? 'scale(1.08)' : undefined }}
                />
                <span
                  className="flex-1 truncate text-[18px] leading-tight"
                  style={active ? { color: t.text } : undefined}
                >
                  {svc.title}
                </span>
                {expanded
                  ? <ChevronDown className="w-4 h-4 flex-shrink-0" style={{ color: t.accent }} />
                  : <ChevronRight className="w-4 h-4 text-gray-300 flex-shrink-0" />}
              </Link>

              {/* The expanded service reveals its coloured sub-items */}
              {expanded && (
                <div
                  className="ml-[26px] mt-1 mb-1.5 pl-3.5 space-y-0.5 border-l-2"
                  style={{ borderColor: t.bg }}
                >
                  {svc.items.map((item, i) => item.hash ? (
                    <a key={i} href={item.hash}
                      style={{ color: t.text }}
                      className="block px-2.5 py-1.5 rounded-lg text-sm font-medium opacity-80 hover:opacity-100 transition-opacity">
                      {item.label}
                    </a>
                  ) : (
                    <NavLink key={i} to={item.to} end={item.end}
                      onMouseEnter={() => handlePreload(item.to)}
                      onFocus={() => handlePreload(item.to)}
                      style={({ isActive }) => isActive ? { color: t.text, backgroundColor: t.bg } : { color: t.text }}
                      className={({ isActive }) =>
                        `block px-2.5 py-1.5 rounded-lg text-sm transition-all ${
                          isActive ? 'font-semibold' : 'font-medium opacity-80 hover:opacity-100'
                        }`
                      }>
                      {item.label}
                    </NavLink>
                  ))}
                </div>
              )}
            </div>
          )
        })}
      </nav>

      {/* ── Secondary workspace/admin links — small footer dropdown ── */}
      <div className="px-2.5 py-2.5 border-t border-gray-100">
        <button
          onClick={() => setToolsOpen(v => !v)}
          className="w-full flex items-center gap-2 px-2.5 py-2 rounded-lg text-[11px] font-bold text-gray-400 uppercase tracking-widest hover:text-gray-600 hover:bg-gray-50 transition-colors"
        >
          <span className="flex-1 text-left">Workspace</span>
          <ChevronDown className={`w-3.5 h-3.5 transition-transform ${toolsOpen ? 'rotate-180' : ''}`} />
        </button>
        {toolsOpen && (
          <div className="mt-1 space-y-0.5">
            {WORKSPACE_TOOLS.map(({ to, icon: Icon, label }) => (
              <NavLink
                key={to}
                to={to}
                end
                onMouseEnter={() => handlePreload(to)}
                onFocus={() => handlePreload(to)}
                className={({ isActive }) =>
                  `flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-sm transition-colors ${
                    isActive ? 'text-gray-900 bg-gray-100 font-semibold' : 'text-gray-500 hover:text-gray-900 hover:bg-gray-50 font-medium'
                  }`
                }
              >
                <Icon className="w-4 h-4 flex-shrink-0" /> {label}
              </NavLink>
            ))}
          </div>
        )}
      </div>
    </aside>
  )
}
