import { useState } from 'react'
import { NavLink, Link, useNavigate, useLocation } from 'react-router-dom'
import {
  LayoutDashboard, Shield, Lock, Tag, Briefcase, ChevronLeft, ChevronDown,
  ChevronRight, BarChart2, ClipboardList, Users, HardDrive, Mail,
  Server, Settings,
} from 'lucide-react'
import { preloadComponent } from '../utils/preload'
import { routePreloadMap } from '../utils/preloadMap'

// ── The four CyberMeters services — the only primary sections in the sidebar ──
// Compact accordion: all four always listed; the active one expands its items.
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
// never dominate the service sidebar.
const WORKSPACE_TOOLS = [
  { to: '/ws/dashboard',           icon: LayoutDashboard, label: 'Dashboard'    },
  { to: '/ws/scorecard',           icon: Shield,          label: 'Scorecard'    },
  { to: '/ws/executive-dashboard', icon: BarChart2,       label: 'Executive'    },
  { to: '/ws/audit-log',           icon: ClipboardList,   label: 'Audit Log'    },
  { to: '/ws/members',             icon: Users,           label: 'Team Members' },
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

  // Hover-to-preload: start fetching a lazy route's chunk as soon as the user
  // shows intent (hover/focus), so navigation feels instant.
  const handlePreload = (to) => {
    const loader = routePreloadMap[to]
    if (loader) preloadComponent(loader)
  }

  return (
    <aside className="w-52 lg:w-[19%] lg:max-w-[256px] lg:min-w-[200px] flex-shrink-0 bg-white border-r border-gray-100 sticky top-16 h-[calc(100vh-64px)] overflow-y-auto flex flex-col">

      {/* Workspace name */}
      <div className="px-3 pt-4 pb-3 border-b border-gray-100">
        <button
          onClick={() => navigate('/workspaces')}
          className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-gray-600 transition-colors mb-2"
        >
          <ChevronLeft className="w-3 h-3" />
          All workspaces
        </button>
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded-md bg-brand-600 flex items-center justify-center flex-shrink-0">
            <Briefcase className="w-3.5 h-3.5 text-white" />
          </div>
          <span className="text-sm font-semibold text-gray-800 truncate">{wsName || 'Workspace'}</span>
        </div>
      </div>

      {/* ── Four services (accordion) ── */}
      <nav className="flex-1 px-2 py-3 space-y-0.5">
        {SERVICES.map(svc => {
          const active = activeKey === svc.key
          const Icon = svc.icon
          return (
            <div key={svc.key}>
              <Link
                to={svc.to}
                onMouseEnter={() => handlePreload(svc.to)}
                onFocus={() => handlePreload(svc.to)}
                className={`flex items-center gap-2 px-2.5 py-2 rounded-lg text-sm transition-colors ${
                  active ? 'bg-brand-50 text-brand-700 font-semibold' : 'text-gray-700 hover:bg-gray-50 font-medium'
                }`}
              >
                <Icon className={`w-4 h-4 flex-shrink-0 ${active ? 'text-brand-600' : 'text-gray-400'}`} />
                <span className="flex-1 truncate">{svc.title}</span>
                {active
                  ? <ChevronDown className="w-3.5 h-3.5 text-brand-500 flex-shrink-0" />
                  : <ChevronRight className="w-3.5 h-3.5 text-gray-300 flex-shrink-0" />}
              </Link>

              {/* Only the active service expands */}
              {active && (
                <div className="ml-[18px] mt-0.5 mb-1 pl-3 border-l border-gray-100 space-y-0.5">
                  {svc.items.map((item, i) => item.hash ? (
                    <a key={i} href={item.hash}
                      className="block px-2 py-1 rounded-md text-xs text-gray-500 hover:text-gray-900 hover:bg-gray-50 transition-colors">
                      {item.label}
                    </a>
                  ) : (
                    <NavLink key={i} to={item.to} end={item.end}
                      onMouseEnter={() => handlePreload(item.to)}
                      onFocus={() => handlePreload(item.to)}
                      className={({ isActive }) =>
                        `block px-2 py-1 rounded-md text-xs transition-colors ${
                          isActive ? 'text-brand-700 bg-brand-50 font-semibold' : 'text-gray-500 hover:text-gray-900 hover:bg-gray-50'
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
      <div className="px-2 py-2 border-t border-gray-100">
        <button
          onClick={() => setToolsOpen(v => !v)}
          className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-xs font-semibold text-gray-400 uppercase tracking-widest hover:text-gray-600 hover:bg-gray-50 transition-colors"
        >
          <span className="flex-1 text-left">Workspace</span>
          <ChevronDown className={`w-3.5 h-3.5 transition-transform ${toolsOpen ? 'rotate-180' : ''}`} />
        </button>
        {toolsOpen && (
          <div className="mt-0.5 space-y-0.5">
            {WORKSPACE_TOOLS.map(({ to, icon: Icon, label }) => (
              <NavLink
                key={to}
                to={to}
                end
                onMouseEnter={() => handlePreload(to)}
                onFocus={() => handlePreload(to)}
                className={({ isActive }) =>
                  `flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-xs transition-colors ${
                    isActive ? 'text-brand-700 bg-brand-50 font-semibold' : 'text-gray-500 hover:text-gray-900 hover:bg-gray-50 font-medium'
                  }`
                }
              >
                <Icon className="w-3.5 h-3.5 flex-shrink-0" /> {label}
              </NavLink>
            ))}
          </div>
        )}
      </div>
    </aside>
  )
}
