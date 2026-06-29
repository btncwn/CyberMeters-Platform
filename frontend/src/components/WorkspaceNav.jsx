import { NavLink, useNavigate, useLocation } from 'react-router-dom'
import {
  LayoutDashboard, Shield, Layers, Zap, Cloud, Terminal, Lock, Tag, Briefcase,
  ChevronLeft, FileText, BarChart2, ClipboardList, Users, HardDrive, Mail,
  ShieldCheck, KeyRound, Server, ScanLine, Clock, AlertTriangle, LayoutGrid,
} from 'lucide-react'

// ── Full workspace ("Intelligence") sidebar — fallback for non-service routes ─
const WS_NAV = [
  { to: '/ws/executive-dashboard', icon: BarChart2,       label: 'Executive'        },
  { to: '/ws/dashboard',           icon: LayoutDashboard, label: 'Dashboard'        },
  { to: '/ws/scorecard',           icon: Shield,          label: 'Scorecard'        },
  { to: '/ws/third-party',      icon: Layers,          label: 'Third-Party'      },
  { to: '/ws/saas-exposure',    icon: Zap,             label: 'SaaS Exposure'    },
  { to: '/ws/cloud-assets',     icon: Cloud,           label: 'Cloud Assets'     },
  { to: '/ws/admin-surfaces',   icon: Terminal,        label: 'Admin Surfaces'   },
  { to: '/ws/certificates',     icon: Lock,            label: 'Certificates'     },
  { to: '/ws/brand-monitoring', icon: Tag,             label: 'Brand Monitoring' },
  { to: '/ws/email-protection', icon: Mail,            label: 'Email Protection' },
  { to: '/ws/reports',          icon: FileText,        label: 'Reports'          },
  { to: '/ws/audit-log',        icon: ClipboardList,   label: 'Audit Log'        },
  { to: '/ws/members',          icon: Users,           label: 'Team Members'     },
  { to: '/ws/retention',        icon: HardDrive,       label: 'Retention'        },
]

// ── Service-specific menus ───────────────────────────────────────────────────
// Anchor items (`hash`) scroll to a section on the current service page; route
// items (`to`) navigate. Only sections that actually exist are anchored.
const SERVICES = {
  email: {
    key: 'email', title: 'Email Protection', icon: Mail,
    match: p => p.startsWith('/ws/email-protection'),
    items: [
      { to: '/ws/email-protection', icon: Mail,        label: 'Overview' },
      { hash: '#dmarc-setup',       icon: ShieldCheck, label: 'DMARC Setup' },
      { hash: '#sender-inventory',  icon: Users,       label: 'Sender Inventory' },
      { hash: '#auth-detail',       icon: KeyRound,    label: 'Authentication Detail' },
      { to: '/ws/reports',          icon: FileText,    label: 'Reports' },
      { to: '/ws/audit-log',        icon: ClipboardList, label: 'Audit Log' },
      { to: '/ws/retention',        icon: HardDrive,   label: 'Retention' },
    ],
  },
  brand: {
    key: 'brand', title: 'Brand Protection', icon: Tag,
    match: p => p.startsWith('/ws/brand-monitoring'),
    items: [
      { to: '/ws/brand-monitoring', icon: Tag,           label: 'Overview' },
      { hash: '#typosquats',        icon: Layers,        label: 'Typosquat Candidates' },
      { hash: '#brand-summary',     icon: AlertTriangle, label: 'Brand Findings' },
      { to: '/ws/reports',          icon: FileText,      label: 'Reports' },
      { to: '/ws/audit-log',        icon: ClipboardList, label: 'Audit Log' },
    ],
  },
  surface: {
    key: 'surface', title: 'Attack Surface', icon: Server,
    match: p => p.startsWith('/assets') || p.startsWith('/ws/admin-surfaces')
      || p.startsWith('/ws/cloud-assets') || p.startsWith('/ws/saas-exposure')
      || p.startsWith('/ws/third-party'),
    items: [
      { to: '/assets',            icon: Server,    label: 'Overview' },
      { to: '/scans',             icon: ScanLine,  label: 'Scans' },
      { to: '/ws/admin-surfaces', icon: Terminal,  label: 'Admin Surfaces' },
      { to: '/ws/cloud-assets',   icon: Cloud,     label: 'Cloud Assets' },
      { to: '/ws/saas-exposure',  icon: Zap,       label: 'SaaS Exposure' },
      { to: '/ws/third-party',    icon: Layers,    label: 'Third-Party' },
      { to: '/ws/reports',        icon: FileText,  label: 'Reports' },
    ],
  },
  certs: {
    key: 'certs', title: 'Certificates & Trust', icon: Lock,
    match: p => p.startsWith('/ws/certificates'),
    items: [
      { to: '/ws/certificates', icon: Lock,        label: 'Overview' },
      { hash: '#cert-inventory', icon: Layers,      label: 'Inventory' },
      { hash: '#cert-expiry',    icon: Clock,       label: 'Expiry Risk' },
      { hash: '#cert-actions',   icon: AlertTriangle, label: 'Recommended Actions' },
      { hash: '#cert-trust',     icon: ShieldCheck, label: 'Trust Posture' },
      { to: '/ws/reports',       icon: FileText,    label: 'Reports' },
      { to: '/scans/new',        icon: ScanLine,    label: 'Run Scan' },
    ],
  },
}

// "Other services" secondary group (current service is filtered out at render).
const OTHER_SERVICES = [
  { key: 'services', to: '/services',            icon: LayoutGrid, label: 'Services' },
  { key: 'email',    to: '/ws/email-protection', icon: Mail,       label: 'Email Protection' },
  { key: 'brand',    to: '/ws/brand-monitoring', icon: Tag,        label: 'Brand Protection' },
  { key: 'surface',  to: '/assets',              icon: Server,     label: 'Attack Surface' },
  { key: 'certs',    to: '/ws/certificates',     icon: Lock,       label: 'Certificates & Trust' },
]

function detectService(pathname) {
  for (const svc of Object.values(SERVICES)) {
    if (svc.match(pathname)) return svc
  }
  return null
}

const ACTIVE_CLS = 'flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-brand-700 bg-brand-50 text-sm font-semibold'
const IDLE_CLS   = 'flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-gray-500 hover:text-gray-900 hover:bg-gray-50 text-sm font-medium transition-colors'

function NavItem({ item }) {
  const Icon = item.icon
  if (item.hash) {
    // Same-page anchor — native scroll, no active highlight (no scroll-spy in v1).
    return (
      <a href={item.hash} className={IDLE_CLS}>
        <Icon className="w-4 h-4 flex-shrink-0" /> {item.label}
      </a>
    )
  }
  return (
    <NavLink to={item.to} end className={({ isActive }) => (isActive ? ACTIVE_CLS : IDLE_CLS)}>
      <Icon className="w-4 h-4 flex-shrink-0" /> {item.label}
    </NavLink>
  )
}

export default function WorkspaceNav({ wsName }) {
  const navigate = useNavigate()
  const { pathname } = useLocation()
  const service = detectService(pathname)

  return (
    <aside className="w-52 flex-shrink-0 bg-white border-r border-gray-100 sticky top-16 h-[calc(100vh-64px)] overflow-y-auto flex flex-col">

      {/* Workspace name */}
      <div className="px-4 pt-5 pb-3 border-b border-gray-100">
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

      {service ? (
        /* ── Service-focused sidebar ── */
        <nav className="flex-1 px-2 py-3 flex flex-col">
          <p className="px-2 py-1.5 text-[10px] font-semibold text-brand-600 uppercase tracking-widest">
            {service.title}
          </p>
          <div className="space-y-0.5">
            {service.items.map((item, i) => <NavItem key={item.to || item.hash || i} item={item} />)}
          </div>

          {/* Other services — visually secondary */}
          <div className="mt-auto pt-4">
            <p className="px-2 py-1.5 text-[10px] font-semibold text-gray-400 uppercase tracking-widest">
              Other services
            </p>
            <div className="space-y-0.5">
              {OTHER_SERVICES.filter(s => s.key !== service.key).map(s => (
                <NavLink
                  key={s.key}
                  to={s.to}
                  end
                  className={({ isActive }) =>
                    `flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-xs transition-colors ${
                      isActive ? 'text-brand-700 bg-brand-50 font-semibold' : 'text-gray-400 hover:text-gray-700 hover:bg-gray-50 font-medium'
                    }`
                  }
                >
                  <s.icon className="w-3.5 h-3.5 flex-shrink-0" /> {s.label}
                </NavLink>
              ))}
            </div>
          </div>
        </nav>
      ) : (
        /* ── Full workspace sidebar (fallback) ── */
        <nav className="flex-1 px-2 py-3 space-y-0.5">
          <p className="px-2 py-1.5 text-[10px] font-semibold text-gray-400 uppercase tracking-widest">
            Intelligence
          </p>
          {WS_NAV.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) => (isActive ? ACTIVE_CLS : IDLE_CLS)}
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              {label}
            </NavLink>
          ))}
        </nav>
      )}
    </aside>
  )
}
