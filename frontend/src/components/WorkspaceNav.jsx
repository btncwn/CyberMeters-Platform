import { NavLink, Link, useNavigate, useLocation } from 'react-router-dom'
import {
  LayoutDashboard, Shield, Lock, Tag, Briefcase, ChevronLeft, FileText,
  BarChart2, ClipboardList, Users, HardDrive, Mail, Server,
} from 'lucide-react'

// ── The four CyberMeters services — ALWAYS present in the workspace sidebar ───
// Each shows its name (leads) and a short description beneath. The current
// service is highlighted and expands its in-service items.
const SERVICES = [
  {
    key: 'email', title: 'Email Protection', icon: Mail, to: '/ws/email-protection',
    desc: 'Managed DMARC, SPF/DKIM readiness, sender intelligence, enforcement guidance.',
    match: p => p.startsWith('/ws/email-protection'),
    items: [
      { hash: '#dmarc-setup',      label: 'DMARC Setup' },
      { hash: '#sender-inventory', label: 'Sender Inventory' },
      { hash: '#auth-detail',      label: 'Authentication Detail' },
    ],
  },
  {
    key: 'brand', title: 'Brand Protection', icon: Tag, to: '/ws/brand-monitoring',
    desc: 'Lookalike domains, typosquats, impersonation risk, brand-abuse monitoring.',
    match: p => p.startsWith('/ws/brand-monitoring'),
    items: [
      { hash: '#typosquats',    label: 'Typosquat Candidates' },
      { hash: '#brand-summary', label: 'Brand Findings' },
    ],
  },
  {
    key: 'surface', title: 'Attack Surface', icon: Server, to: '/assets',
    desc: 'Assets, scans, schedules, admin surfaces, cloud assets, SaaS exposure, third-party exposure.',
    match: p => p.startsWith('/assets') || p.startsWith('/ws/admin-surfaces')
      || p.startsWith('/ws/cloud-assets') || p.startsWith('/ws/saas-exposure')
      || p.startsWith('/ws/third-party') || p.startsWith('/scans') || p.startsWith('/schedules'),
    items: [
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
    desc: 'SSL/TLS certificates, expiry monitoring, HTTPS posture, MTA-STS/TLS-RPT, transport trust.',
    match: p => p.startsWith('/ws/certificates'),
    items: [
      { hash: '#cert-inventory', label: 'Inventory' },
      { hash: '#cert-expiry',    label: 'Expiry Risk' },
      { hash: '#cert-actions',   label: 'Recommended Actions' },
      { hash: '#cert-trust',     label: 'Trust Posture' },
    ],
  },
]

// Secondary workspace tools — reachable but visually quiet beneath the services.
const WORKSPACE_TOOLS = [
  { to: '/ws/dashboard',  icon: LayoutDashboard, label: 'Dashboard'  },
  { to: '/ws/scorecard',  icon: Shield,          label: 'Scorecard'  },
  { to: '/ws/executive-dashboard', icon: BarChart2, label: 'Executive' },
  { to: '/ws/reports',    icon: FileText,        label: 'Reports'    },
  { to: '/ws/audit-log',  icon: ClipboardList,   label: 'Audit Log'  },
  { to: '/ws/members',    icon: Users,           label: 'Team Members' },
  { to: '/ws/retention',  icon: HardDrive,       label: 'Retention'  },
]

function detectServiceKey(pathname) {
  const s = SERVICES.find(svc => svc.match(pathname))
  return s ? s.key : null
}

export default function WorkspaceNav({ wsName }) {
  const navigate = useNavigate()
  const { pathname } = useLocation()
  const activeKey = detectServiceKey(pathname)

  return (
    <aside className="w-60 flex-shrink-0 bg-white border-r border-gray-100 sticky top-16 h-[calc(100vh-64px)] overflow-y-auto flex flex-col">

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

      <nav className="flex-1 px-2 py-3">
        {/* ── The four services — always present ── */}
        <p className="px-2 py-1.5 text-[10px] font-semibold text-gray-400 uppercase tracking-widest">Services</p>
        <div className="space-y-1">
          {SERVICES.map(svc => {
            const active = activeKey === svc.key
            const Icon = svc.icon
            return (
              <div key={svc.key}>
                <Link
                  to={svc.to}
                  className={`flex items-start gap-2.5 px-2.5 py-2 rounded-lg transition-colors ${
                    active ? 'bg-brand-50 ring-1 ring-brand-100' : 'hover:bg-gray-50'
                  }`}
                >
                  <span className={`w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5 ${
                    active ? 'bg-brand-600' : 'bg-gray-100'
                  }`}>
                    <Icon className={`w-4 h-4 ${active ? 'text-white' : 'text-gray-500'}`} />
                  </span>
                  <span className="min-w-0">
                    <span className={`block text-sm font-semibold leading-snug ${active ? 'text-brand-700' : 'text-gray-800'}`}>
                      {svc.title}
                    </span>
                    <span className="block text-[11px] text-gray-400 leading-snug mt-0.5">{svc.desc}</span>
                  </span>
                </Link>

                {/* Active service expands its in-service items */}
                {active && svc.items?.length > 0 && (
                  <div className="ml-7 mt-1 mb-1 pl-3 border-l border-gray-100 space-y-0.5">
                    {svc.items.map((item, i) => item.hash ? (
                      <a key={i} href={item.hash} className="block px-2 py-1.5 rounded-md text-xs font-medium text-gray-500 hover:text-gray-900 hover:bg-gray-50 transition-colors">
                        {item.label}
                      </a>
                    ) : (
                      <NavLink key={i} to={item.to} className={({ isActive }) =>
                        `block px-2 py-1.5 rounded-md text-xs font-medium transition-colors ${
                          isActive ? 'text-brand-700 bg-brand-50' : 'text-gray-500 hover:text-gray-900 hover:bg-gray-50'
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
        </div>

        {/* ── Secondary workspace tools ── */}
        <p className="px-2 pt-5 pb-1.5 text-[10px] font-semibold text-gray-400 uppercase tracking-widest">Workspace</p>
        <div className="space-y-0.5">
          {WORKSPACE_TOOLS.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end
              className={({ isActive }) =>
                `flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-sm transition-colors ${
                  isActive ? 'text-brand-700 bg-brand-50 font-semibold' : 'text-gray-500 hover:text-gray-900 hover:bg-gray-50 font-medium'
                }`
              }
            >
              <Icon className="w-4 h-4 flex-shrink-0" /> {label}
            </NavLink>
          ))}
        </div>
      </nav>
    </aside>
  )
}
