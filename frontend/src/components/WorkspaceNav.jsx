import { NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard, Shield, Package2, Layers, Zap,
  Cloud, Terminal, Lock, Tag, Bell, Briefcase, ChevronLeft, FileText,
  BarChart2, TrendingUp, ShieldCheck,
} from 'lucide-react'

const WS_NAV = [
  { to: '/ws/executive-dashboard', icon: BarChart2,       label: 'Executive'        },
  { to: '/ws/business-risk',       icon: TrendingUp,      label: 'Business Risk'    },
  { to: '/ws/cyber-essentials',    icon: ShieldCheck,     label: 'Cyber Essentials' },
  { to: '/ws/dashboard',           icon: LayoutDashboard, label: 'Dashboard'        },
  { to: '/ws/scorecard',           icon: Shield,          label: 'Scorecard'        },
  { to: '/ws/vendors',          icon: Package2,        label: 'Vendor Risk'      },
  { to: '/ws/third-party',      icon: Layers,          label: 'Third-Party'      },
  { to: '/ws/saas-exposure',    icon: Zap,             label: 'SaaS Exposure'    },
  { to: '/ws/cloud-assets',     icon: Cloud,           label: 'Cloud Assets'     },
  { to: '/ws/admin-surfaces',   icon: Terminal,        label: 'Admin Surfaces'   },
  { to: '/ws/certificates',     icon: Lock,            label: 'Certificates'     },
  { to: '/ws/brand-monitoring', icon: Tag,             label: 'Brand Monitoring' },
  { to: '/ws/alerts',           icon: Bell,            label: 'Alerts'           },
  { to: '/ws/reports',          icon: FileText,        label: 'Reports'          },
]

export default function WorkspaceNav({ wsName }) {
  const navigate = useNavigate()

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

      {/* Nav items */}
      <nav className="flex-1 px-2 py-3 space-y-0.5">
        <p className="px-2 py-1.5 text-[10px] font-semibold text-gray-400 uppercase tracking-widest">
          Intelligence
        </p>
        {WS_NAV.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              isActive
                ? 'flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-brand-700 bg-brand-50 text-sm font-semibold'
                : 'flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-gray-500 hover:text-gray-900 hover:bg-gray-50 text-sm font-medium transition-colors'
            }
          >
            <Icon className="w-4 h-4 flex-shrink-0" />
            {label}
          </NavLink>
        ))}
      </nav>
    </aside>
  )
}
