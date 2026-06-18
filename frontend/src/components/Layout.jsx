import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard, Server, ScanLine, FileBarChart2,
  Settings, Shield, Plus, Bell, ChevronDown,
} from 'lucide-react'

const NAV = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/assets',    icon: Server,          label: 'Assets'    },
  { to: '/scans',     icon: ScanLine,        label: 'Scans'     },
  { to: '/reports',   icon: FileBarChart2,   label: 'Reports'   },
  { to: '/settings',  icon: Settings,        label: 'Settings'  },
]

export default function Layout() {
  const navigate = useNavigate()

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">

      {/* Top nav */}
      <header className="bg-white border-b border-gray-100 sticky top-0 z-50">
        <div className="max-w-screen-xl mx-auto px-6 h-16 flex items-center gap-6">

          {/* Logo */}
          <button
            onClick={() => navigate('/dashboard')}
            className="flex items-center gap-2.5 flex-shrink-0 group mr-2"
          >
            <div className="w-8 h-8 rounded-lg bg-brand-600 flex items-center justify-center group-hover:bg-brand-700 transition-colors">
              <Shield className="w-[18px] h-[18px] text-white" strokeWidth={2.5} />
            </div>
            <div className="leading-none">
              <div className="font-bold text-gray-900 text-[15px] tracking-tight">CyberMeters</div>
              <div className="text-[10px] font-semibold text-brand-600 tracking-widest uppercase mt-0.5">Platform</div>
            </div>
          </button>

          {/* Nav */}
          <nav className="flex items-center gap-0.5">
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
            <button className="relative w-9 h-9 flex items-center justify-center rounded-xl text-gray-400 hover:text-gray-700 hover:bg-gray-100 transition-colors">
              <Bell className="w-[18px] h-[18px]" />
              <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-red-500 border-2 border-white" />
            </button>

            <button onClick={() => navigate('/scans/new')} className="btn-primary">
              <Plus className="w-4 h-4" />
              New Scan
            </button>

            <button className="flex items-center gap-1.5 pl-2 pr-2.5 py-1.5 rounded-xl hover:bg-gray-100 transition-colors ml-1">
              <div className="w-7 h-7 rounded-full bg-brand-600 flex items-center justify-center text-xs font-bold text-white">
                T
              </div>
              <ChevronDown className="w-3.5 h-3.5 text-gray-400" />
            </button>
          </div>
        </div>
      </header>

      {/* Content */}
      <main className="flex-1">
        <Outlet />
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-100 bg-white">
        <div className="max-w-screen-xl mx-auto px-6 py-3 flex items-center justify-between">
          <span className="text-xs text-gray-400">© {new Date().getFullYear()} CyberMeters — Attack Surface Management</span>
          <span className="text-xs text-gray-300 mono">{new Date().toUTCString().slice(0, 22)} UTC</span>
        </div>
      </footer>
    </div>
  )
}
