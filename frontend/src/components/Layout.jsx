import { useState, useEffect, useRef } from 'react'
import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard, Server, ScanLine, FileBarChart2,
  Settings, Shield, Plus, Bell, ChevronDown, Calendar,
  Briefcase, ChevronRight, Check,
} from 'lucide-react'
import { api } from '../api'

const NAV = [
  { to: '/dashboard',  icon: LayoutDashboard, label: 'Dashboard'  },
  { to: '/workspaces', icon: Briefcase,       label: 'Workspaces' },
  { to: '/assets',     icon: Server,          label: 'Assets'     },
  { to: '/scans',      icon: ScanLine,        label: 'Scans'      },
  { to: '/schedules',  icon: Calendar,        label: 'Schedules'  },
  { to: '/reports',    icon: FileBarChart2,   label: 'Reports'    },
  { to: '/settings',   icon: Settings,        label: 'Settings'   },
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
    navigate(`/workspaces/${ws.id}`)
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
            <WorkspaceSelector />

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
