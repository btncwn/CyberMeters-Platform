// WorkspaceMenu — the workspace button at the foot of the rail and its
// popover: the active workspace, the switch list, Manage workspaces, Members
// & roles, Clear selection, and the workspace tools (every route the old
// sidebar reached stays reachable). Writes the same localStorage keys the
// rest of the app reads and fires a `storage` event so the shell follows at
// once. Closes on Escape and on an outside click; focus returns to the button.
import { useEffect, useRef, useState } from 'react'
import { Building2, Check } from 'lucide-react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../../api'

export const WORKSPACE_MENU_ID = 'cm-workspace-menu'

// Secondary workspace/admin destinations — unchanged set, one place.
export const WORKSPACE_TOOLS = Object.freeze([
  { to: '/ws/dashboard',           label: 'Administration' },
  { to: '/ws/scorecard',           label: 'Scorecard' },
  { to: '/ws/executive-dashboard', label: 'Executive dashboard' },
  { to: '/ws/cases',               label: 'Operations' },
  { to: '/ws/related-changes',     label: 'Related changes' },
  { to: '/ws/audit-log',           label: 'Audit log' },
  { to: '/ws/alerts',              label: 'Alert channels' },
  { to: '/ws/retention',           label: 'Usage & retention' },
  { to: '/settings',               label: 'Settings' },
])

export default function WorkspaceMenu({ wsId, wsName, placement = 'up' }) {
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [workspaces, setWorkspaces] = useState(null)
  const [loading, setLoading] = useState(false)
  const ref = useRef(null)
  const buttonRef = useRef(null)

  function close({ refocus } = {}) {
    setOpen(false)
    if (refocus) buttonRef.current?.focus()
  }

  useEffect(() => {
    if (!open) return undefined
    function onPointerDown(e) { if (ref.current && !ref.current.contains(e.target)) close() }
    function onKeyDown(e) { if (e.key === 'Escape') { e.preventDefault(); close({ refocus: true }) } }
    document.addEventListener('mousedown', onPointerDown)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('mousedown', onPointerDown)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [open])

  async function toggle() {
    const opening = !open
    setOpen(opening)
    if (opening && workspaces === null && !loading) {
      setLoading(true)
      try {
        const data = await api.getWorkspaces()
        setWorkspaces(Array.isArray(data?.workspaces) ? data.workspaces : [])
      } catch { setWorkspaces([]) }
      finally { setLoading(false) }
    }
  }

  function select(ws) {
    localStorage.setItem('cybermeters_workspace_id', ws.id)
    localStorage.setItem('cybermeters_workspace_name', ws.name)
    window.dispatchEvent(new Event('storage'))
    close({ refocus: true })
    navigate('/ws/dashboard')
  }

  function clear() {
    localStorage.removeItem('cybermeters_workspace_id')
    localStorage.removeItem('cybermeters_workspace_name')
    window.dispatchEvent(new Event('storage'))
    close({ refocus: true })
    // The /ws/... pages belong to the workspace just cleared, so leave them.
    navigate('/workspaces')
  }

  const itemClass = 'flex items-center gap-2 px-4 py-2 text-[15px] text-gray-800 hover:bg-gray-50 transition-colors'
  const position = placement === 'up' ? 'left-0 bottom-full mb-2' : 'right-0 bottom-full mb-2'

  return (
    <div className="relative" ref={ref} data-testid="workspace-menu">
      <button
        ref={buttonRef}
        type="button"
        onClick={toggle}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={WORKSPACE_MENU_ID}
        aria-label={wsName ? `Workspace: ${wsName}` : 'Select a workspace'}
        className={`cm-rail-item ${open ? 'cm-rail-item-active' : ''}`}
      >
        <Building2 className="w-5 h-5" aria-hidden="true" />
        <span className="cm-tip" aria-hidden="true">{wsName || 'Select a workspace'}</span>
      </button>

      {open && (
        <div id={WORKSPACE_MENU_ID} role="menu" aria-label="Workspace" className={`cm-popover ${position} w-72 max-h-[70vh] overflow-y-auto`}>
          <div className="px-4 pt-3 pb-2 border-b border-gray-100">
            <p className="text-xs font-semibold uppercase tracking-wider text-gray-500">Workspace</p>
            <p className="text-[15px] font-semibold text-gray-900 truncate" data-testid="active-workspace-name">{wsName || 'No workspace selected'}</p>
          </div>
          <div className="py-1">
            <p className="px-4 pt-2 pb-1 text-xs font-semibold uppercase tracking-wider text-gray-500">Switch workspace</p>
            {loading && <p className="px-4 py-1.5 text-[15px] text-gray-500">Loading…</p>}
            {!loading && Array.isArray(workspaces) && workspaces.length === 0 && (
              <p className="px-4 py-1.5 text-[15px] text-gray-500">No workspaces yet</p>
            )}
            {Array.isArray(workspaces) && workspaces.map((ws) => (
              <button
                key={ws.id}
                type="button"
                role="menuitem"
                onClick={() => select(ws)}
                aria-current={ws.id === wsId ? 'true' : undefined}
                className={`${itemClass} w-full text-left ${ws.id === wsId ? 'font-semibold bg-gray-50' : ''}`}
              >
                <span className="flex-1 truncate">{ws.name}</span>
                {ws.id === wsId && <Check className="w-4 h-4 text-brand-600 shrink-0" aria-hidden="true" />}
              </button>
            ))}
          </div>
          <div className="border-t border-gray-100 py-1">
            <Link role="menuitem" to="/workspaces" onClick={() => close({ refocus: true })} className={`${itemClass} font-semibold text-brand-700`}>Manage workspaces</Link>
            <Link role="menuitem" to="/ws/members" onClick={() => close({ refocus: true })} className={itemClass}>Members &amp; roles</Link>
            {wsId && (
              <button type="button" role="menuitem" onClick={clear} className={`${itemClass} w-full text-left text-gray-600`}>Clear selection</button>
            )}
          </div>
          {wsId && (
            <div className="border-t border-gray-100 py-1">
              <p className="px-4 pt-2 pb-1 text-xs font-semibold uppercase tracking-wider text-gray-500">Workspace tools</p>
              {WORKSPACE_TOOLS.map(({ to, label }) => (
                <Link key={to} role="menuitem" to={to} onClick={() => close({ refocus: true })} className={itemClass}>{label}</Link>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
