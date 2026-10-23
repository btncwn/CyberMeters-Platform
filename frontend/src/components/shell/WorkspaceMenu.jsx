// WorkspaceMenu — the workspace card deck in the bottom-left of the shell and
// its popover: the active workspace, the switch list, then the workspace's own
// places (founder, 17 Oct 2026 — account things in the account menu, workspace
// things here): Manage workspaces, Domains, Members & roles, Alert channels,
// Usage & retention, Audit log. Writes the same
// localStorage keys the rest of the app reads and fires a `storage` event so
// the shell follows at once. Closes on Escape and on an outside click; focus
// returns to the button.
import { useEffect, useRef, useState } from 'react'
import { Check } from 'lucide-react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../../api'
import { setActiveWorkspace } from '../../lib/activeWorkspace'

export const WORKSPACE_MENU_ID = 'cm-workspace-menu'

// The selected workspace's own places. Domains (adding, importing and
// verifying them) moved here from the dissolved /ws/dashboard page.
export const WORKSPACE_PLACES = Object.freeze([
  { to: '/ws/domains',   label: 'Domains' },
  { to: '/ws/members',   label: 'Members & roles' },
  { to: '/ws/alerts',    label: 'Alert channels' },
  { to: '/ws/retention', label: 'Usage & retention' },
  { to: '/ws/audit-log', label: 'Audit log' },
])

export function workspaceInitial(name) {
  const source = String(name || '').trim()
  return source ? source[0].toUpperCase() : '?'
}

export default function WorkspaceMenu({ wsId, wsName, domainName = null, size = 'deck' }) {
  const mini = size === 'mini'
  // 'compact': the same card at 76px, floating bottom-left below 1024px (S1-SHELL-V2).
  const compact = size === 'compact'
  // The card's letter is the selected domain's initial (cybermeters.com → C,
  // blackbullbarbers.co.uk → B), falling back to the workspace name; hover
  // never changes it. The tooltip names the same thing.
  const subject = String(domainName || '').trim() || wsName
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
    setActiveWorkspace(ws.id, ws.name)
    close({ refocus: true })
    navigate('/dashboard')
  }

  const itemClass = 'flex items-center gap-2 px-4 py-2 text-[15px] text-gray-800 hover:bg-gray-50 transition-colors'

  return (
    <div className={mini ? 'relative' : `relative cm-wsdock${compact ? ' cm-wsdock-compact' : ''}`} ref={ref} data-testid="workspace-menu">
      <button
        ref={buttonRef}
        type="button"
        onClick={toggle}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={WORKSPACE_MENU_ID}
        aria-label={wsName ? `Workspace: ${wsName}` : 'Select a workspace'}
        title={subject ? `Workspace · ${subject}` : undefined}
        className={mini ? 'cm-wsmini' : `cm-wsbtn${compact ? ' cm-wsbtn-compact' : ''}`}
        data-testid={mini ? 'workspace-mini-button' : 'workspace-dock-button'}
      >
        {/* The card deck (founder prototype v2): a navy-to-blue card with the
            serif initial and a WORKSPACE label, two offset white cards behind.
            The mini card keeps the initial only. */}
        <span className="cm-wsbtn-initial" aria-hidden="true" data-testid="workspace-initial">{workspaceInitial(subject)}</span>
        {/* The card keeps its WORKSPACE label at every size; on the 76px card it sits at the 13px floor. */}
        {!mini && <span className="cm-wsbtn-label" aria-hidden="true">Workspace</span>}
        {!mini && <span className="cm-tip cm-wsbtn-tip" aria-hidden="true">{subject ? `Workspace · ${subject}` : 'Select a workspace'}</span>}
      </button>

      {open && (
        <div id={WORKSPACE_MENU_ID} role="menu" aria-label="Workspace" className={`cm-popover ${mini ? 'right-0 top-full mt-2 w-72' : 'left-0 bottom-full mb-3 w-[300px]'} max-h-[70vh] overflow-y-auto`}>
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
                {ws.id === wsId && <Check className="w-4 h-4 text-brand-700 shrink-0" aria-hidden="true" />}
              </button>
            ))}
          </div>
          <div className="border-t border-gray-100 py-1">
            <Link role="menuitem" to="/workspaces" onClick={() => close({ refocus: true })} className={`${itemClass} font-semibold text-brand-700`}>Manage workspaces</Link>
            {WORKSPACE_PLACES.map(({ to, label }) => (
              <Link key={to} role="menuitem" to={to} onClick={() => close({ refocus: true })} className={itemClass}>{label}</Link>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
