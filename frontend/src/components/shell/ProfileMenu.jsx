// ProfileMenu — the account button (the signed-in person's initial) and its
// popover: name and role, Field Guide, Billing, Account & security; a Settings
// group (founder, 16 Oct 2026: Administration, Alert channels, Audit log and
// Usage & retention for the selected workspace, then the account Settings);
// then Sign out. Closes on Escape and on an outside click; focus returns to
// the button when it closes from the keyboard or after choosing an item.
import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { logoutWithToken } from '../../api'
import { TOKEN_KEY } from '../../context/authKeys'
import { useAuth } from '../../context/AuthContext'

export const PROFILE_MENU_ID = 'cm-profile-menu'

// Workspace-scoped settings — shown only while a workspace is selected. The
// routes and their access checks are unchanged; only the entry point moved
// here from the workspace popover.
export const WORKSPACE_SETTINGS = Object.freeze([
  { to: '/ws/dashboard',  label: 'Administration' },
  { to: '/ws/alerts',     label: 'Alert channels' },
  { to: '/ws/audit-log',  label: 'Audit log' },
  { to: '/ws/retention',  label: 'Usage & retention' },
])

export function initialFor(user) {
  const source = String(user?.name || user?.email || '').trim()
  return source ? source[0].toUpperCase() : '?'
}

export default function ProfileMenu({ roleLabel = null, workspaceId = null }) {
  const navigate = useNavigate()
  const { user, logout } = useAuth()
  const [open, setOpen] = useState(false)
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

  function handleLogout() {
    const currentToken = localStorage.getItem(TOKEN_KEY)
    close({ refocus: true })
    // Clear the local session first so the UI never waits on the network; the
    // server-side revocation follows with the token it had.
    logout()
    if (currentToken) logoutWithToken(currentToken)
    navigate('/login', { replace: true })
  }

  const itemClass = 'flex items-center px-4 py-2 text-[15px] text-gray-800 hover:bg-gray-50 transition-colors'

  return (
    <div className="relative" ref={ref}>
      <button
        ref={buttonRef}
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={PROFILE_MENU_ID}
        aria-label="Account menu"
        className="cm-avatar"
      >
        {initialFor(user)}
      </button>

      {open && (
        <div id={PROFILE_MENU_ID} role="menu" aria-label="Account" className="cm-popover right-0 top-full mt-2 w-64 max-h-[80vh] overflow-y-auto">
          <div className="px-4 pt-3 pb-2 border-b border-gray-100">
            <p className="text-[15px] font-semibold text-gray-900 truncate">{user?.name || user?.email || 'Signed in'}</p>
            {roleLabel && <p className="text-xs text-gray-500 truncate">{roleLabel}</p>}
          </div>
          <div className="py-1">
            <Link role="menuitem" to="/guide" onClick={() => close({ refocus: true })} className={itemClass}>Field Guide</Link>
            <Link role="menuitem" to="/billing" onClick={() => close({ refocus: true })} className={itemClass}>Billing</Link>
            <Link role="menuitem" to="/account" onClick={() => close({ refocus: true })} className={itemClass}>Account &amp; security</Link>
          </div>
          <div className="border-t border-gray-100 py-1" data-testid="profile-settings-group">
            <p className="px-4 pt-2 pb-1 text-xs font-semibold uppercase tracking-wider text-gray-500">Settings</p>
            {workspaceId && WORKSPACE_SETTINGS.map(({ to, label }) => (
              <Link key={to} role="menuitem" to={to} onClick={() => close({ refocus: true })} className={itemClass}>{label}</Link>
            ))}
            <Link role="menuitem" to="/settings" onClick={() => close({ refocus: true })} className={itemClass}>Settings</Link>
          </div>
          <div className="border-t border-gray-100 py-1">
            <button type="button" role="menuitem" onClick={handleLogout} className={`${itemClass} w-full text-left text-red-700 hover:bg-red-50`}>Sign out</button>
          </div>
        </div>
      )}
    </div>
  )
}
