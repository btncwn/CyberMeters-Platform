/**
 * NotificationBell — workspace-scoped in-app notification panel.
 *
 * Reads the active workspace from localStorage (cybermeters_workspace_id).
 * Polls every 60s for new notifications. Shows unread count badge.
 * Clicking a notification marks it read and navigates to the related scan
 * (if metadata_json contains a scan_id). "Mark all read" bulk-clears.
 * Footer includes "View all →" link to /notifications.
 *
 * Only renders the panel when a workspace is selected — falls back to a
 * plain Bell icon (no panel) if no workspace is active.
 */
import { useState, useEffect, useRef, useCallback } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  Bell, X, CheckCheck, AlertTriangle, ShieldAlert,
  FileText, Globe, ScanLine, Info,
} from 'lucide-react'
import { api } from '../api'

// ── Severity / type helpers ────────────────────────────────────────────────────

const SEVERITY_CFG = {
  critical: { dot: 'bg-red-500',    text: 'text-red-600',    bg: 'bg-red-50'    },
  high:     { dot: 'bg-orange-400', text: 'text-orange-600', bg: 'bg-orange-50' },
  medium:   { dot: 'bg-amber-400',  text: 'text-amber-600',  bg: 'bg-amber-50'  },
  low:      { dot: 'bg-blue-400',   text: 'text-blue-600',   bg: 'bg-blue-50'   },
  info:     { dot: 'bg-gray-300',   text: 'text-gray-500',   bg: 'bg-gray-50'   },
}

function severityCfg(sev) {
  return SEVERITY_CFG[sev] ?? SEVERITY_CFG.info
}

function TypeIcon({ type }) {
  const cls = 'w-4 h-4 flex-shrink-0'
  switch (type) {
    case 'critical_finding':  return <ShieldAlert className={`${cls} text-red-500`} />
    case 'high_finding':      return <AlertTriangle className={`${cls} text-orange-400`} />
    case 'scan_completed':    return <ScanLine className={`${cls} text-brand-500`} />
    case 'report_generated':  return <FileText className={`${cls} text-brand-500`} />
    case 'domain_verified':   return <Globe className={`${cls} text-brand-500`} />
    default:                  return <Info className={`${cls} text-gray-400`} />
  }
}

function fmtRelative(isoStr) {
  if (!isoStr) return ''
  const s = isoStr.includes('T') ? isoStr : isoStr.replace(' ', 'T') + 'Z'
  const diff = Date.now() - new Date(s).getTime()
  const mins = Math.floor(diff / 60_000)
  if (mins < 1)   return 'just now'
  if (mins < 60)  return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24)   return `${hrs}h ago`
  const days = Math.floor(hrs / 24)
  return `${days}d ago`
}

// ── Main component ─────────────────────────────────────────────────────────────

export default function NotificationBell() {
  const wsId    = localStorage.getItem('cybermeters_workspace_id')
  const navigate = useNavigate()

  const [open,          setOpen]         = useState(false)
  const [notifications, setNotifications] = useState([])
  const [unreadCount,   setUnreadCount]  = useState(0)
  const [loading,       setLoading]      = useState(false)
  const [markingAll,    setMarkingAll]   = useState(false)
  const ref = useRef(null)

  // Close on outside click
  useEffect(() => {
    function handler(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const load = useCallback(async (silent = false) => {
    if (!wsId) return
    if (!silent) setLoading(true)
    try {
      const data = await api.getWorkspaceNotifications(wsId, { limit: 30 })
      setNotifications(data.notifications || [])
      setUnreadCount(data.unread_count ?? 0)
    } catch { /* silent */ }
    finally { setLoading(false) }
  }, [wsId])

  // Load on mount + poll every 60s
  useEffect(() => {
    load()
    const id = setInterval(() => load(true), 60_000)
    return () => clearInterval(id)
  }, [load])

  // Reload silently when panel opens
  useEffect(() => {
    if (open) load(true)
  }, [open, load])

  async function handleMarkRead(notifId) {
    if (!wsId) return
    // Optimistically update UI
    setNotifications(prev =>
      prev.map(n => n.id === notifId ? { ...n, status: 'read' } : n)
    )
    setUnreadCount(prev => Math.max(0, prev - 1))
    try {
      await api.markNotificationRead(wsId, notifId)
    } catch { /* revert on error — reload */ load(true) }
  }

  async function handleMarkAll() {
    if (!wsId || markingAll) return
    setMarkingAll(true)
    try {
      await api.markNotificationRead(wsId, 'all')
      setNotifications(prev => prev.map(n => ({ ...n, status: 'read' })))
      setUnreadCount(0)
    } catch { load(true) }
    finally { setMarkingAll(false) }
  }

  // If no workspace selected, render a plain non-interactive bell
  if (!wsId) {
    return (
      <button className="relative w-9 h-9 flex items-center justify-center rounded-xl text-gray-400 hover:text-gray-700 hover:bg-gray-100 transition-colors">
        <Bell className="w-[18px] h-[18px]" />
      </button>
    )
  }

  const hasUnread = unreadCount > 0

  return (
    <div className="relative" ref={ref}>
      {/* Bell button */}
      <button
        onClick={() => setOpen(v => !v)}
        className="relative w-9 h-9 flex items-center justify-center rounded-xl text-gray-400 hover:text-gray-700 hover:bg-gray-100 transition-colors"
        aria-label={`Notifications${hasUnread ? ` (${unreadCount} unread)` : ''}`}
      >
        <Bell className="w-[18px] h-[18px]" />
        {hasUnread && (
          <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-red-500 border-2 border-white" />
        )}
      </button>

      {/* Panel */}
      {open && (
        <div className="absolute right-0 top-full mt-2 w-80 bg-white rounded-2xl shadow-xl border border-gray-100 z-50 overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-gray-100">
            <div className="flex items-center gap-2">
              <Bell className="w-4 h-4 text-gray-400" />
              <span className="font-semibold text-gray-900 text-sm">Notifications</span>
              {hasUnread && (
                <span className="px-1.5 py-0.5 rounded-full text-[10px] font-bold bg-red-500 text-white leading-none">
                  {unreadCount > 99 ? '99+' : unreadCount}
                </span>
              )}
            </div>
            <div className="flex items-center gap-1">
              {hasUnread && (
                <button
                  onClick={handleMarkAll}
                  disabled={markingAll}
                  className="flex items-center gap-1 text-xs text-brand-600 hover:text-brand-700 font-medium px-2 py-1 rounded-lg hover:bg-brand-50 transition-colors disabled:opacity-50"
                >
                  <CheckCheck className="w-3.5 h-3.5" />
                  All read
                </button>
              )}
              <button
                onClick={() => setOpen(false)}
                className="w-7 h-7 flex items-center justify-center rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-colors"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Notification list */}
          <div className="max-h-[420px] overflow-y-auto">
            {loading && notifications.length === 0 ? (
              <div className="px-4 py-8 text-center text-sm text-gray-400">Loading…</div>
            ) : notifications.length === 0 ? (
              <div className="px-4 py-10 text-center">
                <Bell className="w-8 h-8 text-gray-200 mx-auto mb-2" />
                <p className="text-sm text-gray-400">No notifications yet.</p>
                <p className="text-xs text-gray-300 mt-1">Events appear here after scans and reports.</p>
              </div>
            ) : (
              <ul className="divide-y divide-gray-50">
                {notifications.map(n => {
                  const cfg      = severityCfg(n.severity)
                  const isUnread = n.status === 'unread'

                  // Parse scan_id from metadata for click-through navigation
                  let scanId = null
                  try {
                    const meta = n.metadata_json ? JSON.parse(n.metadata_json) : null
                    scanId = meta?.scan_id ?? null
                  } catch { /* ignore */ }

                  function handleNotifClick() {
                    if (isUnread) handleMarkRead(n.id)
                    if (scanId) {
                      setOpen(false)
                      navigate(`/scans/${scanId}`)
                    }
                  }

                  return (
                    <li
                      key={n.id}
                      onClick={handleNotifClick}
                      className={`flex gap-3 px-4 py-3.5 transition-colors ${isUnread ? 'bg-brand-50/30' : ''} ${scanId ? 'cursor-pointer hover:bg-gray-50' : 'cursor-default hover:bg-gray-50/50'}`}
                    >
                      {/* Type icon */}
                      <div className="flex-shrink-0 mt-0.5">
                        <TypeIcon type={n.type} />
                      </div>

                      {/* Content */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-start justify-between gap-2">
                          <p className={`text-xs font-semibold leading-snug ${isUnread ? 'text-gray-900' : 'text-gray-600'}`}>
                            {n.title}
                          </p>
                          <div className="flex items-center gap-1 flex-shrink-0">
                            {scanId && (
                              <span className="text-[10px] text-brand-500 font-medium">→</span>
                            )}
                            {isUnread && (
                              <button
                                onClick={e => { e.stopPropagation(); handleMarkRead(n.id) }}
                                title="Mark as read"
                                className="w-5 h-5 flex items-center justify-center rounded text-gray-300 hover:text-brand-500 hover:bg-brand-50 transition-colors"
                              >
                                <X className="w-3 h-3" />
                              </button>
                            )}
                          </div>
                        </div>
                        {n.message && (
                          <p className="text-xs text-gray-400 mt-0.5 leading-relaxed line-clamp-2">{n.message}</p>
                        )}
                        <div className="flex items-center gap-2 mt-1.5">
                          <span className={`inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider ${cfg.text}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
                            {n.severity}
                          </span>
                          <span className="text-[10px] text-gray-300">·</span>
                          <span className="text-[10px] text-gray-400">{fmtRelative(n.created_at)}</span>
                        </div>
                      </div>
                    </li>
                  )
                })}
              </ul>
            )}
          </div>

          {/* Footer */}
          <div className="border-t border-gray-100 px-4 py-2.5 flex items-center justify-between">
            <p className="text-[10px] text-gray-300">
              {notifications.length > 0
                ? `${notifications.length} shown · refreshes every 60s`
                : 'Auto-refreshes every 60s'}
            </p>
            <Link
              to="/notifications"
              onClick={() => setOpen(false)}
              className="text-[11px] font-medium text-brand-600 hover:text-brand-700 transition-colors"
            >
              View all →
            </Link>
          </div>
        </div>
      )}
    </div>
  )
}
