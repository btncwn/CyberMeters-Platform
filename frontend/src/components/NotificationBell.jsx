/**
 * NotificationBell — workspace-scoped in-app notification panel.
 *
 * Reads the active workspace from localStorage (cybermeters_workspace_id).
 * Polls every 60s for new notifications. Shows unread count badge.
 * Clicking a notification marks it read and navigates to the related scan,
 * report, or lifecycle record when metadata provides a safe in-app target.
 * Footer includes "View all →" link to /notifications.
 *
 * Only renders the panel when a workspace is selected — falls back to a
 * plain Bell icon (no panel) if no workspace is active.
 */
import { useState, useEffect, useRef, useCallback } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Bell, X } from 'lucide-react'
import { api } from '../api'
import { DOMAIN_KEY_LABELS } from '../lib/caseDisplay'

// ── Severity / type helpers ────────────────────────────────────────────────────

const SEVERITY_CFG = {
  critical: { dot: 'bg-red-500',    text: 'text-red-600',    bg: 'bg-red-50'    },
  high:     { dot: 'bg-orange-400', text: 'text-orange-600', bg: 'bg-orange-50' },
  medium:   { dot: 'bg-amber-400',  text: 'text-amber-600',  bg: 'bg-amber-50'  },
  low:      { dot: 'bg-blue-400',   text: 'text-blue-600',   bg: 'bg-blue-50'   },
  info:     { dot: 'bg-gray-300',   text: 'text-gray-500',   bg: 'bg-gray-50'   },
}

const BELL_QUERY = { limit: 30 }

function severityCfg(sev) {
  return SEVERITY_CFG[sev] ?? SEVERITY_CFG.info
}

// Exported for the DOM-XSS safety suite: this is the load-bearing sanitiser for
// alert deep-links (notification meta.link), which can carry attacker-influenced
// data. It admits ONLY a same-origin path — a leading '/' (but not protocol-
// relative '//'), or an absolute URL whose origin matches the app — and returns
// null for everything else (javascript:, data:, cross-origin), so navigate() is
// never handed a dangerous target.
export function appPath(raw) {
  if (typeof raw !== 'string' || !raw) return null
  if (raw.startsWith('/') && !raw.startsWith('//')) return raw
  try {
    const u = new URL(raw)
    return u.origin === window.location.origin ? `${u.pathname}${u.search}${u.hash}` : null
  } catch { return null }
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
  const [loadError,     setLoadError]    = useState(null)
  const [hasLoadedSuccessfully, setHasLoadedSuccessfully] = useState(false)
  const [failedQuery,   setFailedQuery]  = useState(null)
  const ref = useRef(null)
  const loadGenerationRef = useRef(0)
  const markRequestsInFlightRef = useRef(0)
  const markRecoveryNeededRef = useRef(false)

  // Close on outside click
  useEffect(() => {
    function handler(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const load = useCallback(async (silent = false, query = BELL_QUERY) => {
    if (!wsId) return
    const requestQuery = { ...query }
    const generation = ++loadGenerationRef.current
    const blockedByMark = markRequestsInFlightRef.current > 0
    if (!silent && !blockedByMark) setLoading(true)
    try {
      const data = await api.getWorkspaceNotifications(wsId, requestQuery)
      if (generation !== loadGenerationRef.current || blockedByMark) return
      setNotifications(data.notifications || [])
      setUnreadCount(data.unread_count ?? 0)
      setHasLoadedSuccessfully(true)
      setLoadError(null)
      setFailedQuery(null)
      markRecoveryNeededRef.current = false
    } catch {
      if (generation !== loadGenerationRef.current || blockedByMark) return
      setLoadError('Notifications could not be loaded.')
      setFailedQuery(requestQuery)
    }
    finally {
      if (generation === loadGenerationRef.current && !blockedByMark) setLoading(false)
    }
  }, [wsId])

  function retryLoad() {
    if (failedQuery) load(false, failedQuery)
  }

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
    markRequestsInFlightRef.current += 1
    loadGenerationRef.current += 1
    setLoading(false)
    // Optimistically update UI
    setNotifications(prev =>
      prev.map(n => n.id === notifId ? { ...n, status: 'read' } : n)
    )
    setUnreadCount(prev => Math.max(0, prev - 1))
    try {
      await api.markNotificationRead(wsId, notifId)
    } catch {
      markRecoveryNeededRef.current = true
    } finally {
      markRequestsInFlightRef.current = Math.max(0, markRequestsInFlightRef.current - 1)
      loadGenerationRef.current += 1
      setLoading(false)
      if (markRequestsInFlightRef.current === 0 && markRecoveryNeededRef.current) {
        load(true)
      }
    }
  }

  async function handleMarkAll() {
    if (!wsId || markingAll) return
    markRequestsInFlightRef.current += 1
    loadGenerationRef.current += 1
    setLoading(false)
    setMarkingAll(true)
    try {
      await api.markNotificationRead(wsId, 'all')
      setNotifications(prev => prev.map(n => ({ ...n, status: 'read' })))
      setUnreadCount(0)
    } catch {
      markRecoveryNeededRef.current = true
    } finally {
      markRequestsInFlightRef.current = Math.max(0, markRequestsInFlightRef.current - 1)
      loadGenerationRef.current += 1
      setLoading(false)
      setMarkingAll(false)
      if (markRequestsInFlightRef.current === 0 && markRecoveryNeededRef.current) {
        load(true)
      }
    }
  }

  // If no workspace selected, render a plain non-interactive bell
  if (!wsId) {
    return (
      <button className="relative w-11 h-11 flex items-center justify-center rounded-[8px] text-white hover:bg-white/10 transition-colors" aria-label="Notifications">
        <Bell className="w-[22px] h-[22px]" />
      </button>
    )
  }

  const hasUnread = unreadCount > 0

  return (
    <div className="relative" ref={ref}>
      {/* Bell button */}
      <button
        onClick={() => setOpen(v => !v)}
        className="relative w-11 h-11 flex items-center justify-center rounded-[8px] text-white hover:bg-white/10 transition-colors"
        aria-label={`Notifications${hasUnread ? ` (${unreadCount} unread)` : ''}`}
      >
        <Bell className="w-[22px] h-[22px]" />
        {hasUnread && (
          <span className="absolute top-2 right-2 w-2.5 h-2.5 rounded-full bg-[#E29535] border-2 border-[#071B40]" />
        )}
      </button>

      {/* Panel */}
      {open && (
        <div className="fixed left-4 right-4 mt-2 sm:absolute sm:left-auto sm:right-0 sm:top-full sm:w-80 bg-white rounded-2xl shadow-xl border border-gray-100 z-50 overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-gray-100">
            <div className="flex items-center gap-2">
              <span className="font-semibold text-gray-900 text-sm">Notifications</span>
              {hasUnread && (
                <span className="px-1.5 py-0.5 rounded-full text-xs font-bold bg-red-500 text-white leading-none">
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
                  All read
                </button>
              )}
              <button
                onClick={() => setOpen(false)}
                className="w-7 h-7 flex items-center justify-center rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-colors"
                aria-label="Close notifications"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Notification list */}
          <div className="max-h-[420px] overflow-y-auto">
            {loadError && !hasLoadedSuccessfully ? (
              <div role="alert" className="px-4 py-8 text-center">
                <p className="text-sm font-semibold text-gray-700">We couldn’t load notifications.</p>
                <p className="text-xs text-gray-400 mt-1">Check your connection and try again.</p>
                <button
                  type="button"
                  onClick={retryLoad}
                  disabled={loading}
                  className="mt-3 px-3 py-1.5 text-xs font-semibold text-brand-600 rounded-lg bg-brand-50 hover:bg-brand-100 transition-colors disabled:opacity-50"
                >
                  {loading ? 'Retrying…' : 'Retry'}
                </button>
              </div>
            ) : (
              <>
                {loadError && (
                  <div role="alert" className="flex items-start gap-2 px-4 py-3 bg-amber-50 border-b border-amber-100 text-amber-800">
                    <p className="text-xs leading-relaxed flex-1">
                      <span className="font-semibold">Couldn’t refresh notifications.</span>{' '}
                      Showing the last known notifications.
                    </p>
                    <button
                      type="button"
                      onClick={retryLoad}
                      disabled={loading}
                      className="text-xs font-semibold underline underline-offset-2 disabled:opacity-50"
                    >
                      {loading ? 'Retrying…' : 'Retry'}
                    </button>
                  </div>
                )}

                {loading && notifications.length === 0 && !loadError ? (
                  <div className="px-4 py-8 text-center text-sm text-gray-400">Loading…</div>
                ) : notifications.length === 0 && !loadError ? (
                  <div className="px-4 py-10 text-center">
                    <p className="text-sm text-gray-400">No notifications yet.</p>
                    <p className="text-xs text-gray-300 mt-1">Events appear here after scans and reports.</p>
                  </div>
                ) : notifications.length > 0 ? (
                  <ul className="divide-y divide-gray-50">
                    {notifications.map(n => {
                  const cfg      = severityCfg(n.severity)
                  const isUnread = n.status === 'unread'

                  // Resolve a click-through target. The list API returns metadata
                  // already parsed as `metadata` and drops the raw `metadata_json`
                  // string — accept either so notifications stay clickable.
                  let link = null
                  let meta = null
                  try {
                    meta = n.metadata ?? (n.metadata_json ? JSON.parse(n.metadata_json) : null)
                    link = meta?.scan_id ? `/scans/${meta.scan_id}` : meta?.report_id ? '/reports' : appPath(meta?.link)
                  } catch { /* ignore */ }

                  function handleNotifClick() {
                    if (isUnread) handleMarkRead(n.id)
                    if (link) {
                      setOpen(false)
                      navigate(link)
                    }
                  }

                      return (
                        <li
                          key={n.id}
                          onClick={handleNotifClick}
                          className={`flex gap-3 px-4 py-3.5 transition-colors ${isUnread ? 'bg-brand-50/30' : ''} ${link ? 'cursor-pointer hover:bg-gray-50' : 'cursor-default hover:bg-gray-50/50'}`}
                        >
                      {/* Content */}
                      <div className="flex-1 min-w-0">
                        {DOMAIN_KEY_LABELS[meta?.domain_key || meta?.domain] && (
                          <p className="text-xs text-gray-500 mb-0.5">{DOMAIN_KEY_LABELS[meta?.domain_key || meta?.domain]}</p>
                        )}
                        <div className="flex items-start justify-between gap-2">
                          <p className={`text-xs font-semibold leading-snug ${isUnread ? 'text-gray-900' : 'text-gray-600'}`}>
                            {n.title}
                          </p>
                          <div className="flex items-center gap-1 flex-shrink-0">
                            {link && (
                              <span className="text-xs text-brand-500 font-medium">→</span>
                            )}
                            {isUnread && (
                              <button
                                onClick={e => { e.stopPropagation(); handleMarkRead(n.id) }}
                                title="Mark as read"
                                aria-label="Mark as read"
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
                          <span className={`inline-flex items-center gap-1 text-xs font-semibold uppercase tracking-wider ${cfg.text}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
                            {n.severity}
                          </span>
                          <span className="text-xs text-gray-300">·</span>
                          <span className="text-xs text-gray-400">{fmtRelative(n.created_at)}</span>
                        </div>
                      </div>
                        </li>
                      )
                    })}
                  </ul>
                ) : null}
              </>
            )}
          </div>

          {/* Footer */}
          <div className="border-t border-gray-100 px-4 py-2.5 flex items-center justify-between">
            <p className="text-xs text-gray-300">
              {notifications.length > 0
                ? `${notifications.length} shown · refreshes every 60s`
                : 'Auto-refreshes every 60s'}
            </p>
            <Link
              to="/notifications"
              onClick={() => setOpen(false)}
              className="text-xs font-medium text-brand-600 hover:text-brand-700 transition-colors"
            >
              View all →
            </Link>
          </div>
        </div>
      )}
    </div>
  )
}
