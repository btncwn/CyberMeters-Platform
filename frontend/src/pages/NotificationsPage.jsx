/**
 * NotificationsPage — full notification history with filters, mark-read,
 * and click-through navigation to the relevant scan.
 *
 * Route: /notifications (protected, inside Layout)
 *
 * Filter model:
 *   status   — 'all' | 'unread'
 *   severity — 'all' | 'critical' | 'high' | 'medium' | 'low' | 'info'
 *
 * Each notification card navigates to the scan, report, or lifecycle record
 * when metadata provides a safe in-app target.
 */
import { useState, useEffect, useCallback } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import {
  Bell, CheckCheck, AlertTriangle, ShieldAlert,
  FileText, Globe, ScanLine, Info, ChevronDown,
  ArrowLeft, Mail, Lock, ClipboardCheck, MonitorCheck, KeyRound, Boxes,
} from 'lucide-react'
import { api } from '../api'

// ── Shared severity config ────────────────────────────────────────────────────

const SEVERITY_CFG = {
  critical: {
    dot:    'bg-red-500',
    text:   'text-red-600',
    bg:     'bg-red-50',
    border: 'border-red-200',
    pill:   'bg-red-100 text-red-700',
    label:  'Critical',
  },
  high: {
    dot:    'bg-orange-400',
    text:   'text-orange-600',
    bg:     'bg-orange-50',
    border: 'border-orange-200',
    pill:   'bg-orange-100 text-orange-700',
    label:  'High',
  },
  medium: {
    dot:    'bg-amber-400',
    text:   'text-amber-600',
    bg:     'bg-amber-50',
    border: 'border-amber-200',
    pill:   'bg-amber-100 text-amber-700',
    label:  'Medium',
  },
  low: {
    dot:    'bg-blue-400',
    text:   'text-blue-600',
    bg:     'bg-blue-50',
    border: 'border-blue-200',
    pill:   'bg-blue-100 text-blue-700',
    label:  'Low',
  },
  info: {
    dot:    'bg-gray-300',
    text:   'text-gray-500',
    bg:     'bg-gray-50',
    border: 'border-gray-200',
    pill:   'bg-gray-100 text-gray-600',
    label:  'Info',
  },
}

function severityCfg(sev) {
  return SEVERITY_CFG[sev] ?? SEVERITY_CFG.info
}

// ── Type icon ─────────────────────────────────────────────────────────────────

function TypeIcon({ type, domainKey, className = 'w-5 h-5 flex-shrink-0' }) {
  switch (domainKey) {
    case 'email_protection':               return <Mail           className={`${className} text-blue-500`} />
    case 'brand_protection':               return <ShieldAlert    className={`${className} text-red-500`} />
    case 'attack_surface':                 return <Globe          className={`${className} text-teal-600`} />
    case 'certificates_trust':             return <Lock           className={`${className} text-sky-600`} />
    case 'cyber_essentials_readiness':     return <ClipboardCheck className={`${className} text-emerald-600`} />
    case 'website_security':               return <MonitorCheck   className={`${className} text-amber-600`} />
    case 'identity_exposure':              return <KeyRound       className={`${className} text-indigo-600`} />
    case 'shadow_it_unmanaged_technology': return <Boxes          className={`${className} text-purple-600`} />
    default: break
  }
  switch (type) {
    case 'critical_finding':  return <ShieldAlert  className={`${className} text-red-500`} />
    case 'high_finding':      return <AlertTriangle className={`${className} text-orange-400`} />
    case 'scan_completed':    return <ScanLine      className={`${className} text-brand-500`} />
    case 'report_generated':  return <FileText      className={`${className} text-brand-500`} />
    case 'domain_verified':   return <Globe         className={`${className} text-brand-500`} />
    default:                  return <Info          className={`${className} text-gray-400`} />
  }
}

// ── Relative time ─────────────────────────────────────────────────────────────

function fmtRelative(isoStr) {
  if (!isoStr) return ''
  const s    = isoStr.includes('T') ? isoStr : isoStr.replace(' ', 'T') + 'Z'
  const diff = Date.now() - new Date(s).getTime()
  const mins = Math.floor(diff / 60_000)
  if (mins < 1)  return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24)  return `${hrs}h ago`
  const days = Math.floor(hrs / 24)
  if (days < 7)  return `${days}d ago`
  return new Date(s).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })
}

// ── Severity filter pills ─────────────────────────────────────────────────────

const SEVERITY_FILTERS = [
  { value: 'all',      label: 'All severities' },
  { value: 'critical', label: 'Critical'        },
  { value: 'high',     label: 'High'            },
  { value: 'medium',   label: 'Medium'          },
  { value: 'low',      label: 'Low'             },
  { value: 'info',     label: 'Info'            },
]

// ── Notification card ─────────────────────────────────────────────────────────

function NotificationCard({ n, onMarkRead }) {
  const navigate = useNavigate()
  const cfg      = severityCfg(n.severity)
  const isUnread = n.status === 'unread'

  // The list API returns metadata already parsed as an object (`metadata`) and
  // drops the raw `metadata_json` string; accept either shape so a notification
  // is never left un-clickable just because of the field name.
  let meta = n.metadata ?? null
  if (!meta && n.metadata_json) {
    try { meta = JSON.parse(n.metadata_json) } catch { meta = null }
  }

  const scanId    = meta?.scan_id ?? null
  const reportId  = meta?.report_id ?? null
  const domain    = meta?.domain ?? null

  // `metadata.link` is the lifecycle deep link — the alert's own record. It was ignored
  // here entirely: this card derived a destination ONLY from scan_id/report_id, so every
  // Email/Website/CE lifecycle alert rendered `cursor-default` and went nowhere, while the
  // same alert's EMAIL carried a link. Same alert, two answers to "where do I go".
  //
  // Only same-origin app paths are followed. The backend builds these from the configured
  // frontend origin, but a card that will `navigate()` anywhere a metadata field tells it
  // to is a redirect waiting to happen, so an absolute URL is reduced to its path and
  // anything that is not a rooted app path is refused.
  const recordHref = (() => {
    const raw = meta?.link
    if (typeof raw !== 'string' || !raw) return null
    if (raw.startsWith('/')) return raw
    try {
      const u = new URL(raw)
      return u.origin === window.location.origin ? `${u.pathname}${u.search}${u.hash}` : null
    } catch { return null }
  })()

  const link      = scanId ? `/scans/${scanId}` : reportId ? '/reports' : recordHref
  const linkLabel = scanId ? 'View scan →' : reportId ? 'View report →' : recordHref ? 'View record →' : null

  function handleClick() {
    if (isUnread) onMarkRead(n.id)
    if (link) navigate(link)
  }

  return (
    <div
      onClick={handleClick}
      className={`
        flex gap-4 px-5 py-4 border-b border-gray-100 last:border-0 transition-colors
        ${isUnread ? 'bg-brand-50/20' : 'bg-white'}
        ${link ? 'cursor-pointer hover:bg-gray-50' : 'cursor-default'}
      `}
    >
      {/* Type icon */}
      <div className="flex-shrink-0 mt-0.5">
        <TypeIcon type={n.type} domainKey={meta?.domain_key || meta?.domain} />
      </div>

      {/* Main content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <p className={`text-sm font-semibold leading-snug ${isUnread ? 'text-gray-900' : 'text-gray-600'}`}>
              {n.title}
            </p>
            {n.message && (
              <p className="text-sm text-gray-400 mt-0.5 leading-relaxed">{n.message}</p>
            )}
            <div className="flex flex-wrap items-center gap-2 mt-2">
              {/* Severity pill */}
              <span className={`inline-flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full ${cfg.pill}`}>
                <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
                {cfg.label}
              </span>
              {/* Timestamp */}
              <span className="text-[11px] text-gray-400">{fmtRelative(n.created_at)}</span>
              {/* Domain tag */}
              {domain && (
                <span className="text-[11px] text-gray-400">· {domain}</span>
              )}
            </div>
          </div>

          {/* Right side: unread dot + scan link */}
          <div className="flex items-center gap-3 flex-shrink-0 mt-0.5">
            {link && (
              <span className="text-xs text-brand-600 font-medium whitespace-nowrap">
                {linkLabel}
              </span>
            )}
            {isUnread && (
              <span className="w-2 h-2 rounded-full bg-brand-500 flex-shrink-0" />
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

const PAGE_LIMIT = 50

export default function NotificationsPage() {
  const wsId = localStorage.getItem('cybermeters_workspace_id')

  const [statusFilter,   setStatusFilter]   = useState('all')       // 'all' | 'unread'
  const [severityFilter, setSeverityFilter] = useState('all')
  const [notifications,  setNotifications]  = useState([])
  const [unreadCount,    setUnreadCount]    = useState(0)
  const [totalCount,     setTotalCount]     = useState(0)
  const [loading,        setLoading]        = useState(false)
  const [loadingMore,    setLoadingMore]    = useState(false)
  const [markingAll,     setMarkingAll]     = useState(false)
  const [offset,         setOffset]         = useState(0)
  const [hasMore,        setHasMore]        = useState(false)

  // ── Load notifications ────────────────────────────────────────────────────

  const load = useCallback(async (reset = true) => {
    if (!wsId) return
    const isReset = reset
    if (isReset) setLoading(true)
    else setLoadingMore(true)

    try {
      const params = { limit: PAGE_LIMIT }
      if (statusFilter === 'unread') params.status = 'unread'

      const data = await api.getWorkspaceNotifications(wsId, params)
      const all  = data.notifications || []

      if (isReset) {
        setNotifications(all)
        setOffset(all.length)
      } else {
        setNotifications(prev => [...prev, ...all])
        setOffset(prev => prev + all.length)
      }

      setUnreadCount(data.unread_count ?? 0)
      setTotalCount(data.count ?? all.length)
      setHasMore(all.length === PAGE_LIMIT)
    } catch { /* silent */ }
    finally {
      setLoading(false)
      setLoadingMore(false)
    }
  }, [wsId, statusFilter])

  // Re-fetch when status filter changes
  useEffect(() => {
    setOffset(0)
    load(true)
  }, [load, statusFilter])

  // ── Client-side severity filter ───────────────────────────────────────────

  const visible = severityFilter === 'all'
    ? notifications
    : notifications.filter(n => n.severity === severityFilter)

  // ── Mark read ─────────────────────────────────────────────────────────────

  async function handleMarkRead(notifId) {
    if (!wsId) return
    setNotifications(prev =>
      prev.map(n => n.id === notifId ? { ...n, status: 'read' } : n)
    )
    setUnreadCount(prev => Math.max(0, prev - 1))
    try {
      await api.markNotificationRead(wsId, notifId)
    } catch { load(true) }
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

  // ── Empty state ───────────────────────────────────────────────────────────

  function EmptyState() {
    if (statusFilter === 'unread') {
      return (
        <div className="py-20 text-center">
          <CheckCheck className="w-10 h-10 text-green-300 mx-auto mb-3" />
          <p className="text-sm font-medium text-gray-500">All caught up</p>
          <p className="text-xs text-gray-400 mt-1">No unread notifications.</p>
        </div>
      )
    }
    return (
      <div className="py-20 text-center">
        <Bell className="w-10 h-10 text-gray-200 mx-auto mb-3" />
        <p className="text-sm font-medium text-gray-500">No notifications yet</p>
        <p className="text-xs text-gray-400 mt-1">Events appear here after scans complete.</p>
      </div>
    )
  }

  // ── No workspace state ────────────────────────────────────────────────────

  if (!wsId) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <Bell className="w-12 h-12 text-gray-200 mx-auto mb-4" />
          <h2 className="text-lg font-semibold text-gray-700 mb-1">No workspace selected</h2>
          <p className="text-sm text-gray-400 mb-4">Select a workspace to view notifications.</p>
          <Link to="/workspaces" className="text-sm text-brand-600 hover:underline">
            Go to Workspaces
          </Link>
        </div>
      </div>
    )
  }

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-3xl mx-auto px-4 py-8">

        {/* Header */}
        <div className="flex items-start justify-between mb-6">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <Link
                to="/dashboard"
                className="text-xs text-gray-400 hover:text-gray-600 flex items-center gap-1 transition-colors"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                Back
              </Link>
            </div>
            <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-3">
              Notifications
              {unreadCount > 0 && (
                <span className="px-2 py-0.5 text-sm font-semibold rounded-full bg-red-500 text-white leading-none">
                  {unreadCount > 99 ? '99+' : unreadCount}
                </span>
              )}
            </h1>
            <p className="text-sm text-gray-400 mt-0.5">
              {totalCount > 0
                ? `${totalCount} total · ${unreadCount} unread`
                : 'No notifications yet'}
            </p>
          </div>

          {unreadCount > 0 && (
            <button
              onClick={handleMarkAll}
              disabled={markingAll}
              className="flex items-center gap-1.5 text-sm text-brand-600 hover:text-brand-700 font-medium px-3 py-2 rounded-xl hover:bg-brand-50 transition-colors disabled:opacity-50"
            >
              <CheckCheck className="w-4 h-4" />
              {markingAll ? 'Marking…' : 'Mark all read'}
            </button>
          )}
        </div>

        {/* Filters */}
        <div className="bg-white rounded-2xl border border-gray-100 shadow-sm mb-4 overflow-hidden">
          <div className="flex items-center gap-1 px-4 py-3 border-b border-gray-100">
            {/* Status tabs */}
            <div className="flex rounded-xl bg-gray-100 p-0.5 mr-3">
              {[
                { value: 'all',    label: 'All'    },
                { value: 'unread', label: 'Unread' },
              ].map(({ value, label }) => (
                <button
                  key={value}
                  onClick={() => setStatusFilter(value)}
                  className={`px-3 py-1 text-xs font-semibold rounded-lg transition-colors ${
                    statusFilter === value
                      ? 'bg-white text-gray-900 shadow-sm'
                      : 'text-gray-500 hover:text-gray-700'
                  }`}
                >
                  {label}
                  {value === 'unread' && unreadCount > 0 && (
                    <span className="ml-1 text-[10px] text-red-500 font-bold">
                      {unreadCount > 99 ? '99+' : unreadCount}
                    </span>
                  )}
                </button>
              ))}
            </div>

            {/* Severity pills */}
            <div className="flex items-center gap-1 flex-wrap">
              {SEVERITY_FILTERS.map(({ value, label }) => {
                const isActive = severityFilter === value
                const cfg = value !== 'all' ? severityCfg(value) : null
                return (
                  <button
                    key={value}
                    onClick={() => setSeverityFilter(value)}
                    className={`px-2.5 py-1 text-[11px] font-semibold rounded-full transition-colors ${
                      isActive
                        ? value === 'all'
                          ? 'bg-gray-900 text-white'
                          : cfg.pill + ' ring-1 ring-inset ring-current'
                        : 'text-gray-400 hover:text-gray-600 hover:bg-gray-100'
                    }`}
                  >
                    {label}
                  </button>
                )
              })}
            </div>
          </div>

          {/* Notification list */}
          {loading ? (
            <div className="py-16 text-center">
              <div className="w-6 h-6 border-2 border-brand-600 border-t-transparent rounded-full animate-spin mx-auto" />
            </div>
          ) : visible.length === 0 ? (
            <EmptyState />
          ) : (
            <>
              <div>
                {visible.map(n => (
                  <NotificationCard
                    key={n.id}
                    n={n}
                    onMarkRead={handleMarkRead}
                  />
                ))}
              </div>

              {/* Load more */}
              {hasMore && severityFilter === 'all' && (
                <div className="px-4 py-4 border-t border-gray-100">
                  <button
                    onClick={() => load(false)}
                    disabled={loadingMore}
                    className="w-full flex items-center justify-center gap-2 text-sm text-gray-500 hover:text-gray-700 py-2 rounded-xl hover:bg-gray-50 transition-colors disabled:opacity-50"
                  >
                    {loadingMore ? (
                      <div className="w-4 h-4 border-2 border-gray-300 border-t-transparent rounded-full animate-spin" />
                    ) : (
                      <>
                        <ChevronDown className="w-4 h-4" />
                        Load more
                      </>
                    )}
                  </button>
                </div>
              )}
            </>
          )}
        </div>

        {/* Footer note */}
        <p className="text-[11px] text-gray-300 text-center">
          Notifications are workspace-scoped · auto-generated after each scan
        </p>
      </div>
    </div>
  )
}
