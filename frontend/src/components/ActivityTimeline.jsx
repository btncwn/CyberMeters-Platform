import { useState, useEffect, useCallback } from 'react'
import {
  Activity, LogIn, LogOut, Globe, ShieldCheck, Users, UserMinus,
  ScanLine, FileText, Bell, RefreshCw, ChevronDown, Mail, Lock,
  ClipboardCheck, MonitorCheck, KeyRound, Boxes, ShieldAlert,
} from 'lucide-react'
import { api } from '../api'

// ── Event type config ────────────────────────────────────────────────────────

const EVENT_CONFIG = {
  login:                    { icon: LogIn,       color: 'text-brand-600',  bg: 'bg-brand-50'  },
  logout:                   { icon: LogOut,      color: 'text-gray-500',   bg: 'bg-gray-100'  },
  workspace_created:        { icon: Activity,    color: 'text-brand-600',  bg: 'bg-brand-50'  },
  workspace_member_added:   { icon: Users,       color: 'text-brand-600',  bg: 'bg-brand-50'  },
  workspace_member_removed: { icon: UserMinus,   color: 'text-red-500',    bg: 'bg-red-50'    },
  domain_added:             { icon: Globe,       color: 'text-brand-600',  bg: 'bg-brand-50'  },
  domain_imported:          { icon: Globe,       color: 'text-brand-600',  bg: 'bg-brand-50'  },
  domain_verified:          { icon: ShieldCheck, color: 'text-green-600',  bg: 'bg-green-50'  },
  report_generated:         { icon: FileText,    color: 'text-purple-600', bg: 'bg-purple-50' },
  scan_started:             { icon: ScanLine,    color: 'text-amber-500',  bg: 'bg-amber-50'  },
  scan_completed:           { icon: ScanLine,    color: 'text-brand-600',  bg: 'bg-brand-50'  },
  notification_read:        { icon: Bell,        color: 'text-gray-500',   bg: 'bg-gray-100'  },
  email_protection_alert:   { icon: Mail,        color: 'text-blue-600',   bg: 'bg-blue-50'   },
  brand_protection_alert:   { icon: ShieldAlert, color: 'text-red-600',    bg: 'bg-red-50'    },
  attack_surface_alert:     { icon: Globe,       color: 'text-teal-600',   bg: 'bg-teal-50'   },
  certificates_trust_alert: { icon: Lock,        color: 'text-sky-600',    bg: 'bg-sky-50'    },
  cyber_essentials_alert:   { icon: ClipboardCheck, color: 'text-emerald-600', bg: 'bg-emerald-50' },
  website_security_alert:   { icon: MonitorCheck, color: 'text-amber-600', bg: 'bg-amber-50'  },
  identity_exposure_alert:  { icon: KeyRound,    color: 'text-indigo-600', bg: 'bg-indigo-50' },
  shadow_it_alert:          { icon: Boxes,       color: 'text-purple-600', bg: 'bg-purple-50' },
}

function eventConfig(type) {
  return EVENT_CONFIG[type] ?? { icon: Activity, color: 'text-gray-400', bg: 'bg-gray-100' }
}

function fmtTime(str) {
  if (!str) return '—'
  const s = str.includes('T') ? str : str.replace(' ', 'T') + 'Z'
  const d = new Date(s)
  const now = new Date()
  const diffMs = now - d
  const diffMin = Math.floor(diffMs / 60000)
  if (diffMin < 1)  return 'just now'
  if (diffMin < 60) return `${diffMin}m ago`
  const diffH = Math.floor(diffMin / 60)
  if (diffH < 24)   return `${diffH}h ago`
  const diffD = Math.floor(diffH / 24)
  if (diffD < 7)    return `${diffD}d ago`
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

function fmtFull(str) {
  if (!str) return '—'
  const s = str.includes('T') ? str : str.replace(' ', 'T') + 'Z'
  return new Date(s).toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

function EventIcon({ type }) {
  const { icon: Icon, color, bg } = eventConfig(type)
  return (
    <div className={`w-7 h-7 rounded-full ${bg} flex items-center justify-center flex-shrink-0`}>
      <Icon className={`w-3.5 h-3.5 ${color}`} />
    </div>
  )
}

function EventRow({ event }) {
  const actor = event.actor?.name || event.actor?.email || null
  return (
    <div className="flex items-start gap-3 py-2.5 border-b border-gray-50 last:border-0">
      <EventIcon type={event.event_type} />
      <div className="flex-1 min-w-0">
        <p className="text-sm text-gray-700 leading-snug">
          {actor && <span className="font-medium text-gray-900">{actor} </span>}
          {event.description || event.event_type.replace(/_/g, ' ')}
        </p>
        {event.entity_id && (
          <p className="text-xs text-gray-400 font-mono mt-0.5 truncate">{event.entity_id}</p>
        )}
      </div>
      <time
        className="text-xs text-gray-400 flex-shrink-0 mt-0.5"
        title={fmtFull(event.created_at)}
      >
        {fmtTime(event.created_at)}
      </time>
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

const PAGE_SIZE = 25

export default function ActivityTimeline({ workspaceId }) {
  const [events,   setEvents]   = useState([])
  const [loading,  setLoading]  = useState(false)
  const [error,    setError]    = useState(null)
  const [offset,   setOffset]   = useState(0)
  const [hasMore,  setHasMore]  = useState(false)
  const [filter,   setFilter]   = useState('')

  const load = useCallback(async (reset = false) => {
    if (!workspaceId) return
    setLoading(true)
    setError(null)
    const currentOffset = reset ? 0 : offset
    try {
      const params = { limit: PAGE_SIZE, offset: currentOffset }
      if (filter) params.event_type = filter
      const data = await api.getWorkspaceActivity(workspaceId, params)
      const incoming = data.events || []
      setEvents(prev => reset ? incoming : [...prev, ...incoming])
      setOffset(currentOffset + incoming.length)
      setHasMore(incoming.length === PAGE_SIZE)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [workspaceId, offset, filter])

  // Reset + reload when filter changes
  useEffect(() => {
    setOffset(0)
    setEvents([])
    if (workspaceId) {
      setLoading(true)
      setError(null)
      const params = { limit: PAGE_SIZE, offset: 0 }
      if (filter) params.event_type = filter
      api.getWorkspaceActivity(workspaceId, params)
        .then(data => {
          const incoming = data.events || []
          setEvents(incoming)
          setOffset(incoming.length)
          setHasMore(incoming.length === PAGE_SIZE)
        })
        .catch(e => setError(e.message))
        .finally(() => setLoading(false))
    }
  }, [workspaceId, filter])

  const EVENT_TYPES = [
    { value: '', label: 'All activity' },
    { value: 'scan_started',             label: 'Scans started' },
    { value: 'scan_completed',           label: 'Scans completed' },
    { value: 'domain_added',             label: 'Domains added' },
    { value: 'domain_imported',          label: 'Domains imported' },
    { value: 'domain_verified',          label: 'Domains verified' },
    { value: 'report_generated',         label: 'Reports generated' },
    { value: 'workspace_member_added',   label: 'Members added' },
    { value: 'workspace_member_removed', label: 'Members removed' },
    { value: 'login',                    label: 'Logins' },
    { value: 'logout',                   label: 'Logouts' },
    { value: 'notification_read',        label: 'Notifications read' },
    { value: 'email_protection_alert',   label: 'Email Protection alerts' },
    { value: 'brand_protection_alert',   label: 'Brand Protection alerts' },
    { value: 'attack_surface_alert',     label: 'Attack Surface alerts' },
    { value: 'certificates_trust_alert', label: 'Certificate alerts' },
    { value: 'cyber_essentials_alert',   label: 'Cyber Essentials alerts' },
    { value: 'website_security_alert',   label: 'Website Security alerts' },
    { value: 'identity_exposure_alert',  label: 'Identity Exposure alerts' },
    { value: 'shadow_it_alert',          label: 'Shadow IT alerts' },
  ]

  return (
    <div className="card p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-gray-400" />
          <h2 className="text-sm font-semibold text-gray-900">Activity</h2>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={filter}
            onChange={e => setFilter(e.target.value)}
            className="text-xs border border-gray-200 rounded-lg px-2 py-1 text-gray-600 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            {EVENT_TYPES.map(t => (
              <option key={t.value} value={t.value}>{t.label}</option>
            ))}
          </select>
          <button
            onClick={() => load(true)}
            disabled={loading}
            className="p-1 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-colors disabled:opacity-40"
            title="Refresh"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Content */}
      {error && (
        <p className="text-xs text-red-500 py-2">{error}</p>
      )}

      {!loading && !error && events.length === 0 && (
        <div className="py-8 text-center">
          <Activity className="w-8 h-8 text-gray-200 mx-auto mb-2" />
          <p className="text-sm text-gray-400">No activity yet</p>
        </div>
      )}

      {events.length > 0 && (
        <div>
          {events.map(e => <EventRow key={e.id} event={e} />)}
        </div>
      )}

      {/* Load more */}
      {hasMore && (
        <button
          onClick={() => load(false)}
          disabled={loading}
          className="mt-3 w-full flex items-center justify-center gap-1.5 py-2 text-xs text-gray-500 hover:text-gray-700 hover:bg-gray-50 rounded-lg transition-colors disabled:opacity-40"
        >
          {loading
            ? <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            : <><ChevronDown className="w-3.5 h-3.5" /> Load more</>
          }
        </button>
      )}

      {loading && events.length === 0 && (
        <div className="py-8 text-center">
          <RefreshCw className="w-5 h-5 text-gray-300 mx-auto animate-spin" />
        </div>
      )}
    </div>
  )
}
