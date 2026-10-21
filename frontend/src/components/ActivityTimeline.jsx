import { useState, useEffect, useCallback } from 'react'
import { RefreshCw } from 'lucide-react'
import { api } from '../api'
import { formatDate, formatDay, parseServerDate } from '../utils/dates'
import InternalIdCopyButton from './InternalIdCopyButton'

const GROUPED_ALERT_LABELS = {
  cyber_essentials_readiness: 'Cyber Essentials alerts',
  shadow_it_unmanaged_technology: 'Shadow IT alerts',
}

function fmtTime(str) {
  if (!str) return '—'
  const d = parseServerDate(str)
  const now = new Date()
  const diffMs = now - d
  const diffMin = Math.floor(diffMs / 60000)
  if (diffMin < 1)  return 'just now'
  if (diffMin < 60) return `${diffMin}m ago`
  const diffH = Math.floor(diffMin / 60)
  if (diffH < 24)   return `${diffH}h ago`
  const diffD = Math.floor(diffH / 24)
  if (diffD < 7)    return `${diffD}d ago`
  return formatDay(str)
}

function fmtFull(str) {
  if (!str) return '—'
  return formatDate(str)
}

function EventRow({ event }) {
  const actor = event.actor?.name || event.actor?.email || null
  return (
    <div className="flex items-start gap-3 py-2.5 border-b border-gray-50 last:border-0">
      <div className="flex-1 min-w-0">
        <p className="text-sm text-gray-700 leading-snug">
          {actor && <span className="font-medium text-gray-900">{actor} </span>}
          {event.description || event.event_type.replace(/_/g, ' ')}
        </p>
        {event.entity_id && <InternalIdCopyButton id={event.entity_id} label="activity reference" />}
      </div>
      <time
        className="text-xs text-gray-400 shrink-0 mt-0.5"
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
    { value: 'cyber_essentials_alerts',  label: GROUPED_ALERT_LABELS.cyber_essentials_readiness },
    { value: 'website_security_alert',   label: 'Website Security alerts' },
    { value: 'identity_exposure_alert',  label: 'Identity Exposure alerts' },
    { value: 'shadow_it_alerts',         label: GROUPED_ALERT_LABELS.shadow_it_unmanaged_technology },
  ]

  return (
    <div className="card p-6">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 mb-4">
        <h2 className="text-sm font-semibold text-gray-900">Activity</h2>
        {/* The filter's widest option must never push the page past a phone's edge. */}
        <div className="flex items-center gap-2 min-w-0">
          <select
            value={filter}
            onChange={e => setFilter(e.target.value)}
            className="min-w-0 max-w-full text-xs border border-gray-200 rounded-lg px-2 py-1 text-gray-600 bg-white focus:outline-hidden focus:ring-2 focus:ring-brand-500"
          >
            {EVENT_TYPES.map(t => (
              <option key={t.value} value={t.value}>{t.label}</option>
            ))}
          </select>
          <button
            onClick={() => load(true)}
            disabled={loading}
            className="inline-flex items-center gap-1 px-2 py-1 rounded-lg text-xs font-medium text-gray-500 hover:text-gray-700 hover:bg-gray-100 transition-colors disabled:opacity-40"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
            <span>Reload</span>
          </button>
        </div>
      </div>

      {/* Content */}
      {error && (
        <p className="text-xs text-red-700 py-2">{error}</p>
      )}

      {!loading && !error && events.length === 0 && (
        <div className="py-8 text-center">
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
            : 'Load more'
          }
        </button>
      )}

      {loading && events.length === 0 && (
        <div className="py-8 text-center">
          <RefreshCw className="w-5 h-5 text-gray-600 mx-auto animate-spin" />
        </div>
      )}
    </div>
  )
}
