import { useState, useEffect, useCallback } from 'react'
import {
  Globe, Network, Mail, Lock, AlertTriangle, Activity,
  RefreshCw, ChevronDown, Clock, ShieldAlert, ClipboardCheck,
  MonitorCheck, KeyRound, Boxes,
} from 'lucide-react'
import { api } from '../api'

// ─────────────────────────────────────────────────────────────────────────────
// Exposure Timeline feed — the chronological "what changed" stream that turns a
// one-time scan into a subscription product. Consumes GET /exposure/feed, whose
// events are already enriched server-side with `category`, `title`, and a
// customer-safe `description` (before → after). The UI only maps category → icon
// and severity → badge; it never re-derives labels.
// ─────────────────────────────────────────────────────────────────────────────

const CATEGORY_CONFIG = {
  asset:       { icon: Globe,         color: 'text-teal-600',  bg: 'bg-teal-50'  },
  dns:         { icon: Network,       color: 'text-teal-600',  bg: 'bg-teal-50'  },
  email:       { icon: Mail,          color: 'text-blue-600',  bg: 'bg-blue-50'  },
  certificate: { icon: Lock,          color: 'text-sky-600',   bg: 'bg-sky-50'   },
  exposure:    { icon: AlertTriangle, color: 'text-amber-600', bg: 'bg-amber-50' },
  email_protection:               { icon: Mail,           color: 'text-blue-600',    bg: 'bg-blue-50' },
  brand_protection:               { icon: ShieldAlert,    color: 'text-red-600',     bg: 'bg-red-50' },
  attack_surface:                 { icon: Globe,          color: 'text-teal-600',    bg: 'bg-teal-50' },
  certificates_trust:             { icon: Lock,           color: 'text-sky-600',     bg: 'bg-sky-50' },
  cyber_essentials_readiness:     { icon: ClipboardCheck, color: 'text-emerald-600', bg: 'bg-emerald-50' },
  website_security:               { icon: MonitorCheck,   color: 'text-amber-600',   bg: 'bg-amber-50' },
  identity_exposure:              { icon: KeyRound,       color: 'text-indigo-600',  bg: 'bg-indigo-50' },
  shadow_it_unmanaged_technology: { icon: Boxes,          color: 'text-purple-600',  bg: 'bg-purple-50' },
}
function categoryConfig(cat) {
  return CATEGORY_CONFIG[cat] ?? { icon: Activity, color: 'text-gray-400', bg: 'bg-gray-100' }
}

const SEVERITY_STYLE = {
  info:     'bg-gray-100 text-gray-500',
  low:      'bg-blue-50 text-blue-600',
  medium:   'bg-amber-50 text-amber-700',
  high:     'bg-red-50 text-red-600',
  critical: 'bg-red-100 text-red-700',
}

const CATEGORY_FILTERS = [
  { value: '',            label: 'All changes' },
  { value: 'asset',       label: 'Assets' },
  { value: 'dns',         label: 'DNS' },
  { value: 'email',       label: 'Email' },
  { value: 'certificate', label: 'Certificates' },
  { value: 'exposure',    label: 'Exposure' },
  { value: 'email_protection',               label: 'Email Protection' },
  { value: 'brand_protection',               label: 'Brand Protection' },
  { value: 'attack_surface',                 label: 'Attack Surface' },
  { value: 'certificates_trust',             label: 'Certificates & Trust' },
  { value: 'cyber_essentials_readiness',     label: 'Cyber Essentials' },
  { value: 'website_security',               label: 'Website Security' },
  { value: 'identity_exposure',              label: 'Identity Exposure' },
  { value: 'shadow_it_unmanaged_technology', label: 'Shadow IT' },
]

const SEVERITY_FILTERS = [
  { value: '',       label: 'Any severity' },
  { value: 'low',    label: 'Low & up' },
  { value: 'medium', label: 'Medium & up' },
  { value: 'high',   label: 'High & up' },
]

const PAGE_SIZE = 50

function toDate(str) {
  if (!str) return null
  const s = str.includes('T') ? str : str.replace(' ', 'T') + 'Z'
  const d = new Date(s)
  return Number.isNaN(d.getTime()) ? null : d
}
function dayKey(str) {
  const d = toDate(str)
  return d ? d.toISOString().slice(0, 10) : 'unknown'
}
function dayLabel(str) {
  const d = toDate(str)
  if (!d) return 'Unknown date'
  const today = new Date().toISOString().slice(0, 10)
  const key = d.toISOString().slice(0, 10)
  if (key === today) return 'Today'
  return d.toLocaleDateString(undefined, { weekday: 'short', month: 'long', day: 'numeric', year: 'numeric' })
}
function fmtTime(str) {
  const d = toDate(str)
  return d ? d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }) : ''
}

// Group a reverse-chron list into [{ key, label, events }] preserving order.
function groupByDay(events) {
  const groups = []
  const index = new Map()
  for (const e of events) {
    const key = dayKey(e.created_at)
    if (!index.has(key)) {
      const g = { key, label: dayLabel(e.created_at), events: [] }
      index.set(key, g)
      groups.push(g)
    }
    index.get(key).events.push(e)
  }
  return groups
}

function EventRow({ event }) {
  const { icon: Icon, color, bg } = categoryConfig(event.category)
  const sev = SEVERITY_STYLE[event.severity] ?? SEVERITY_STYLE.info
  return (
    <div className="flex items-start gap-3 py-3 border-b border-gray-50 last:border-0">
      <div className={`w-8 h-8 rounded-full ${bg} flex items-center justify-center flex-shrink-0`}>
        <Icon className={`w-4 h-4 ${color}`} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <p className="text-sm font-semibold text-gray-900 leading-snug">{event.title}</p>
          <span className={`text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded ${sev}`}>
            {event.severity}
          </span>
        </div>
        {event.description && (
          <p className="text-sm text-gray-600 leading-snug mt-0.5">{event.description}</p>
        )}
        {event.hostname && (
          <p className="text-xs text-gray-400 font-mono mt-1 truncate">{event.hostname}</p>
        )}
      </div>
      <time className="text-xs text-gray-400 flex-shrink-0 mt-0.5">{fmtTime(event.created_at)}</time>
    </div>
  )
}

export default function ExposureTimeline({ workspaceId }) {
  const [events,   setEvents]   = useState([])
  const [total,    setTotal]    = useState(null)
  const [loading,  setLoading]  = useState(false)
  const [error,    setError]    = useState(null)
  const [offset,   setOffset]   = useState(0)
  const [hasMore,  setHasMore]  = useState(false)
  const [category, setCategory] = useState('')
  const [severity, setSeverity] = useState('')

  const fetchPage = useCallback(async (currentOffset, append) => {
    if (!workspaceId) return
    setLoading(true)
    setError(null)
    try {
      const params = { limit: PAGE_SIZE, offset: currentOffset }
      if (category) params.category = category
      if (severity) params.severity = severity
      const data = await api.getExposureFeed(workspaceId, params)
      const incoming = data.events || []
      setEvents(prev => append ? [...prev, ...incoming] : incoming)
      setOffset(currentOffset + incoming.length)
      setTotal(data.pagination?.total ?? null)
      setHasMore(Boolean(data.pagination?.has_more))
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [workspaceId, category, severity])

  // Reset + reload whenever the workspace or a filter changes.
  useEffect(() => {
    setEvents([]); setOffset(0)
    fetchPage(0, false)
  }, [fetchPage])

  const groups = groupByDay(events)

  return (
    <div className="card p-6">
      {/* Header + filters */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4 text-brand-600" />
          <h2 className="text-sm font-semibold text-gray-900">
            Changes{total != null ? ` · ${total}` : ''}
          </h2>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={severity}
            onChange={e => setSeverity(e.target.value)}
            className="text-xs border border-gray-200 rounded-lg px-2 py-1 text-gray-600 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            {SEVERITY_FILTERS.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
          </select>
          <button
            onClick={() => fetchPage(0, false)}
            disabled={loading}
            className="p-1 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-colors disabled:opacity-40"
            title="Refresh"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Category chips */}
      <div className="flex flex-wrap gap-1.5 mb-4">
        {CATEGORY_FILTERS.map(c => (
          <button
            key={c.value}
            onClick={() => setCategory(c.value)}
            className={`text-xs font-medium px-3 py-1 rounded-full border transition-colors ${
              category === c.value
                ? 'bg-brand-600 text-white border-brand-600'
                : 'bg-white text-gray-600 border-gray-200 hover:border-brand-300'
            }`}
          >
            {c.label}
          </button>
        ))}
      </div>

      {error && <p className="text-xs text-red-500 py-2">{error}</p>}

      {/* First-run / empty state — explains the subscription value, doesn't scold */}
      {!loading && !error && events.length === 0 && (
        <div className="py-10 text-center">
          <Clock className="w-8 h-8 text-gray-200 mx-auto mb-3" />
          <p className="text-sm font-medium text-gray-500">No changes recorded yet</p>
          <p className="text-xs text-gray-400 mt-1 max-w-xs mx-auto leading-relaxed">
            Your exposure timeline builds as we re-scan your domains — check back after the next scan
            to see what changed on your internet-facing footprint.
          </p>
        </div>
      )}

      {/* Day-grouped feed */}
      {groups.map(g => (
        <div key={g.key} className="mb-2">
          <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mt-4 mb-1">{g.label}</p>
          {g.events.map(e => <EventRow key={e.id} event={e} />)}
        </div>
      ))}

      {hasMore && (
        <button
          onClick={() => fetchPage(offset, true)}
          disabled={loading}
          className="mt-3 w-full flex items-center justify-center gap-1.5 py-2 text-xs text-gray-500 hover:text-gray-700 hover:bg-gray-50 rounded-lg transition-colors disabled:opacity-40"
        >
          {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <><ChevronDown className="w-3.5 h-3.5" /> Load more</>}
        </button>
      )}

      {loading && events.length === 0 && (
        <div className="py-10 text-center"><RefreshCw className="w-5 h-5 text-gray-300 mx-auto animate-spin" /></div>
      )}
    </div>
  )
}
