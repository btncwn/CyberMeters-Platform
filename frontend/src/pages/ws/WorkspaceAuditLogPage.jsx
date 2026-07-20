import { parseServerDate } from '../../utils/dates'
import { useState, useEffect, useCallback } from 'react'
import { useWorkspace } from '../../hooks/useWorkspace'
import {
  ClipboardList, Search, Filter, Download, ChevronLeft,
  ChevronRight, AlertTriangle, RefreshCw, User, Tag, Calendar,
} from 'lucide-react'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'
import { api } from '../../api'

const PAGE_SIZE = 50

const EVENT_TYPE_OPTIONS = [
  { value: '', label: 'All event types' },
  { value: 'login',                label: 'Login' },
  { value: 'logout',               label: 'Logout' },
  { value: 'login_failed',         label: 'Login failed' },
  { value: 'scan_started',         label: 'Scan started' },
  { value: 'scan_completed',       label: 'Scan completed' },
  { value: 'domain_added',         label: 'Domain added' },
  { value: 'domain_verified',      label: 'Domain verified' },
  { value: 'domain_removed',       label: 'Domain removed' },
  { value: 'report_generated',     label: 'Report generated' },
  { value: 'workspace_created',    label: 'Workspace created' },
  { value: 'workspace_member_added',   label: 'Member added' },
  { value: 'workspace_member_removed', label: 'Member removed' },
  { value: 'mfa_enabled',          label: 'MFA enabled' },
  { value: 'mfa_disabled',         label: 'MFA disabled' },
  { value: 'mfa_challenge_success', label: 'MFA verified' },
  { value: 'mfa_challenge_failed',  label: 'MFA failed' },
  { value: 'recovery_code_used',   label: 'Recovery code used' },
  { value: 'audit_log_viewed',     label: 'Audit log viewed' },
  { value: 'audit_log_exported',   label: 'Audit log exported' },
]

const ENTITY_TYPE_OPTIONS = [
  { value: '',          label: 'All entity types' },
  { value: 'user',      label: 'User' },
  { value: 'domain',    label: 'Domain' },
  { value: 'scan',      label: 'Scan' },
  { value: 'report',    label: 'Report' },
  { value: 'workspace', label: 'Workspace' },
  { value: 'member',    label: 'Member' },
]

function formatTime(ts) {
  if (!ts) return '—'
  const d = parseServerDate(ts)
  return d.toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

function MetaSummary({ metadata }) {
  if (!metadata || typeof metadata !== 'object') return <span className="text-gray-400">—</span>
  const entries = Object.entries(metadata)
    .filter(([, v]) => v !== null && v !== undefined && v !== '[redacted]')
    .slice(0, 3)
  if (!entries.length) return <span className="text-gray-400">—</span>
  return (
    <span className="font-mono text-xs text-gray-500 truncate max-w-[200px] inline-block">
      {entries.map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`).join(' · ')}
    </span>
  )
}

export default function WorkspaceAuditLogPage() {
  // Workspace comes from the canonical context hook, not a route param — the
  // /ws/* routes declare no :workspaceId, so useParams().workspaceId was always
  // undefined here and every API call went to /workspaces/undefined/... (403).
  // Same defect class as the four lifecycle pages fixed in PR #197.
  const { wsId, loading: wsLoading } = useWorkspace()

  // Filters
  const [search,      setSearch]      = useState('')
  const [eventType,   setEventType]   = useState('')
  const [entityType,  setEntityType]  = useState('')
  const [dateFrom,    setDateFrom]    = useState('')
  const [dateTo,      setDateTo]      = useState('')
  const [searchInput, setSearchInput] = useState('')

  // Data
  const [events,   setEvents]   = useState([])
  const [total,    setTotal]    = useState(0)
  const [offset,   setOffset]   = useState(0)
  const [loading,  setLoading]  = useState(false)
  const [error,    setError]    = useState(null)

  // Export state
  const [exporting, setExporting] = useState(null) // 'csv' | 'json' | null

  const activeFilters = { event_type: eventType, entity_type: entityType,
                          date_from: dateFrom, date_to: dateTo, search,
                          limit: PAGE_SIZE, offset }

  const load = useCallback(async (off = 0) => {
    if (!wsId) return
    setLoading(true)
    setError(null)
    try {
      const data = await api.getWorkspaceAuditEvents(wsId, {
        ...activeFilters, offset: off,
      })
      setEvents(data.events || [])
      setTotal(data.pagination?.total ?? 0)
      setOffset(off)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [wsId, eventType, entityType, dateFrom, dateTo, search])

  useEffect(() => { load(0) }, [load])

  function applySearch(e) {
    e.preventDefault()
    setSearch(searchInput.trim())
  }

  function resetFilters() {
    setSearch(''); setSearchInput(''); setEventType(''); setEntityType('')
    setDateFrom(''); setDateTo('')
  }

  async function doExport(format) {
    setExporting(format)
    try {
      const blob = await api.exportWorkspaceAuditEvents(wsId, {
        event_type: eventType, entity_type: entityType,
        date_from: dateFrom, date_to: dateTo, search,
      }, format)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `audit-log-${wsId}.${format}`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      setError(e.message)
    } finally {
      setExporting(null)
    }
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1

  if (!wsLoading && !wsId) return <NoWorkspaceSelected />

  return (
    <WsPage title="Audit Log">
      <div className="space-y-5">

        {/* Header */}
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold text-gray-900 flex items-center gap-2">
              <ClipboardList className="w-5 h-5 text-brand-600" />
              Audit Log
            </h1>
            <p className="text-sm text-gray-500 mt-0.5">
              Review security and administrative activity for this workspace.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => doExport('csv')}
              disabled={!!exporting}
              className="btn-secondary flex items-center gap-1.5 text-sm"
            >
              <Download className="w-4 h-4" />
              {exporting === 'csv' ? 'Exporting…' : 'Export CSV'}
            </button>
            <button
              onClick={() => doExport('json')}
              disabled={!!exporting}
              className="btn-secondary flex items-center gap-1.5 text-sm"
            >
              <Download className="w-4 h-4" />
              {exporting === 'json' ? 'Exporting…' : 'Export JSON'}
            </button>
            <button
              onClick={() => load(offset)}
              disabled={loading}
              className="btn-secondary p-2"
              title="Refresh"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {/* Filters */}
        <div className="card p-4 space-y-3">
          <div className="flex items-center gap-2 text-xs font-semibold text-gray-500 uppercase tracking-wider">
            <Filter className="w-3.5 h-3.5" />
            Filters
          </div>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <div>
              <label className="block text-xs text-gray-500 mb-1">Event type</label>
              <select
                value={eventType}
                onChange={e => setEventType(e.target.value)}
                className="input text-sm"
              >
                {EVENT_TYPE_OPTIONS.map(o => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-gray-500 mb-1">Entity type</label>
              <select
                value={entityType}
                onChange={e => setEntityType(e.target.value)}
                className="input text-sm"
              >
                {ENTITY_TYPE_OPTIONS.map(o => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-gray-500 mb-1">
                <Calendar className="w-3 h-3 inline mr-1" />From
              </label>
              <input
                type="date"
                value={dateFrom}
                onChange={e => setDateFrom(e.target.value)}
                className="input text-sm"
              />
            </div>
            <div>
              <label className="block text-xs text-gray-500 mb-1">
                <Calendar className="w-3 h-3 inline mr-1" />To
              </label>
              <input
                type="date"
                value={dateTo}
                onChange={e => setDateTo(e.target.value)}
                className="input text-sm"
              />
            </div>
          </div>
          <form onSubmit={applySearch} className="flex items-center gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
              <input
                type="text"
                className="input pl-9 text-sm"
                placeholder="Search event type, entity, description…"
                value={searchInput}
                onChange={e => setSearchInput(e.target.value)}
              />
            </div>
            <button type="submit" className="btn-primary text-sm px-4">Search</button>
            {(search || eventType || entityType || dateFrom || dateTo) && (
              <button type="button" onClick={resetFilters} className="btn-secondary text-sm">
                Clear
              </button>
            )}
          </form>
        </div>

        {/* Error */}
        {error && (
          <div className="flex items-center gap-2.5 px-4 py-3 bg-red-50 border border-red-100 rounded-xl text-sm text-red-600">
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
            {error}
          </div>
        )}

        {/* Table */}
        <div className="card overflow-hidden">
          {/* Results info */}
          <div className="px-4 py-3 border-b border-gray-100 flex items-center justify-between">
            <span className="text-xs text-gray-500">
              {loading ? 'Loading…' : `${total.toLocaleString()} event${total !== 1 ? 's' : ''}`}
            </span>
            {total > 0 && (
              <span className="text-xs text-gray-400">
                Page {currentPage} of {totalPages}
              </span>
            )}
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-100">
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider w-44">Time</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Event</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider w-40">
                    <span className="flex items-center gap-1"><User className="w-3 h-3" />Actor</span>
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider w-36">
                    <span className="flex items-center gap-1"><Tag className="w-3 h-3" />Entity</span>
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {loading && events.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-4 py-12 text-center text-sm text-gray-400">
                      Loading…
                    </td>
                  </tr>
                )}
                {!loading && events.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-4 py-12 text-center text-sm text-gray-400">
                      No audit events found.
                    </td>
                  </tr>
                )}
                {events.map(ev => (
                  <tr key={ev.id} className="hover:bg-gray-50 transition-colors">
                    <td className="px-4 py-3 text-xs text-gray-500 whitespace-nowrap font-mono">
                      {formatTime(ev.created_at)}
                    </td>
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center px-2 py-0.5 rounded-md bg-gray-100 text-gray-700 text-xs font-mono font-medium">
                        {ev.event_type}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-600 truncate max-w-[160px]">
                      {ev.actor_email || ev.actor_user_id || (
                        <span className="text-gray-400 italic">system</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-500">
                      {ev.entity_type ? (
                        <span>
                          <span className="font-medium">{ev.entity_type}</span>
                          {ev.entity_id && (
                            <span className="ml-1 font-mono text-gray-400 truncate max-w-[80px] inline-block align-bottom">
                              {ev.entity_id.slice(0, 12)}
                            </span>
                          )}
                        </span>
                      ) : <span className="text-gray-300">—</span>}
                    </td>
                    <td className="px-4 py-3">
                      {ev.description
                        ? <span className="text-xs text-gray-600">{ev.description}</span>
                        : <MetaSummary metadata={ev.metadata} />
                      }
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {total > PAGE_SIZE && (
            <div className="px-4 py-3 border-t border-gray-100 flex items-center justify-between">
              <button
                onClick={() => load(Math.max(0, offset - PAGE_SIZE))}
                disabled={offset === 0 || loading}
                className="btn-secondary flex items-center gap-1 text-sm disabled:opacity-40"
              >
                <ChevronLeft className="w-4 h-4" />
                Previous
              </button>
              <span className="text-xs text-gray-500">
                Showing {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total.toLocaleString()}
              </span>
              <button
                onClick={() => load(offset + PAGE_SIZE)}
                disabled={offset + PAGE_SIZE >= total || loading}
                className="btn-secondary flex items-center gap-1 text-sm disabled:opacity-40"
              >
                Next
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>
      </div>
    </WsPage>
  )
}
