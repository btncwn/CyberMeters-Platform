// Website Security — the read surface migration 089 never had.
//
// The engine has recorded a durable row per (domain, condition) on every scan since it
// shipped, and alerted on them. Nothing could read them: no route, no page, no api.js
// method, and both engine read helpers had zero callers. Customers were told a condition
// began with no way to see what it was or whether it ever cleared.
//
// This is a focused read surface, not a nav or dashboard redesign. Every state, severity
// and scope note is server-owned — the page maps them to labels and never decides whether
// something is fixed. The honesty rule it enforces visually: `no longer seen` and `not
// determined` are different facts, and only the first is good news.
import { useCallback, useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api } from '../../api'
import { useWorkspace } from '../../hooks/useWorkspace'
import { NoWorkspaceSelected } from '../../components/WsPage'
import {
  monitoringMeta, severityMeta, scanQualityMeta, unknownReasonText,
  toneClass, isSettled, conditionLabel,
} from '../../lib/websiteSecurityDisplay'

function Pill({ meta, title }) {
  if (!meta) return null
  return (
    <span title={title || meta.hint || undefined}
          className={`inline-block rounded-full border px-2 py-0.5 text-xs ${toneClass(meta.tone)}`}>
      {meta.label}
    </span>
  )
}

const STATUS_FILTERS = [
  { value: '', label: 'All states' },
  { value: 'observed', label: 'Observed' },
  { value: 'unknown', label: 'Not determined' },
  { value: 'no_longer_observed', label: 'No longer seen' },
  { value: 'baseline', label: 'Pre-existing' },
]

function ConditionRow({ item, expanded, onToggle, detail, detailError }) {
  const mon = monitoringMeta(item.monitoring_status)
  const sev = severityMeta(item.severity)
  const quality = scanQualityMeta(item.last_scan_quality)
  const reason = unknownReasonText(item.unknown_reason)
  const settled = isSettled(item)

  return (
    // `id` is the alert deep-link anchor: an alert links to
    // /ws/website-security?condition=<id>#<id> and the row scrolls into view.
    <div id={item.id} className="border-b border-gray-100 last:border-0">
      <button type="button" onClick={onToggle}
              aria-expanded={expanded}
              className="flex w-full flex-col gap-2 px-4 py-3 text-left hover:bg-gray-50 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="truncate font-medium text-gray-800">{conditionLabel(item)}</span>
            <Pill meta={sev} />
            <Pill meta={mon} />
            {/* Evidence completeness rides alongside the state, always — a condition
                graded on a partial scan is not settled, however it reads. */}
            {item.last_scan_quality !== 'complete' && <Pill meta={quality} />}
          </div>
          <p className="mt-0.5 truncate text-xs text-gray-500">{item.domain}</p>
        </div>
        <div className="shrink-0 text-xs text-gray-500">
          {settled
            ? <span>Cleared · last seen {item.last_seen_at?.slice(0, 10) || '—'}</span>
            : <span>First seen {item.first_seen_at?.slice(0, 10) || '—'}</span>}
        </div>
      </button>

      {expanded && (
        <div className="bg-gray-50 px-4 py-3 text-sm">
          {/* The reason we could not tell is the most important thing on this row when it
              applies, so it is stated in words rather than left as a slug. */}
          {item.monitoring_status === 'unknown' && (
            <p className="mb-3 rounded border border-gray-200 bg-white px-3 py-2 text-xs text-gray-600">
              <strong className="text-gray-700">Not determined.</strong>{' '}
              {reason || 'CyberMeters could not confirm this condition on the latest scan.'}{' '}
              This is not a fix — it means the evidence is missing, not that the issue is gone.
            </p>
          )}
          <dl className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-2">
            <div><dt className="text-xs text-gray-500">Condition</dt><dd className="font-mono text-xs text-gray-700">{item.condition_key}</dd></div>
            <div><dt className="text-xs text-gray-500">Detected by</dt><dd className="text-xs text-gray-700">{item.detecting_module || '—'}</dd></div>
            <div><dt className="text-xs text-gray-500">Evidence</dt><dd className="text-xs text-gray-700">{scanQualityMeta(item.last_scan_quality).label}</dd></div>
            <div><dt className="text-xs text-gray-500">Evidence source</dt><dd className="text-xs text-gray-700">Scan {item.last_scan_id || '—'}</dd></div>
            <div><dt className="text-xs text-gray-500">First seen</dt><dd className="text-xs text-gray-700">{item.first_seen_at?.slice(0, 16).replace('T', ' ') || '—'}</dd></div>
            <div><dt className="text-xs text-gray-500">Last seen</dt><dd className="text-xs text-gray-700">{item.last_seen_at?.slice(0, 16).replace('T', ' ') || '—'}</dd></div>
          </dl>

          <div className="mt-3">
            <p className="mb-1 text-xs font-medium text-gray-600">History</p>
            {detailError && <p className="text-xs text-red-600">{detailError}</p>}
            {!detail && !detailError && <p className="text-xs text-gray-400">Loading history…</p>}
            {detail && detail.events?.length === 0 && <p className="text-xs text-gray-400">No recorded changes yet.</p>}
            {detail && detail.events?.length > 0 && (
              <ul className="space-y-1">
                {detail.events.map((e) => (
                  <li key={e.id} className="flex gap-2 text-xs text-gray-600">
                    <span className="shrink-0 font-mono text-gray-400">{e.created_at?.slice(0, 16).replace('T', ' ')}</span>
                    <span>{String(e.event_type).replace(/_/g, ' ')}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

export default function WebsiteSecurityPage() {
  // Workspace comes from the canonical context hook, not a route param — the
  // /ws/* routes declare no :workspaceId, so useParams().workspaceId is always
  // undefined and would produce /api/workspaces/undefined/... (403). The alert
  // deep-link (?condition=<id>) still uses useSearchParams below.
  const { wsId: workspaceId, loading: wsLoading } = useWorkspace()
  const [searchParams, setSearchParams] = useSearchParams()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [status, setStatus] = useState('')
  const [expanded, setExpanded] = useState(searchParams.get('condition') || null)
  const [detail, setDetail] = useState(null)
  const [detailError, setDetailError] = useState(null)

  const load = useCallback(() => {
    if (!workspaceId) return   // never call the API with a null/unresolved workspace id
    setLoading(true)
    api.getWebsiteSecurityConditions(workspaceId, status ? { monitoring_status: status } : {})
      .then((res) => { setData(res); setError(null) })
      .catch((e) => setError(e?.status === 401
        ? 'Your session has expired. Sign in again to view website security.'
        : 'Could not load website security conditions.'))
      .finally(() => setLoading(false))
  }, [workspaceId, status])

  useEffect(() => { load() }, [load])

  // Alert deep link: /ws/website-security?condition=<id> expands that row and scrolls to
  // it. If the record is gone (purged, or the link is stale) the page still renders the
  // module list — a dead link degrades to a useful page, never a broken screen.
  useEffect(() => {
    const target = searchParams.get('condition')
    if (!target || !data?.items) return
    if (!data.items.some((i) => i.id === target)) return
    setExpanded(target)
    const el = document.getElementById(target)
    if (el) el.scrollIntoView({ block: 'center' })
  }, [searchParams, data])

  useEffect(() => {
    if (!expanded || !workspaceId) { setDetail(null); setDetailError(null); return }
    setDetail(null); setDetailError(null)
    api.getWebsiteSecurityCondition(workspaceId, expanded)
      .then(setDetail)
      .catch(() => setDetailError('Could not load this condition’s history.'))
  }, [workspaceId, expanded])

  const toggle = (id) => {
    const next = expanded === id ? null : id
    setExpanded(next)
    const p = new URLSearchParams(searchParams)
    if (next) p.set('condition', next); else p.delete('condition')
    setSearchParams(p, { replace: true })
  }

  const items = data?.items || []
  const linkedMissing = searchParams.get('condition') && data && !items.some((i) => i.id === searchParams.get('condition'))

  if (!wsLoading && !workspaceId) return <NoWorkspaceSelected />

  return (
    <div className="mx-auto max-w-5xl px-4 py-6">
      <header className="mb-4">
        <h1 className="text-xl font-semibold text-gray-900">Website Security</h1>
        <p className="mt-1 text-sm text-gray-600">
          Conditions CyberMeters has observed on your websites, when each began, and whether it has cleared.
        </p>
      </header>

      {/* The server owns the scope note. Rendering it rather than writing page copy is what
          stops the honesty boundary drifting per screen. */}
      {data?.scope_note && (
        <p className="mb-4 rounded border border-gray-200 bg-gray-50 px-3 py-2 text-xs text-gray-600">{data.scope_note}</p>
      )}

      {/* A stale alert link lands here: say so plainly and leave the customer on a useful
          page rather than an empty or broken one. */}
      {linkedMissing && (
        <p className="mb-4 rounded border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
          That condition is no longer in this list — it may have been cleared, or the link may be out of date.
          Everything currently recorded is shown below.
        </p>
      )}

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <label htmlFor="ws-status" className="text-xs text-gray-500">State</label>
        <select id="ws-status" value={status} onChange={(e) => setStatus(e.target.value)}
                className="rounded border border-gray-200 bg-white px-2 py-1 text-xs text-gray-700">
          {STATUS_FILTERS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
        </select>
        {data?.pagination?.total != null && (
          <span className="text-xs text-gray-400">
            {items.length} of {data.pagination.total}
          </span>
        )}
      </div>

      <div className="rounded-lg border border-gray-200 bg-white">
        {loading && <p className="px-4 py-8 text-center text-sm text-gray-400">Loading…</p>}
        {!loading && error && <p className="px-4 py-8 text-center text-sm text-red-600">{error}</p>}
        {!loading && !error && items.length === 0 && (
          <p className="px-4 py-8 text-center text-sm text-gray-500">
            {status
              ? 'No conditions in this state.'
              : 'No website security conditions recorded yet. They appear here after a scan observes one.'}
          </p>
        )}
        {!loading && !error && items.map((item) => (
          <ConditionRow key={item.id} item={item}
                        expanded={expanded === item.id}
                        onToggle={() => toggle(item.id)}
                        detail={expanded === item.id ? detail : null}
                        detailError={expanded === item.id ? detailError : null} />
        ))}
      </div>
    </div>
  )
}
