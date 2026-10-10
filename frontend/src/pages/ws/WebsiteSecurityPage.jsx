import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { ChevronDown, FolderOpen, RefreshCw, ScanLine } from 'lucide-react'
import { api } from '../../api'
import { useWorkspace } from '../../hooks/useWorkspace'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'
import WebsiteScanOverview from '../../components/WebsiteScanOverview'
import { SERVICE_COLORS } from '../../theme/serviceColors'
import {
  monitoringMeta, severityMeta, scanQualityMeta, unknownReasonText,
  toneClass, conditionLabel,
} from '../../lib/websiteSecurityDisplay'

const PAGE_SIZE = 50
const CASES = '/ws/cases?domain_key=website_security'
const ACTION = 'inline-flex items-center rounded-lg border border-gray-300 bg-white px-4 py-2.5 text-sm font-medium text-gray-800 hover:bg-gray-50'
const date = (value) => value ? String(value).slice(0, 16).replace('T', ' ') : 'Not recorded'
const STATUS_FILTERS = [
  ['', 'All states'], ['observed', 'Observed'], ['unknown', 'Not determined'],
  ['no_longer_observed', 'No longer seen'], ['baseline', 'Pre-existing'],
]

function Pill({ meta }) {
  return <span title={meta.hint} className={`rounded-full border px-2.5 py-1 text-sm ${toneClass(meta.tone)}`}>{meta.label}</span>
}

function ConditionRow({ item, expanded, onToggle, detail, detailError }) {
  const uncertain = item.monitoring_status === 'unknown' || item.last_scan_quality !== 'complete'
  const caseId = detail?.linked_case?.id
  return (
    <div id={item.id} className="border-b border-gray-100 last:border-0">
      <button type="button" onClick={onToggle} aria-expanded={expanded}
              className="flex w-full items-start gap-3 px-5 py-5 text-left hover:bg-gray-50 focus-visible:outline-brand-600">
        <div className="min-w-0 flex-1">
          <p className="text-base font-semibold leading-relaxed text-gray-900 break-words">{conditionLabel(item)}</p>
          <p className="mt-1 text-sm text-gray-600 break-all">{item.domain}</p>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <Pill meta={monitoringMeta(item.monitoring_status)} />
            {!uncertain && item.monitoring_status !== 'no_longer_observed' && <Pill meta={severityMeta(item.severity)} />}
            {item.last_scan_quality !== 'complete' && <span className="text-sm text-gray-600">{scanQualityMeta(item.last_scan_quality).label}</span>}
          </div>
          <p className="mt-2 text-sm text-gray-500">Last seen: {date(item.last_seen_at)}</p>
        </div>
        <ChevronDown aria-hidden="true" className={`mt-1 h-5 w-5 shrink-0 text-gray-500 ${expanded ? 'rotate-180' : ''}`} />
      </button>
      {expanded && (
        <div className="space-y-4 bg-gray-50 px-5 pb-5 pt-3 text-base text-gray-700">
          {item.monitoring_status === 'unknown' && <p><strong>Current status not confirmed.</strong> {unknownReasonText(item.unknown_reason) || 'The latest check could not determine whether this condition is still present.'} This does not mean it has been fixed.</p>}
          {uncertain && <p className="text-sm">Last recorded severity: <strong>{severityMeta(item.severity).label}</strong>. {item.monitoring_status === 'unknown' ? 'This is a historical rating, not a confirmed current issue.' : 'The latest scan evidence is incomplete; this rating needs that context.'}</p>}
          <div className="flex flex-wrap gap-2">
            {caseId && <Link className={ACTION} to={`/ws/cases/${encodeURIComponent(caseId)}`}>Open managed case</Link>}
            {item.last_scan_id && <Link className={ACTION} to={`/scans/${encodeURIComponent(item.last_scan_id)}?view=technical#website-evidence`}>View scan evidence</Link>}
            <Link className={ACTION} to={`/scans/new?domain=${encodeURIComponent(item.domain)}`}>Recheck domain</Link>
          </div>
          <p className="text-sm text-gray-600">Recheck opens the scan form. A new scan only confirms a fix when the relevant check succeeds.</p>
          {!caseId && detail && <p className="text-sm">No linked case was returned. <Link className="text-brand-700 underline" to={CASES}>View Website Security cases</Link></p>}
          {detailError && <p role="alert" className="text-sm text-red-700">{detailError}</p>}
          <details className="rounded-lg border border-gray-200 bg-white px-4 py-3">
            <summary className="cursor-pointer font-medium">History and scan details</summary>
            <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
              <div><dt className="text-gray-500">First seen</dt><dd>{date(item.first_seen_at)}</dd></div>
              <div><dt className="text-gray-500">Last seen</dt><dd>{date(item.last_seen_at)}</dd></div>
              <div><dt className="text-gray-500">Evidence quality</dt><dd>{scanQualityMeta(item.last_scan_quality).label}</dd></div>
              <div><dt className="text-gray-500">Check</dt><dd className="break-words">{item.detecting_module || 'Not recorded'}</dd></div>
            </dl>
            {!detail && !detailError && <p className="mt-3 text-sm">Loading history…</p>}
            {detail && !detail.events?.length && <p className="mt-3 text-sm">No recorded changes yet.</p>}
            {detail?.events?.length > 0 && <ul className="mt-4 space-y-2 text-sm">
              {detail.events.map((event) => <li key={event.id}>{date(event.created_at)} · {String(event.event_type).replace(/_/g, ' ')}</li>)}
            </ul>}
          </details>
        </div>
      )}
    </div>
  )
}

function WebsiteSecurityContent({ workspaceId, workspaceName }) {
  const [params, setParams] = useSearchParams()
  const expanded = params.get('condition')
  const [status, setStatus] = useState('')
  const [offset, setOffset] = useState(0)
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [detail, setDetail] = useState(null)
  const [detailError, setDetailError] = useState(null)
  const [refresh, setRefresh] = useState(0)

  useEffect(() => {
    let cancelled = false
    setLoading(true); setError(null)
    api.getWebsiteSecurityConditions(workspaceId, { limit: PAGE_SIZE, offset, ...(status ? { monitoring_status: status } : {}) })
      .then((res) => { if (!cancelled) setData(res) })
      .catch((err) => { if (!cancelled) setError(err?.status === 401 ? 'Your session has expired. Sign in again to view website security.' : 'Could not load website security conditions.') })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [workspaceId, offset, status, refresh])

  useEffect(() => {
    let cancelled = false
    setDetail(null); setDetailError(null)
    if (expanded) api.getWebsiteSecurityCondition(workspaceId, expanded)
      .then((res) => { if (!cancelled) setDetail({ ...res, requestedId: expanded }) })
      .catch(() => { if (!cancelled) setDetailError('Could not load this condition’s history or linked case.') })
    return () => { cancelled = true }
  }, [workspaceId, expanded, refresh])

  // A notification may point beyond the first page. Resolve it directly through
  // the tenant-scoped detail endpoint instead of treating it as a missing record.
  const currentDetail = detail?.requestedId === expanded ? detail : null
  const items = data?.items || []
  const linkedItem = currentDetail?.item && !items.some((item) => item.id === expanded) ? currentDetail.item : null
  useEffect(() => {
    if (!loading && expanded) document.getElementById(expanded)?.scrollIntoView({ block: 'nearest' })
  }, [loading, expanded, linkedItem])

  const toggle = (id) => {
    const next = new URLSearchParams(params)
    if (id && expanded !== id) next.set('condition', id); else next.delete('condition')
    setParams(next, { replace: true })
  }
  const changePage = (next) => { setOffset(next); toggle(null) }
  const total = data?.pagination?.total ?? items.length
  const row = (item) => <ConditionRow key={item.id} item={item} expanded={expanded === item.id} onToggle={() => toggle(item.id)} detail={expanded === item.id ? currentDetail : null} detailError={expanded === item.id ? detailError : null} />

  return (
    <WsPage wsId={workspaceId} wsName={workspaceName}>
      <header className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div className="min-w-0">
          <span className="eyebrow" style={{ color: SERVICE_COLORS.website.text }}>Website Security</span>
          <h1 className="page-title">Website Security</h1>
          <p className="page-subtitle text-base">Review HTTPS, browser protections and cookie evidence. Track findings through to verification.</p>
          <p className="mt-1 text-sm text-gray-500">{workspaceName || 'Workspace'}</p>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          <Link className="btn-primary" to="/scans/new"><ScanLine className="h-4 w-4" />Run a scan</Link>
          <Link className="btn-secondary" to={CASES}><FolderOpen className="h-4 w-4" />Managed cases</Link>
          <button type="button" className="btn-ghost" aria-label="Refresh website security" onClick={() => setRefresh((value) => value + 1)}><RefreshCw className="h-5 w-5" /></button>
        </div>
      </header>
      <WebsiteScanOverview workspaceId={workspaceId} refresh={refresh} />
      <div className="mb-4"><h2 className="section-title">Tracked findings</h2><p className="mt-1 text-base text-gray-600">Across this workspace. Open a finding for its evidence, managed case and recheck.</p></div>
      {data?.scope_note && <details className="mb-5 text-sm text-gray-600"><summary className="cursor-pointer font-medium">What this checks</summary><p className="mt-2 max-w-3xl leading-relaxed">{data.scope_note}</p></details>}
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <label htmlFor="ws-status" className="text-sm text-gray-700">State</label>
        <select id="ws-status" value={status} onChange={(event) => { setStatus(event.target.value); setOffset(0); toggle(null) }} className="rounded-lg border border-gray-300 bg-white px-3 py-2 text-base">
          {STATUS_FILTERS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
        {!loading && !error && <span className="text-sm text-gray-600" aria-live="polite">{items.length ? `${offset + 1}–${offset + items.length} of ${total}` : `0 of ${total} findings`}</span>}
      </div>
      {!loading && !error && linkedItem && <section className="mb-4 rounded-xl border border-gray-200 bg-white"><h2 className="px-5 pt-4 text-sm font-medium text-gray-600">Linked finding · outside this page</h2>{row(linkedItem)}</section>}
      {expanded && detailError && !items.some((item) => item.id === expanded) && <p role="alert" className="mb-4 text-sm text-red-700">{detailError}</p>}
      <div className="card overflow-hidden">
        {loading && <p className="p-8 text-center text-base text-gray-500">Loading…</p>}
        {!loading && error && <p role="alert" className="p-8 text-base text-red-700">{error}</p>}
        {!loading && !error && !items.length && <p className="p-6 text-base text-gray-600">{status ? 'No conditions in this state.' : 'No website security conditions recorded yet. Check the scan overview above for the available evidence; an empty list does not prove the website is secure.'}</p>}
        {!loading && !error && items.map(row)}
      </div>
      {(total > PAGE_SIZE || offset > 0) && <nav aria-label="Findings pages" className="mt-4 flex justify-between gap-3">
        <button className={`${ACTION} disabled:opacity-40`} disabled={loading || offset === 0} onClick={() => changePage(Math.max(0, offset - PAGE_SIZE))}>Previous</button>
        <button className={`${ACTION} disabled:opacity-40`} disabled={loading || Boolean(error) || offset + PAGE_SIZE >= total} onClick={() => changePage(offset + PAGE_SIZE)}>Next</button>
      </nav>}
    </WsPage>
  )
}

export default function WebsiteSecurityPage() {
  const { wsId, wsName, loading } = useWorkspace()
  if (loading) return <p className="p-6 text-base text-gray-500">Loading workspace…</p>
  if (!wsId) return <NoWorkspaceSelected />
  // Workspace changes discard prior rows and any in-flight detail presentation.
  return <WebsiteSecurityContent key={wsId} workspaceId={wsId} workspaceName={wsName} />
}
