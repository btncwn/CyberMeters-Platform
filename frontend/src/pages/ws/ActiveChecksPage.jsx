import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../../api'
import { useWorkspace } from '../../hooks/useWorkspace'
import { NoWorkspaceSelected } from '../../components/WsPage'
import { ActiveCheckReceipt } from './ActiveCheckPermissionsPage'
import { formatViewerTime } from '../../lib/reportTime'
import { formatDate } from '../../utils/dates'
import { isTlsSpecialCheck, TLS_SPECIAL_CHECK_NAMES, tlsSpecialCheckResult } from '../../../../shared/tls/special-check-words.js'

const HISTORY_LIMIT = 20 // The existing workspace-scans route returns its latest 20 records.
const RECEIPT_LIMIT = 20
const RESULT_LIMIT = 100
const domainName = value => typeof value === 'string' ? value.trim().toLowerCase().replace(/\.$/, '') : ''
const statuses = { completed: 'Completed', failed: 'Interrupted', interrupted: 'Interrupted', queued: 'Queued', running: 'In progress', processing: 'In progress' }

// Read only explicit saved controls. A consent or a completed scan supplies no result.
export function recordedActiveChecks(report) {
  const endpoints = Array.isArray(report?.modules?.tls_assessment?.endpoints) ? report.modules.tls_assessment.endpoints : []
  return endpoints.flatMap(endpoint => (Array.isArray(endpoint?.checks) ? endpoint.checks : [])
    .filter(row => isTlsSpecialCheck(row?.control))
    .map(row => ({
      host: typeof endpoint.hostname === 'string' && endpoint.hostname ? endpoint.hostname : 'Host not recorded',
      port: Number.isInteger(endpoint.port) ? endpoint.port : null,
      check: TLS_SPECIAL_CHECK_NAMES[row.control],
      result: tlsSpecialCheckResult(row, endpoint),
      observedAt: typeof row.observed_at === 'string' ? row.observed_at : null,
    })))
}

function savedIdentity(value, scan) {
  return value && domainName(value.domain) === domainName(scan.domain)
}

export default function ActiveChecksPage() {
  const { wsId, wsName, loading } = useWorkspace()
  const [refresh, setRefresh] = useState(0)
  const [lists, setLists] = useState(null)
  const [domain, setDomain] = useState('')
  const [detail, setDetail] = useState(null)
  const scope = useRef(wsId)
  scope.current = wsId
  const generation = useRef(0)
  const detailGeneration = useRef(0)

  useEffect(() => {
    const request = ++generation.current
    ++detailGeneration.current
    setDomain('')
    setDetail(null)
    setLists(null)
    if (!wsId) return
    let alive = true
    Promise.allSettled([
      Promise.resolve().then(() => api.getActiveCheckConsents(wsId)),
      Promise.resolve().then(() => api.getWorkspaceScans(wsId)),
    ]).then(([permissions, history]) => {
      if (!alive || scope.current !== wsId || generation.current !== request) return
      const consentData = permissions.status === 'fulfilled' ? permissions.value : null
      const historyData = history.status === 'fulfilled' ? history.value : null
      const permissionsOk = Array.isArray(consentData?.consents) && (!consentData.workspace_id || consentData.workspace_id === wsId)
      const historyOk = Array.isArray(historyData?.scans) && (!historyData.workspace_id || historyData.workspace_id === wsId)
      setLists({
        wsId,
        permissionsOk,
        historyOk,
        consents: permissionsOk ? consentData.consents.filter(c => c && typeof c.id === 'string' && domainName(c.domain)) : [],
        catalogue: permissionsOk && Array.isArray(consentData.catalogue) ? consentData.catalogue : [],
        authority: permissionsOk ? consentData.authority : null,
        scans: historyOk ? historyData.scans.filter(s => s && typeof s.id === 'string' && domainName(s.domain)).slice(0, HISTORY_LIMIT) : [],
      })
    })
    return () => { alive = false; ++detailGeneration.current }
  }, [wsId, refresh])

  function chooseDomain(value) {
    ++detailGeneration.current
    setDetail(null)
    setDomain(value)
  }

  async function readChecks(scan) {
    if (detail?.scan.id === scan.id && detail.status !== 'error') return
    const request = ++detailGeneration.current
    const workspace = wsId
    const current = () => scope.current === workspace && detailGeneration.current === request
    setDetail({ wsId: workspace, domain, scan, status: 'loading' })
    try {
      // Verify the detail identity against the workspace-list entry before reading its report.
      const payload = await api.getScan(scan.id)
      if (!current()) return
      const record = payload?.scan || payload
      if (record?.id !== scan.id || !savedIdentity(record, scan) || (record.workspace_id && record.workspace_id !== workspace)) throw new Error('Unmatched scan')
      const report = await api.getScanReport(scan.id)
      if (!current()) return
      if (report?.scan_id !== scan.id || !savedIdentity(report, scan)) throw new Error('Unmatched report')
      setDetail({ wsId: workspace, domain, scan, status: 'ready', rows: recordedActiveChecks(report) })
    } catch {
      if (current()) setDetail({ wsId: workspace, domain, scan, status: 'error' })
    }
  }

  if (!loading && !wsId) return <NoWorkspaceSelected />
  // Hide old-workspace records immediately, before the next effect clears state.
  const current = lists?.wsId === wsId ? lists : null
  const selected = detail?.wsId === wsId && detail.domain === domain ? detail : null
  const domains = [...new Set([...(current?.scans || []), ...(current?.consents || [])].map(row => domainName(row.domain)))].sort()
  const scans = (current?.scans || []).filter(row => !domain || domainName(row.domain) === domain)
  const consents = (current?.consents || []).filter(row => !domain || domainName(row.domain) === domain)
  const labels = Object.fromEntries((current?.catalogue || []).map(c => [c.id, c.label]))
  const availability = Object.fromEntries((current?.catalogue || []).map(c => [c.id, c.available === true]))

  return (
    <div className="max-w-(--breakpoint-xl) mx-auto px-4 sm:px-6 py-8 space-y-6">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-gray-900">Active Checks</h1>
          <p className="text-sm text-gray-600 mt-1">Permissions and saved active-check results{wsName ? ` for ${wsName}` : ''}.</p>
        </div>
        <Link to="/ws/active-checks/permission" className="btn-primary">Manage permissions</Link>
      </header>
      <p className="text-sm text-gray-600">A permission allows a check; it does not mean the check ran. Authorised checks run only on scans you start, never on scheduled scans. Manage permissions to request or revoke authorisation.</p>

      {!current ? <p role="status" className="text-sm text-gray-500">Reading permissions and scan history…</p> : <>
        <div className="flex flex-wrap items-end justify-between gap-3">
          <label className="text-sm font-medium text-gray-800">Domain
            <select className="input mt-1 block max-w-full" value={domain} onChange={event => chooseDomain(event.target.value)}>
              <option value="">All domains</option>
              {domains.map(name => <option key={name} value={name}>{name}</option>)}
            </select>
          </label>
          <button type="button" className="btn-secondary" onClick={() => setRefresh(value => value + 1)}>Reload records</button>
        </div>

        <section aria-labelledby="active-permissions" className="space-y-3">
          <h2 id="active-permissions" className="text-base font-semibold text-gray-900">Permissions on record</h2>
          {!current.permissionsOk ? <p role="alert" className="text-sm text-red-700">Permissions could not be read. No permission status is assumed.</p>
            : consents.length === 0 ? <p className="text-sm text-gray-600">No permission is recorded for {domain || 'this workspace'}. Past results, if any, remain separate below.</p>
            : <>
              <ul className="space-y-3">{consents.slice(0, RECEIPT_LIMIT).map(consent => <ActiveCheckReceipt key={consent.id} consent={consent} labels={labels} availability={availability} authority={current.authority} canManage={false} />)}</ul>
              {consents.length > RECEIPT_LIMIT && <p className="text-sm text-gray-600">Showing the first {RECEIPT_LIMIT} permissions. Manage permissions to see every record.</p>}
            </>}
        </section>

        <section aria-labelledby="active-history" className="space-y-3">
          <h2 id="active-history" className="text-base font-semibold text-gray-900">Recorded check history</h2>
          <p className="text-sm text-gray-600">The latest {HISTORY_LIMIT} workspace scans are available here. Filter by domain, then read a saved scan to see which active checks have an explicit result. A completed scan alone does not show that an active check ran.</p>
          {!current.historyOk ? <p role="alert" className="text-sm text-red-700">Scan history could not be read. No check results are assumed.</p>
            : scans.length === 0 ? <p className="text-sm text-gray-600">No recent scans are recorded for {domain || 'this workspace'}.</p>
            : <ul className="divide-y divide-gray-100 rounded-xl border border-gray-200" aria-label="Recent scans">
              {scans.map(scan => <li key={scan.id} className="p-4 flex flex-wrap items-center justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-gray-900 break-words">{scan.domain}</p>
                  <p className="text-sm text-gray-600">Scan started {formatViewerTime(scan.created_at)} · {statuses[scan.status] || 'Status not available'}</p>
                </div>
                <div className="flex flex-wrap items-center gap-3">
                  {['completed', 'failed', 'interrupted'].includes(scan.status)
                    ? <button type="button" className="btn-secondary" aria-label={`Read saved checks for ${scan.domain} from ${formatViewerTime(scan.created_at)}`} disabled={selected?.scan.id === scan.id && selected.status === 'loading'} onClick={() => readChecks(scan)}>Read saved checks</button>
                    : <span className="text-sm text-gray-600">No finished record yet</span>}
                  <Link className="cm-rowlink text-sm font-semibold" to={`/scans/${encodeURIComponent(scan.id)}?view=technical`}>Open scan details</Link>
                </div>
              </li>)}
            </ul>}

          {selected && <section aria-labelledby="saved-active-checks" className="card p-4 sm:p-6 space-y-3" aria-live="polite">
            <h3 id="saved-active-checks" className="text-base font-semibold text-gray-900">Saved checks for {selected.scan.domain}</h3>
            <p className="text-sm text-gray-600">Historical evidence from this scan. Today's permission status does not change its recorded results.</p>
            {selected.status === 'loading' && <p role="status" className="text-sm text-gray-600">Reading the saved check record…</p>}
            {selected.status === 'error' && <div className="space-y-2"><p role="alert" className="text-sm text-red-700">Saved checks could not be read or matched to this scan. Their results remain unknown.</p><button type="button" className="btn-secondary" onClick={() => readChecks(selected.scan)}>Retry saved checks</button></div>}
            {selected.status === 'ready' && (selected.rows.length === 0
              ? <p className="text-sm text-gray-600">No active-check result was recorded in this scan. This does not mean the checks passed or that they ran.</p>
              : <>
                <ul className="divide-y divide-gray-100" aria-label="Saved active-check outcomes">{selected.rows.slice(0, RESULT_LIMIT).map((row, index) => <li key={index} className="py-3 space-y-1">
                  <h4 className="text-sm font-semibold text-gray-900 break-words">{row.check} · {row.host}{row.port == null ? '' : `:${row.port}`}</h4>
                  <p className="text-sm text-gray-800">{row.result}</p>
                  <p className="text-xs text-gray-500">{row.observedAt ? `Observed ${formatDate(row.observedAt, 'Not recorded', { timeZone: 'UTC' })} UTC` : 'Observation time not recorded'}</p>
                </li>)}</ul>
                {selected.rows.length > RESULT_LIMIT && <p className="text-sm text-gray-600">Showing the first {RESULT_LIMIT} recorded checks. Open scan details for the full record.</p>}
              </>)}
          </section>}
        </section>
      </>}

      <p className="text-sm text-gray-600">Public IP targets and declared-range port scanning use separate consent under <Link to="/assets" className="cm-rowlink font-semibold">Network assets</Link>.</p>
    </div>
  )
}
