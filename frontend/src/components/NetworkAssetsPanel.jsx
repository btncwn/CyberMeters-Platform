import { useCallback, useEffect, useRef, useState } from 'react'
import { Activity, RefreshCw, Server, X } from 'lucide-react'
import { api } from '../api'
import LiveTlsEvidence from './LiveTlsEvidence'
import { parseServerDate } from '../utils/dates'

const OBSERVATION_LABELS = { open: 'Open', closed: 'Closed', timeout: 'Timed out', error: 'Measurement failed', not_run: 'Not run' }
const RUN_LABELS = { queued: 'Queued', running: 'Running', completed: 'Completed', failed: 'Failed' }
const CHANGE_LABELS = { opened: 'Port became open', closed: 'Port became closed', changed: 'Observed service details changed', discovered: 'First observed service' }
const count = value => Number.isInteger(value) && value >= 0 ? value : null
const pending = scan => ['queued', 'running'].includes(scan?.status)
const date = value => {
  if (!value) return 'Not recorded'
  const parsed = parseServerDate(value)
  return Number.isFinite(parsed?.getTime()) ? parsed.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : 'Not recorded'
}

function Observation({ state }) {
  return <span className={`inline-flex rounded px-2 py-1 text-xs font-medium ${state === 'open' ? 'bg-blue-50 text-blue-800' : 'bg-gray-100 text-gray-700'}`}>{OBSERVATION_LABELS[state] || 'Not assessed'}</span>
}

function Coverage({ coverage, quality }) {
  const planned = count(coverage?.planned)
  const attempted = count(coverage?.attempted)
  const completed = count(coverage?.completed)
  const notRun = count(coverage?.not_run)
  return <div className="text-sm text-gray-600 space-y-1">
    <p>{quality === 'complete' ? 'Selected checks completed. This is not a security clearance.' : quality === 'partial' ? 'Partial coverage: some selected checks did not complete.' : 'Coverage has not been established.'}</p>
    {planned !== null && <p>{planned} planned{attempted !== null ? ` · ${attempted} attempted` : ''}{completed !== null ? ` · ${completed} completed` : ''}{notRun !== null ? ` · ${notRun} not run` : ''}</p>}
  </div>
}

function ObservationTable({ rows = [], persisted = false, onViewScan }) {
  return <div className="relative overflow-x-auto"><table className="data-table w-full min-w-[800px]">
    <thead><tr><th>Address</th><th>Port / transport</th><th>Last check</th><th>Service evidence</th><th>Observation times</th>{onViewScan && <th><span className="sr-only">Evidence</span></th>}</tr></thead>
    <tbody>{rows.map((row, index) => <tr key={`${row.address}:${row.port}:${row.transport}:${index}`}>
      <td className="font-mono text-xs">{row.address || 'Not recorded'}{row.hostname && <span className="block font-sans text-gray-500">{row.hostname}</span>}</td>
      <td>{count(row.port) ?? 'Not recorded'} / {row.transport || 'Not recorded'}</td>
      <td><Observation state={row.state} />
        {persisted && row.last_observed_state && row.state && row.last_observed_state !== row.state && <p className="text-xs text-gray-500 mt-1">Last observed: {OBSERVATION_LABELS[row.last_observed_state]?.toLowerCase() || 'not assessed'}</p>}
        {row.reason && <p className="text-xs text-gray-500 mt-1">{row.reason}</p>}
      </td>
      <td>{persisted && !['open', 'closed'].includes(row.state) && (row.service || row.tls) && <span className="block text-xs text-gray-500">Retained from the last observation</span>}{row.service?.name && row.service?.basis ? <><span>{row.service.name}</span><span className="block text-xs text-gray-500">{row.service.basis}</span></> : 'Not identified'}
        {row.tls && <div className="mt-2 min-w-[220px] max-w-lg"><LiveTlsEvidence evidence={row.tls} /></div>}
        {row.service?.banner_sample && <details className="text-xs mt-1"><summary>Observed response</summary><pre className="whitespace-pre-wrap break-all max-w-md">{row.service.banner_sample}</pre></details>}
      </td>
      <td className="text-xs">{persisted ? <>Last observed {date(row.last_seen_at)}<span className="block text-gray-500">Last checked {date(row.last_checked_at)}</span></> : date(row.observed_at)}{persisted && row.first_seen_at && <span className="block text-gray-500">First seen {date(row.first_seen_at)}</span>}</td>
      {onViewScan && <td>{row.last_scan_id && <button className="text-brand-700 text-sm underline" onClick={() => onViewScan(row.last_scan_id)}>View scan</button>}</td>}
    </tr>)}</tbody>
  </table></div>
}

function ChangeList({ changes = [] }) {
  if (!changes.length) return <p className="text-sm text-gray-500">No changes recorded in this scope.</p>
  return <ul className="space-y-2 text-sm">{changes.map((change, index) => <li key={`${change.scan_id}:${change.address}:${change.port}:${index}`}>
    <span className="font-medium">{CHANGE_LABELS[change.type] || 'Observation changed'}</span> — {change.address}:{change.port}
    <span className="block text-xs text-gray-500">{date(change.observed_at)}</span>
  </li>)}</ul>
}

export default function NetworkAssetsPanel({ workspaceId }) {
  const workspaceRef = useRef(workspaceId)
  workspaceRef.current = workspaceId
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [refreshing, setRefreshing] = useState(false)
  const [busy, setBusy] = useState(false)
  const [loadingMore, setLoadingMore] = useState(false)
  const paginationRequest = useRef(0)
  const [message, setMessage] = useState(null)
  const [tab, setTab] = useState('targets')
  const [target, setTarget] = useState('')
  const [label, setLabel] = useState('')
  const [authorized, setAuthorized] = useState(false)
  const [ports, setPorts] = useState([])
  const portsInitialized = useRef(null)
  const [detail, setDetail] = useState(null)
  const detailRequest = useRef(0)
  const loadRequest = useRef(0)

  const refresh = useCallback(async (signal) => {
    if (!workspaceId) return
    const ticket = ++loadRequest.current
    paginationRequest.current += 1
    setLoadingMore(false)
    setRefreshing(true)
    try {
      const [targets, inventory, scans] = await Promise.all([
        api.getNetworkTargets(workspaceId, { signal }),
        api.getNetworkAssets(workspaceId, { signal }),
        api.getNetworkScans(workspaceId, { signal }),
      ])
      if (signal?.aborted || workspaceRef.current !== workspaceId || ticket !== loadRequest.current) return
      const capabilities = targets.capabilities || {}
      setData({ workspaceId, targets: targets.targets || [], assets: inventory.assets || [], assetTotal: count(inventory.total), nextCursor: inventory.next_cursor ?? null, changes: inventory.changes || [], scans: scans.scans || [], scanTotal: count(scans.total), scansTruncated: scans.truncated === true, capabilities })
      if (portsInitialized.current !== workspaceId) {
        const available = (capabilities.allowed_ports || []).filter(port => Number.isInteger(port) && port > 0 && port <= 65535)
        setPorts([443, 80].filter(port => available.includes(port)))
        portsInitialized.current = workspaceId
      }
      setError(null)
    } catch (failure) {
      if (failure?.name !== 'AbortError' && workspaceRef.current === workspaceId && ticket === loadRequest.current) setError(failure.message || 'Network inventory could not be loaded.')
    } finally {
      if (workspaceRef.current === workspaceId && ticket === loadRequest.current) setRefreshing(false)
    }
  }, [workspaceId])

  useEffect(() => {
    const controller = new AbortController()
    detailRequest.current += 1
    setDetail(null); setMessage(null); setError(null); setTarget(''); setLabel(''); setAuthorized(false); setTab('targets'); setBusy(false); setLoadingMore(false)
    refresh(controller.signal)
    return () => { controller.abort(); loadRequest.current += 1 }
  }, [refresh])

  const current = data?.workspaceId === workspaceId ? data : null
  const hasPendingRun = current?.scans.some(pending) === true
  useEffect(() => {
    if (!hasPendingRun) return
    const controller = new AbortController()
    const timer = setTimeout(() => refresh(controller.signal), 5000)
    return () => { clearTimeout(timer); controller.abort() }
  }, [hasPendingRun, data, refresh])

  const capabilities = current?.capabilities || {}
  const allowedPorts = (capabilities.allowed_ports || []).filter(port => Number.isInteger(port) && port > 0 && port <= 65535)
  const selectedPorts = ports.filter(port => allowedPorts.includes(port))
  const maxPorts = count(capabilities.limits?.max_ports)
  const maxPairs = count(capabilities.limits?.max_pairs)
  const canScan = capabilities.can_scan === true && capabilities.collector_available === true
  const validPorts = selectedPorts.length > 0 && maxPorts !== null && selectedPorts.length <= maxPorts
  const withinPairs = row => count(row.address_count) !== null && maxPairs !== null && row.address_count * selectedPorts.length <= maxPairs

  async function act(operation, success) {
    if (busy) return
    const scope = workspaceId
    setBusy(true); setMessage(null); setError(null)
    try {
      const result = await operation()
      if (workspaceRef.current !== scope) return
      setMessage(success)
      if (result?.scan) setData(previous => previous?.workspaceId === scope ? { ...previous, scans: [result.scan, ...previous.scans.filter(scan => scan.id !== result.scan.id)] } : previous)
      await refresh()
      return result
    } catch (failure) {
      if (workspaceRef.current === scope) setError(failure.message || 'The request could not be completed.')
    } finally {
      if (workspaceRef.current === scope) setBusy(false)
    }
  }

  async function addTarget(event) {
    event.preventDefault()
    if (!authorized || !target.trim() || capabilities.can_manage !== true) return
    const saved = await act(() => api.addNetworkTarget(workspaceId, { target: target.trim(), authorization_confirmed: true, ...(label.trim() ? { label: label.trim() } : {}) }), 'Network target saved. Authorization is recorded as your declaration.')
    if (saved && workspaceRef.current === workspaceId) { setTarget(''); setLabel(''); setAuthorized(false) }
  }

  async function loadMoreAssets() {
    if (loadingMore || refreshing || current?.nextCursor == null) return
    const ticket = ++paginationRequest.current
    const scope = workspaceId
    const cursor = current.nextCursor
    setLoadingMore(true)
    try {
      const page = await api.getNetworkAssets(scope, { cursor })
      if (workspaceRef.current !== scope || ticket !== paginationRequest.current) return
      setData(previous => {
        if (previous?.workspaceId !== scope || previous.nextCursor !== cursor) return previous
        const assets = new Map(previous.assets.map(row => [`${row.address}:${row.port}:${row.transport}`, row]))
        for (const row of page.assets || []) assets.set(`${row.address}:${row.port}:${row.transport}`, row)
        return { ...previous, assets: [...assets.values()], assetTotal: count(page.total), nextCursor: page.next_cursor ?? null }
      })
      setError(null)
    } catch (failure) {
      if (workspaceRef.current === scope && ticket === paginationRequest.current) setError(failure.message || 'More network observations could not be loaded.')
    } finally {
      if (workspaceRef.current === scope && ticket === paginationRequest.current) setLoadingMore(false)
    }
  }

  async function viewScan(scanId) {
    const ticket = ++detailRequest.current
    const scope = workspaceId
    setDetail({ workspaceId, loading: true })
    try {
      const result = await api.getNetworkScan(workspaceId, scanId)
      if (workspaceRef.current === scope && ticket === detailRequest.current) setDetail({ ...result, workspaceId, loading: false })
    } catch (failure) {
      if (workspaceRef.current === scope && ticket === detailRequest.current) setDetail({ workspaceId, loading: false, error: failure.message || 'Scan evidence could not be loaded.' })
    }
  }

  if (!workspaceId) return null
  return <section className="card p-5 space-y-4" aria-label="Network assets">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div><h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2"><Server className="w-5 h-5" />Network assets</h2><p className="text-sm text-gray-500 mt-1">Public IP addresses and networks you are authorized to test. An open port is an observation, not a vulnerability.</p></div>
      <button className="btn-secondary text-sm" onClick={() => refresh()} disabled={refreshing || busy}><RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />Refresh network assets</button>
    </div>
    {error && <p role="alert" className="text-sm text-red-700 bg-red-50 rounded p-3">{error}{current && ' Previously loaded observations remain shown.'}</p>}
    {message && <p role="status" className="text-sm text-brand-700">{message}</p>}
    {!current && !error && <p className="text-sm text-gray-500" role="status">Loading network inventory…</p>}
    {current && <>
      {capabilities.collector_available !== true && <p className="text-sm text-amber-800 bg-amber-50 p-3 rounded">Network scanning is currently unavailable. Recorded targets and observations remain available.</p>}
      <div className="flex flex-wrap gap-2" role="tablist" aria-label="Network asset views">{[['targets', 'Targets'], ['services', 'Services'], ['scans', 'Recent scans']].map(([value, title]) => <button role="tab" aria-selected={tab === value} key={value} className={tab === value ? 'btn-primary text-sm' : 'btn-secondary text-sm'} onClick={() => setTab(value)}>{title}</button>)}</div>

      {tab === 'targets' && <div className="space-y-4" role="tabpanel" aria-label="Targets">
        {capabilities.can_manage === true && <form onSubmit={addTarget} className="rounded border border-gray-200 bg-gray-50 p-4 space-y-3">
          <div className="grid sm:grid-cols-2 gap-3"><label className="text-sm font-medium">IP address or CIDR<input className="input w-full mt-1" value={target} onChange={event => setTarget(event.target.value)} placeholder="203.0.113.10 or 203.0.113.0/28" maxLength={80} required /></label><label className="text-sm font-medium">Label (optional)<input className="input w-full mt-1" value={label} onChange={event => setLabel(event.target.value)} maxLength={120} /></label></div>
          <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={authorized} onChange={event => setAuthorized(event.target.checked)} className="mt-1" />I own this address range or have permission to test it.</label>
          <p className="text-xs text-gray-500">This records your authorization declaration; it is not independent ownership verification.{count(capabilities.limits?.max_addresses) !== null ? ` Up to ${capabilities.limits.max_addresses} public addresses per target.` : ''}</p>
          <button className="btn-primary text-sm" type="submit" disabled={busy || !authorized || !target.trim()}>Add network target</button>
        </form>}
        {capabilities.can_scan === true && <fieldset className="space-y-2"><legend className="font-medium text-sm">Ports to check</legend><div className="flex flex-wrap gap-x-4 gap-y-2">{allowedPorts.map(port => <label className="flex items-center gap-1 text-sm" key={port}><input type="checkbox" checked={selectedPorts.includes(port)} onChange={event => setPorts(previous => event.target.checked ? [...new Set([...previous, port])] : previous.filter(value => value !== port))} disabled={busy} />{port}</label>)}</div>
          <p className="text-xs text-gray-500">Only selected TCP ports are checked.{maxPorts !== null && ` Up to ${maxPorts} ports per scan.`}{maxPairs !== null && ` Up to ${maxPairs} address/port checks per scan.`}</p>
          {!validPorts && <p className="text-sm text-amber-800">Select one or more ports within the available limit.</p>}
        </fieldset>}
        {!current.targets.length ? <p className="text-sm text-gray-500">No network targets recorded yet.</p> : <div className="relative overflow-x-auto"><table className="data-table w-full min-w-[800px]"><thead><tr><th>Target</th><th>Scope</th><th>Authorization</th><th><span className="sr-only">Scan</span></th></tr></thead><tbody>{current.targets.map(row => <tr key={row.id}>
          <td className="font-mono text-xs">{row.target}{row.label && <span className="block font-sans text-gray-500">{row.label}</span>}</td><td>{count(row.address_count) === null ? 'Address count not recorded' : `${row.address_count} address${row.address_count === 1 ? '' : 'es'}`}</td><td className="text-xs">{row.authorization_status === 'attested' ? 'Authorization declared' : 'Authorization not established'}<span className="block text-gray-500">{date(row.authorized_at)}</span></td>
          <td>{capabilities.can_scan === true && <><button className="btn-secondary text-sm" disabled={busy || !canScan || !validPorts || !withinPairs(row) || hasPendingRun || row.authorization_status !== 'attested'} onClick={() => act(() => api.startNetworkScan(workspaceId, row.id, selectedPorts), 'Network scan queued. Results will appear when the selected checks finish.')}><Activity className="w-4 h-4" />{hasPendingRun ? 'Scan in progress' : 'Run scan'}</button>{validPorts && !withinPairs(row) && <p className="text-xs text-amber-800 mt-1">Reduce the selected ports to fit this target’s scan limit.</p>}</>}</td>
        </tr>)}</tbody></table></div>}
      </div>}

      {tab === 'services' && <div role="tabpanel" aria-label="Services" className="space-y-4">
        <p className="text-sm text-gray-500">Service names require observed protocol evidence. Unanswered checks do not establish that a service disappeared.</p>
        {current.assets.length ? <ObservationTable rows={current.assets} persisted onViewScan={viewScan} /> : <p className="text-sm text-gray-500">No service observations recorded yet. A completed scan is needed to establish coverage.</p>}
        <div className="flex flex-wrap items-center justify-between gap-2"><p className="text-xs text-gray-500">Showing {current.assets.length}{current.assetTotal !== null ? ` of ${current.assetTotal}` : ''} recorded service observations.</p>{current.nextCursor !== null && <button className="btn-secondary text-sm" onClick={loadMoreAssets} disabled={loadingMore || refreshing}>{loadingMore ? 'Loading more…' : 'Load more observations'}</button>}</div>
        <h3 className="font-semibold text-sm">Recent changes</h3><p className="text-xs text-gray-500">From the latest 25 completed scans. Open a scan to see its full change record.</p><ChangeList changes={current.changes} />
      </div>}

      {tab === 'scans' && <div role="tabpanel" aria-label="Recent scans" className="space-y-3"><p className="text-xs text-gray-500">Showing {current.scans.length}{current.scanTotal !== null ? ` of ${current.scanTotal}` : ''} network scans. This view includes the latest 100 runs.{current.scansTruncated && ' Older runs remain accessible from their scan reference.'}</p>{!current.scans.length ? <p className="text-sm text-gray-500">No network scans recorded yet.</p> : current.scans.map(scan => <div key={scan.id} className="border border-gray-200 rounded p-3 space-y-2">
        <div className="flex flex-wrap justify-between gap-2"><span className="font-medium text-sm">{scan.target || current.targets.find(row => row.id === scan.target_id)?.target || 'Target not recorded'}</span><span className="text-sm">{RUN_LABELS[scan.status] || 'Unknown status'}</span></div>
        <p className="text-xs text-gray-500">Started {date(scan.created_at)}{scan.completed_at ? ` · Finished ${date(scan.completed_at)}` : ''}</p>
        {!pending(scan) && <Coverage coverage={scan.coverage} quality={scan.quality} />}{scan.reason && <p className="text-sm text-gray-600">{scan.reason}</p>}
        <div className="flex flex-wrap gap-2"><button className="btn-secondary text-sm" onClick={() => viewScan(scan.id)}>View evidence</button>{canScan && !pending(scan) && <button className="btn-secondary text-sm" disabled={busy || hasPendingRun} onClick={() => act(() => api.retestNetworkScan(workspaceId, scan.id), 'Retest queued for the same target and ports.')}>Retest same scope</button>}</div>
      </div>)}</div>}
    </>}

    {detail?.workspaceId === workspaceId && <div className="border border-brand-200 bg-brand-50/30 rounded p-4 space-y-3" aria-label="Network scan evidence">
      <div className="flex justify-between items-center"><h3 className="font-semibold">Network scan evidence</h3><button aria-label="Close network scan evidence" onClick={() => { detailRequest.current += 1; setDetail(null) }}><X className="w-5 h-5" /></button></div>
      {detail.loading ? <p>Loading evidence…</p> : detail.error ? <p role="alert" className="text-red-700">{detail.error}</p> : <>
        <p className="text-xs text-gray-500">Scan reference: {detail.scan?.id || 'Not recorded'}</p>
        <Coverage coverage={detail.receipt?.coverage || detail.scan?.coverage} quality={detail.receipt?.quality || detail.scan?.quality} />
        {detail.receipt?.observations?.length ? <ObservationTable rows={detail.receipt.observations.map(row => ({ ...row, observed_at: row.observed_at || detail.receipt.finished_at }))} /> : <p className="text-sm">No measured observations are recorded for this scan.</p>}
        <ChangeList changes={(detail.changes || []).map(change => ({ ...change, scan_id: change.scan_id || detail.scan?.id, observed_at: change.observed_at || detail.receipt?.finished_at || detail.scan?.completed_at }))} />
      </>}
    </div>}
  </section>
}
