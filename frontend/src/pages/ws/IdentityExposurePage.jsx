// Identity Exposure Managed Workflow — a focused managed surface (not a nav or
// dashboard redesign). It renders the server-owned canonical managed identity
// records and posts classification / ownership / remediation / verification
// actions the BACKEND validates. The set of allowed actions comes from the server
// response — the frontend never invents risk, verification, or actions. It draws
// a hard, visible line between what is OBSERVED EXTERNALLY, what the CUSTOMER
// classified, and what CyberMeters has VERIFIED.
import { Fragment, useEffect, useState, useCallback, useRef } from 'react'
import { useAppDialog } from '../../components/AppDialog'
import { Link } from 'react-router-dom'
import { api } from '../../api'
import { useWorkspace } from '../../hooks/useWorkspace'
import { NoWorkspaceSelected } from '../../components/WsPage'
import ModuleContract from '../../components/module/ModuleContract'
import {
  classificationMeta, riskMeta, ownershipMeta, verificationMeta, surfaceLabel, toneClass,
  isAwaitingVerification, IDENTITY_SCOPE_NOTE, identityClaimMeta, confidenceDetailLabel,
} from '../../lib/identityExposureDisplay'

function Pill({ meta }) {
  return <span className={`inline-block rounded-full border px-2 py-0.5 text-xs ${toneClass(meta.tone)}`}>{meta.label}</span>
}

const CLASS_FILTERS = ['', 'unreviewed', 'expected', 'unexpected', 'investigate', 'exception', 'retired']

// "What we observed" (S1-SHELL-V2b): counts of the backend's own records by
// claim kind, from the unfiltered list. Counting is presentation; what each
// record IS (claim_kind, reachability) is the backend's.
// SUMMARY_LIMIT is the backend's own maximum page (routes/identity-exposure.js):
// when a page comes back full, the claim-kind counts are lower bounds ("N+").
export const SUMMARY_LIMIT = 500
export function identitySummaryFigures({ status, items, counts, atLimit = false }) {
  const by = (kind) => (items || []).filter((it) => it?.identity_claim?.claim_kind === kind).length
  // Never 0 for "not known": loading and error say so (R1 15:55).
  const v = (n) => (status === 'loading' ? 'Loading…' : status !== 'ok' ? 'Not available' : atLimit ? `${n}+` : n)
  // counts.unreviewed is workspace-wide (not page-bound): never "+"; a missing field is "Not available".
  const unreviewed = status === 'loading' ? 'Loading…' : status !== 'ok' || !Number.isInteger(counts?.unreviewed) ? 'Not available' : counts.unreviewed
  return [
    { key: 'providers', id: 'identity-providers-observed', label: 'Provider relationships', value: v(by('provider_relationship')), explanation: 'Identity providers observed for your domains' },
    { key: 'possible', id: 'identity-hostnames-possible', label: 'Possible identity hostnames', value: v(by('surface_candidate')), explanation: 'Hostnames that may host a sign-in page; not confirmed' },
    { key: 'measured', id: 'identity-measured', label: 'Measured sign-in surfaces', value: v(by('measured_identity_surface')), explanation: 'Hostnames where CyberMeters measured a sign-in endpoint' },
    { key: 'unreviewed', id: 'identity-unreviewed', label: 'Not yet reviewed', value: unreviewed, explanation: 'Records you have not classified yet' },
  ]
}

// The sidebar's "Measured endpoints": every record with measured endpoints, in
// every state (an honest sentence before any is measured).
export function MeasuredEndpoints({ status, items, atLimit = false }) {
  const rows = status === 'ok' ? (items || []).filter((it) => Array.isArray(it?.measured_endpoints) && it.measured_endpoints.length > 0) : []
  return (
    <section id="identity-measured-endpoints" className="card p-6 mb-6" aria-labelledby="identity-measured-endpoints-heading" data-testid="identity-measured-endpoints">
      <h2 id="identity-measured-endpoints-heading" className="font-semibold text-gray-900 mb-1">Measured endpoints</h2>
      <p className="text-sm text-gray-500 leading-relaxed mb-4 max-w-3xl">Sign-in endpoints CyberMeters measured on your hostnames, and whether they answered. A measured endpoint is an observation, not evidence of misuse.</p>
      {status === 'loading' ? <p className="text-sm text-gray-500">Loading…</p>
        : status !== 'ok' ? <p className="text-sm text-gray-600">Not available — the identity records could not be loaded.</p>
          : !rows.length ? <p className="text-sm text-gray-600">{atLimit
            ? `None among the first ${SUMMARY_LIMIT} identity records.`
            : 'No endpoint has been measured yet. This fills after a scan measures a sign-in endpoint on a monitored hostname.'}</p>
            : (
              <ul className="divide-y divide-gray-100">
                {rows.map((it) => (
                  <li key={it.identity_exposure_id} className="py-3 flex flex-col sm:flex-row sm:items-start sm:justify-between gap-1 sm:gap-4">
                    <span className="text-sm font-medium text-gray-900 break-all">{it.primary_hostname || it.provider_name || surfaceLabel(it.surface_type)}</span>
                    <span className="text-sm text-gray-700 sm:text-right break-all">
                      <span className="font-semibold">{identityClaimMeta(it.identity_claim).label}</span>
                      <span className="block text-gray-600">{it.measured_endpoints.join(', ')}</span>
                    </span>
                  </li>
                ))}
              </ul>
            )}
    </section>
  )
}

function IdentitySurfaceDetail({ workspaceId, recordId }) {
  const [detail, setDetail] = useState(null)
  const [error, setError] = useState(false)
  useEffect(() => {
    let active = true
    setDetail(null)
    setError(false)
    api.getIdentitySurface(workspaceId, recordId).then(
      (value) => { if (active) setDetail(value) },
      () => { if (active) setError(true) },
    )
    return () => { active = false }
  }, [workspaceId, recordId])

  if (error) return <p role="alert" className="text-sm text-red-700">Could not load this surface's history.</p>
  if (!detail) return <p className="text-sm text-slate-500">Loading history…</p>
  const events = Array.isArray(detail.events) ? detail.events : []
  return (
    <div className="space-y-3">
      <h3 className="text-sm font-semibold text-slate-800">Event history</h3>
      {events.length === 0 ? <p className="text-sm text-slate-500">No recorded events.</p> : (
        <ol className="space-y-2 text-sm text-slate-600">
          {events.map((event) => <li key={event.id}>
            <span className="font-medium text-slate-800">{event.event_type?.replaceAll('_', ' ') || 'Recorded event'}</span>
            {event.actor_type && ` · ${event.actor_type}`}
            {event.created_at && ` · ${event.created_at}`}
          </li>)}
        </ol>
      )}
      {detail.linked_case && (
        <p className="text-sm">
          Linked case: <Link className="text-blue-700 hover:underline" to={`/ws/cases/${encodeURIComponent(detail.linked_case.id)}`}>
            {detail.linked_case.id}
          </Link>
          {detail.linked_case.status && ` · ${detail.linked_case.status}`}
        </p>
      )}
    </div>
  )
}

export default function IdentityExposurePage() {
  const dialog = useAppDialog()
  // Workspace comes from the canonical context hook, not a route param — the
  // /ws/* routes declare no :workspaceId, so useParams().workspaceId is always
  // undefined and would produce /api/workspaces/undefined/... (403).
  const { wsId: workspaceId, wsName: workspaceName, loading: wsLoading } = useWorkspace()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('')
  // "What we observed" and Measured endpoints read ONLY the unfiltered load (a
  // filter chip never changes them): its status, records, workspace-wide counts
  // and whether the page came back full.
  const [summary, setSummary] = useState({ status: 'loading', items: [], counts: null, atLimit: false })
  // Another workspace's records, counts or filter never stand in for this one's.
  useEffect(() => {
    setFilter('')
    setSummary({ status: 'loading', items: [], counts: null, atLimit: false })
  }, [workspaceId])
  const [busy, setBusy] = useState(null)
  const [expandedId, setExpandedId] = useState(null)
  const requestGeneration = useRef(0)

  const load = useCallback(() => {
    const generation = ++requestGeneration.current
    setData(null)
    setError(null)
    setExpandedId(null)
    if (!workspaceId) { setLoading(false); return }   // never call the API with a null/unresolved workspace id
    setLoading(true)
    const unfiltered = !filter
    if (unfiltered) setSummary((prev) => ({ ...prev, status: 'loading' }))
    api.getIdentitySurfaces(workspaceId, unfiltered ? { limit: SUMMARY_LIMIT } : { customer_classification: filter })
      .then((res) => {
        if (generation !== requestGeneration.current) return
        setData(res); setError(null)
        if (unfiltered) {
          const list = Array.isArray(res?.items) ? res.items : []
          setSummary({ status: Array.isArray(res?.items) ? 'ok' : 'error', items: list, counts: res?.counts || null, atLimit: list.length >= SUMMARY_LIMIT })
        }
      })
      .catch(() => {
        if (generation !== requestGeneration.current) return
        setError('Could not load managed identity surfaces.')
        if (unfiltered) setSummary({ status: 'error', items: [], counts: null, atLimit: false })
      })
      .finally(() => { if (generation === requestGeneration.current) setLoading(false) })
  }, [workspaceId, filter])

  useEffect(() => { load(); return () => { requestGeneration.current += 1 } }, [load])

  const can = (item, action) => Array.isArray(item?.allowed_actions) && item.allowed_actions.includes(action)

  async function act(item, action) {
    const id = item.identity_exposure_id
    const payload = { action }
    if (action === 'classify_unexpected' || action === 'classify_investigate' || action === 'retire') {
      const what = action === 'retire' ? 'Retire' : action === 'classify_unexpected' ? 'Mark as unexpected' : 'Mark for investigation'
      const reason = await dialog.prompt({
        title: `${what}: ${item.primary_hostname || item.provider_name || 'this surface'}`,
        label: 'Reason',
        confirmLabel: what,
        tone: action === 'retire' ? 'danger' : undefined,
        required: true,
      })
      if (!reason) return
      payload.reason = reason
    } else if (action === 'record_exception') {
      const subject = item.primary_hostname || 'this surface'
      const reason = await dialog.prompt({ title: `Record an exception for ${subject}`, label: 'Exception reason', confirmLabel: 'Next', required: true })
      if (!reason) return
      const until = await dialog.prompt({ title: `Record an exception for ${subject}`, label: 'Exception expiry date', inputType: 'date', confirmLabel: 'Record exception', required: true })
      if (!until) return
      payload.reason = reason
      payload.exception_until = new Date(until).toISOString()
    } else if (action === 'assign_business_owner' || action === 'assign_technical_owner' || action === 'assign_identity_owner') {
      const role = action.replace('assign_', '').replace('_owner', '')
      const roleName = role[0].toUpperCase() + role.slice(1)
      const owner = await dialog.prompt({ title: `${roleName} owner for ${item.primary_hostname || 'this surface'}`, label: `${roleName} owner`, confirmLabel: 'Assign owner', required: true })
      if (!owner) return
      payload.owner = owner
    } else if (action === 'set_business_purpose') {
      const purpose = await dialog.prompt({ title: `Business purpose for ${item.primary_hostname || 'this surface'}`, label: 'Business purpose', confirmLabel: 'Save purpose' })
      if (purpose == null) return
      payload.business_purpose = purpose
    } else if (action === 'record_surface_removed' || action === 'record_configuration_changed') {
      if (!(await dialog.confirm({
        title: 'Record this as done?',
        message: 'This is your assertion only. CyberMeters will not mark it verified until it re-observes the expected change externally.',
        confirmLabel: 'Record as done',
      }))) return
    }
    setBusy(id)
    try {
      if (action === 'request_verification') await api.identitySurfaceVerify(workspaceId, id)
      else await api.identitySurfaceAction(workspaceId, id, payload)
      load()
    } catch { setError('Action failed.') }
    finally { setBusy(null) }
  }

  const items = data?.items || []
  const counts = data?.counts || {}
  const isEmpty = !loading && !error && items.length === 0 && !filter

  if (!wsLoading && !workspaceId) return <NoWorkspaceSelected />

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <ModuleContract
        domainKey="identity_exposure"
        workspaceId={workspaceId}
        workspaceName={workspaceName}
        description="Review and own provider relationships and possible identity-facing hostnames for your domains."
        actions={<Link to="/ws/identity-assets" className="btn-secondary inline-flex text-sm">People &amp; evidence →</Link>}
        /* The area template (18 Oct 2026): a real empty state — one sentence on what
           fills this page, and the one button that does it in "Do this next". */
        figures={isEmpty ? null : identitySummaryFigures(summary)}
        nextAction={isEmpty ? {
          title: 'No identity records yet',
          body: 'This page fills after a scan finds a provider relationship or a possible identity-facing hostname for a monitored domain.',
          label: 'Run a scan',
          to: '/scans/new',
        } : null}
        overview={isEmpty ? (
          <div className="card p-6" data-testid="identity-empty">
            <p className="text-sm text-gray-700">This page fills after a scan finds a provider relationship or a possible identity-facing hostname for a monitored domain.</p>
          </div>
        ) : (
          <>
            {/* Backend counts per classification — the customer's own record, not a verdict. */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3" data-testid="identity-classification-counts">
              {CLASS_FILTERS.filter((c) => c !== '').map((c) => (
                <div key={c} className="card p-4">
                  <p className="text-[15px] font-semibold text-gray-900 leading-snug">{classificationMeta(c).label}</p>
                  <p className="text-[14px] font-bold mt-2 leading-none tabular-nums text-gray-800">{loading ? '…' : error ? '—' : (counts[c] ?? 0)}</p>
                </div>
              ))}
            </div>
          </>
        )}
      >
      <h2 className="font-semibold text-slate-800 mt-6">Login-surface review</h2>
      <div className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-500 my-3">
        {IDENTITY_SCOPE_NOTE}
      </div>

      <div className="flex flex-wrap items-center gap-2 my-4">
        {CLASS_FILTERS.map((c) => (
          <button
            key={c || 'all'}
            onClick={() => setFilter(c)}
            className={`text-xs rounded-full border px-3 py-1 ${filter === c ? 'bg-slate-800 text-white border-slate-800' : 'bg-white text-slate-600 border-slate-200'}`}
          >
            {c === '' ? (summary.status === 'ok' ? `All (${summary.atLimit ? `${SUMMARY_LIMIT}+` : summary.items.length})` : 'All') : `${classificationMeta(c).label} (${counts[c] ?? 0})`}
          </button>
        ))}
      </div>

      {loading && <p className="text-sm text-slate-400">Loading…</p>}
      {error && <p className="text-sm text-red-700">{error}</p>}
      {!loading && !error && items.length === 0 && (
        <p className="text-sm text-slate-400">No managed identity evidence yet. Records appear here after a scan identifies a provider relationship or possible identity-facing hostname for a monitored domain.</p>
      )}

      {!loading && !error && items.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-slate-400 border-b border-slate-100">
                <th className="py-2 px-3 font-medium">Surface</th>
                <th className="py-2 px-3 font-medium">Observed</th>
                <th className="py-2 px-3 font-medium">Risk</th>
                <th className="py-2 px-3 font-medium">Classification</th>
                <th className="py-2 px-3 font-medium">Owner</th>
                <th className="py-2 px-3 font-medium">Verification</th>
                <th className="py-2 px-3 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((it) => (
                <Fragment key={it.identity_exposure_id}>
                <tr className="border-b border-slate-50 align-top">
                  <td className="py-2 px-3">
                    <div className="font-medium text-slate-700">{it.primary_hostname || it.provider_name || surfaceLabel(it.surface_type)}</div>
                    <div className="text-xs text-slate-400">{surfaceLabel(it.surface_type)}{it.provider_name ? ` · ${it.provider_name}` : ''}</div>
                    <div className="text-xs text-slate-400">{identityClaimMeta(it.identity_claim).label}</div>
                    <div className="text-xs text-slate-400">{confidenceDetailLabel(it.confidence_detail)} · reachability {it.identity_claim?.reachability?.status?.replace(/_/g, ' ') || 'not evaluated'}</div>
                    {it.linked_case_id && (
                      <Link to={`/ws/cases/${encodeURIComponent(it.linked_case_id)}`} className="text-xs text-brand-700 hover:underline">
                        Open case →
                      </Link>
                    )}
                  </td>
                  <td className="py-2 px-3 text-xs text-slate-600 min-w-48">
                    <div>First seen: {it.first_seen_at || 'Not available'}</div>
                    <div>Last seen: {it.last_seen_at || 'Not available'}</div>
                    {Array.isArray(it.measured_endpoints) && it.measured_endpoints.length > 0 && (
                      <div className="mt-1 break-all">Measured: {it.measured_endpoints.join(', ')}</div>
                    )}
                    <div className="mt-1">Monitoring: {it.monitoring_status || 'Not available'}</div>
                    {it.monitoring_reason && <div>Reason: {it.monitoring_reason}</div>}
                  </td>
                  <td className="py-2 px-3">
                    <Pill meta={riskMeta(it.risk_status)} />
                    {it.recurrence_type && <div className="text-xs text-brand-700 mt-0.5">{it.recurrence_type.replace(/_/g, ' ')}</div>}
                  </td>
                  <td className="py-2 px-3">
                    <Pill meta={classificationMeta(it.customer_classification)} />
                    <div className="text-xs text-slate-400 mt-0.5">Classified by you</div>
                  </td>
                  <td className="py-2 px-3">
                    <Pill meta={ownershipMeta(it.ownership_status)} />
                    {(it.business_owner || it.technical_owner || it.identity_owner) && (
                      <div className="text-xs text-slate-400 mt-0.5">{it.identity_owner || it.technical_owner || it.business_owner}</div>
                    )}
                  </td>
                  <td className="py-2 px-3">
                    <Pill meta={verificationMeta(it.verification_status)} />
                    {isAwaitingVerification(it) && (
                      <div className="text-xs text-brand-700 mt-0.5">Recorded by you — not yet verified</div>
                    )}
                    {it.verified_at && <div className="text-xs text-slate-300 mt-0.5">Verified by CyberMeters {it.verified_at.slice(0, 10)}</div>}
                  </td>
                  <td className="py-2 px-3">
                    <div className="flex flex-wrap gap-1">
                      <button
                        type="button"
                        className="text-xs rounded-sm border border-slate-200 text-slate-700 px-2 py-0.5"
                        aria-expanded={expandedId === it.identity_exposure_id}
                        aria-controls={`identity-history-${it.identity_exposure_id}`}
                        onClick={() => setExpandedId(expandedId === it.identity_exposure_id ? null : it.identity_exposure_id)}
                      >History</button>
                      {can(it, 'classify_expected') && <button disabled={busy === it.identity_exposure_id} onClick={() => act(it, 'classify_expected')} className="text-xs rounded-sm border border-brand-200 text-brand-700 px-2 py-0.5">Expected</button>}
                      {can(it, 'classify_unexpected') && <button disabled={busy === it.identity_exposure_id} onClick={() => act(it, 'classify_unexpected')} className="text-xs rounded-sm border border-red-200 text-red-700 px-2 py-0.5">Unexpected</button>}
                      {can(it, 'assign_identity_owner') && <button disabled={busy === it.identity_exposure_id} onClick={() => act(it, 'assign_identity_owner')} className="text-xs rounded-sm border border-slate-200 text-slate-600 px-2 py-0.5">Owner</button>}
                      {can(it, 'record_surface_removed') && <button disabled={busy === it.identity_exposure_id} onClick={() => act(it, 'record_surface_removed')} className="text-xs rounded-sm border border-slate-200 text-slate-600 px-2 py-0.5">Record removed</button>}
                      {can(it, 'request_verification') && <button disabled={busy === it.identity_exposure_id} onClick={() => act(it, 'request_verification')} className="text-xs rounded-sm border border-blue-200 text-blue-700 px-2 py-0.5">Verify</button>}
                      {can(it, 'record_exception') && <button disabled={busy === it.identity_exposure_id} onClick={() => act(it, 'record_exception')} className="text-xs rounded-sm border border-[1.5px] border-brand-700 text-brand-700 px-2 py-0.5">Exception</button>}
                      {can(it, 'retire') && <button disabled={busy === it.identity_exposure_id} onClick={() => act(it, 'retire')} className="text-xs rounded-sm border border-slate-200 text-slate-600 px-2 py-0.5">Retire</button>}
                    </div>
                  </td>
                </tr>
                {expandedId === it.identity_exposure_id && <tr id={`identity-history-${it.identity_exposure_id}`}>
                  <td colSpan={7} className="bg-slate-50 p-4">
                    <IdentitySurfaceDetail workspaceId={workspaceId} recordId={it.identity_exposure_id} />
                  </td>
                </tr>}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <MeasuredEndpoints status={summary.status} items={summary.items} atLimit={summary.atLimit} />
      </ModuleContract>
      {dialog.element}
    </div>
  )
}
