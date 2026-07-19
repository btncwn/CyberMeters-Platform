// Identity Exposure Managed Workflow — a focused managed surface (not a nav or
// dashboard redesign). It renders the server-owned canonical managed identity
// records and posts classification / ownership / remediation / verification
// actions the BACKEND validates. The set of allowed actions comes from the server
// response — the frontend never invents risk, verification, or actions. It draws
// a hard, visible line between what is OBSERVED EXTERNALLY, what the CUSTOMER
// classified, and what CyberMeters has VERIFIED.
import { useEffect, useState, useCallback } from 'react'
import { api } from '../../api'
import { useWorkspace } from '../../hooks/useWorkspace'
import { NoWorkspaceSelected } from '../../components/WsPage'
import {
  classificationMeta, riskMeta, ownershipMeta, verificationMeta, surfaceLabel, toneClass,
  isAwaitingVerification, IDENTITY_SCOPE_NOTE,
} from '../../lib/identityExposureDisplay'

function Pill({ meta }) {
  return <span className={`inline-block rounded-full border px-2 py-0.5 text-xs ${toneClass(meta.tone)}`}>{meta.label}</span>
}

const CLASS_FILTERS = ['', 'unreviewed', 'expected', 'unexpected', 'investigate', 'exception', 'retired']

export default function IdentityExposurePage() {
  // Workspace comes from the canonical context hook, not a route param — the
  // /ws/* routes declare no :workspaceId, so useParams().workspaceId is always
  // undefined and would produce /api/workspaces/undefined/... (403).
  const { wsId: workspaceId, loading: wsLoading } = useWorkspace()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('')
  const [busy, setBusy] = useState(null)

  const load = useCallback(() => {
    if (!workspaceId) return   // never call the API with a null/unresolved workspace id
    setLoading(true)
    api.getIdentitySurfaces(workspaceId, filter ? { customer_classification: filter } : {})
      .then((res) => { setData(res); setError(null) })
      .catch(() => setError('Could not load managed identity surfaces.'))
      .finally(() => setLoading(false))
  }, [workspaceId, filter])

  useEffect(() => { load() }, [load])

  const serverActions = data?.actions || []
  const can = (a) => serverActions.includes(a)

  async function act(item, action) {
    const id = item.identity_exposure_id
    const payload = { action }
    if (action === 'classify_unexpected' || action === 'classify_investigate' || action === 'retire') {
      const reason = window.prompt(`Reason for "${action.replace(/_/g, ' ')}" of ${item.primary_hostname || item.provider_name || 'this surface'}:`)
      if (!reason) return
      payload.reason = reason
    } else if (action === 'record_exception') {
      const reason = window.prompt(`Exception reason for ${item.primary_hostname || 'this surface'}:`)
      if (!reason) return
      const until = window.prompt('Exception expiry (YYYY-MM-DD):')
      if (!until) return
      payload.reason = reason
      payload.exception_until = new Date(until).toISOString()
    } else if (action === 'assign_business_owner' || action === 'assign_technical_owner' || action === 'assign_identity_owner') {
      const role = action.replace('assign_', '').replace('_owner', '')
      const owner = window.prompt(`${role[0].toUpperCase() + role.slice(1)} owner for ${item.primary_hostname || 'this surface'}:`)
      if (!owner) return
      payload.owner = owner
    } else if (action === 'set_business_purpose') {
      const purpose = window.prompt('Business purpose for this surface:')
      if (purpose == null) return
      payload.business_purpose = purpose
    } else if (action === 'record_surface_removed' || action === 'record_configuration_changed') {
      if (!window.confirm('Record this as done?\n\nThis is your assertion only — CyberMeters will NOT mark it verified until it re-observes the expected change externally.')) return
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

  if (!wsLoading && !workspaceId) return <NoWorkspaceSelected />

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="mb-2">
        <h1 className="text-xl font-semibold text-slate-800">Identity Exposure</h1>
        <p className="text-sm text-slate-500 mt-1">
          Review, own, remediate and verify the public identity and login surfaces observed for your domains.
        </p>
      </div>

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
            {c === '' ? `All (${items.length})` : `${classificationMeta(c).label} (${counts[c] ?? 0})`}
          </button>
        ))}
      </div>

      {loading && <p className="text-sm text-slate-400">Loading…</p>}
      {error && <p className="text-sm text-red-600">{error}</p>}
      {!loading && !error && items.length === 0 && (
        <p className="text-sm text-slate-400">No managed identity surfaces yet. Records appear here after a scan observes identity providers or login surfaces for a monitored domain.</p>
      )}

      {!loading && !error && items.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-slate-400 border-b border-slate-100">
                <th className="py-2 px-3 font-medium">Surface</th>
                <th className="py-2 px-3 font-medium">Risk</th>
                <th className="py-2 px-3 font-medium">Classification</th>
                <th className="py-2 px-3 font-medium">Owner</th>
                <th className="py-2 px-3 font-medium">Verification</th>
                <th className="py-2 px-3 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((it) => (
                <tr key={it.identity_exposure_id} className="border-b border-slate-50 align-top">
                  <td className="py-2 px-3">
                    <div className="font-medium text-slate-700">{it.primary_hostname || it.provider_name || surfaceLabel(it.surface_type)}</div>
                    <div className="text-xs text-slate-400">{surfaceLabel(it.surface_type)}{it.provider_name ? ` · ${it.provider_name}` : ''}</div>
                    <div className="text-[11px] text-slate-400">Observed externally{it.confidence ? ` · ${it.confidence} confidence` : ''}</div>
                    {it.linked_case_id && <div className="text-xs text-amber-600">Open case</div>}
                  </td>
                  <td className="py-2 px-3">
                    <Pill meta={riskMeta(it.risk_status)} />
                    {it.recurrence_type && <div className="text-xs text-amber-600 mt-0.5">{it.recurrence_type.replace(/_/g, ' ')}</div>}
                  </td>
                  <td className="py-2 px-3">
                    <Pill meta={classificationMeta(it.customer_classification)} />
                    <div className="text-[11px] text-slate-400 mt-0.5">Classified by you</div>
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
                      <div className="text-xs text-amber-600 mt-0.5">Recorded by you — not yet verified</div>
                    )}
                    {it.verified_at && <div className="text-[11px] text-slate-300 mt-0.5">Verified by CyberMeters {it.verified_at.slice(0, 10)}</div>}
                  </td>
                  <td className="py-2 px-3">
                    <div className="flex flex-wrap gap-1">
                      {can('classify_expected') && <button disabled={busy === it.identity_exposure_id} onClick={() => act(it, 'classify_expected')} className="text-xs rounded border border-green-200 text-green-700 px-2 py-0.5">Expected</button>}
                      {can('classify_unexpected') && <button disabled={busy === it.identity_exposure_id} onClick={() => act(it, 'classify_unexpected')} className="text-xs rounded border border-red-200 text-red-700 px-2 py-0.5">Unexpected</button>}
                      {can('assign_identity_owner') && <button disabled={busy === it.identity_exposure_id} onClick={() => act(it, 'assign_identity_owner')} className="text-xs rounded border border-slate-200 text-slate-600 px-2 py-0.5">Owner</button>}
                      {can('record_surface_removed') && <button disabled={busy === it.identity_exposure_id} onClick={() => act(it, 'record_surface_removed')} className="text-xs rounded border border-slate-200 text-slate-600 px-2 py-0.5">Record removed</button>}
                      {can('request_verification') && <button disabled={busy === it.identity_exposure_id} onClick={() => act(it, 'request_verification')} className="text-xs rounded border border-blue-200 text-blue-700 px-2 py-0.5">Verify</button>}
                      {can('record_exception') && <button disabled={busy === it.identity_exposure_id} onClick={() => act(it, 'record_exception')} className="text-xs rounded border border-amber-200 text-amber-700 px-2 py-0.5">Exception</button>}
                      {can('retire') && <button disabled={busy === it.identity_exposure_id} onClick={() => act(it, 'retire')} className="text-xs rounded border border-slate-200 text-slate-600 px-2 py-0.5">Retire</button>}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
