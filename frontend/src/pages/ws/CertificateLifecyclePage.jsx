// Certificates Managed Lifecycle â a focused managed surface (not a nav/dashboard
// redesign). It renders the server-owned canonical certificate lifecycle and
// posts ownership / planning / verification actions the BACKEND validates. The
// set of allowed actions comes from the server response â the frontend never
// invents renewal states, verification results, or actions. It draws a hard,
// visible line between a CUSTOMER-RECORDED renewal (asserted) and an EXTERNALLY
// VERIFIED replacement (the product actually observed a distinct new cert).
import { useEffect, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../../api'
import { useWorkspace } from '../../hooks/useWorkspace'
import { NoWorkspaceSelected } from '../../components/WsPage'
import {
  readinessMeta, coverageMeta, ownershipMeta, verificationMeta, toneClass,
  daysRemainingLabel, isAwaitingVerification, CERT_LIFECYCLE_SCOPE_NOTE,
} from '../../lib/certificateLifecycleDisplay'

function Pill({ meta }) {
  return <span className={`inline-block rounded-full border px-2 py-0.5 text-xs ${toneClass(meta.tone)}`}>{meta.label}</span>
}

const READINESS_FILTERS = ['', 'critical', 'high', 'preparation', 'planning', 'monitoring', 'expired']

export default function CertificateLifecyclePage() {
  // Workspace comes from the canonical context hook, not a route param â the
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
    api.getCertificateLifecycle(workspaceId, filter ? { renewal_readiness: filter } : {})
      .then((res) => { setData(res); setError(null) })
      .catch(() => setError('Could not load the certificate lifecycle.'))
      .finally(() => setLoading(false))
  }, [workspaceId, filter])

  useEffect(() => { load() }, [load])

  const serverActions = data?.actions || []
  const can = (a) => serverActions.includes(a)

  async function act(item, action) {
    const id = item.certificate_lifecycle_id
    const payload = { action }
    if (action === 'set_expected_hostnames') {
      const raw = window.prompt(`Expected hostnames for ${item.primary_hostname} (comma-separated):`,
        (item.expected_hostnames || []).join(', ') || item.primary_hostname)
      if (raw == null) return
      payload.expected_hostnames = raw.split(',').map((h) => h.trim()).filter(Boolean)
    } else if (action === 'assign_business_owner' || action === 'assign_technical_owner' || action === 'assign_renewal_owner') {
      const role = action.replace('assign_', '').replace('_owner', '')
      const owner = window.prompt(`${role[0].toUpperCase() + role.slice(1)} owner for ${item.primary_hostname}:`)
      if (!owner) return
      payload.owner = owner
    } else if (action === 'record_provider') {
      const provider = window.prompt(`Certificate provider / CA for ${item.primary_hostname}:`, item.provider || '')
      if (provider == null) return
      payload.provider = provider
    } else if (action === 'record_replacement_expected') {
      const when = window.prompt('Expected replacement date (YYYY-MM-DD):')
      if (!when) return
      payload.replacement_expected_at = new Date(when).toISOString()
    } else if (action === 'record_replacement_completed') {
      if (!window.confirm('Record that you have installed the replacement certificate?\n\nThis is your assertion only â CyberMeters will NOT mark it verified until it observes a distinct new certificate on the expected hostnames with a later expiry.')) return
    } else if (action === 'record_exception') {
      const reason = window.prompt(`Exception reason for ${item.primary_hostname}:`)
      if (!reason) return
      const until = window.prompt('Exception expiry (YYYY-MM-DD):')
      if (!until) return
      payload.reason = reason
      payload.exception_until = new Date(until).toISOString()
    } else if (action === 'retire') {
      const reason = window.prompt(`Reason for retiring ${item.primary_hostname}:`)
      if (!reason) return
      payload.reason = reason
    }
    setBusy(id)
    try {
      if (action === 'request_verification') await api.certificateLifecycleVerify(workspaceId, id)
      else await api.certificateLifecycleAction(workspaceId, id, payload)
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
        <h1 className="text-xl font-semibold text-slate-800">Certificate Lifecycle</h1>
        <p className="text-sm text-slate-500 mt-1">
          Observe, own, plan renewal, and verify replacement for every monitored certificate.
        </p>
      </div>

      <div className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-500 my-3">
        {CERT_LIFECYCLE_SCOPE_NOTE}
      </div>

      <div className="flex flex-wrap items-center gap-2 my-4">
        {READINESS_FILTERS.map((c) => (
          <button
            key={c || 'all'}
            onClick={() => setFilter(c)}
            className={`text-xs rounded-full border px-3 py-1 ${filter === c ? 'bg-slate-800 text-white border-slate-800' : 'bg-white text-slate-600 border-slate-200'}`}
          >
            {c === '' ? `All (${items.length})` : `${readinessMeta(c).label} (${counts[c] ?? 0})`}
          </button>
        ))}
      </div>

      {loading && <p className="text-sm text-slate-400">Loadingâ¦</p>}
      {error && <p className="text-sm text-red-600">{error}</p>}
      {!loading && !error && items.length === 0 && (
        <p className="text-sm text-slate-400">No certificates under management yet. Records appear here after a scan observes a certificate for a monitored domain.</p>
      )}

      {!loading && !error && items.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-slate-400 border-b border-slate-100">
                <th className="py-2 px-3 font-medium">Certificate</th>
                <th className="py-2 px-3 font-medium">Expiry / Renewal</th>
                <th className="py-2 px-3 font-medium">Coverage</th>
                <th className="py-2 px-3 font-medium">Owner</th>
                <th className="py-2 px-3 font-medium">Verification</th>
                <th className="py-2 px-3 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((it) => (
                <tr key={it.certificate_lifecycle_id} className="border-b border-slate-50 align-top">
                  <td className="py-2 px-3">
                    <div className="font-medium text-slate-700">{it.primary_hostname}</div>
                    <div className="text-xs text-slate-400">{it.issuer || 'Issuer unknown'}</div>
                    {it.replacement_detected_at && <div className="text-xs text-blue-600 mt-0.5">Replacement observed</div>}
                    {it.linked_case_id && (
                      <Link to={`/ws/cases/${encodeURIComponent(it.linked_case_id)}`} className="text-xs text-amber-600 hover:underline">
                        Open case →
                      </Link>
                    )}
                  </td>
                  <td className="py-2 px-3">
                    <Pill meta={readinessMeta(it.renewal_readiness)} />
                    <div className="text-xs text-slate-400 mt-0.5">{daysRemainingLabel(it.days_remaining)}</div>
                    {it.not_after && <div className="text-xs text-slate-300">{it.not_after.slice(0, 10)}</div>}
                  </td>
                  <td className="py-2 px-3">
                    <Pill meta={coverageMeta(it.coverage_status)} />
                    {Array.isArray(it.coverage_detail?.missing) && it.coverage_detail.missing.length > 0 && (
                      <div className="text-xs text-red-500 mt-0.5">Missing: {it.coverage_detail.missing.slice(0, 2).join(', ')}</div>
                    )}
                  </td>
                  <td className="py-2 px-3">
                    <Pill meta={ownershipMeta(it.ownership_status)} />
                    {(it.business_owner || it.technical_owner || it.renewal_owner) && (
                      <div className="text-xs text-slate-400 mt-0.5">{it.renewal_owner || it.technical_owner || it.business_owner}</div>
                    )}
                    {it.recurrence_type && <div className="text-xs text-amber-600 mt-0.5">{it.recurrence_type.replace(/_/g, ' ')}</div>}
                  </td>
                  <td className="py-2 px-3">
                    <Pill meta={verificationMeta(it.verification_status)} />
                    {isAwaitingVerification(it) && (
                      <div className="text-xs text-amber-600 mt-0.5">Recorded by you â not yet verified</div>
                    )}
                    {it.verified_at && <div className="text-xs text-slate-300 mt-0.5">Verified {it.verified_at.slice(0, 10)}</div>}
                  </td>
                  <td className="py-2 px-3">
                    <div className="flex flex-wrap gap-1">
                      {can('set_expected_hostnames') && <button disabled={busy === it.certificate_lifecycle_id} onClick={() => act(it, 'set_expected_hostnames')} className="text-xs rounded border border-slate-200 text-slate-600 px-2 py-0.5">Expected hosts</button>}
                      {can('assign_renewal_owner') && <button disabled={busy === it.certificate_lifecycle_id} onClick={() => act(it, 'assign_renewal_owner')} className="text-xs rounded border border-slate-200 text-slate-600 px-2 py-0.5">Owner</button>}
                      {can('plan_renewal') && <button disabled={busy === it.certificate_lifecycle_id} onClick={() => act(it, 'plan_renewal')} className="text-xs rounded border border-blue-200 text-blue-700 px-2 py-0.5">Plan</button>}
                      {can('record_replacement_completed') && <button disabled={busy === it.certificate_lifecycle_id} onClick={() => act(it, 'record_replacement_completed')} className="text-xs rounded border border-slate-200 text-slate-600 px-2 py-0.5">Record renewal</button>}
                      {can('request_verification') && <button disabled={busy === it.certificate_lifecycle_id} onClick={() => act(it, 'request_verification')} className="text-xs rounded border border-green-200 text-green-700 px-2 py-0.5">Verify</button>}
                      {can('record_exception') && <button disabled={busy === it.certificate_lifecycle_id} onClick={() => act(it, 'record_exception')} className="text-xs rounded border border-amber-200 text-amber-700 px-2 py-0.5">Exception</button>}
                      {can('retire') && <button disabled={busy === it.certificate_lifecycle_id} onClick={() => act(it, 'retire')} className="text-xs rounded border border-slate-200 text-slate-600 px-2 py-0.5">Retire</button>}
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
