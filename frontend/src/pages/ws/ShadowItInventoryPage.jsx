// Shadow IT & Unmanaged Technology — approved inventory page. A focused managed
// surface (not a nav/dashboard redesign). It renders the server-owned canonical
// inventory and posts classification/ownership/lifecycle actions the BACKEND
// validates. The set of allowed actions comes from the server response — the
// frontend never invents classification states or actions.
import { useEffect, useState, useCallback } from 'react'
import { api } from '../../api'
import { useWorkspace } from '../../hooks/useWorkspace'
import { NoWorkspaceSelected } from '../../components/WsPage'
import {
  classificationMeta, monitoringMeta, ownershipMeta, toneClass, SHADOW_IT_SCOPE_NOTE,
} from '../../lib/shadowItDisplay'

function Pill({ meta }) {
  return <span className={`inline-block rounded-full border px-2 py-0.5 text-xs ${toneClass(meta.tone)}`}>{meta.label}</span>
}

export default function ShadowItInventoryPage() {
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
    api.getShadowItInventory(workspaceId, filter ? { classification: filter } : {})
      .then((res) => { setData(res); setError(null) })
      .catch(() => setError('Could not load the technology inventory.'))
      .finally(() => setLoading(false))
  }, [workspaceId, filter])

  useEffect(() => { load() }, [load])

  // Allowed actions are server-provided; the UI only surfaces those.
  const serverActions = data?.actions || []
  const can = (a) => serverActions.includes(a)

  async function act(item, action) {
    const payload = { action }
    if (action === 'reject' || action === 'retire') {
      const reason = window.prompt(`Reason for "${action}" of ${item.display_name}:`)
      if (!reason) return
      payload.reason = reason
    } else if (action === 'mark_exception') {
      const reason = window.prompt(`Exception reason for ${item.display_name}:`)
      if (!reason) return
      const until = window.prompt('Exception expiry (YYYY-MM-DD):')
      if (!until) return
      payload.reason = reason
      payload.exception_until = new Date(until).toISOString()
    } else if (action === 'assign_business_owner' || action === 'assign_technical_owner') {
      const owner = window.prompt(`${action === 'assign_business_owner' ? 'Business' : 'Technical'} owner for ${item.display_name}:`)
      if (!owner) return
      payload.owner = owner
    } else if (action === 'set_business_purpose') {
      const purpose = window.prompt(`Business purpose for ${item.display_name}:`)
      if (purpose == null) return
      payload.business_purpose = purpose
    }
    setBusy(item.inventory_item_id)
    try { await api.shadowItAction(workspaceId, item.inventory_item_id, payload); load() }
    catch { setError('Action failed.') }
    finally { setBusy(null) }
  }

  const items = data?.items || []
  const counts = data?.counts || {}

  if (!wsLoading && !workspaceId) return <NoWorkspaceSelected />

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="mb-2">
        <h1 className="text-xl font-semibold text-slate-800">Shadow IT &amp; Unmanaged Technology</h1>
        <p className="text-sm text-slate-500 mt-1">{SHADOW_IT_SCOPE_NOTE}</p>
      </div>

      <div className="flex flex-wrap items-center gap-2 my-4">
        {['', 'unreviewed', 'approved', 'rejected', 'exception', 'retired'].map((c) => (
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
        <p className="text-sm text-slate-400">No externally observed technology recorded yet. Items appear here after a scan correlates observed vendors and services.</p>
      )}

      {!loading && !error && items.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-slate-400 border-b border-slate-100">
                <th className="py-2 px-3 font-medium">Technology</th>
                <th className="py-2 px-3 font-medium">Category</th>
                <th className="py-2 px-3 font-medium">Classification</th>
                <th className="py-2 px-3 font-medium">Owner</th>
                <th className="py-2 px-3 font-medium">Monitoring</th>
                <th className="py-2 px-3 font-medium">Last seen</th>
                <th className="py-2 px-3 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((it) => (
                <tr key={it.inventory_item_id} className="border-b border-slate-50 align-top">
                  <td className="py-2 px-3">
                    <div className="font-medium text-slate-700">{it.display_name}</div>
                    <div className="text-xs text-slate-400">{it.provider}{it.confidence ? ` · ${it.confidence} confidence` : ''}</div>
                    {it.linked_case_id && <div className="text-xs text-amber-600">Open case</div>}
                  </td>
                  <td className="py-2 px-3 text-slate-500 capitalize">{(it.category || '—').replace(/_/g, ' ')}</td>
                  <td className="py-2 px-3"><Pill meta={classificationMeta(it.classification)} /></td>
                  <td className="py-2 px-3">
                    <Pill meta={ownershipMeta(it.ownership_status)} />
                    {(it.business_owner || it.technical_owner) && <div className="text-xs text-slate-400 mt-0.5">{it.business_owner || it.technical_owner}</div>}
                    {it.recurrence_type && <div className="text-xs text-amber-600 mt-0.5">{it.recurrence_type.replace(/_/g, ' ')}</div>}
                  </td>
                  <td className="py-2 px-3"><Pill meta={monitoringMeta(it.monitoring_status)} /></td>
                  <td className="py-2 px-3 text-slate-400 text-xs">{it.last_seen_at ? it.last_seen_at.slice(0, 10) : '—'}</td>
                  <td className="py-2 px-3">
                    <div className="flex flex-wrap gap-1">
                      {can('approve') && <button disabled={busy === it.inventory_item_id} onClick={() => act(it, 'approve')} className="text-xs rounded border border-green-200 text-green-700 px-2 py-0.5">Approve</button>}
                      {can('reject') && <button disabled={busy === it.inventory_item_id} onClick={() => act(it, 'reject')} className="text-xs rounded border border-red-200 text-red-700 px-2 py-0.5">Reject</button>}
                      {can('mark_exception') && <button disabled={busy === it.inventory_item_id} onClick={() => act(it, 'mark_exception')} className="text-xs rounded border border-amber-200 text-amber-700 px-2 py-0.5">Exception</button>}
                      {can('assign_business_owner') && <button disabled={busy === it.inventory_item_id} onClick={() => act(it, 'assign_business_owner')} className="text-xs rounded border border-slate-200 text-slate-600 px-2 py-0.5">Owner</button>}
                      {can('set_business_purpose') && <button disabled={busy === it.inventory_item_id} onClick={() => act(it, 'set_business_purpose')} className="text-xs rounded border border-slate-200 text-slate-600 px-2 py-0.5">Purpose</button>}
                      {can('retire') && <button disabled={busy === it.inventory_item_id} onClick={() => act(it, 'retire')} className="text-xs rounded border border-slate-200 text-slate-600 px-2 py-0.5">Retire</button>}
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
