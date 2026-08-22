// Shadow IT & Unmanaged Technology — approved inventory page. A focused managed
// surface (not a nav/dashboard redesign). It renders the server-owned canonical
// inventory and posts classification/ownership/lifecycle actions the BACKEND
// validates. The set of allowed actions comes from the server response — the
// frontend never invents classification states or actions.
import { useEffect, useState, useCallback, useRef } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import { api } from '../../api'
import { useWorkspace } from '../../hooks/useWorkspace'
import { NoWorkspaceSelected } from '../../components/WsPage'
import {
  SHADOW_IT_FIRST_OBSERVATION_LABEL,
  classificationMeta, monitoringMeta, ownershipMeta, onboardingMeta, removalMeta,
  toneClass, SHADOW_IT_SCOPE_NOTE,
} from '../../lib/shadowItDisplay'

function Pill({ meta }) {
  return <span className={`inline-block rounded-full border px-2 py-0.5 text-xs ${toneClass(meta.tone)}`}>{meta.label}</span>
}

// The customer-facing action surface. Grouping mirrors the BACKEND's own field
// grouping (classification / ownership / onboarding_status / removal_status) so
// the UI introduces no taxonomy of its own — the action names are the server's
// verbatim, and a control is rendered ONLY when the server advertises it.
// Tailwind classes are written as whole literal strings so the JIT scanner can
// see them; never build these by concatenation.
const ACTION_TONE = {
  green: 'border-green-200 text-green-700',
  red:   'border-red-200 text-red-700',
  amber: 'border-amber-200 text-amber-700',
  slate: 'border-slate-200 text-slate-600',
}

const ACTION_GROUPS = [
  {
    key: 'classification',
    label: 'Classification',
    actions: [
      { action: 'approve',        label: 'Approve',       tone: 'green' },
      { action: 'reject',         label: 'Reject',        tone: 'red'   },
      { action: 'mark_exception', label: 'Exception',     tone: 'amber' },
      { action: 'retire',         label: 'Retire',        tone: 'slate' },
      { action: 'reopen_review',  label: 'Reopen review', tone: 'slate' },
    ],
  },
  {
    key: 'ownership',
    label: 'Ownership',
    actions: [
      // Two distinct owner roles now exist, so the original "Owner" label is
      // disambiguated rather than left ambiguous.
      { action: 'assign_business_owner',  label: 'Business owner',  tone: 'slate' },
      { action: 'assign_technical_owner', label: 'Technical owner', tone: 'slate' },
      { action: 'set_business_purpose',   label: 'Purpose',         tone: 'slate' },
    ],
  },
  {
    key: 'onboarding',
    label: 'Onboarding',
    actions: [
      { action: 'begin_onboarding', label: 'Start onboarding', tone: 'slate' },
      { action: 'mark_onboarded',   label: 'Mark onboarded',   tone: 'slate' },
    ],
  },
  {
    key: 'removal',
    label: 'Removal',
    actions: [
      { action: 'begin_removal', label: 'Start removal', tone: 'slate' },
      // Customer assertion only — see the confirmation copy in act().
      { action: 'mark_removed',  label: 'Mark removed',  tone: 'slate' },
    ],
  },
]

// Human label for an action, used in customer-facing failure copy so an error
// never shows a raw backend enum.
const ACTION_LABEL = Object.fromEntries(
  ACTION_GROUPS.flatMap((g) => g.actions.map((a) => [a.action, a.label])),
)

export default function ShadowItInventoryPage() {
  // Workspace comes from the canonical context hook, not a route param — the
  // /ws/* routes declare no :workspaceId, so useParams().workspaceId is always
  // undefined and would produce /api/workspaces/undefined/... (403).
  const { wsId: workspaceId, loading: wsLoading } = useWorkspace()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  // Action failures are held SEPARATELY from the load error. The list below is
  // rendered only when `error` is null, so reusing one slot meant a single failed
  // action erased the entire inventory the customer was working in.
  const [actionError, setActionError] = useState(null)
  const [filter, setFilter] = useState('')
  const [busy, setBusy] = useState(null)
  // Deep-link target from an alert CTA (/ws/shadow-it?item=<id>). The id is the
  // server's own opaque surrogate; the list below is already workspace-scoped, so
  // a foreign id simply matches nothing.
  const [searchParams] = useSearchParams()
  const focusItemId = searchParams.get('item')
  const focusRef = useRef(null)
  useEffect(() => {
    if (focusRef.current) focusRef.current.scrollIntoView({ block: 'center' })
  }, [data, focusItemId])

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
    } else if (action === 'reopen_review') {
      // Returns the item to "Not yet classified" — the reason is optional at the
      // backend, so an empty answer is accepted but a cancel aborts.
      const reason = window.prompt(`Reopen ${item.display_name} for review — reason (optional):`)
      if (reason == null) return
      payload.reason = reason
    } else if (action === 'mark_removed') {
      // Customer assertion, never a CyberMeters verification. The backend records
      // this as `customer_asserted_not_verified`; the confirmation must say the
      // same thing in the customer's own words rather than imply confirmation.
      const confirmed = window.confirm(
        `Record that ${item.display_name} has been removed?\n\n` +
        'This records YOUR assertion. CyberMeters has not verified the removal — ' +
        'if the technology is still observed externally, this item will be shown ' +
        'as contradicting your assertion.',
      )
      if (!confirmed) return
    }
    setActionError(null)
    setBusy(item.inventory_item_id)
    try { await api.shadowItAction(workspaceId, item.inventory_item_id, payload); load() }
    catch {
      // Deliberately claims nothing about server state: the request failed from
      // here, which does not prove the change was not applied.
      setActionError(`“${ACTION_LABEL[action] || action}” did not complete for ${item.display_name}. The list below may not reflect the latest state — reload to confirm.`)
    }
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
      {/* Action-level failure. Rendered ABOVE the inventory and deliberately not
          part of the table's render gate, so a failed action never removes the
          list the customer is working in. */}
      {actionError && (
        <div role="alert" className="mb-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          {actionError}
        </div>
      )}
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
                <tr
                  key={it.inventory_item_id}
                  ref={it.inventory_item_id === focusItemId ? focusRef : null}
                  className={`border-b border-slate-50 align-top ${it.inventory_item_id === focusItemId ? 'bg-amber-50/60 ring-1 ring-inset ring-amber-200' : ''}`}
                >
                  <td className="py-2 px-3">
                    <div className="font-medium text-slate-700">
                      {it.display_name}
                      {/* BL-1: the backend owns this flag (same event + same 7-day
                          window as the weekly digest), so the indicator and the
                          digest can never disagree. Observation is not a verdict —
                          this says CyberMeters saw it and nobody has reviewed it. */}
                      {it.newly_observed === true && (
                        <span
                          className="ml-2 inline-flex items-center rounded-full bg-sky-50 px-2 py-0.5 text-[10px] font-semibold text-sky-700 ring-1 ring-sky-200 align-middle"
                          title={SHADOW_IT_FIRST_OBSERVATION_LABEL}
                        >
                          New
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-slate-400">{it.provider}{it.confidence ? ` · ${it.confidence} confidence` : ''}</div>
                    {it.linked_case_id && (
                      <Link to={`/ws/cases/${encodeURIComponent(it.linked_case_id)}`} className="text-xs text-amber-600 hover:underline">
                        Open case →
                      </Link>
                    )}
                    {it.inventory_item_id === focusItemId && (it.observed_hostnames || []).length > 0 && (
                      <div className="text-xs text-slate-400 mt-0.5">Observed: {it.observed_hostnames.slice(0, 2).join(', ')}</div>
                    )}
                  </td>
                  <td className="py-2 px-3 text-slate-500 capitalize">{(it.category || '—').replace(/_/g, ' ')}</td>
                  <td className="py-2 px-3">
                    <Pill meta={classificationMeta(it.classification)} />
                    {/* Managed lifecycle the customer drives through the actions
                        below. Rendered here rather than under Monitoring because
                        these are customer decisions, not external observations —
                        and a control whose effect is invisible is not usable. */}
                    {onboardingMeta(it.onboarding_status) && (
                      <div className="text-xs text-slate-500 mt-1">{onboardingMeta(it.onboarding_status).label}</div>
                    )}
                    {removalMeta(it.removal_status, it.removal_verified) && (
                      <div className={`text-xs mt-0.5 ${removalMeta(it.removal_status, it.removal_verified).tone === 'red' ? 'text-red-600' : removalMeta(it.removal_status, it.removal_verified).tone === 'amber' ? 'text-amber-600' : 'text-slate-500'}`}>
                        {removalMeta(it.removal_status, it.removal_verified).label}
                      </div>
                    )}
                  </td>
                  <td className="py-2 px-3">
                    <Pill meta={ownershipMeta(it.ownership_status)} />
                    {(it.business_owner || it.technical_owner) && <div className="text-xs text-slate-400 mt-0.5">{it.business_owner || it.technical_owner}</div>}
                    {/* Server-owned recurrence meaning — the same sentence the alert
                        email and in-app card carry. Falls back to the raw type only
                        when the server sent no summary. */}
                    {(it.recurrence_summary || it.recurrence_type) && (
                      <div className="text-xs text-amber-600 mt-0.5">{it.recurrence_summary || it.recurrence_type.replace(/_/g, ' ')}</div>
                    )}
                    {it.inventory_item_id === focusItemId && it.recommended_next_action && (
                      <div className="text-xs text-slate-500 mt-0.5"><span className="font-medium">Recommended:</span> {it.recommended_next_action}</div>
                    )}
                  </td>
                  <td className="py-2 px-3"><Pill meta={monitoringMeta(it.monitoring_status)} /></td>
                  <td className="py-2 px-3 text-slate-400 text-xs">{it.last_seen_at ? it.last_seen_at.slice(0, 10) : '—'}</td>
                  <td className="py-2 px-3" aria-busy={busy === it.inventory_item_id}>
                    {/* One control per server-advertised action, grouped for
                        hierarchy. A group disappears entirely when the server
                        advertises none of its actions, so a viewer (actions: [])
                        sees no action surface at all. */}
                    <div className="space-y-1.5 min-w-[12rem]">
                      {ACTION_GROUPS.map((group) => {
                        const available = group.actions.filter((a) => can(a.action))
                        if (available.length === 0) return null
                        return (
                          <div key={group.key} role="group" aria-label={`${group.label} actions for ${it.display_name}`}>
                            <div className="text-[10px] uppercase tracking-wide text-slate-400">{group.label}</div>
                            <div className="flex flex-wrap gap-1 mt-0.5">
                              {available.map((a) => (
                                <button
                                  key={a.action}
                                  type="button"
                                  disabled={busy === it.inventory_item_id}
                                  onClick={() => act(it, a.action)}
                                  className={`text-xs rounded border px-2 py-0.5 disabled:opacity-50 disabled:cursor-not-allowed ${ACTION_TONE[a.tone]}`}
                                >
                                  {a.label}
                                </button>
                              ))}
                            </div>
                          </div>
                        )
                      })}
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
