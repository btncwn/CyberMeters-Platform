// Shadow IT & Unmanaged Technology — approved inventory page. A focused managed
// surface (not a nav/dashboard redesign). It renders the server-owned canonical
// inventory and posts classification/ownership/lifecycle actions the BACKEND
// validates. The set of allowed actions comes from the server response — the
// frontend never invents classification states or actions.
import { Fragment, useEffect, useState, useCallback, useRef } from 'react'
import { useAppDialog } from '../../components/AppDialog'
import { useSearchParams, Link, useLocation, useNavigate } from 'react-router-dom'
import { api } from '../../api'
import { formatDay } from '../../utils/dates'
import { useWorkspace } from '../../hooks/useWorkspace'
import { NoWorkspaceSelected } from '../../components/WsPage'
import ModuleContract, { useAreaAnchor } from '../../components/module/ModuleContract'
import {
  SHADOW_IT_FIRST_OBSERVATION_LABEL,
  classificationMeta, monitoringMeta, ownershipMeta, onboardingMeta, removalMeta,
  toneClass, SHADOW_IT_SCOPE_NOTE, nextShadowItActions,
} from '../../lib/shadowItDisplay'
import { keyLabel } from '../../lib/keyLabel'
import { phaseMeta } from '../../lib/caseDisplay'

function Pill({ meta }) {
  return <span className={`inline-block rounded-full border px-2 py-0.5 text-xs ${toneClass(meta.tone)}`}>{meta.label}</span>
}

const SOURCE_LABELS = {
  vendor: 'Vendor signal', cloud_asset: 'Cloud asset', identity_provider: 'Identity provider',
  email_sender: 'DMARC report', saas_portal: 'SaaS portal',
}

function SourceEvidence({ item }) {
  const sources = String(item.source_type || '').split(',').map(value => value.trim()).filter(Boolean)
  const identifiers = Array.isArray(item.observed_identifiers) ? item.observed_identifiers : []
  return <div className="mt-1 space-y-1 text-xs text-slate-600">
    {sources.length > 0 && <div className="flex flex-wrap gap-1" aria-label="Observation sources">
      {sources.map(source => <span key={source} className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5">
        Observed via {SOURCE_LABELS[source] || source.replaceAll('_', ' ')}
      </span>)}
    </div>}
    {identifiers.length > 0 && <div className="break-all">Observed identifiers: {identifiers.join(', ')}</div>}
    {item.evidence_age_days != null && <div>Evidence age: {item.evidence_age_days} days</div>}
  </div>
}

function ShadowItHistory({ workspaceId, itemId }) {
  const [detail, setDetail] = useState(null)
  const [error, setError] = useState(false)
  useEffect(() => {
    let active = true
    setDetail(null)
    setError(false)
    api.getShadowItItem(workspaceId, itemId).then(
      value => { if (active) setDetail(value) },
      () => { if (active) setError(true) },
    )
    return () => { active = false }
  }, [workspaceId, itemId])
  if (error) return <p role="alert" className="text-sm text-red-700">Could not load this item's history.</p>
  if (!detail) return <p className="text-sm text-slate-500">Loading history…</p>
  const events = Array.isArray(detail.events) ? detail.events : []
  return <div className="space-y-3">
    <h3 className="text-sm font-semibold text-slate-800">Event history</h3>
    {events.length === 0 ? <p className="text-sm text-slate-500">No recorded events.</p> : <ol className="space-y-2 text-sm text-slate-600">
      {events.map(event => <li key={event.id}>
        <span className="font-medium text-slate-800">{event.event_type?.replaceAll('_', ' ') || 'Recorded event'}</span>
        {event.actor_type && ` · ${keyLabel(event.actor_type)}`}
        {event.created_at && ` · ${event.created_at}`}
      </li>)}
    </ol>}
    {detail.linked_case && <p className="text-sm"><Link className="text-blue-700 hover:underline" to={`/ws/cases/${encodeURIComponent(detail.linked_case.id)}`}>Open the linked case</Link>{detail.linked_case.status && ` · ${phaseMeta(detail.linked_case.status).label}`}</p>}
  </div>
}

// The customer-facing action surface. Grouping mirrors the BACKEND's own field
// grouping (classification / ownership / onboarding_status / removal_status) so
// the UI introduces no taxonomy of its own — the action names are the server's
// verbatim, and a control is rendered ONLY when the server advertises it.
// Tailwind classes are written as whole literal strings so the JIT scanner can
// see them; never build these by concatenation.
const ACTION_TONE = {
  green: 'border-brand-200 text-brand-700',
  red:   'border-red-200 text-red-700',
  amber: 'border-[1.5px] border-brand-700 text-brand-700',
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
const ACTION_TONE_BY_ACTION = Object.fromEntries(
  ACTION_GROUPS.flatMap((g) => g.actions.map((a) => [a.action, a.tone])),
)

// "What we observed" (S1-SHELL-V2b): the backend's classification counts are
// workspace-wide (countShadowItByClassification), so the last known counts hold
// across filter chips; loading and unavailable say so, never 0 (R1 rules).
export function shadowItSummaryFigures({ status, counts }) {
  return ['unreviewed', 'approved', 'rejected', 'exception'].map((c) => ({
    key: c, id: `shadow-it-${c}`, label: classificationMeta(c).label,
    value: status === 'loading' ? 'Loading…' : status !== 'ok' || !Number.isInteger(counts?.[c]) ? 'Not available' : counts[c],
  }))
}

// The backend's own page maximum (routes/shadow-it.js): a full page bounds any list read from it.
export const SUMMARY_LIMIT = 500

// Chip labels (R1 17:58): a count only when the backend's counts are known —
// never "(0)" while loading, after a workspace switch or on error. "All" is the
// sum of the workspace-wide counts, never a page length.
export function chipLabel(c, { status, counts }) {
  const known = status === 'ok' && counts && typeof counts === 'object'
  if (c === '') {
    const values = known ? Object.values(counts).filter((n) => Number.isInteger(n)) : []
    return values.length ? `All (${values.reduce((a, b) => a + b, 0)})` : 'All'
  }
  const label = classificationMeta(c).label
  return known && Number.isInteger(counts[c]) ? `${label} (${counts[c]})` : label
}

// The sidebar's "Rejected but still seen": items the customer rejected that the
// backend still observes (monitoring_reason rejected_still_observed). Every state.
export function RejectedStillSeen({ status, items, atLimit = false }) {
  const rows = status === 'ok' ? (items || []).filter((it) => it?.monitoring_reason === 'rejected_still_observed') : []
  return (
    <section id="shadow-it-rejected-still-seen" className="card p-6 my-6" aria-labelledby="shadow-it-rejected-still-seen-heading" data-testid="shadow-it-rejected-still-seen">
      <h2 id="shadow-it-rejected-still-seen-heading" className="font-semibold text-gray-900 mb-1">Rejected but still seen</h2>
      <p className="text-sm text-gray-500 leading-relaxed mb-4 max-w-3xl">Technology you rejected that the latest scans still observe. Rejecting it records your decision; it does not remove it.</p>
      {status === 'loading' ? <p className="text-sm text-gray-500">Loading…</p>
        : status !== 'ok' ? <p className="text-sm text-gray-600">Not available — the inventory could not be loaded.</p>
          : !rows.length ? <p className="text-sm text-gray-600">{atLimit ? `None among the first ${SUMMARY_LIMIT} inventory items.` : 'Nothing you rejected is still observed.'}</p>
            : (
              <ul className="divide-y divide-gray-100">
                {rows.map((it) => (
                  <li key={it.inventory_item_id} className="py-3 flex flex-col sm:flex-row sm:items-start sm:justify-between gap-1 sm:gap-4">
                    <span className="text-sm font-medium text-gray-900 break-all">{it.display_name || 'Unnamed item'}</span>
                    <span className="text-sm text-gray-600 sm:text-right">{it.last_seen_at ? `Last observed ${formatDay(it.last_seen_at)}` : 'Last observation not recorded'}</span>
                  </li>
                ))}
              </ul>
            )}
    </section>
  )
}

export default function ShadowItInventoryPage() {
  const dialog = useAppDialog()
  // Workspace comes from the canonical context hook, not a route param — the
  // /ws/* routes declare no :workspaceId, so useParams().workspaceId is always
  // undefined and would produce /api/workspaces/undefined/... (403).
  const { wsId: workspaceId, wsName: workspaceName, loading: wsLoading } = useWorkspace()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  // Action failures are held SEPARATELY from the load error. The list below is
  // rendered only when `error` is null, so reusing one slot meant a single failed
  // action erased the entire inventory the customer was working in.
  const [actionError, setActionError] = useState(null)
  const [filter, setFilter] = useState('')
  // The workspace-wide counts (held from the last successful load, any filter) and
  // the unfiltered page (Summary lists and "Rejected but still seen").
  const [countsState, setCountsState] = useState({ status: 'loading', counts: null })
  const [summary, setSummary] = useState({ status: 'loading', items: [], atLimit: false })
  // Another workspace's counts, items or filter never stand in for this one's.
  useEffect(() => {
    setCountsState({ status: 'loading', counts: null })
    setSummary({ status: 'loading', items: [], atLimit: false })
  }, [workspaceId])
  const [busy, setBusy] = useState(null)
  const [expandedId, setExpandedId] = useState(null)
  const [moreOpenId, setMoreOpenId] = useState(null)
  const requestGeneration = useRef(0)
  // Deep-link target from an alert CTA (/ws/shadow-it?item=<id>). The id is the
  // server's own opaque surrogate; the list below is already workspace-scoped, so
  // a foreign id simply matches nothing.
  const [searchParams] = useSearchParams()
  const focusItemId = searchParams.get('item')
  // ?filter= is the source of truth both ways (C-38b N01): the sidebar's
  // "Approved inventory" (?filter=approved) selects Approved, a link without it
  // ("Observed technology") selects All again.
  const filterParam = searchParams.get('filter')
  useEffect(() => {
    setFilter(['unreviewed', 'approved', 'rejected', 'exception', 'retired'].includes(filterParam) ? filterParam : '')
  }, [filterParam])
  // A chip writes the URL (hash kept, history replaced); the effect above applies it.
  const navigate = useNavigate()
  const location = useLocation()
  const selectFilter = useCallback((c) => {
    const next = new URLSearchParams(location.search)
    if (c) next.set('filter', c); else next.delete('filter')
    const search = next.toString()
    setFilter(c)
    navigate({ pathname: location.pathname, search: search ? `?${search}` : '', hash: location.hash }, { replace: true })
  }, [location.pathname, location.search, location.hash, navigate])
  const focusRef = useRef(null)
  useEffect(() => {
    if (focusRef.current) focusRef.current.scrollIntoView({ block: 'center' })
  }, [data, focusItemId])

  const load = useCallback(() => {
    const generation = ++requestGeneration.current
    setData(null)
    setError(null)
    setExpandedId(null)
    if (!workspaceId) { setLoading(false); return }   // never call the API with a null/unresolved workspace id
    setLoading(true)
    const unfiltered = !filter
    if (unfiltered) setSummary((prev) => ({ ...prev, status: 'loading' }))
    api.getShadowItInventory(workspaceId, unfiltered ? { limit: SUMMARY_LIMIT } : { classification: filter })
      .then((res) => {
        if (generation !== requestGeneration.current) return
        setData(res); setError(null)
        setCountsState(res?.counts && typeof res.counts === 'object' ? { status: 'ok', counts: res.counts } : { status: 'error', counts: null })
        if (unfiltered) {
          const list = Array.isArray(res?.items) ? res.items : []
          setSummary({ status: Array.isArray(res?.items) ? 'ok' : 'error', items: list, atLimit: list.length >= SUMMARY_LIMIT })
        }
      })
      .catch(() => {
        if (generation !== requestGeneration.current) return
        setError('Could not load the technology inventory.')
        setCountsState((prev) => (prev.status === 'ok' ? prev : { status: 'error', counts: null }))
        if (unfiltered) setSummary({ status: 'error', items: [], atLimit: false })
      })
      .finally(() => { if (generation === requestGeneration.current) setLoading(false) })
  }, [workspaceId, filter])

  useEffect(() => { load(); return () => { requestGeneration.current += 1 } }, [load])

  // A filtered view (e.g. the sidebar's ?filter=approved) still needs the
  // unfiltered page for the Summary lists: fetch it on its own when missing.
  const summaryGeneration = useRef(0)
  const loadSummary = useCallback(() => {
    if (!workspaceId) return
    const generation = ++summaryGeneration.current
    setSummary((prev) => ({ ...prev, status: 'loading' }))
    api.getShadowItInventory(workspaceId, { limit: SUMMARY_LIMIT })
      .then((res) => {
        if (generation !== summaryGeneration.current) return
        const list = Array.isArray(res?.items) ? res.items : []
        setSummary({ status: Array.isArray(res?.items) ? 'ok' : 'error', items: list, atLimit: list.length >= SUMMARY_LIMIT })
        if (res?.counts && typeof res.counts === 'object') setCountsState({ status: 'ok', counts: res.counts })
      })
      .catch(() => { if (generation === summaryGeneration.current) setSummary({ status: 'error', items: [], atLimit: false }) })
  }, [workspaceId])
  const summaryMissing = summary.status === 'loading' && summary.items.length === 0
  useEffect(() => {
    if (filter && summaryMissing) loadSummary()
    return () => { summaryGeneration.current += 1 }
  }, [filter, summaryMissing, loadSummary])

  // Allowed actions are server-provided; the UI only surfaces those.
  const serverActions = data?.actions || []
  const can = (a) => serverActions.includes(a)

  async function act(item, action) {
    const payload = { action }
    if (action === 'reject' || action === 'retire') {
      const what = action === 'reject' ? 'Reject' : 'Retire'
      const reason = await dialog.prompt({ title: `${what} ${item.display_name}?`, label: 'Reason', confirmLabel: what, tone: 'danger', required: true })
      if (!reason) return
      payload.reason = reason
    } else if (action === 'mark_exception') {
      const reason = await dialog.prompt({ title: `Record an exception for ${item.display_name}`, label: 'Exception reason', confirmLabel: 'Next', required: true })
      if (!reason) return
      const until = await dialog.prompt({ title: `Record an exception for ${item.display_name}`, label: 'Exception expiry date', inputType: 'date', confirmLabel: 'Record exception', required: true })
      if (!until) return
      payload.reason = reason
      payload.exception_until = new Date(until).toISOString()
    } else if (action === 'assign_business_owner' || action === 'assign_technical_owner') {
      const roleName = action === 'assign_business_owner' ? 'Business' : 'Technical'
      const owner = await dialog.prompt({ title: `${roleName} owner for ${item.display_name}`, label: `${roleName} owner`, confirmLabel: 'Assign owner', required: true })
      if (!owner) return
      payload.owner = owner
    } else if (action === 'set_business_purpose') {
      const purpose = await dialog.prompt({ title: `Business purpose for ${item.display_name}`, label: 'Business purpose', confirmLabel: 'Save purpose' })
      if (purpose == null) return
      payload.business_purpose = purpose
    } else if (action === 'reopen_review') {
      // Returns the item to "Not yet classified" — the reason is optional at the
      // backend, so an empty answer is accepted but a cancel aborts.
      const reason = await dialog.prompt({ title: `Reopen ${item.display_name} for review?`, label: 'Reason (optional)', confirmLabel: 'Reopen for review' })
      if (reason == null) return
      payload.reason = reason
    } else if (action === 'mark_removed') {
      // Customer assertion, never a CyberMeters verification. The backend records
      // this as `customer_asserted_not_verified`; the confirmation must say the
      // same thing in the customer's own words rather than imply confirmation.
      const confirmed = await dialog.confirm({
        title: `Record that ${item.display_name} has been removed?`,
        message: 'This records YOUR assertion. CyberMeters has not verified the removal — ' +
          'if the technology is still observed externally, this item will be shown ' +
          'as contradicting your assertion.',
        confirmLabel: 'Record as removed',
      })
      if (!confirmed) return
    }
    setActionError(null)
    setBusy(item.inventory_item_id)
    // A classification change moves items between the Summary lists too.
    try { await api.shadowItAction(workspaceId, item.inventory_item_id, payload); load(); if (filter) loadSummary() }
    catch {
      // Deliberately claims nothing about server state: the request failed from
      // here, which does not prove the change was not applied.
      setActionError(`“${ACTION_LABEL[action] || action}” did not complete for ${item.display_name}. The list below may not reflect the latest state — reload to confirm.`)
    }
    finally { setBusy(null) }
  }

  const items = data?.items || []
  const counts = countsState.counts || {}
  // "All" is every item in the workspace, never the length of the filtered list.
  const inlineClassify = ['approve', 'reject', 'mark_exception'].filter(can)
  const goToAnchor = useAreaAnchor()
  // Overview lists the unclassified items themselves (founder, 18 Oct 2026): the
  // first five, and "See all" opens the inventory filtered to them.
  // From the unfiltered page: a filter chip never empties the Summary's list.
  const unclassified = summary.items.filter((it) => it.classification === 'unreviewed')
  const seeAllUnclassified = () => { selectFilter('unreviewed'); goToAnchor('shadow-it-inventory') }
  const isEmpty = !loading && !error && items.length === 0 && !filter

  if (!wsLoading && !workspaceId) return <NoWorkspaceSelected />

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <ModuleContract
        domainKey="shadow_it_unmanaged_technology"
        workspaceId={workspaceId}
        workspaceName={workspaceName}
        description={SHADOW_IT_SCOPE_NOTE}
        /* The area template (18 Oct 2026): the backend's classification counts are
           "What we observed" — the customer's own record, never a verdict. */
        figures={isEmpty ? null : shadowItSummaryFigures(countsState)}
        nextAction={isEmpty ? {
          title: 'No externally observed technology yet',
          body: 'This page fills after a scan correlates the vendors and services seen for your domains.',
          label: 'Run a scan',
          to: '/scans/new',
        } : (countsState.status === 'ok' && Number.isInteger(counts.unreviewed) && counts.unreviewed > 0) ? {
          title: `${counts.unreviewed} item${counts.unreviewed === 1 ? '' : 's'} not yet classified`,
          body: 'Approve, reject or record an exception for each, so CyberMeters knows what you expect to see.',
          label: 'Classify items',
          onClick: seeAllUnclassified,
        } : null}
        overview={isEmpty ? (
          <div className="card p-6" data-testid="shadow-it-empty">
            <p className="text-sm text-gray-700">This page fills after a scan correlates the vendors and services seen for your domains.</p>
          </div>
        ) : (
          <section className="card p-5" aria-labelledby="shadow-it-unclassified-heading" data-testid="shadow-it-unclassified">
            <div className="flex items-baseline justify-between gap-3">
              <h3 id="shadow-it-unclassified-heading" className="text-sm font-semibold text-gray-900">Not yet classified</h3>
              {unclassified.length > 0 && <button type="button" onClick={seeAllUnclassified} className="btn-secondary text-sm">{countsState.status === 'ok' && Number.isInteger(counts.unreviewed)
                ? `Classify all ${counts.unreviewed} item${counts.unreviewed === 1 ? '' : 's'}`
                : 'Classify all unreviewed'}</button>}
            </div>
            {summary.status === 'loading' && <p className="text-sm text-gray-600 mt-2">Loading…</p>}
            {summary.status === 'error' && <p className="text-sm text-red-700 mt-2">Could not load the technology inventory.</p>}
            {summary.status === 'ok' && unclassified.length === 0 && <p className="text-sm text-gray-600 mt-2">{summary.atLimit ? `None among the first ${SUMMARY_LIMIT} inventory items.` : 'Every observed item has a classification.'}</p>}
            {summary.status === 'ok' && unclassified.length > 0 && (
              <ul className="mt-2 divide-y divide-gray-100">
                {unclassified.slice(0, 5).map((it) => (
                  <li key={it.inventory_item_id} className="flex flex-wrap items-center justify-between gap-3 py-2" data-testid="shadow-it-unclassified-item">
                    <span className="min-w-0">
                      <span className="block text-sm font-medium text-gray-900 break-words">{it.display_name}</span>
                      <span className="block text-xs text-gray-600 capitalize">{(it.category || 'Uncategorised').replace(/_/g, ' ')}{it.last_seen_at ? ` · last seen ${it.last_seen_at.slice(0, 10)}` : ''}</span>
                    </span>
                    {/* Classify right here (founder, 21 Oct 2026) — the same act() path
                        and dialogs as the inventory, only the server's actions. */}
                    {inlineClassify.length > 0 && (
                      <span className="flex flex-wrap gap-1.5" aria-busy={busy === it.inventory_item_id}>
                        {inlineClassify.map((action) => (
                          <button key={action} type="button" disabled={busy === it.inventory_item_id} onClick={() => act(it, action)}
                            aria-label={`${ACTION_LABEL[action]} ${it.display_name}`}
                            className={`text-xs font-semibold rounded-md border px-2.5 py-1 disabled:opacity-50 disabled:cursor-not-allowed ${ACTION_TONE[ACTION_TONE_BY_ACTION[action]]}`}>
                            {ACTION_LABEL[action]}
                          </button>
                        ))}
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </section>
        )}
      >
      <div id="shadow-it-inventory" className="flex flex-wrap items-center gap-2 my-4 scroll-mt-24">
        {['', 'unreviewed', 'approved', 'rejected', 'exception', 'retired'].map((c) => (
          <button
            key={c || 'all'}
            onClick={() => selectFilter(c)}
            aria-pressed={filter === c}
            className={`text-xs rounded-full border px-3 py-1 ${filter === c ? 'bg-slate-800 text-white border-slate-800' : 'bg-white text-slate-600 border-slate-200'}`}
          >
            {chipLabel(c, countsState)}
          </button>
        ))}
      </div>

      {loading && <p className="text-sm text-slate-400">Loading…</p>}
      {error && <p className="text-sm text-red-700">{error}</p>}
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
              {/* Seen in the latest scan first; items the latest scan did not see
                  follow under their own heading and are never counted as observed. */}
              {[...items.filter((it) => it.monitoring_status !== 'no_longer_observed'), ...items.filter((it) => it.monitoring_status === 'no_longer_observed')].map((it, index, ordered) => (
                <Fragment key={it.inventory_item_id}>
                {it.monitoring_status === 'no_longer_observed' && ordered[index - 1]?.monitoring_status !== 'no_longer_observed' && (
                  <tr data-testid="shadow-it-not-seen-heading">
                    <th colSpan={7} scope="rowgroup" className="bg-slate-50 px-3 py-2 text-left text-xs font-semibold text-slate-600">
                      Not seen in the latest scan ({ordered.filter((x) => x.monitoring_status === 'no_longer_observed').length}) — kept for your record, not counted as externally observed
                    </th>
                  </tr>
                )}
                <tr
                  ref={it.inventory_item_id === focusItemId ? focusRef : null}
                  className={`border-b border-slate-50 align-top ${it.inventory_item_id === focusItemId ? 'bg-transparent ring-1 ring-inset ring-brand-200' : ''}`}
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
                          className="ml-2 inline-flex items-center rounded-full bg-sky-50 px-2 py-0.5 text-xs font-semibold text-sky-700 ring-1 ring-sky-200 align-middle"
                          title={SHADOW_IT_FIRST_OBSERVATION_LABEL}
                        >
                          New
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-slate-400">{it.provider}{it.confidence ? ` · ${it.confidence} confidence` : ''}</div>
                    <SourceEvidence item={it} />
                    {it.linked_case_id && (
                      <Link to={`/ws/cases/${encodeURIComponent(it.linked_case_id)}`} className="text-xs text-brand-700 hover:underline">
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
                      <div className={`text-xs mt-0.5 ${removalMeta(it.removal_status, it.removal_verified).tone === 'red' ? 'text-red-700' : removalMeta(it.removal_status, it.removal_verified).tone === 'amber' ? 'text-brand-700' : 'text-slate-500'}`}>
                        {removalMeta(it.removal_status, it.removal_verified).label}
                      </div>
                    )}
                  </td>
                  <td className="py-2 px-3">
                    <Pill meta={ownershipMeta(it.ownership_status)} />
                    {(it.business_owner || it.technical_owner) && <div className="text-xs text-slate-400 mt-0.5">{it.business_owner || it.technical_owner}</div>}
                  </td>
                  <td className="py-2 px-3">
                    <Pill meta={monitoringMeta(it.monitoring_status)} />
                    {/* Server-owned recurrence meaning — the same sentence the alert
                        email and in-app card carry. It describes what CyberMeters
                        observed, so it sits with Monitoring, not under Owner. Falls
                        back to the raw type only when the server sent no summary. */}
                    {(it.recurrence_summary || it.recurrence_type) && (
                      <div className="text-xs text-brand-700 mt-1" data-testid="shadow-it-recurrence">{it.recurrence_summary || it.recurrence_type.replace(/_/g, ' ')}</div>
                    )}
                    {it.inventory_item_id === focusItemId && it.recommended_next_action && (
                      <div className="text-xs text-slate-500 mt-0.5"><span className="font-medium">Recommended:</span> {it.recommended_next_action}</div>
                    )}
                  </td>
                  <td className="py-2 px-3 text-slate-400 text-xs">{it.last_seen_at ? it.last_seen_at.slice(0, 10) : '—'}</td>
                  <td className="py-2 px-3" aria-busy={busy === it.inventory_item_id}>
                    <button type="button" className="mb-2 text-xs rounded-sm border border-slate-200 text-slate-700 px-2 py-0.5"
                      aria-expanded={expandedId === it.inventory_item_id}
                      aria-controls={`shadow-it-history-${it.inventory_item_id}`}
                      onClick={() => setExpandedId(expandedId === it.inventory_item_id ? null : it.inventory_item_id)}
                    >History</button>
                    {/* The next sensible step first (founder, 21 Oct 2026: a row
                        offered thirteen buttons at once); every other advertised
                        action is one click away under More. */}
                    {nextShadowItActions(it).filter(can).length > 0 && (
                      <div className="flex flex-wrap gap-1 mb-1.5" data-testid="shadow-it-next-actions">
                        {nextShadowItActions(it).filter(can).map((action) => (
                          <button key={action} type="button" disabled={busy === it.inventory_item_id} onClick={() => act(it, action)}
                            className={`text-xs font-semibold rounded-sm border px-2 py-0.5 disabled:opacity-50 disabled:cursor-not-allowed ${ACTION_TONE[ACTION_TONE_BY_ACTION[action]]}`}>
                            {ACTION_LABEL[action]}
                          </button>
                        ))}
                      </div>
                    )}
                    {serverActions.some((a) => !nextShadowItActions(it).includes(a)) && (
                      <button type="button" className="mb-1.5 ml-1 text-xs rounded-sm border border-slate-200 text-slate-700 px-2 py-0.5"
                        aria-expanded={moreOpenId === it.inventory_item_id}
                        aria-controls={`shadow-it-more-${it.inventory_item_id}`}
                        aria-label={`More actions for ${it.display_name}`}
                        onClick={() => setMoreOpenId(moreOpenId === it.inventory_item_id ? null : it.inventory_item_id)}
                      >More</button>
                    )}
                    {/* One control per server-advertised action, grouped for
                        hierarchy. A group disappears entirely when the server
                        advertises none of its actions, so a viewer (actions: [])
                        sees no action surface at all. */}
                    {moreOpenId === it.inventory_item_id && (
                    <div id={`shadow-it-more-${it.inventory_item_id}`}>
                    <div className="space-y-1.5 min-w-48">
                      {ACTION_GROUPS.map((group) => {
                        const available = group.actions.filter((a) => can(a.action) && !nextShadowItActions(it).includes(a.action))
                        if (available.length === 0) return null
                        return (
                          <div key={group.key} role="group" aria-label={`${group.label} actions for ${it.display_name}`}>
                            <div className="text-xs uppercase tracking-wide text-slate-400">{group.label}</div>
                            <div className="flex flex-wrap gap-1 mt-0.5">
                              {available.map((a) => (
                                <button
                                  key={a.action}
                                  type="button"
                                  disabled={busy === it.inventory_item_id}
                                  onClick={() => act(it, a.action)}
                                  className={`text-xs rounded-sm border px-2 py-0.5 disabled:opacity-50 disabled:cursor-not-allowed ${ACTION_TONE[a.tone]}`}
                                >
                                  {a.label}
                                </button>
                              ))}
                            </div>
                          </div>
                        )
                      })}
                    </div>
                    </div>
                    )}
                  </td>
                </tr>
                {expandedId === it.inventory_item_id && <tr id={`shadow-it-history-${it.inventory_item_id}`}>
                  <td colSpan={7} className="bg-slate-50 p-4"><ShadowItHistory workspaceId={workspaceId} itemId={it.inventory_item_id} /></td>
                </tr>}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <RejectedStillSeen status={summary.status} items={summary.items} atLimit={summary.atLimit} />
      </ModuleContract>
      {dialog.element}
    </div>
  )
}
