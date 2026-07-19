// Related Changes — workspace list surface (M6 Phase B1).
//
// A related change is a DETERMINISTIC correlation: ≥2 independent signal
// families that changed together on the same registrable domain in the same
// period. This component lists those change clusters for a workspace and lets
// the customer filter by review state. It is read-only presentation: every
// state (customer_state, direction, confidence, completeness) is owned by the
// backend and rendered verbatim. The frontend NEVER derives a security verdict.
//
// Vocabulary lock: "related changes", "change cluster", "observed in the same
// period", "may be connected", "confirm whether planned". Never "attack chain",
// "compromise", "incident", "anomaly" or "threat". Change is not compromise.
import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { GitCompareArrows } from 'lucide-react'
import { api } from '../api'
import EmptyState from './EmptyState'
import ErrorAlert from './ErrorAlert'
import Spinner from './Spinner'
import {
  ruleLabel,
  directionMeta,
  customerStateMeta,
  completenessMeta,
  toneClass,
  signalFamilyText,
  confidenceLabel,
  shortDate,
  HONESTY_NOTE,
  CUSTOMER_STATE_FILTERS,
  emptyStateFor,
} from '../lib/relatedChangesDisplay'

/** @param {{ tone: string, children: import('react').ReactNode }} props */
function Tag({ tone, children }) {
  return (
    <span className={`inline-block rounded-full border px-2 py-0.5 text-xs font-medium ${toneClass(tone)}`}>
      {children}
    </span>
  )
}

export default function RelatedChangesList({ workspaceId }) {
  const navigate = useNavigate()
  const [items, setItems] = useState([])
  const [assessment, setAssessment] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [stateFilter, setStateFilter] = useState('')
  const [reloadKey, setReloadKey] = useState(0)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    api
      .getRelatedChanges(workspaceId, stateFilter ? { customer_state: stateFilter } : {})
      .then((res) => {
        if (cancelled) return
        const list = res?.related_changes || []
        // Sort by most recently observed first — the backend supplies last_seen.
        list.sort((a, b) => String(b?.last_seen || '').localeCompare(String(a?.last_seen || '')))
        setItems(list)
        setAssessment(res?.assessment || null)
        setError(null)
      })
      .catch(() => {
        if (!cancelled) setError('We could not load related changes. Please try again.')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [workspaceId, stateFilter, reloadKey])

  const goToDetail = (id) => navigate(`/ws/related-changes/${encodeURIComponent(id)}`)

  return (
    <section aria-label="Related changes">
      <div className="rounded-xl border border-slate-200 bg-brand-50/40 px-4 py-3 mb-5 flex items-start gap-2.5">
        <GitCompareArrows className="w-4 h-4 text-brand-600 flex-shrink-0 mt-0.5" aria-hidden="true" />
        <p className="text-xs text-slate-600 leading-relaxed">{HONESTY_NOTE}</p>
      </div>

      <div className="flex items-center justify-between gap-3 mb-4">
        <p className="text-xs text-slate-500">
          {loading ? 'Loading…' : `${items.length} change ${items.length === 1 ? 'cluster' : 'clusters'} observed in this period.`}
        </p>
        <label className="flex items-center gap-2 text-xs text-slate-500">
          <span className="sr-only">Filter by review state</span>
          <select
            className="text-xs border border-slate-200 rounded-md px-2 py-1 text-slate-600"
            value={stateFilter}
            onChange={(e) => setStateFilter(e.target.value)}
            aria-label="Filter related changes by review state"
          >
            <option value="">All review states</option>
            {CUSTOMER_STATE_FILTERS.map((s) => (
              <option key={s} value={s}>
                {customerStateMeta(s).label}
              </option>
            ))}
          </select>
        </label>
      </div>

      {loading && (
        <div className="flex items-center justify-center py-24">
          <Spinner />
        </div>
      )}

      {!loading && error && <ErrorAlert message={error} onRetry={() => setReloadKey((k) => k + 1)} />}

      {!loading && !error && items.length === 0 && (() => {
        const empty = emptyStateFor(assessment, Boolean(stateFilter))
        return (
          <EmptyState
            icon={GitCompareArrows}
            title={empty.title}
            description={empty.description}
          />
        )
      })()}

      {!loading && !error && items.length > 0 && (
        <ul className="space-y-3">
          {items.map((rc) => {
            const dir = directionMeta(rc.direction)
            const state = customerStateMeta(rc.customer_state)
            const complete = completenessMeta(rc.completeness)
            return (
              <li key={rc.id}>
                <button
                  type="button"
                  onClick={() => goToDetail(rc.id)}
                  className="w-full text-left rounded-xl border border-slate-200 bg-white p-4 hover:border-brand-200 hover:bg-slate-50 transition-colors focus:outline-none focus:ring-2 focus:ring-brand-200"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      {/* Explanation first, number second. */}
                      <p className="text-sm font-semibold text-slate-900 leading-snug">{ruleLabel(rc.rule_id)}</p>
                      <p className="text-xs text-slate-500 mt-0.5 truncate">
                        {rc.registrable_domain} · {signalFamilyText(rc.signal_family_count)} · observed in the same period
                      </p>
                    </div>
                    <Tag tone={state.tone}>{state.label}</Tag>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 mt-3">
                    <Tag tone={dir.tone}>{dir.label}</Tag>
                    <Tag tone={complete.tone}>{complete.label}</Tag>
                    <span className="text-xs text-slate-400">{confidenceLabel(rc.confidence)}</span>
                    {rc.recurrence_count > 1 && (
                      <span className="text-xs text-slate-400">· Seen {rc.recurrence_count} times</span>
                    )}
                    {rc.linked_case_id && <span className="text-xs text-brand-600">· Linked to a case</span>}
                    <span className="text-xs text-slate-400 ml-auto">Last seen {shortDate(rc.last_seen)}</span>
                  </div>
                </button>
              </li>
            )
          })}
        </ul>
      )}
    </section>
  )
}
