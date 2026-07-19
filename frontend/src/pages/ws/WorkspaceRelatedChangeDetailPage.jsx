// Related Change — detail surface (M6 Phase B1).
//
// Shows one deterministic change cluster: the correlation summary, the list of
// related-evidence POINTERS (producer + source table + entity key + observed
// time — CyberMeters links to the underlying observations rather than copying
// them), and the customer's review actions (mark expected / mark unrelated /
// confirm unexpected, link an existing case, create a case from this cluster).
//
// The backend owns every state. This page renders customer_state, direction,
// confidence and completeness verbatim and never derives a security verdict or
// severity. Vocabulary lock applies: correlated observations that MAY be
// connected — change is not compromise.
import { useCallback, useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, GitCompareArrows, Link2, FolderPlus } from 'lucide-react'
import { api } from '../../api'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'
import { useWorkspace } from '../../hooks/useWorkspace'
import {
  ruleLabel,
  directionMeta,
  customerStateMeta,
  completenessMeta,
  toneClass,
  signalFamilyText,
  producerText,
  confidenceLabel,
  producerFamilyLabel,
  shortDate,
  FEEDBACK_OPTIONS,
  HONESTY_NOTE,
} from '../../lib/relatedChangesDisplay'

const CARD = 'rounded-xl border border-slate-200 bg-white p-5'

/** @param {{ tone: string, children: import('react').ReactNode }} props */
function Tag({ tone, children }) {
  return (
    <span className={`inline-block rounded-full border px-2.5 py-1 text-xs font-medium ${toneClass(tone)}`}>
      {children}
    </span>
  )
}

export default function WorkspaceRelatedChangeDetailPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const { wsId, wsName, loading: wsLoading } = useWorkspace()

  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  // Action state.
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(null) // which action is in flight
  const [actionError, setActionError] = useState(null)
  const [actionOk, setActionOk] = useState(null)
  const [caseIdInput, setCaseIdInput] = useState('')

  const load = useCallback(() => {
    if (!wsId) return
    setLoading(true)
    api
      .getRelatedChange(wsId, id)
      .then((res) => {
        setData(res)
        setError(null)
      })
      .catch(() => setError('We could not load this related change.'))
      .finally(() => setLoading(false))
  }, [wsId, id])

  useEffect(() => {
    load()
  }, [load])

  if (!wsLoading && !wsId) return <NoWorkspaceSelected />

  const rc = data?.related_change
  const evidence = data?.evidence || []

  const state = rc ? customerStateMeta(rc.customer_state) : null
  const dir = rc ? directionMeta(rc.direction) : null
  const complete = rc ? completenessMeta(rc.completeness) : null

  async function submitFeedback(nextState) {
    setBusy(`feedback:${nextState}`)
    setActionError(null)
    setActionOk(null)
    try {
      const res = await api.relatedChangeFeedback(wsId, id, {
        state: nextState,
        ...(note.trim() ? { note: note.trim() } : {}),
      })
      // Reflect the server-confirmed state without a full refetch.
      setData((prev) =>
        prev ? { ...prev, related_change: { ...prev.related_change, customer_state: res?.customer_state ?? nextState } } : prev,
      )
      setActionOk('Your review was recorded.')
      setNote('')
    } catch {
      setActionError('We could not record your review. Please try again.')
    } finally {
      setBusy(null)
    }
  }

  async function linkCase() {
    const caseId = caseIdInput.trim()
    if (!caseId) {
      setActionError('Enter a case ID to link.')
      return
    }
    setBusy('link')
    setActionError(null)
    setActionOk(null)
    try {
      const res = await api.linkRelatedChangeCase(wsId, id, { case_id: caseId })
      setData((prev) =>
        prev ? { ...prev, related_change: { ...prev.related_change, linked_case_id: res?.linked_case_id ?? caseId } } : prev,
      )
      setActionOk('Linked to the case.')
      setCaseIdInput('')
    } catch {
      setActionError('We could not link that case. Check the case ID and try again.')
    } finally {
      setBusy(null)
    }
  }

  async function createCase() {
    setBusy('create')
    setActionError(null)
    setActionOk(null)
    try {
      const res = await api.createRelatedChangeCase(wsId, id)
      if (res?.case_id) {
        setData((prev) =>
          prev ? { ...prev, related_change: { ...prev.related_change, linked_case_id: res.case_id } } : prev,
        )
        setActionOk('A managed case was created from this related change.')
      }
    } catch {
      setActionError('We could not create a case from this related change. Please try again.')
    } finally {
      setBusy(null)
    }
  }

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading || wsLoading} error={error} onRetry={load}>
      {rc && (
        <div className="space-y-5">
          <button
            onClick={() => navigate(-1)}
            className="inline-flex items-center gap-1.5 text-sm text-slate-500 hover:text-slate-700"
          >
            <ArrowLeft className="w-4 h-4" /> Back to related changes
          </button>

          {/* ── Header ─────────────────────────────────────────────────── */}
          <div className={CARD}>
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-400 mb-2">
                  <GitCompareArrows className="w-3.5 h-3.5" aria-hidden="true" /> Change cluster
                </span>
                <h1 className="text-lg font-semibold text-slate-900">{ruleLabel(rc.rule_id)}</h1>
                <p className="text-sm text-slate-600 mt-1">
                  {rc.registrable_domain} · {signalFamilyText(rc.signal_family_count)} and{' '}
                  {producerText(rc.independent_producer_count)} observed in the same period.
                </p>
              </div>
              {state && <Tag tone={state.tone}>{state.label}</Tag>}
            </div>

            <div className="flex flex-wrap items-center gap-2 mt-3">
              {dir && <Tag tone={dir.tone}>{dir.label}</Tag>}
              {complete && <Tag tone={complete.tone}>{complete.label}</Tag>}
              <span className="text-xs text-slate-400">{confidenceLabel(rc.confidence)}</span>
            </div>

            <div className="flex flex-wrap gap-x-6 gap-y-1 mt-3 text-xs text-slate-500">
              <span>First seen: {shortDate(rc.first_seen)}</span>
              <span>Last seen: {shortDate(rc.last_seen)}</span>
              <span>Seen {rc.recurrence_count ?? 1} times</span>
              {rc.linked_case_id && (
                <span className="text-brand-600">Linked case: {rc.linked_case_id}</span>
              )}
            </div>

            {state?.description && <p className="text-xs text-slate-500 mt-3">{state.description}</p>}
          </div>

          {/* ── Honesty note ───────────────────────────────────────────── */}
          <div className="rounded-xl border border-slate-200 bg-brand-50/40 px-4 py-3 flex items-start gap-2.5">
            <GitCompareArrows className="w-4 h-4 text-brand-600 flex-shrink-0 mt-0.5" aria-hidden="true" />
            <p className="text-xs text-slate-600 leading-relaxed">{HONESTY_NOTE}</p>
          </div>

          {/* ── Related evidence ───────────────────────────────────────── */}
          <div className={CARD}>
            <h2 className="text-sm font-semibold text-slate-800">Related evidence</h2>
            <p className="text-xs text-slate-500 mt-1">
              CyberMeters links to the underlying observations rather than copying them. Each pointer below identifies a
              signal family and the record it was observed in.
            </p>

            {evidence.length === 0 ? (
              <p className="text-xs text-slate-400 mt-4">No related evidence pointers are available for this cluster.</p>
            ) : (
              <ul className="mt-4 divide-y divide-slate-100">
                {evidence.map((e, i) => (
                  <li key={e.source_record_id || e.evidence_ref || i} className="py-3 flex flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-slate-800">{producerFamilyLabel(e.producer_family)}</p>
                      <p className="text-xs text-slate-500 mt-0.5 break-words">
                        {e.entity_key || e.source_record_id || '—'}
                        {e.source_event_type ? ` · ${e.source_event_type}` : ''}
                      </p>
                      {e.source_table && <p className="text-xs text-slate-400 mt-0.5 font-mono">{e.source_table}</p>}
                    </div>
                    <span className="text-xs text-slate-400 whitespace-nowrap">{shortDate(e.observed_at)}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {/* ── Review actions ─────────────────────────────────────────── */}
          <div className={CARD}>
            <h2 className="text-sm font-semibold text-slate-800">Confirm whether planned</h2>
            <p className="text-xs text-slate-500 mt-1">
              Record whether these changes were planned. Confirming they were unexpected marks the cluster as requiring
              verification.
            </p>

            <label className="block mt-4">
              <span className="text-xs font-medium text-slate-600">Note (optional)</span>
              <textarea
                value={note}
                onChange={(e) => setNote(e.target.value)}
                rows={2}
                placeholder="Add context for your review…"
                className="mt-1 w-full text-sm border border-slate-200 rounded-md px-3 py-2 text-slate-700 focus:outline-none focus:ring-2 focus:ring-brand-200"
              />
            </label>

            <div className="flex flex-wrap gap-2 mt-3">
              {FEEDBACK_OPTIONS.map((opt) => (
                <button
                  key={opt.state}
                  type="button"
                  onClick={() => submitFeedback(opt.state)}
                  disabled={!!busy}
                  className="text-xs rounded-md border border-slate-200 bg-white text-slate-700 px-3 py-1.5 font-medium hover:bg-slate-50 disabled:opacity-50"
                >
                  {busy === `feedback:${opt.state}` ? 'Saving…' : opt.label}
                </button>
              ))}
            </div>

            {/* Case linkage */}
            <div className="mt-6 pt-5 border-t border-slate-100">
              <h3 className="text-xs font-semibold text-slate-700 uppercase tracking-wide">Managed case</h3>
              <div className="flex flex-col sm:flex-row gap-2 mt-3">
                <input
                  type="text"
                  value={caseIdInput}
                  onChange={(e) => setCaseIdInput(e.target.value)}
                  placeholder="Existing case ID"
                  aria-label="Existing case ID"
                  className="flex-1 text-sm border border-slate-200 rounded-md px-3 py-1.5 text-slate-700 focus:outline-none focus:ring-2 focus:ring-brand-200"
                />
                <button
                  type="button"
                  onClick={linkCase}
                  disabled={!!busy}
                  className="inline-flex items-center justify-center gap-1.5 text-xs rounded-md border border-slate-200 bg-white text-slate-700 px-3 py-1.5 font-medium hover:bg-slate-50 disabled:opacity-50"
                >
                  <Link2 className="w-3.5 h-3.5" /> {busy === 'link' ? 'Linking…' : 'Link to existing case'}
                </button>
                <button
                  type="button"
                  onClick={createCase}
                  disabled={!!busy}
                  className="inline-flex items-center justify-center gap-1.5 text-xs rounded-md border border-brand-200 bg-brand-50 text-brand-700 px-3 py-1.5 font-medium hover:bg-brand-100 disabled:opacity-50"
                >
                  <FolderPlus className="w-3.5 h-3.5" /> {busy === 'create' ? 'Creating…' : 'Create case from this related change'}
                </button>
              </div>
            </div>

            {actionError && <p className="text-xs text-red-600 mt-3" role="alert">{actionError}</p>}
            {actionOk && <p className="text-xs text-green-700 mt-3" role="status">{actionOk}</p>}
          </div>
        </div>
      )}
    </WsPage>
  )
}
