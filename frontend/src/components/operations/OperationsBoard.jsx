// OperationsBoard — the Operations view of one workspace's managed cases, in
// four lanes: Triage · In progress / waiting · Ready to verify · Closed.
//
// Presentation only. Every case comes from GET /workspaces/:id/cases; which
// lane a case belongs to follows from the backend `canonical_phase` and
// `verification_support` through the common status vocabulary
// (lib/statusVocabulary.js), and the phase label on each row is the shared
// caseDisplay descriptor the detail page uses — so a case concluded on the
// customer's word reads "Attested by customer — not externally verifiable",
// never "Verified". Transitions are not decided here: a row opens the case
// detail, where the backend's available_transitions drive the actions.
import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../../api'
import { phaseMeta, phaseClass, domainKeyLabel, DOMAIN_KEY_LABELS, caseDisplayTitle } from '../../lib/caseDisplay'
import { caseStatus, statusMeta } from '../../lib/statusVocabulary'
import { MODULES } from '../../lib/moduleRegistry'

// Lanes in working order. `words` are the vocabulary words a lane collects.
export const LANES = Object.freeze([
  { id: 'triage',          label: 'Triage',                words: ['action_required', 'recurring'],
    empty: 'Nothing to triage. New and reopened cases appear here.' },
  { id: 'in_progress',     label: 'In progress / waiting', words: ['in_progress'],
    empty: 'No case has an action under way.' },
  { id: 'ready_to_verify', label: 'Ready to verify',       words: ['ready_to_verify'],
    empty: 'No case is waiting for its fix to be checked.' },
  { id: 'closed',          label: 'Closed',                words: ['verified', 'attested', 'external', 'closed'],
    empty: 'No case has been concluded yet.' },
])
export const LANE_IDS = Object.freeze(LANES.map((l) => l.id))
const LANE_BY_WORD = new Map(LANES.flatMap((l) => l.words.map((w) => [w, l.id])))

/** Lane id for one backend case; a word the lanes do not know lands in Triage (someone must look). */
export function laneForCase(c) {
  return LANE_BY_WORD.get(caseStatus(c)) || 'triage'
}

export function laneCounts(cases) {
  const counts = Object.fromEntries(LANE_IDS.map((id) => [id, 0]))
  for (const c of Array.isArray(cases) ? cases : []) counts[laneForCase(c)] += 1
  return counts
}

const fmtDate = (s) => (s ? String(s).slice(0, 10) : '—')

function CaseRow({ c }) {
  const meta = phaseMeta(c.canonical_phase, c.verification_support)
  const word = statusMeta(caseStatus(c))
  return (
    <li className="py-3 flex flex-col sm:flex-row sm:items-start gap-2 sm:gap-4" data-testid="case-row" data-case-id={c.case_id} data-lane-word={caseStatus(c)}>
      <div className="min-w-0 flex-1">
        <Link to={`/ws/cases/${encodeURIComponent(c.case_id)}`} className="text-sm font-semibold text-gray-900 hover:text-brand-800">
          {caseDisplayTitle(c)}
        </Link>
        <p className="text-xs text-gray-500 mt-0.5">
          {domainKeyLabel(c.domain_key)}
          {c.domain ? ` · ${c.domain}` : ''}
          {' · '}
          {c.owner_ref ? `Owner: ${c.owner_ref}` : 'Unassigned'}
          {c.severity ? ` · ${String(c.severity)[0].toUpperCase()}${String(c.severity).slice(1)}` : ''}
          {' · Updated '}{fmtDate(c.updated_at)}
        </p>
      </div>
      <div className="shrink-0 flex items-center gap-2 flex-wrap">
        <span className={`inline-block rounded-full border px-2 py-0.5 text-xs font-medium ${phaseClass(c.canonical_phase, c.verification_support)}`} title={word.label}>
          {meta.label}
        </span>
        {c.reopened_count > 0 && (
          <span className="text-xs text-red-700 font-medium">Reopened {c.reopened_count}×</span>
        )}
      </div>
    </li>
  )
}

/**
 * OperationsBoard
 *   workspaceId    — the selected workspace (cases are workspace-scoped)
 *   domainKey      — '' or one of the eight canonical domain keys
 *   onDomainChange — (key) => void, writes the filter to the URL
 *   view           — one of LANE_IDS (unknown → 'triage')
 *   onViewChange   — (id) => void, writes the lane to the URL
 */
export default function OperationsBoard({ workspaceId, domainKey = '', onDomainChange, view, onViewChange }) {
  const [cases, setCases] = useState([])
  const [request, setRequest] = useState('loading')
  const domainFilter = Object.hasOwn(DOMAIN_KEY_LABELS, domainKey) ? domainKey : ''
  const lane = LANE_IDS.includes(view) ? view : 'triage'

  useEffect(() => {
    let cancelled = false
    setRequest('loading')
    Promise.resolve()
      .then(() => api.getCases(workspaceId, domainFilter ? { domain_key: domainFilter, limit: 200 } : { limit: 200 }))
      .then((res) => { if (!cancelled) { setCases(Array.isArray(res?.cases) ? res.cases : []); setRequest(Array.isArray(res?.cases) ? 'ok' : 'error') } })
      .catch(() => { if (!cancelled) { setCases([]); setRequest('error') } })
    return () => { cancelled = true }
  }, [workspaceId, domainFilter])

  const counts = useMemo(() => laneCounts(cases), [cases])
  const rows = useMemo(() => cases.filter((c) => laneForCase(c) === lane), [cases, lane])
  const current = LANES.find((l) => l.id === lane)

  return (
    <section className="space-y-4" data-testid="operations-board">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div role="tablist" aria-label="Operations lanes" className="flex flex-wrap gap-1 rounded-xl bg-gray-100 p-1">
          {LANES.map((l) => {
            const active = l.id === lane
            return (
              <button
                key={l.id}
                type="button"
                role="tab"
                id={`ops-tab-${l.id}`}
                aria-selected={active}
                aria-controls="ops-lane"
                onClick={() => onViewChange?.(l.id)}
                className={`px-3 py-1.5 rounded-lg text-sm font-semibold transition-colors ${active ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-600 hover:text-gray-900'}`}
              >
                {l.label}
                <span className={`ml-1.5 tabular-nums ${active ? 'text-brand-700' : 'text-gray-400'}`} data-testid={`ops-count-${l.id}`}>
                  {request === 'ok' ? counts[l.id] : '…'}
                </span>
              </button>
            )
          })}
        </div>
        <select
          className="max-w-full text-sm border border-gray-200 rounded-md px-2 py-1.5 text-gray-700 bg-white"
          value={domainFilter}
          aria-label="Filter cases by service"
          onChange={(e) => onDomainChange?.(e.target.value)}
        >
          <option value="">All services</option>
          {MODULES.map((m) => <option key={m.domainKey} value={m.domainKey}>{m.title}</option>)}
        </select>
      </div>

      <div id="ops-lane" role="tabpanel" aria-labelledby={`ops-tab-${lane}`} className="card p-5">
        {request === 'loading' && <p className="text-sm text-gray-500" role="status">Reading managed cases…</p>}
        {request === 'error' && (
          <p className="text-sm text-red-700" role="alert">Managed cases could not be read. Nothing is assumed in the meantime.</p>
        )}
        {request === 'ok' && rows.length === 0 && (
          <p className="text-sm text-gray-500" data-testid="ops-lane-empty">
            {cases.length === 0
              ? 'No managed cases in this workspace yet. Cases open when a finding needs ownership, action and verification.'
              : current.empty}
          </p>
        )}
        {request === 'ok' && rows.length > 0 && (
          <ul className="divide-y divide-gray-100" aria-label={current.label}>
            {rows.map((c) => <CaseRow key={c.case_id} c={c} />)}
          </ul>
        )}
      </div>

      {lane === 'closed' && request === 'ok' && rows.length > 0 && (
        <p className="text-xs text-gray-500">
          "Verified by CyberMeters" is used only when CyberMeters re-observed the fix itself. A fix the product cannot observe is shown as "Attested by customer — not externally verifiable"; one that needs a certification body or auditor as "Requires independent third-party evidence".
        </p>
      )}
    </section>
  )
}
