// Eight-domain managed-maturity panel — PRESENTATION ONLY (M5.f).
// Renders the server-decided per-workspace maturity ledger (from the canonical
// engines/domain-maturity.js). It performs NO stage derivation of its own — it maps the
// server `maturity_stage` to a customer-friendly label/colour, renders the server's own
// explanation and honest flags verbatim, and always shows all eight domains so none
// silently disappears and a domain with no eligible assessment is never shown as mature.
import React, { useState } from 'react'
import { resolveDisplayMaturity, STAGE_META, maturityHistoryRows } from '../lib/maturityDisplay'
import { ATTESTED_LABEL } from '../lib/caseDisplay'
import { api } from '../api'
import { parseServerDate, formatDay } from '../utils/dates'

const TONE = {
  green:  'bg-brand-200 text-brand-900 border-brand-200',
  indigo: 'bg-indigo-50 text-indigo-700 border-indigo-200',
  blue:   'bg-blue-50 text-blue-700 border-blue-200',
  gray:   'bg-gray-50 text-gray-600 border-gray-200',
}

// A verified/monitored stage is CyberMeters' own re-observation. An attestation is
// deliberately NOT green — "attested by customer, not externally verified".
function Flags({ flags }) {
  if (!flags) return null
  const chips = []
  if (flags.attested) chips.push({ text: ATTESTED_LABEL, cls: 'bg-transparent text-brand-700 border-[1.5px] border-brand-700' })
  if (flags.regressed) chips.push({ text: 'Recurred', cls: 'bg-red-50 text-red-700 border-red-200' })
  if (flags.has_unmanaged_issue) chips.push({ text: 'Unmanaged issue', cls: 'bg-transparent text-brand-700 border-[1.5px] border-brand-700' })
  if (!chips.length) return null
  return (
    <div className="flex flex-wrap gap-1 mt-1 justify-end">
      {chips.map((c, i) => (
        <span key={i} className={`inline-block text-xs font-medium px-1.5 py-0.5 rounded-sm border ${c.cls}`}>{c.text}</span>
      ))}
    </div>
  )
}

function fmtDate(value) {
  const t = parseServerDate(value)
  return t && !Number.isNaN(t.getTime()) ? formatDay(t) : '—'
}

// Append-only history of one domain record's stage for this canonical domain,
// read from the ledger (newest first). Rendered verbatim; nothing derived.
function MaturityHistory({ workspaceId, d }) {
  const [state, setState] = useState({ loading: true, error: false, rows: [] })
  React.useEffect(() => {
    let cancelled = false
    Promise.resolve().then(() => api.getMaturityHistory(workspaceId, d.domain_id, d.domain_key))
      .then((res) => { if (!cancelled) setState({ loading: false, error: false, rows: maturityHistoryRows(res?.history) }) })
      .catch(() => { if (!cancelled) setState({ loading: false, error: true, rows: [] }) })
    return () => { cancelled = true }
  }, [workspaceId, d.domain_id, d.domain_key])
  if (state.loading) return <p className="text-xs text-gray-500 mt-2">Loading history…</p>
  if (state.error) return <p role="alert" className="text-xs text-red-700 mt-2">History could not be loaded.</p>
  if (!state.rows.length) return <p className="text-xs text-gray-500 mt-2">No recorded assessments yet.</p>
  return (
    <ol className="mt-2 border-l border-gray-200 pl-3 space-y-1.5" aria-label={`${d.display_name} maturity history`}>
      {state.rows.slice(0, 12).map((r) => (
        <li key={r.key} className="text-xs text-gray-600">
          <span className="text-gray-400">{fmtDate(r.assessed_at)}</span>
          {' · '}
          <span className={r.changed ? 'font-medium text-gray-900' : ''}>{r.label}</span>
          {r.reason && <span className="text-gray-500"> — {r.reason}</span>}
          {r.regressed && <span className="ml-1 text-red-700">(recurred)</span>}
          {r.attested && <span className="ml-1 text-brand-700">({ATTESTED_LABEL})</span>}
        </li>
      ))}
    </ol>
  )
}

function MaturityRow({ d, workspaceId }) {
  const [open, setOpen] = useState(false)
  const canShowHistory = Boolean(workspaceId && d.established && d.domain_id)
  const meta = STAGE_META[d.maturity_stage] || { label: d.maturity_stage || 'unknown', tone: 'gray' }
  // A domain CyberMeters cannot re-observe (ceiling below monitored) can be managed but
  // never CyberMeters-verified — surface the honest reason it will not reach the top rungs.
  const cappedBelowVerified = d.capability_ceiling === 'managed' || d.capability_ceiling === 'observed'
  return (
    <div className="flex items-start justify-between gap-3 py-2.5 border-b border-gray-100 last:border-0">
      <div className="min-w-0">
        <div className="text-sm font-semibold text-gray-900">{d.display_name}</div>
        <div className="text-xs text-gray-500 mt-0.5 leading-relaxed">{d.stage_description}</div>
        {cappedBelowVerified && (
          <div className="text-xs text-gray-400 mt-1">
            Ceiling: {STAGE_META[d.capability_ceiling]?.label || d.capability_ceiling} — CyberMeters cannot re-observe this domain, so it can be managed but not verified.
          </div>
        )}
        {canShowHistory && (
          <button type="button" className="text-xs text-brand-700 hover:underline mt-1" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
            {open ? 'Hide history' : `History${d.domain_name ? ` for ${d.domain_name}` : ''}`}
          </button>
        )}
        {open && canShowHistory && <MaturityHistory workspaceId={workspaceId} d={d} />}
      </div>
      <div className="shrink-0 text-right">
        <span className={`inline-block text-xs font-medium px-2 py-0.5 rounded-md border ${TONE[meta.tone] || TONE.gray}`}>
          {d.stage_label || meta.label}
        </span>
        <Flags flags={d.flags} />
      </div>
    </div>
  )
}

// domains: the server-decided maturity array. Always renders exactly eight domains — if the
// server data is absent/malformed/failed, resolveDisplayMaturity returns the eight canonical
// domains in a non-mature "not_established" stage (no domain ever disappears, none ever
// shows as mature without evidence).
export default function DomainMaturity({
  domains,
  workspaceId = null,
  title = 'Managed maturity — External posture lifecycle',
  subtitle = 'How far each domain has travelled through the managed lifecycle — observed, managed, then verified and monitored by CyberMeters. This is not the security score; a clean domain with nothing to manage sits at “Observed”.',
}) {
  const list = resolveDisplayMaturity(domains)
  return (
    <div className="card p-5">
      <div className="mb-2">
        <h3 className="text-sm font-semibold text-gray-900">{title}</h3>
        {subtitle && <p className="text-xs text-gray-500 mt-0.5 leading-relaxed">{subtitle}</p>}
      </div>
      <div>
        {list.map((d) => <MaturityRow key={d.domain_key} d={d} workspaceId={workspaceId} />)}
      </div>
      <p className="text-xs text-gray-400 mt-3 leading-relaxed">
        “Verified” and “Verified &amp; monitored” mean CyberMeters re-observed the fix itself. A customer
        attestation is shown separately and is never counted as verified. Maturity reflects the last
        complete assessment; domains CyberMeters cannot re-observe can be managed but not verified.
      </p>
    </div>
  )
}
