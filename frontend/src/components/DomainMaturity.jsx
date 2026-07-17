// Eight-domain managed-maturity panel — PRESENTATION ONLY (M5.f).
// Renders the server-decided per-workspace maturity ledger (from the canonical
// engines/domain-maturity.js). It performs NO stage derivation of its own — it maps the
// server `maturity_stage` to a customer-friendly label/colour, renders the server's own
// explanation and honest flags verbatim, and always shows all eight domains so none
// silently disappears and a domain with no eligible assessment is never shown as mature.
import React from 'react'
import { resolveDisplayMaturity, STAGE_META } from '../lib/maturityDisplay'
import { ATTESTED_LABEL } from '../lib/caseDisplay'

const TONE = {
  green:  'bg-emerald-50 text-emerald-700 border-emerald-200',
  indigo: 'bg-indigo-50 text-indigo-700 border-indigo-200',
  blue:   'bg-blue-50 text-blue-700 border-blue-200',
  gray:   'bg-gray-50 text-gray-600 border-gray-200',
}

// A verified/monitored stage is CyberMeters' own re-observation. An attestation is
// deliberately NOT green — "attested by customer, not externally verified".
function Flags({ flags }) {
  if (!flags) return null
  const chips = []
  if (flags.attested) chips.push({ text: ATTESTED_LABEL, cls: 'bg-amber-50 text-amber-700 border-amber-200' })
  if (flags.regressed) chips.push({ text: 'Recurred', cls: 'bg-red-50 text-red-700 border-red-200' })
  if (flags.has_unmanaged_issue) chips.push({ text: 'Unmanaged issue', cls: 'bg-amber-50 text-amber-700 border-amber-200' })
  if (!chips.length) return null
  return (
    <div className="flex flex-wrap gap-1 mt-1 justify-end">
      {chips.map((c, i) => (
        <span key={i} className={`inline-block text-[10px] font-medium px-1.5 py-0.5 rounded border ${c.cls}`}>{c.text}</span>
      ))}
    </div>
  )
}

function MaturityRow({ d }) {
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
          <div className="text-[11px] text-gray-400 mt-1">
            Ceiling: {STAGE_META[d.capability_ceiling]?.label || d.capability_ceiling} — CyberMeters cannot re-observe this domain, so it can be managed but not verified.
          </div>
        )}
      </div>
      <div className="flex-shrink-0 text-right">
        <span className={`inline-block text-[11px] font-medium px-2 py-0.5 rounded-md border ${TONE[meta.tone] || TONE.gray}`}>
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
  title = 'Managed maturity — Eight-Domain Lifecycle',
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
        {list.map((d) => <MaturityRow key={d.domain_key} d={d} />)}
      </div>
      <p className="text-[11px] text-gray-400 mt-3 leading-relaxed">
        “Verified” and “Verified &amp; monitored” mean CyberMeters re-observed the fix itself. A customer
        attestation is shown separately and is never counted as verified. Maturity reflects the last
        complete assessment; domains CyberMeters cannot re-observe can be managed but not verified.
      </p>
    </div>
  )
}
