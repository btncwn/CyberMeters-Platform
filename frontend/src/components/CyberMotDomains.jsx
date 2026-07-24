// Eight-domain Cyber MOT coverage grid — PRESENTATION ONLY.
// Renders the server-resolved `cyber_mot_domains` array (from the canonical
// resolveCyberMotDomainStates). It performs NO state derivation of its own — it maps
// canonical states to customer-friendly labels/colours and always shows all eight
// domains so no domain silently disappears and missing evidence never looks healthy.
import React from 'react'
import { resolveDisplayDomains } from '../lib/cyberMotDisplay'
import {
  customerEvidenceText,
  evidenceLimits,
  evidenceStrengthLabel,
} from '../lib/evidenceStrengthDisplay'

// Canonical state → { label, tone }. Tones map to Tailwind colour sets below.
const STATE_META = {
  assessed_healthy:        { label: 'Healthy',              tone: 'green' },
  issue_detected:          { label: 'Issue detected',       tone: 'red' },
  provisional:             { label: 'Provisional',          tone: 'amber' },
  degraded:                { label: 'Degraded',             tone: 'amber' },
  unavailable:             { label: 'Unavailable',          tone: 'gray' },
  not_configured:          { label: 'Not configured',       tone: 'gray' },
  customer_input_required: { label: 'Input required',       tone: 'blue' },
  monitoring_only:         { label: 'Monitoring',           tone: 'blue' },
  not_yet_assessed:        { label: 'Not assessed',         tone: 'gray' },
  evidence_insufficient:   { label: 'Evidence insufficient', tone: 'amber' },
}

const TONE = {
  green: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  red:   'bg-red-50 text-red-700 border-red-200',
  amber: 'bg-amber-50 text-amber-700 border-amber-200',
  blue:  'bg-blue-50 text-blue-700 border-blue-200',
  gray:  'bg-gray-50 text-gray-600 border-gray-200',
}

function EvidenceStrengthLine({ assertion, fallbackLimits = [] }) {
  const hasGrade = Boolean(assertion?.grade)
  const limits = hasGrade
    ? evidenceLimits([assertion])
    : [...new Set(fallbackLimits.map(customerEvidenceText).filter(Boolean))]
  return (
    <div className="mt-1 rounded-lg border border-slate-100 bg-slate-50 px-2.5 py-1.5 text-[11px] leading-relaxed text-slate-500">
      <p className="font-semibold text-slate-700">
        Evidence strength: {hasGrade ? evidenceStrengthLabel(assertion) : 'Not recorded'}
      </p>
      <p>
        <span className="font-semibold">Basis:</span>
        {' '}{hasGrade
          ? (customerEvidenceText(assertion.basis) || 'No basis recorded.')
          : 'Evidence-Grade metadata was not recorded in this historical snapshot.'}
      </p>
      <p><span className="font-semibold">Limits:</span> {limits.length ? limits.join(' ') : 'No additional limit was recorded.'}</p>
    </div>
  )
}

function DomainRow({ d }) {
  const meta = STATE_META[d.state] || { label: d.state || 'unknown', tone: 'gray' }
  const conclusionLabel = d.conclusion_label || meta.label
  const provisional = d.coverage && d.coverage !== 'complete' && d.state === 'issue_detected'
  return (
    <div className="flex items-start justify-between gap-3 py-2.5 border-b border-gray-100 last:border-0">
      <div className="min-w-0">
        <div className="text-sm font-semibold text-gray-900">{d.display_name}</div>
        <EvidenceStrengthLine assertion={d.evidence_grade} fallbackLimits={d.limitations || []} />
        <div className="text-xs text-gray-500 mt-0.5 leading-relaxed">
          {customerEvidenceText(d.summary || d.description)}
        </div>
      </div>
      <div className="flex-shrink-0 text-right">
        <span className={`inline-block text-[11px] font-medium px-2 py-0.5 rounded-md border ${TONE[meta.tone]}`}>
          {conclusionLabel}{provisional ? ' · provisional' : ''}
        </span>
        {typeof d.finding_count === 'number' && d.finding_count > 0 && (
          <div className="text-[11px] text-gray-400 mt-1">{d.finding_count} finding{d.finding_count === 1 ? '' : 's'}</div>
        )}
      </div>
    </div>
  )
}

// domains: the server-resolved array. Always renders exactly eight domains — if the
// server data is absent/malformed/failed, resolveDisplayDomains returns the eight
// canonical domains in a non-healthy "unavailable" state (no domain ever disappears).
export default function CyberMotDomains({ domains, title = 'Cyber MOT — Eight-Domain Coverage', subtitle = null }) {
  const list = resolveDisplayDomains(domains)
  return (
    <div className="card p-5">
      <div className="mb-2">
        <h3 className="text-sm font-semibold text-gray-900">{title}</h3>
        {subtitle && <p className="text-xs text-gray-500 mt-0.5">{subtitle}</p>}
      </div>
      <div>
        {list.map((d) => <DomainRow key={d.domain_key} d={d} />)}
      </div>
      <p className="text-[11px] text-gray-400 mt-3 leading-relaxed">
        Every domain is always shown with one honest state — a domain with no evidence is never marked healthy.
        Identity Exposure covers spoofing, impersonation and exposed login surfaces (not credential/breach monitoring);
        Shadow IT shows externally observed technology (approved-inventory comparison is not yet configured).
      </p>
    </div>
  )
}
