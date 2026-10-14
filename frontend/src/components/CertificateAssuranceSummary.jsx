import LiveTlsEvidence from './LiveTlsEvidence'
import { customerEvidenceText } from '../lib/evidenceStrengthDisplay'

const STATE_STYLE = {
  observed: 'border-blue-200 bg-blue-50 text-blue-800',
  not_observed: 'border-slate-200 bg-slate-50 text-slate-600',
  unknown: 'border-violet-200 bg-violet-50 text-violet-800',
  unavailable: 'border-gray-200 bg-gray-50 text-gray-600',
  incomplete: 'border-amber-200 bg-amber-50 text-amber-800',
}

// Name match, expiry and trust are checks with a backend-owned outcome: passed,
// failed or not checked. A check that did not run never reads as passed.
const CHECK_STYLE = {
  passed: 'border-emerald-200 bg-emerald-50 text-emerald-800',
  failed: 'border-red-200 bg-red-50 text-red-800',
  not_checked: 'border-gray-200 bg-gray-50 text-gray-600',
}

// Evidence detail is shown in customer words, the same way the PDF shows it:
// internal policy identifiers, publication thresholds and raw provenance
// records stay in the evidence store and are never printed.
const SOURCE_TYPE_TEXT = {
  normative_protocol: 'standards-based protocol observation',
  product_policy: 'CyberMeters product policy',
  configuration_baseline: 'configuration baseline',
  customer_attestation: 'customer attestation',
}
const CORROBORATION_TEXT = {
  'independent-source': 'an independent source',
  'independent-path': 'an independent validation path',
  repeated: 'a repeated observation',
}
const readable = (value) => String(value ?? '').replace(/_/g, ' ').trim()

function observedAt(signal) {
  const value = signal?.provenance && typeof signal.provenance === 'object' ? signal.provenance.observed_at : null
  const date = value ? new Date(value) : null
  return date && !Number.isNaN(date.getTime())
    ? date.toLocaleString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC' }) + ' UTC'
    : null
}

// Published standards are cited by name; every product-policy citation collapses
// to one "CyberMeters product policy" mention.
function citedStandards(authorities) {
  const list = Array.isArray(authorities) ? authorities : []
  const standards = list
    .filter((a) => a?.requirement_type !== 'product_policy')
    .map((a) => {
      const name = a.standard_id || a.id || a.authority
      const version = a.standard_version || a.version
      const section = a.section ? String(a.section) : ''
      return [name, version ? `(${String(version).replace(/^\(|\)$/g, '')})` : null, section || null].filter(Boolean).join(' ')
    })
    .filter(Boolean)
  if (list.some((a) => a?.requirement_type === 'product_policy')) standards.push('CyberMeters product policy')
  return standards.join('; ')
}

const stateLabel = (signal) =>
  signal?.state_label || String(signal?.state || 'not_observed').replace(/_/g, ' ')

function SignalRow({ signal, showEvidence }) {
  if (!signal) return null
  const grade = signal.evidence_grade || {}
  return (
    <div className="rounded-xl border border-slate-100 bg-white p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs font-semibold text-slate-800">{signal.label}</p>
        {signal.check?.label ? (
          <span className={`rounded-full border px-2 py-0.5 text-[13px] font-semibold ${CHECK_STYLE[signal.check.outcome] || CHECK_STYLE.not_checked}`}>
            {signal.check.label}
          </span>
        ) : (
          <span className={`rounded-full border px-2 py-0.5 text-[13px] font-semibold ${STATE_STYLE[signal.state] || STATE_STYLE.not_observed}`}>
            {stateLabel(signal)}
          </span>
        )}
      </div>
      <p className="mt-1 text-xs leading-relaxed text-slate-500">{customerEvidenceText(signal.customer_message)}</p>
      {showEvidence && (
        <div className="mt-2 space-y-0.5 border-t border-slate-100 pt-2 text-[13px] leading-relaxed text-slate-400">
          <p>
            Evidence grade {grade.achieved || 'L0'} · {SOURCE_TYPE_TEXT[signal.source_type] || readable(signal.source_type) || 'source not recorded'}
            {observedAt(signal) ? ` · observed ${observedAt(signal)}` : ''}
          </p>
          <p>
            Required corroboration: {(signal.required_corroboration || []).map((value) => CORROBORATION_TEXT[value] || readable(value)).join(', ') || 'none recorded'}
          </p>
          <p>
            Cited standards: {citedStandards(signal.cited_authorities) || 'not recorded'}
          </p>
        </div>
      )}
    </div>
  )
}

export default function CertificateAssuranceSummary({
  presentation,
  liveTls = null,
  title = 'Certificate Evidence & Trust',
  compact = false,
  showEvidence = false,
  className = '',
}) {
  if (!presentation) return null
  const signals = presentation.signals || {}
  const summary = presentation.summary || {}
  const keys = compact
    ? ['leaf', 'expiry', 'hostname_match', 'chain', 'trust_store_validation', 'revocation_assurance']
    : (presentation.signal_order || Object.keys(signals))

  return (
    <section className={`rounded-2xl border border-slate-200 bg-slate-50/70 p-5 ${className}`}>
      <div className="flex items-start gap-3">
        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-bold text-slate-900">{title}</h3>
          <p className="mt-1 text-xs leading-relaxed text-slate-500">{presentation.scope_note}</p>
          {presentation.historical_notice && (
            <p className="mt-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs leading-relaxed text-amber-800">
              {presentation.historical_notice}
            </p>
          )}
        </div>
      </div>

      {summary.trust_ceiling && (
        <div className="mt-3 flex gap-2 rounded-lg border border-blue-100 bg-white px-3 py-2">
          <p className="text-xs leading-relaxed text-slate-600">{summary.trust_ceiling}</p>
        </div>
      )}

      <div className="mt-3 grid grid-cols-1 gap-2 md:grid-cols-2">
        {keys.map((key) => <SignalRow key={key} signal={signals[key]} showEvidence={showEvidence} />)}
      </div>

      {liveTls && <div className="mt-3"><LiveTlsEvidence evidence={liveTls} /></div>}

      {presentation.relationship?.customer_message && (
        <div className="mt-3 rounded-lg border border-slate-200 bg-white px-3 py-2">
          <p className="text-xs font-semibold text-slate-700">Certificate relationship</p>
          <p className="mt-0.5 text-xs leading-relaxed text-slate-500">
            {presentation.relationship.customer_message}
          </p>
        </div>
      )}
      {presentation.lifecycle?.customer_message && (
        <p className="mt-2 text-xs leading-relaxed text-slate-500">
          <span className="font-semibold text-slate-700">Lifecycle evidence:</span>{' '}
          {presentation.lifecycle.customer_message}
        </p>
      )}
    </section>
  )
}
