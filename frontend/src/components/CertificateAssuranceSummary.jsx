import { Info, LockKeyhole } from 'lucide-react'

const STATE_STYLE = {
  observed: 'border-blue-200 bg-blue-50 text-blue-800',
  not_observed: 'border-slate-200 bg-slate-50 text-slate-600',
  unknown: 'border-violet-200 bg-violet-50 text-violet-800',
  unavailable: 'border-gray-200 bg-gray-50 text-gray-600',
  incomplete: 'border-amber-200 bg-amber-50 text-amber-800',
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
        <span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold ${STATE_STYLE[signal.state] || STATE_STYLE.not_observed}`}>
          {stateLabel(signal)}
        </span>
      </div>
      <p className="mt-1 text-xs leading-relaxed text-slate-500">{signal.customer_message}</p>
      {showEvidence && (
        <div className="mt-2 space-y-0.5 border-t border-slate-100 pt-2 text-[10px] leading-relaxed text-slate-400">
          <p>
            Evidence grade {grade.achieved || 'L0'} · source {signal.source_type || 'not recorded'}
          </p>
          <p>
            Ceiling {grade.observable_ceiling || 'not recorded'} · minimum publishable {grade.minimum_publishable || 'not recorded'}
          </p>
          <p>
            Required corroboration: {(signal.required_corroboration || []).join(', ') || 'none recorded'}
          </p>
          <p>
            Authorities: {(signal.cited_authorities || []).map((a) => [a.standard_id || a.id || a.authority, a.standard_version || a.version, a.section, a.requirement_type].filter(Boolean).join(' ')).join('; ') || 'not recorded'}
          </p>
          <p>
            Provenance: {signal.provenance
              ? (typeof signal.provenance === 'string' ? signal.provenance : JSON.stringify(signal.provenance))
              : 'not recorded'}
          </p>
        </div>
      )}
    </div>
  )
}

export default function CertificateAssuranceSummary({
  presentation,
  title = 'Certificate Evidence & Trust',
  compact = false,
  showEvidence = false,
  className = '',
}) {
  if (!presentation) return null
  const signals = presentation.signals || {}
  const summary = presentation.summary || {}
  const keys = compact
    ? ['certificate_transparency', 'leaf', 'hostname_match', 'chain', 'trust_store_validation', 'revocation_assurance']
    : (presentation.signal_order || Object.keys(signals))

  return (
    <section className={`rounded-2xl border border-slate-200 bg-slate-50/70 p-5 ${className}`}>
      <div className="flex items-start gap-3">
        <LockKeyhole className="mt-0.5 h-4 w-4 flex-shrink-0 text-blue-700" />
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
          <Info className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-blue-600" />
          <p className="text-xs leading-relaxed text-slate-600">{summary.trust_ceiling}</p>
        </div>
      )}

      <div className="mt-3 grid grid-cols-1 gap-2 md:grid-cols-2">
        {keys.map((key) => <SignalRow key={key} signal={signals[key]} showEvidence={showEvidence} />)}
      </div>

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
