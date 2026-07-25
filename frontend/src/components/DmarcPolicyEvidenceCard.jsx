import {
  AlertTriangle,
  CheckCircle,
  ChevronDown,
  FileClock,
  Info,
  ShieldCheck,
} from 'lucide-react'

function toneFor(presentation) {
  if (presentation?.status !== 'current') return 'neutral'
  if (presentation?.monitoring?.state === 'monitoring_degraded') return 'warn'
  if (['present_invalid', 'multiple'].includes(presentation?.observation?.state)) return 'warn'
  return 'ok'
}

const TONE = {
  ok: {
    shell: 'border-brand-100 bg-brand-50/30',
    icon: 'bg-brand-100 text-brand-700',
    Icon: ShieldCheck,
  },
  warn: {
    shell: 'border-amber-200 bg-amber-50/40',
    icon: 'bg-amber-100 text-amber-700',
    Icon: AlertTriangle,
  },
  neutral: {
    shell: 'border-slate-200 bg-slate-50',
    icon: 'bg-white text-slate-500',
    Icon: FileClock,
  },
}

function TagValue({ value }) {
  if (!value?.present) return null
  return (
    <span className={`rounded-md border px-2 py-1 font-mono text-[11px] ${
      value.valid
        ? 'border-slate-200 bg-white text-slate-700'
        : 'border-amber-200 bg-amber-50 text-amber-800'
    }`}>
      {value.tag}={value.raw ?? 'not recorded'}
    </span>
  )
}

function EvidenceGrade({ grade }) {
  if (!grade?.grade) return null
  return (
    <div className="rounded-lg border border-slate-200 bg-white px-3 py-2">
      <p className="text-[11px] font-semibold text-slate-700">
        Evidence Grade {grade.grade}
      </p>
      <p className="mt-0.5 text-[11px] leading-relaxed text-slate-500">
        {grade.basis || 'No evidence basis was recorded.'}
      </p>
      {grade.limits?.length > 0 && (
        <p className="mt-1 text-[11px] leading-relaxed text-slate-500">
          <span className="font-semibold text-slate-600">Limits:</span>{' '}
          {grade.limits.join(' ')}
        </p>
      )}
    </div>
  )
}

function TechnicalAppendix({ appendix }) {
  if (!appendix) return null
  return (
    <details className="group rounded-lg border border-slate-200 bg-white">
      <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2 text-xs font-semibold text-slate-700">
        <ChevronDown className="h-3.5 w-3.5 transition-transform group-open:rotate-180" />
        Technical DMARC evidence
      </summary>
      <div className="space-y-3 border-t border-slate-100 px-3 py-3">
        <dl className="grid gap-x-4 gap-y-1 sm:grid-cols-2">
          {(appendix.facts || []).map((fact) => (
            <div key={`${fact.label}:${fact.value}`} className="min-w-0">
              <dt className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">
                {fact.label}
              </dt>
              <dd className="break-all text-[11px] text-slate-600">{fact.value}</dd>
            </div>
          ))}
        </dl>

        {appendix.lookup_path?.length > 0 && (
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">
              Ordered lookup evidence
            </p>
            <ol className="mt-1 space-y-1">
              {appendix.lookup_path.map((step, index) => (
                <li key={`${step?.question?.name || 'lookup'}:${index}`} className="text-[11px] text-slate-600">
                  {index + 1}. {step?.question?.type || 'DNS'}{' '}
                  <span className="font-mono">{step?.question?.name || 'name not recorded'}</span>
                  {' '}— {step?.outcome || 'outcome not recorded'}
                  {step?.logically_used === false ? ' — not used in the conclusion' : ''}
                </li>
              ))}
            </ol>
          </div>
        )}

        {appendix.raw_records?.length > 0 && (
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">
              Observed record data
            </p>
            <div className="mt-1 space-y-1">
              {appendix.raw_records.map((record, index) => (
                <p key={index} className="break-all rounded bg-slate-50 px-2 py-1 font-mono text-[10px] text-slate-600">
                  {String(record?.raw ?? record?.value ?? record)}
                </p>
              ))}
            </div>
          </div>
        )}
      </div>
    </details>
  )
}

export default function DmarcPolicyEvidenceCard({
  presentation,
  compact = false,
  showTechnical = false,
  className = '',
}) {
  if (!presentation) return null
  const tone = TONE[toneFor(presentation)]
  const Icon = tone.Icon

  if (presentation.status !== 'current') {
    return (
      <section
        className={`rounded-xl border p-4 ${tone.shell} ${className}`}
        aria-label="DMARC methodology notice"
      >
        <div className="flex items-start gap-3">
          <div className={`flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-lg ${tone.icon}`}>
            <Icon className="h-4 w-4" />
          </div>
          <div>
            <p className="text-sm font-bold text-slate-900">{presentation.headline}</p>
            <p className="mt-1 text-xs leading-relaxed text-slate-600">
              {presentation.customer_message}
            </p>
          </div>
        </div>
      </section>
    )
  }

  const policy = presentation.policy || {}
  return (
    <section
      className={`rounded-xl border ${compact ? 'p-3' : 'p-4'} ${tone.shell} ${className}`}
      aria-label="DMARC policy evidence"
    >
      <div className="flex items-start gap-3">
        <div className={`flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-lg ${tone.icon}`}>
          <Icon className="h-4 w-4" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-start justify-between gap-2">
            <div>
              <p className="text-sm font-bold text-slate-900">{presentation.headline}</p>
              <p className="mt-0.5 text-xs leading-relaxed text-slate-600">
                {presentation.customer_message}
              </p>
            </div>
            <span className="rounded-full border border-slate-200 bg-white px-2 py-1 text-[10px] font-semibold text-slate-600">
              {presentation.completeness?.core_label || 'Unavailable'}
            </span>
          </div>

          <div className="mt-2 flex flex-wrap gap-1.5">
            <TagValue value={policy.p} />
            <TagValue value={policy.sp} />
            <TagValue value={policy.np} />
            <TagValue value={policy.t} />
          </div>

          <div className="mt-2 space-y-1">
            {policy.message && (
              <p className="text-xs leading-relaxed text-slate-600">{policy.message}</p>
            )}
            {policy.inheritance_message && (
              <p className="text-xs leading-relaxed text-slate-600">{policy.inheritance_message}</p>
            )}
            {policy.testing_message && (
              <p className="text-xs leading-relaxed text-amber-800">{policy.testing_message}</p>
            )}
            {presentation.legacy_pct?.message && (
              <p className="text-xs leading-relaxed text-amber-800">
                {presentation.legacy_pct.message}
              </p>
            )}
          </div>

          {!compact && (
            <dl className="mt-3 grid gap-2 rounded-lg border border-slate-200 bg-white p-3 sm:grid-cols-3">
              <div>
                <dt className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">
                  Policy source
                </dt>
                <dd className="mt-0.5 text-xs text-slate-700">
                  {policy.source_label}
                  {policy.source_domain ? ` · ${policy.source_domain}` : ''}
                </dd>
              </div>
              <div>
                <dt className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">
                  Organisational domain
                </dt>
                <dd className="mt-0.5 text-xs text-slate-700">
                  {presentation.organisational_domain?.value || 'Not determined'}
                </dd>
              </div>
              <div>
                <dt className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">
                  Monitoring
                </dt>
                <dd className="mt-0.5 text-xs text-slate-700">
                  {presentation.monitoring?.label || 'Unavailable'}
                </dd>
              </div>
            </dl>
          )}

          {presentation.monitoring?.message && (
            <p className={`mt-2 flex items-start gap-1.5 text-[11px] leading-relaxed ${
              presentation.monitoring.state === 'monitoring_degraded'
                ? 'text-amber-800'
                : 'text-slate-500'
            }`}>
              {presentation.monitoring.state === 'monitoring_degraded'
                ? <AlertTriangle className="mt-0.5 h-3 w-3 flex-shrink-0" />
                : <CheckCircle className="mt-0.5 h-3 w-3 flex-shrink-0" />}
              {presentation.monitoring.message}
            </p>
          )}

          {!compact && presentation.external_rua?.destinations?.length > 0 && (
            <div className="mt-3">
              <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">
                Aggregate-report destinations
              </p>
              <ul className="mt-1 space-y-2">
                {presentation.external_rua.destinations.map((destination) => (
                  <li key={`${destination.destination_index}:${destination.uri}`} className="rounded-lg border border-slate-200 bg-white px-3 py-2">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="break-all font-mono text-[11px] text-slate-700">
                        {destination.uri || 'Destination not recorded'}
                      </span>
                      <span className="text-[10px] font-semibold text-slate-600">
                        {destination.status_label}
                      </span>
                    </div>
                    <p className="mt-1 text-[11px] leading-relaxed text-slate-500">
                      {destination.message}
                    </p>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {!compact && <EvidenceGrade grade={presentation.evidence_grade} />}
          {showTechnical && (
            <div className="mt-3">
              <TechnicalAppendix appendix={presentation.technical_appendix} />
            </div>
          )}

          <p className="mt-2 flex items-start gap-1.5 text-[10px] leading-relaxed text-slate-500">
            <Info className="mt-0.5 h-3 w-3 flex-shrink-0" />
            A requested DMARC policy does not prove how every receiver handled mail.
          </p>
        </div>
      </div>
    </section>
  )
}
