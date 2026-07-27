import { AlertTriangle, Bell, Radar } from 'lucide-react'

function AssuranceProjection({ presentation }) {
  if (!presentation) return null
  const signals = (presentation.signal_order || [])
    .map(key => presentation.signals?.[key])
    .filter(Boolean)
  const lifecycle = presentation.lifecycle || {}
  const alertEligibility = presentation.alert_eligibility || {}

  return (
    <div className="rounded-xl border border-gray-100 bg-white p-4 space-y-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-bold text-gray-900">
            {presentation.domain_id ? `Attack Surface evidence · ${presentation.domain_id}` : 'Attack Surface evidence'}
          </h3>
          {presentation.scope_note && (
            <p className="mt-1 text-xs leading-relaxed text-gray-500">{presentation.scope_note}</p>
          )}
        </div>
        <span className="rounded-full bg-gray-50 px-2 py-1 text-[10px] font-semibold text-gray-500">
          {presentation.schema}
        </span>
      </div>

      {presentation.historical_notice && (
        <div className="rounded-lg border border-amber-100 bg-amber-50 px-3 py-2 text-xs leading-relaxed text-amber-800">
          {presentation.historical_notice}
        </div>
      )}

      <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
        {signals.map(signal => (
          <div key={signal.signal_key} className="rounded-lg bg-gray-50 px-3 py-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-semibold text-gray-800">{signal.label}</span>
              <span className="text-[10px] font-semibold text-gray-500">{signal.state_label}</span>
            </div>
            <p className="mt-1 text-[11px] leading-relaxed text-gray-500">
              {signal.customer_message}
            </p>
          </div>
        ))}
      </div>

      <div className="grid gap-3 lg:grid-cols-2">
        <div className="rounded-lg border border-gray-100 p-3">
          <div className="flex items-center gap-2 text-xs font-bold text-gray-800">
            <Radar className="h-3.5 w-3.5 text-brand-600" />
            Asset lifecycle
          </div>
          <p className="mt-1 text-[11px] leading-relaxed text-gray-500">
            {lifecycle.customer_message}
          </p>
          {(lifecycle.records || []).map(record => (
            <div key={record.asset_id || record.hostname} className="mt-2 rounded bg-gray-50 px-2.5 py-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="mono text-[11px] font-semibold text-gray-700">
                  {record.hostname || record.asset_id}
                </span>
                <span className="text-[10px] font-semibold text-gray-600">
                  {record.lifecycle_state_label}
                </span>
              </div>
              <p className="mt-1 text-[11px] text-gray-500">{record.lifecycle_message}</p>
              <p className="mt-1 text-[10px] text-gray-400">
                Latest evidence: {record.last_observation_state_label}
              </p>
            </div>
          ))}
        </div>

        <div className="rounded-lg border border-gray-100 p-3">
          <div className="flex items-center gap-2 text-xs font-bold text-gray-800">
            <Bell className="h-3.5 w-3.5 text-brand-600" />
            ASM alert eligibility
          </div>
          <p className="mt-1 text-[11px] leading-relaxed text-gray-500">
            {alertEligibility.customer_message}
          </p>
          {(alertEligibility.decisions || []).map((decision, index) => (
            <div key={`${decision.event_type}-${decision.reason_code}-${index}`} className="mt-2 rounded bg-gray-50 px-2.5 py-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-[11px] font-semibold text-gray-700">
                  {decision.event_type}
                </span>
                <span className="text-[10px] font-semibold text-gray-600">
                  {decision.eligible ? 'Alert eligible' : 'Alert withheld'}
                </span>
              </div>
              <p className="mt-1 text-[10px] text-gray-400">{decision.reason_code}</p>
              <p className="mt-1 text-[11px] text-gray-500">{decision.reason_message}</p>
            </div>
          ))}
        </div>
      </div>

      <p className="text-[10px] text-gray-400">
        Model versions — signals: {presentation.model_versions?.signal_completeness || 'not recorded'};
        {' '}lifecycle: {presentation.model_versions?.lifecycle_policy || 'not recorded'};
        {' '}alert eligibility: {presentation.model_versions?.alert_eligibility || 'not recorded'}.
      </p>
    </div>
  )
}

export default function AttackSurfaceAssurance({ presentations, coverage = null }) {
  const rows = Array.isArray(presentations)
    ? presentations
    : (presentations ? [presentations] : [])
  if (rows.length === 0) {
    return (
      <div className="rounded-xl border border-amber-100 bg-amber-50 px-4 py-3 text-xs text-amber-800">
        <div className="flex items-center gap-2 font-semibold">
          <AlertTriangle className="h-3.5 w-3.5" />
          Attack Surface evidence was not recorded
        </div>
        <p className="mt-1">No favourable security or availability conclusion is inferred.</p>
      </div>
    )
  }
  return (
    <div className="space-y-3">
      {coverage?.truncated && (
        <div className="rounded-xl border border-amber-100 bg-amber-50 px-4 py-3 text-xs leading-relaxed text-amber-800">
          <div className="flex items-center gap-2 font-semibold">
            <AlertTriangle className="h-3.5 w-3.5" />
            Partial lifecycle evidence
          </div>
          <p className="mt-1">{coverage.customer_message}</p>
        </div>
      )}
      {rows.map((presentation, index) => (
        <AssuranceProjection
          key={presentation.domain_id || `${presentation.schema}-${index}`}
          presentation={presentation}
        />
      ))}
    </div>
  )
}
