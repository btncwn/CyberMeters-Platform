// Customer names for the asset event types an alert decision refers to. The
// decision itself (eligible or withheld, and why) stays backend-owned.
const ALERT_EVENT_NAMES = {
  new_asset_discovered: 'New asset',
  asset_reappeared: 'Asset seen again',
  asset_no_longer_seen: 'No longer externally observed',
  takeover_risk_detected: 'Possible subdomain takeover',
  wildcard_dns_detected: 'Wildcard DNS',
  cloud_storage_detected: 'Cloud storage',
}

// Notes that several signals share (the observation caveat, an unrecorded
// coverage limit) are shown once under the signals instead of on every row.
function sharedSignalNotes(signals) {
  const notes = []
  for (const signal of signals) {
    for (const note of [signal.caveat, signal.coverage_message]) {
      if (note && !notes.includes(note)) notes.push(note)
    }
  }
  return notes
}

function signalText(signal) {
  return typeof signal.statement === 'string' && signal.statement
    ? signal.statement
    : signal.customer_message
}

function AssuranceProjection({ presentation }) {
  if (!presentation) return null
  const signals = (presentation.signal_order || [])
    .map(key => presentation.signals?.[key])
    .filter(Boolean)
  const notes = sharedSignalNotes(signals.filter(signal => typeof signal.statement === 'string' && signal.statement))
  const lifecycle = presentation.lifecycle || {}
  const alertEligibility = presentation.alert_eligibility || {}

  return (
    <div className="rounded-xl border border-gray-100 bg-white p-4 space-y-4">
      <div>
        <h3 className="text-sm font-bold text-gray-900">
          {presentation.domain ? `Attack Surface evidence · ${presentation.domain}` : 'Attack Surface evidence'}
        </h3>
        <p className="mt-1 text-xs leading-relaxed text-gray-500">
          Each check is reported on its own. A check that could not run or did not finish is shown as such, never as a clean result.
        </p>
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
              <span className="text-xs font-semibold text-gray-500">{signal.state_label}</span>
            </div>
            <p className="mt-1 text-xs leading-relaxed text-gray-500">
              {signalText(signal)}
            </p>
          </div>
        ))}
      </div>

      {notes.length > 0 && (
        <ul className="space-y-0.5 text-xs leading-relaxed text-gray-400" aria-label="Notes that apply to these checks">
          {notes.map(note => <li key={note}>{note}</li>)}
        </ul>
      )}

      <div className="grid gap-3 lg:grid-cols-2">
        <div className="rounded-lg border border-gray-100 p-3">
          <div className="flex items-center gap-2 text-xs font-bold text-gray-800">
            Asset lifecycle
          </div>
          <p className="mt-1 text-xs leading-relaxed text-gray-500">
            {lifecycle.customer_message}
          </p>
          {(lifecycle.records || []).map(record => (
            <div key={record.asset_id || record.hostname} className="mt-2 rounded bg-gray-50 px-2.5 py-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="mono text-xs font-semibold text-gray-700">
                  {record.hostname || 'Unnamed asset'}
                </span>
                <span className="text-xs font-semibold text-gray-600">
                  {record.lifecycle_state_label}
                </span>
              </div>
              <p className="mt-1 text-xs text-gray-500">{record.lifecycle_message}</p>
              <p className="mt-1 text-xs text-gray-400">
                Latest evidence: {record.last_observation_state_label}
              </p>
            </div>
          ))}
        </div>

        <div className="rounded-lg border border-gray-100 p-3">
          <div className="flex items-center gap-2 text-xs font-bold text-gray-800">
            ASM alert eligibility
          </div>
          <p className="mt-1 text-xs leading-relaxed text-gray-500">
            {alertEligibility.customer_message}
          </p>
          {(alertEligibility.decisions || []).map((decision, index) => (
            <div key={`${decision.event_type}-${decision.reason_code}-${index}`} className="mt-2 rounded bg-gray-50 px-2.5 py-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs font-semibold text-gray-700">
                  {ALERT_EVENT_NAMES[decision.event_type] || 'Asset change'}
                </span>
                <span className="text-xs font-semibold text-gray-600">
                  {decision.eligible ? 'Alert eligible' : 'Alert withheld'}
                </span>
              </div>
              <p className="mt-1 text-xs text-gray-500">{decision.reason_message}</p>
            </div>
          ))}
        </div>
      </div>
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
            Partial lifecycle evidence
          </div>
          <p className="mt-1">{coverage.customer_message}</p>
        </div>
      )}
      {rows.map((presentation, index) => (
        <AssuranceProjection
          key={presentation.domain_id || `presentation-${index}`}
          presentation={presentation}
        />
      ))}
    </div>
  )
}
