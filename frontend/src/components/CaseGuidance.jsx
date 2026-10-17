import { useId } from 'react'
import { Link } from 'react-router-dom'

// What the case asks of the customer, how CyberMeters re-checks the fix, what the
// latest re-check found and how the case ended. Every sentence is the backend's
// (engines/case-guidance.js): this component lays the facts out and decides
// nothing — it never upgrades a waiting re-check, and it never calls a case
// verified unless the backend's closure says CyberMeters verified it.

const CARD = 'rounded-xl border border-slate-200 bg-white p-5'

function fmt(ts) {
  if (!ts) return null
  return String(ts).replace('T', ' ').replace('Z', '').slice(0, 16)
}

const OUTCOME_TONE = {
  fixed: 'text-brand-700',
  still_present: 'text-red-700',
  waiting: 'text-brand-700',
}

function Fact({ term, children }) {
  if (!children) return null
  return (
    <div>
      <dt className="text-xs text-slate-500">{term}</dt>
      <dd className="text-sm text-slate-700 mt-0.5">{children}</dd>
    </div>
  )
}

function HostList({ hosts, label }) {
  if (!Array.isArray(hosts) || hosts.length === 0) return null
  return (
    <ul className="mt-2 space-y-1 list-disc pl-5" aria-label={label}>
      {hosts.map((host, index) => (
        <li key={`${host.hostname || 'host'}-${index}`} className="text-sm text-slate-700 wrap-break-word">{host.label}</li>
      ))}
    </ul>
  )
}

export default function CaseGuidance({ guidance }) {
  const todoId = useId()
  const recheckId = useId()
  if (!guidance || typeof guidance !== 'object') return null
  const { remediation, recheck, last_recheck: last, closure, continuity } = guidance
  const related = continuity
    ? [continuity.previous_case, continuity.next_case, continuity.still_seen].filter((item) => item?.label)
    : []
  const ownerLine = remediation
    ? [remediation.owner_label, remediation.effort ? `${remediation.effort} effort` : null].filter(Boolean).join(', ')
    : null

  return (
    <>
      {remediation && (
        <section aria-labelledby={todoId} className={CARD}>
          <h2 id={todoId} className="text-sm font-semibold text-slate-800 mb-3">What to do</h2>
          {remediation.title && <p className="text-base font-medium text-slate-900 mb-3">{remediation.title}</p>}
          <dl className="space-y-3">
            <Fact term="What was found">{remediation.explanation}</Fact>
            <Fact term="Why it matters">{remediation.business_impact}</Fact>
            <Fact term="Recommended action">{remediation.recommended_action}</Fact>
            <Fact term="Who usually does it">{ownerLine}</Fact>
          </dl>
        </section>
      )}

      {(recheck || last || closure || related.length > 0) && (
        <section aria-labelledby={recheckId} className={CARD}>
          <h2 id={recheckId} className="text-sm font-semibold text-slate-800 mb-3">How the fix is checked</h2>
          {recheck?.label && <p className="text-sm text-slate-700">{recheck.label}</p>}
          {recheck?.fixed_when && (
            <p className="text-sm text-slate-700 mt-2">
              <span className="font-medium">Counts as fixed when: </span>{recheck.fixed_when}
            </p>
          )}
          {recheck?.rule && <p className="text-xs text-slate-500 mt-2">{recheck.rule}</p>}

          {last && (
            <div className="mt-4 border-t border-slate-100 pt-4">
              <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
                <h3 className="text-xs font-semibold text-slate-600">Last re-check</h3>
                {fmt(last.at) && <span className="text-xs text-slate-500">{fmt(last.at)}</span>}
              </div>
              <p className={`text-sm font-medium mt-1 ${OUTCOME_TONE[last.outcome] || 'text-slate-700'}`}>{last.label}</p>
              {last.reason && <p className="text-sm text-slate-600 mt-1">{last.reason}</p>}
              <HostList hosts={last.hosts} label="What each affected host answered" />
            </div>
          )}

          {closure && (
            <div className="mt-4 border-t border-slate-100 pt-4">
              <h3 className="text-xs font-semibold text-slate-600">How this case ended</h3>
              <p className="text-sm text-slate-700 mt-1">
                {closure.label}
                {fmt(closure.at) ? <span className="text-slate-500">{` on ${fmt(closure.at)}`}</span> : null}
              </p>
            </div>
          )}

          {related.length > 0 && (
            <div className="mt-4 border-t border-slate-100 pt-4">
              <h3 className="text-xs font-semibold text-slate-600">Earlier and later cases</h3>
              <ul className="mt-1 space-y-1">
                {related.map((item) => (
                  <li key={item.label} className="text-sm text-slate-700">
                    {item.label}
                    {item.case_id && (
                      <>{' '}<Link className="text-brand-700 hover:underline" to={`/ws/cases/${encodeURIComponent(item.case_id)}`}>Open that case</Link></>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </section>
      )}
    </>
  )
}
