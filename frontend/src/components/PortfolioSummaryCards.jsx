import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import { PORTFOLIO_MATURITY_STATE_TEXT, attentionReasons, portfolioMaturityRows } from '../lib/portfolioMaturityDisplay'

const TONE = {
  green: 'bg-brand-200 text-brand-900 border-brand-200',
  indigo: 'bg-indigo-50 text-indigo-700 border-indigo-200',
  blue: 'bg-blue-50 text-blue-700 border-blue-200',
  gray: 'bg-gray-50 text-gray-600 border-gray-200',
}

function useLoad(fn) {
  const [state, setState] = useState({ loading: true, error: null, data: null })
  useEffect(() => {
    let cancelled = false
    Promise.resolve().then(fn)
      .then((data) => { if (!cancelled) setState({ loading: false, error: null, data }) })
      .catch((e) => { if (!cancelled) setState({ loading: false, error: e || new Error('failed'), data: null }) })
    return () => { cancelled = true }
  }, [fn])
  return state
}

// The portfolio summary sentence is written by the backend (it decides what
// may be said, e.g. no all-clear for unassessed customers); shown verbatim.
export function PortfolioExecutiveSummary() {
  const { loading, error, data } = useLoad(api.getPortfolioExecutiveSummary)
  if (error?.error === 'plan_feature_required') return null
  return (
    <section className="card p-6 mb-8" aria-label="Portfolio summary">
      <div className="flex items-center gap-2 mb-2">
        <h2 className="text-sm font-semibold text-gray-900">Portfolio summary</h2>
        {data?.partial_failure && <span className="text-xs rounded-sm px-2 py-0.5 bg-transparent text-brand-700">Partial</span>}
      </div>
      {loading && <p className="text-sm text-gray-500">Loading…</p>}
      {!loading && error && <p role="alert" className="text-sm text-red-700">The portfolio summary could not be loaded.</p>}
      {!loading && data && (
        <>
          <p className="text-sm text-gray-700 leading-relaxed max-w-4xl">{data.executive_summary}</p>
          {data.top_attention?.length > 0 && (
            <ul className="mt-3 space-y-1" aria-label="Customers needing attention">
              {data.top_attention.map((r) => (
                <li key={r.workspace_id} className="text-sm">
                  <Link to={`/workspaces/${encodeURIComponent(r.workspace_id)}`} className="font-medium text-brand-700 hover:underline">{r.workspace_name}</Link>
                  {attentionReasons(r).length > 0 && <span className="text-gray-500"> — {attentionReasons(r).join(', ')}</span>}
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </section>
  )
}

export function PortfolioMaturity() {
  const { loading, error, data } = useLoad(api.getPortfolioMaturity)
  if (error?.error === 'plan_feature_required') return null
  const stateText = data ? PORTFOLIO_MATURITY_STATE_TEXT[data.portfolio_state] : null
  return (
    <section className="card p-6 mb-8" aria-label="Managed maturity across customers">
      <h2 className="text-sm font-semibold text-gray-900 mb-1">Managed maturity across customers</h2>
      <p className="text-xs text-gray-500 mb-3 max-w-3xl">
        Each domain shows the least mature customer: the portfolio is only as far along as the customer furthest behind.
        Customers without a completed assessment count as not established.
      </p>
      {loading && <p className="text-sm text-gray-500">Loading…</p>}
      {!loading && error && <p role="alert" className="text-sm text-red-700">Portfolio maturity could not be loaded.</p>}
      {!loading && data && stateText && data.portfolio_state !== 'assessed' && (
        <p className={`text-sm ${data.portfolio_state === 'unavailable' ? 'text-red-700' : 'text-gray-600'} mb-2`} role={data.portfolio_state === 'unavailable' ? 'alert' : undefined}>{stateText}</p>
      )}
      {!loading && data && data.portfolio_state !== 'unavailable' && data.portfolio_state !== 'no_workspaces' && (
        <ul className="divide-y divide-gray-100">
          {portfolioMaturityRows(data.domains).map((r) => (
            <li key={r.key} className="py-2.5 flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="text-sm font-semibold text-gray-900">{r.name}</div>
                <div className="text-xs text-gray-500">{r.coverage}</div>
                {r.notes.length > 0 && <div className="text-xs text-brand-700 mt-0.5">{r.notes.join(' · ')}</div>}
              </div>
              <span className={`text-xs font-medium px-2 py-0.5 rounded-md border ${TONE[r.tone] || TONE.gray}`}>{r.label}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
