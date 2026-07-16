// ── MSP Portfolio — per-domain state and trend ────────────────────────────────
// One row per managed customer domain, showing all EIGHT Cyber MOT domains with their
// own state, trend and evidence freshness.
//
// This page renders decisions it did not make. Every state, trend, priority, reason and
// count comes from GET /api/portfolio/domains; there is no ladder, no threshold and no
// derivation here. PortfolioRiskPage carried a byte-identical copy of the backend's
// 75/55/35 ladder and it drifted — that is the specific mistake this page is written to
// avoid.
import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, Clock, FolderOpen, Shield } from 'lucide-react'
import { api } from '../api'
import { PlanGate } from '../components/PlanUsageCard'
import {
  domainStateMeta, freshnessMeta, hasScore, priorityMeta, toneClass, trendMeta,
} from '../lib/portfolioDomainDisplay'

const Chip = ({ tone, children, title }) => (
  <span title={title} className={`inline-block text-[11px] font-medium px-2 py-0.5 rounded-md border ${toneClass(tone)}`}>
    {children}
  </span>
)

// A domain cell in the eight-domain matrix. Colour is never the only carrier: every
// cell has a text label and a title, so the grid is readable without colour vision and
// to a screen reader.
function DomainCell({ d }) {
  const state = domainStateMeta(d.state)
  const trend = trendMeta(d.trend)
  const stale = d.evidence_freshness === 'stale'
  const why = [
    `${d.display_name}: ${state.label}`,
    d.summary,
    `Trend: ${trend.label} — ${d.trend_reason}`,
    stale ? d.freshness_reason : null,
    d.open_case_count ? `${d.open_case_count} open case${d.open_case_count === 1 ? '' : 's'}` : null,
  ].filter(Boolean).join('\n')

  return (
    <div className={`rounded-md border px-2 py-1.5 ${toneClass(state.tone)}`} title={why}>
      <div className="text-[10px] font-semibold leading-tight truncate">{d.display_name}</div>
      <div className="flex items-center justify-between gap-1 mt-0.5">
        <span className="text-[10px] leading-tight truncate">{state.label}</span>
        <span className="text-[10px] leading-none" aria-hidden="true">{trend.symbol}</span>
        <span className="sr-only">, trend: {trend.srLabel}</span>
      </div>
      {stale && <div className="text-[9px] mt-0.5 font-semibold">stale evidence</div>}
    </div>
  )
}

function DomainRow({ row }) {
  const [open, setOpen] = useState(false)
  const pri = priorityMeta(row.priority)
  const fresh = freshnessMeta(row.evidence_freshness)

  return (
    <div className="card p-4">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-bold text-gray-900">{row.hostname}</span>
            <Chip tone={pri.tone}>{pri.label} priority</Chip>
            <Chip tone={fresh.tone} title={row.freshness_reason}>{fresh.label}</Chip>
            {row.open_case_count > 0 && (
              <Chip tone="info">{row.open_case_count} open case{row.open_case_count === 1 ? '' : 's'}</Chip>
            )}
          </div>
          <div className="text-xs text-gray-500 mt-1">
            {row.workspace_name} · {row.freshness_reason}
          </div>
        </div>
        <div className="text-right flex-shrink-0">
          {/* No score is not a zero and not a 100 — the reason is shown instead of a
              number, and the /100 is omitted rather than printed with nothing in it. */}
          {hasScore(row.overall_score) && row.overall_rating ? (
            <>
              <div className="text-lg font-bold text-gray-900">{row.overall_score}<span className="text-xs text-gray-400">/100</span></div>
              <div className="text-[11px] text-gray-500 capitalize">{row.overall_rating}</div>
            </>
          ) : (
            <div className="text-[11px] text-slate-500 max-w-[16rem]">{row.overall_reason}</div>
          )}
        </div>
      </div>

      {/* The eight, always. Never averaged into the number above. */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-1.5 mt-3">
        {row.cyber_mot_domains.map((d) => <DomainCell key={d.domain_key} d={d} />)}
      </div>

      {row.attention_reasons.length > 0 && (
        <div className="mt-3">
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
            className="text-xs font-semibold text-brand-700 hover:underline"
          >
            {open ? 'Hide' : 'Show'} {row.attention_reasons.length} reason{row.attention_reasons.length === 1 ? '' : 's'} this needs attention
          </button>
          {open && (
            <ul className="mt-2 space-y-1">
              {row.attention_reasons.map((r, i) => (
                <li key={`${r.domain_key}-${r.kind}-${i}`} className="text-xs text-gray-600 flex gap-2">
                  <span className="text-gray-300 mt-0.5">•</span>
                  <span>{r.detail}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {/* Drill-down carries the ids the API authorised — never a hostname lookup. */}
      <div className="mt-3 flex gap-3 text-xs">
        {row.drill_down.scan_id && (
          <Link to={`/scans/${row.drill_down.scan_id}`} className="text-brand-700 font-semibold hover:underline">
            View the assessment behind this →
          </Link>
        )}
        <Link to={`/domain/${encodeURIComponent(row.hostname)}/history`} className="text-gray-500 hover:underline">
          History
        </Link>
      </div>
    </div>
  )
}

const Legend = () => (
  <details className="card p-4">
    <summary className="text-xs font-semibold text-gray-700 cursor-pointer">What these states and trends mean</summary>
    <div className="grid md:grid-cols-2 gap-4 mt-3 text-xs text-gray-600">
      <div>
        <div className="font-semibold text-gray-800 mb-1">State</div>
        <ul className="space-y-1">
          <li><b>Healthy</b> — assessed on a complete scan, no material issue observed.</li>
          <li><b>Issue detected</b> — a material finding is outstanding.</li>
          <li><b>Provisional</b> — no issue seen, but the scan's coverage was incomplete.</li>
          <li><b>Evidence insufficient</b> — we tried to assess this and could not.</li>
          <li><b>Not assessed</b> — no completed assessment has recorded a state. This is not a clean bill of health.</li>
          <li><b>Input required</b> — needs the customer's questionnaire before it can be assessed.</li>
          <li><b>Monitoring</b> — observed only; no verdict is claimed.</li>
        </ul>
      </div>
      <div>
        <div className="font-semibold text-gray-800 mb-1">Trend</div>
        <ul className="space-y-1">
          <li><b>Improving / Recovered</b> — issues resolved between two comparable assessments.</li>
          <li><b>Stable</b> — two comparable assessments, same evidence.</li>
          <li><b>Worsening / New risk</b> — new or more severe issues than the previous assessment.</li>
          <li><b>No history</b> — fewer than two comparable assessments. This is not the same as stable.</li>
          <li><b>Not comparable</b> — the assessments cannot be honestly compared: one did not complete, evidence disappeared, or the way this domain is assessed changed. A change we made is never shown as a change you caused.</li>
        </ul>
      </div>
    </div>
  </details>
)

export default function PortfolioDomainsPage() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('')
  const [sort, setSort] = useState('priority')
  const [page, setPage] = useState(0)
  const LIMIT = 25

  const load = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const params = { limit: LIMIT, offset: page * LIMIT, sort }
      if (filter) params.filter = filter
      setData(await api.getPortfolioDomains(params))
    } catch (err) { setError(err) } finally { setLoading(false) }
  }, [filter, sort, page])

  useEffect(() => { load() }, [load])

  const summary = data?.summary
  const totalPages = useMemo(
    () => (data?.pagination ? Math.max(1, Math.ceil(data.pagination.total / LIMIT)) : 1),
    [data],
  )

  if (loading && !data) {
    return <div className="p-6 flex items-center justify-center min-h-64"><div className="animate-spin rounded-full h-8 w-8 border-2 border-gray-200 border-t-brand-600" /></div>
  }
  if (error?.error === 'plan_feature_required') {
    return <div className="p-6 max-w-screen-xl mx-auto"><PlanGate error={error}>{null}</PlanGate></div>
  }
  if (error) {
    return (
      <div className="p-6 max-w-screen-xl mx-auto">
        <div className="card p-6 border border-red-100 bg-red-50 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
          <div>
            <div className="text-sm font-semibold text-red-800">Could not load your portfolio</div>
            <div className="text-xs text-red-700 mt-1">{error.message || 'Please try again.'}</div>
            <button onClick={load} className="btn-secondary mt-3 text-xs">Retry</button>
          </div>
        </div>
      </div>
    )
  }

  const rows = data?.domains ?? []

  return (
    <div className="p-6 max-w-screen-xl mx-auto">
      <div className="mb-6">
        <div className="eyebrow">MSP Portfolio</div>
        <h1 className="page-title">Domain state &amp; trend</h1>
        <p className="page-subtitle">
          Every managed domain across all eight Cyber MOT security domains — what state it is in, what changed, and how current the evidence is.
        </p>
      </div>

      {/* Explanation first, number second. The coverage note leads because a count drawn
          from partial evidence is worth less than knowing it is partial. */}
      {summary && (
        <>
          {summary.coverage_note && (
            <div className="card p-4 mb-4 border border-amber-100 bg-amber-50 flex items-start gap-2">
              <Clock className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
              <div className="text-xs text-amber-800">{summary.coverage_note}</div>
            </div>
          )}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-4">
            {[
              ['Domains', summary.total_domains, `across ${summary.total_customers} customer${summary.total_customers === 1 ? '' : 's'}`],
              ['Need attention', summary.attention_required, 'issues, worsening or unknown'],
              ['Worsening', summary.worsening_domains, 'vs. previous comparable scan'],
              ['Stale evidence', summary.stale_domains, 'not recently assessed'],
              ['Open cases', summary.open_cases, 'across the portfolio'],
            ].map(([label, value, sub]) => (
              <div key={label} className="stat-tile">
                <div className="metric-label">{label}</div>
                <div className="metric-value">{value}</div>
                <div className="metric-sub">{sub}</div>
              </div>
            ))}
          </div>
        </>
      )}

      <div className="flex items-end gap-3 flex-wrap mb-4">
        <label className="text-xs">
          <span className="label block mb-1">Show</span>
          <select value={filter} onChange={(e) => { setFilter(e.target.value); setPage(0) }} className="input text-xs py-1.5">
            <option value="">All domains</option>
            <option value="attention">Needs attention</option>
            <option value="worsening">Worsening</option>
            <option value="stale">Stale evidence</option>
            <option value="unknown">Unknown state</option>
            <option value="incomplete">Incomplete assessment</option>
            <option value="cases">Has open cases</option>
          </select>
        </label>
        <label className="text-xs">
          <span className="label block mb-1">Sort by</span>
          <select value={sort} onChange={(e) => { setSort(e.target.value); setPage(0) }} className="input text-xs py-1.5">
            <option value="priority">Priority</option>
            <option value="worsening">Worsening first</option>
            <option value="severity">Severity</option>
            <option value="score">Lowest score</option>
            <option value="freshness">Stalest evidence</option>
            <option value="cases">Open cases</option>
            <option value="customer">Customer</option>
            <option value="domain">Domain</option>
          </select>
        </label>
        <div className="text-xs text-gray-400 ml-auto">
          {data?.pagination ? `${data.pagination.total} domain${data.pagination.total === 1 ? '' : 's'}` : null}
        </div>
      </div>

      {rows.length === 0 ? (
        <div className="card p-12 text-center" data-testid="portfolio-empty">
          <Shield className="w-10 h-10 text-gray-300 mx-auto mb-3" />
          <div className="text-sm font-semibold text-gray-800">
            {data?.portfolio_state === 'no_workspaces' || data?.portfolio_state === 'no_domains'
              ? 'No domains in your portfolio yet'
              : 'No domains match this view'}
          </div>
          <div className="text-xs text-gray-500 mt-1 max-w-md mx-auto">
            {data?.portfolio_state_reason || 'Try a different filter.'}
          </div>
        </div>
      ) : (
        <div className="space-y-3" data-testid="portfolio-rows">
          {rows.map((r) => <DomainRow key={`${r.workspace_id}:${r.domain_id}`} row={r} />)}
        </div>
      )}

      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-4">
          <button className="btn-secondary text-xs" disabled={page === 0} onClick={() => setPage((p) => Math.max(0, p - 1))}>Previous</button>
          <span className="text-xs text-gray-500">Page {page + 1} of {totalPages}</span>
          <button className="btn-secondary text-xs" disabled={page + 1 >= totalPages} onClick={() => setPage((p) => p + 1)}>Next</button>
        </div>
      )}

      {summary?.by_domain?.length > 0 && (
        <div className="card p-6 mt-6">
          <div className="section-head">
            <h2 className="section-title">Across the portfolio, by security domain</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="data-table min-w-[640px]">
              <thead>
                <tr>
                  <th>Security domain</th><th>Issues</th><th>Healthy</th>
                  <th>Unknown</th><th>Worsening</th><th>Stale</th><th>Open cases</th>
                </tr>
              </thead>
              <tbody>
                {summary.by_domain.map((d) => (
                  <tr key={d.domain_key}>
                    <td className="font-medium text-gray-800">{d.display_name}</td>
                    <td className={d.issue_detected ? 'text-red-600 font-semibold' : 'text-gray-400'}>{d.issue_detected}</td>
                    <td className="text-gray-600">{d.assessed_healthy}</td>
                    <td className={d.unknown ? 'text-slate-600 font-semibold' : 'text-gray-400'}>{d.unknown}</td>
                    <td className={d.worsening ? 'text-red-600 font-semibold' : 'text-gray-400'}>{d.worsening}</td>
                    <td className={d.stale ? 'text-amber-600 font-semibold' : 'text-gray-400'}>{d.stale}</td>
                    <td className="text-gray-600">{d.open_cases}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="text-[11px] text-gray-400 mt-3">
            Counts, not an average. A portfolio-wide score would let one critical domain hide behind seven healthy ones.
          </p>
        </div>
      )}

      <div className="mt-6"><Legend /></div>

      {data?.generated_at && (
        <div className="text-[11px] text-gray-400 mt-4 flex items-center gap-1">
          <FolderOpen className="w-3 h-3" /> Generated {new Date(data.generated_at).toLocaleString('en-GB')}
        </div>
      )}
    </div>
  )
}
