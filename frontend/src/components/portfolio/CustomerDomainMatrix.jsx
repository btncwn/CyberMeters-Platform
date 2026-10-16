// CustomerDomainMatrix — the Portfolio command centre's per-customer view of
// the eight areas, read from GET /api/portfolio/domains (one row per monitored
// domain, carrying the eight persisted resolver states, each with its own
// trend and freshness).
//
// Presentation only. The state word comes from lib/statusVocabulary.js
// (backend state + backend freshness → one vocabulary word), the trend from
// the backend's own trend field, the priority and open-case count from the
// row. Nothing is averaged, derived or defaulted here: a row whose eight-area
// set is missing or malformed shows Error on all eight cells, a loading or
// failed read says so, and an empty portfolio shows the backend's reason.
import { Link } from 'react-router-dom'
import { MODULES, moduleTheme } from '../../lib/moduleRegistry'
import { domainStatus } from '../../lib/statusVocabulary'
import { freshnessMeta, priorityMeta, toneClass, trendMeta } from '../../lib/portfolioDomainDisplay'
import { domainsRequestState } from '../overview/SecurityOverview'
import StatusChip from '../StatusChip'

export const MATRIX_LIMIT = 25

function Chip({ tone, children, title }) {
  return (
    <span title={title} className={`inline-block text-xs font-medium px-2 py-0.5 rounded-md border ${toneClass(tone)}`}>
      {children}
    </span>
  )
}

function AreaCell({ module, entry, request }) {
  const theme = moduleTheme(module.domainKey)
  const status = domainStatus(entry, request)
  const trend = request === 'ok' ? trendMeta(entry?.trend) : null
  const why = request === 'ok' && entry
    ? [entry.summary, entry.trend_reason ? `Trend: ${trend.label} — ${entry.trend_reason}` : null, entry.freshness_reason].filter(Boolean).join('\n')
    : undefined
  return (
    <div
      data-domain-key={module.domainKey}
      className="rounded-md border border-gray-200 bg-white px-2 py-1.5 border-l-4 min-w-0"
      style={theme ? { borderLeftColor: theme.icon } : undefined}
      title={why}
    >
      <div className="text-xs font-semibold text-gray-700 leading-tight">{module.title}</div>
      <div className="mt-1 flex items-center justify-between gap-1">
        <StatusChip status={status} />
        {trend && (
          <>
            <span className="text-sm text-gray-500 leading-none" aria-hidden="true">{trend.symbol}</span>
            <span className="sr-only">, trend: {trend.srLabel}</span>
          </>
        )}
      </div>
    </div>
  )
}

export function CustomerRow({ row, onOpenCustomer }) {
  // Only a valid eight-entry set is shown as read; anything else is an error on
  // every cell — never seven areas, never an invented eighth.
  const request = domainsRequestState(row.cyber_mot_domains, 'ok')
  const byKey = new Map(request === 'ok' ? row.cyber_mot_domains.map((d) => [d.domain_key, d]) : [])
  const pri = priorityMeta(row.priority)
  const fresh = freshnessMeta(row.evidence_freshness)
  const openCases = Number.isFinite(row.open_case_count) ? row.open_case_count : null
  const scanId = row.drill_down?.scan_id
  return (
    <article className="card p-4" data-testid="customer-row" data-workspace-id={row.workspace_id} aria-label={`${row.workspace_name} — ${row.hostname}`}>
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-bold text-gray-900">{row.workspace_name}</span>
            <span className="text-xs text-gray-500">{row.hostname}</span>
          </div>
          <div className="mt-1 flex items-center gap-1.5 flex-wrap">
            <Chip tone={pri.tone}>{pri.label} priority</Chip>
            <Chip tone={fresh.tone} title={row.freshness_reason}>{fresh.label}</Chip>
            <Chip tone={openCases > 0 ? 'info' : 'unknown'}>
              {openCases == null ? 'cases not read' : `${openCases} open case${openCases === 1 ? '' : 's'}`}
            </Chip>
          </div>
          {row.freshness_reason && <p className="text-xs text-gray-500 mt-1">{row.freshness_reason}</p>}
        </div>
        <div className="flex items-center gap-3 shrink-0 text-sm">
          {scanId && (
            <Link to={`/scans/${encodeURIComponent(scanId)}`} className="font-semibold text-gray-500 hover:text-gray-800">Assessment</Link>
          )}
          <button type="button" onClick={() => onOpenCustomer?.(row)} className="font-semibold text-brand-600 hover:text-brand-700">
            Open customer
          </button>
        </div>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 xl:grid-cols-8 gap-1.5 mt-3" data-testid="area-cells">
        {MODULES.map((m) => (
          <AreaCell key={m.domainKey} module={m} entry={byKey.get(m.domainKey) || null} request={request} />
        ))}
      </div>
    </article>
  )
}

/**
 * CustomerDomainMatrix
 *   rows            — backend `domains` array from /portfolio/domains (any shape; validated per row)
 *   request         — 'loading' | 'error' | 'ok'
 *   portfolioState  — backend portfolio_state
 *   reason          — backend portfolio_state_reason
 *   total           — backend pagination.total
 *   onRetry         — re-read
 *   onOpenCustomer  — (row) => select that customer and open its workspace
 */
export default function CustomerDomainMatrix({ rows, request = 'ok', portfolioState, reason, total, onRetry, onOpenCustomer }) {
  const list = request === 'ok' && Array.isArray(rows) ? rows : []
  const state = request === 'ok' && !Array.isArray(rows) ? 'error' : request
  const nothingMonitored = portfolioState === 'no_workspaces' || portfolioState === 'no_domains'
  return (
    <section className="mb-8" aria-labelledby="customer-areas-heading" data-testid="customer-domain-matrix">
      <div className="section-head">
        <div>
          <h2 id="customer-areas-heading" className="section-title">Customers across their external posture</h2>
          <p className="text-xs text-gray-500 mt-1">
            Each monitored domain with the state and trend its latest assessment recorded, highest priority first.
          </p>
        </div>
        <Link to="/portfolio/domains" className="text-sm font-semibold text-brand-600 hover:text-brand-700 shrink-0">
          Full domain view
        </Link>
      </div>

      {state === 'loading' && (
        <div className="card p-5 flex items-center gap-3" role="status">
          <StatusChip status="loading" />
          <span className="text-sm text-gray-600">Reading the state of every customer area…</span>
        </div>
      )}

      {state === 'error' && (
        <div className="card p-5 flex items-center gap-3 flex-wrap" role="alert">
          <StatusChip status="error" />
          <span className="text-sm text-gray-700">The per-customer area states could not be read. Nothing is assumed in the meantime.</span>
          {onRetry && <button type="button" onClick={onRetry} className="ml-auto btn-ghost py-0.5 px-2">Retry</button>}
        </div>
      )}

      {state === 'ok' && list.length === 0 && (
        <div className="card p-8 text-center" data-testid="customer-domain-matrix-empty">
          <p className="text-sm font-semibold text-gray-800">
            {nothingMonitored ? 'No customers are being monitored yet' : 'No customer area states to show'}
          </p>
          <p className="text-xs text-gray-500 mt-1 max-w-md mx-auto">
            {reason || 'The portfolio returned no monitored domains.'}
          </p>
          {nothingMonitored && (
            <Link to="/workspaces" className="btn-primary mt-4 inline-flex">Add a customer</Link>
          )}
        </div>
      )}

      {state === 'ok' && list.length > 0 && (
        <>
          <div className="space-y-3">
            {list.map((r) => (
              <CustomerRow key={`${r.workspace_id}:${r.domain_id}`} row={r} onOpenCustomer={onOpenCustomer} />
            ))}
          </div>
          <p className="text-xs text-gray-500 mt-3">
            {Number.isFinite(total) && total > list.length
              ? `Showing the ${list.length} highest-priority of ${total} monitored domains. `
              : `${list.length} monitored domain${list.length === 1 ? '' : 's'}. `}
            {reason}
          </p>
        </>
      )}
    </section>
  )
}
