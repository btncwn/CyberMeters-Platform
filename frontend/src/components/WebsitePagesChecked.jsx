import { useEffect, useState } from 'react'
import { FileSearch } from 'lucide-react'
import { api } from '../api'
import { parseServerDate } from '../utils/dates'
import { coverageSummary, pageFacts, pageStatusMeta, sensitiveLabel } from '../lib/websitePagesDisplay'

// "Pages checked" — the bounded important-page inventory for this workspace.
// Explanation first, facts second; no verdicts (those come from findings).

function fmt(value) {
  const d = parseServerDate(value)
  return d && !Number.isNaN(d.getTime()) ? d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }) : null
}

function PageRow({ page }) {
  const status = pageStatusMeta(page.monitoring_status)
  const facts = pageFacts(page)
  return (
    <li className="py-3 flex flex-col gap-1">
      <div className="flex flex-wrap items-center gap-2">
        <span className="mono text-sm text-gray-900 break-all">{page.path}</span>
        {sensitiveLabel(page) && <span className="text-xs rounded px-2 py-0.5 bg-brand-50 text-brand-700">{sensitiveLabel(page)}</span>}
        <span className={`text-xs rounded px-2 py-0.5 ${status.tone === 'neutral' ? 'bg-gray-100 text-gray-700' : 'bg-gray-50 text-gray-500'}`} title={status.help || undefined}>{status.label}</span>
      </div>
      {facts.length > 0 && page.monitoring_status !== 'observed' && (
        <p className="text-xs text-gray-500">As of when it was last seen{fmt(page.last_seen_at) ? ` (${fmt(page.last_seen_at)})` : ''}:</p>
      )}
      {facts.length > 0 && (
        <ul className="flex flex-wrap gap-1.5" aria-label={`Observed on ${page.path}`}>
          {facts.map((f) => <li key={f} className="text-xs rounded border border-gray-200 px-2 py-0.5 text-gray-700">{f}</li>)}
        </ul>
      )}
      <p className="text-xs text-gray-500">
        {fmt(page.first_seen_at) ? `First seen ${fmt(page.first_seen_at)}` : null}
        {fmt(page.last_seen_at) ? ` · last seen ${fmt(page.last_seen_at)}` : null}
      </p>
    </li>
  )
}

export default function WebsitePagesChecked({ workspaceId, refresh = 0 }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    // Promise chain so even a synchronous failure renders as an error, never a crash.
    Promise.resolve().then(() => api.getWebsiteSecurityPages(workspaceId))
      .then((res) => { if (!cancelled) setData(res) })
      .catch((e) => { if (!cancelled) setError(e?.message || 'Pages could not be loaded.') })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [workspaceId, refresh])

  const domains = data?.domains || []
  return (
    <section className="card p-5 mb-6" aria-label="Pages checked">
      <div className="flex items-center gap-2 mb-1">
        <FileSearch className="w-4 h-4 text-gray-500" />
        <h2 className="section-title">Pages checked</h2>
      </div>
      <p className="text-sm text-gray-600 mb-3">
        Besides the homepage, CyberMeters checks a small number of your site's own public pages — sign-in, account,
        admin and checkout pages first — for what a visitor's browser would receive.
      </p>
      {data?.scope_note && <details className="mb-3 text-sm text-gray-600"><summary className="cursor-pointer font-medium">What this does not cover</summary><p className="mt-2 max-w-3xl leading-relaxed">{data.scope_note}</p></details>}
      {loading && <p className="text-sm text-gray-500">Loading…</p>}
      {!loading && error && <p role="alert" className="text-sm text-red-700">Pages could not be loaded.</p>}
      {!loading && !error && domains.length === 0 && <p className="text-sm text-gray-600">No domains in this workspace yet.</p>}
      {!loading && !error && domains.map((d) => (
        <div key={d.domain_id} className="mt-3">
          <h3 className="text-sm font-semibold text-gray-900">{d.domain}</h3>
          <p className="text-xs text-gray-500 mb-1">{coverageSummary(d.latest_run)}</p>
          {d.pages.length > 0
            ? <ul className="divide-y divide-gray-100">{d.pages.map((p) => <PageRow key={p.id} page={p} />)}</ul>
            : <p className="text-sm text-gray-600">No pages recorded for this domain yet.</p>}
          {d.truncated && <p className="text-xs text-gray-500 mt-1">Showing {d.pages.length} of {d.total_pages} recorded pages (sign-in, account, admin and checkout pages first).</p>}
        </div>
      ))}
    </section>
  )
}
