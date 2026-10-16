import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import { parseServerDate } from '../utils/dates'
import { snapshotRows } from '../lib/reportSnapshotDisplay'

function fmt(value) {
  const d = parseServerDate(value)
  return d && !Number.isNaN(d.getTime()) ? d.toLocaleString(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—'
}

// Read-only history of the workspace's assessment snapshots. Loaded only when
// opened, so it never slows the reports list.
export default function ReportSnapshotHistory({ wsId }) {
  const [open, setOpen] = useState(false)
  const [state, setState] = useState({ loading: false, error: false, rows: null, more: false })

  function toggle() {
    const next = !open
    setOpen(next)
    if (!next || state.rows || state.loading) return
    setState({ loading: true, error: false, rows: null, more: false })
    Promise.resolve()
      .then(() => Promise.all([api.getReportSnapshots(wsId), api.getWorkspaceDomains(wsId).catch(() => null)]))
      .then(([snap, doms]) => setState({ loading: false, error: false, rows: snapshotRows(snap?.snapshots, doms?.domains), more: Boolean(snap?.pagination?.has_more) }))
      .catch(() => setState({ loading: false, error: true, rows: null, more: false }))
  }

  return (
    <section className="card p-6 mt-6" aria-label="Assessment snapshots">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-semibold text-gray-900">Assessment snapshots</h2>
        <button type="button" className="btn-secondary text-sm" aria-expanded={open} onClick={toggle}>
          {open ? 'Hide' : 'Show history'}
        </button>
      </div>
      <p className="text-sm text-gray-500 mt-1 max-w-3xl">
        Each completed scan leaves one fixed record of every area of your external posture. Reports are produced from these records and are
        never recalculated later, so an old report keeps saying what was true then.
      </p>
      {open && state.loading && <p className="text-sm text-gray-500 mt-3">Loading…</p>}
      {open && state.error && <p role="alert" className="text-sm text-red-700 mt-3">Snapshot history could not be loaded.</p>}
      {open && state.rows && state.rows.length === 0 && <p className="text-sm text-gray-500 mt-3">No snapshots yet. One is recorded after each completed scan.</p>}
      {open && state.rows && state.rows.length > 0 && (
        <ul className="divide-y divide-gray-100 mt-3">
          {state.rows.map((r) => (
            <li key={r.id} className="py-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
              <span className="text-gray-900">{fmt(r.assessed_at)}</span>
              <span className="text-gray-700">{r.domain || 'Domain no longer in this workspace'}</span>
              <span className="text-xs text-gray-500">{r.quality}</span>
              <span className={`text-xs rounded-sm px-2 py-0.5 ${r.current ? 'bg-brand-50 text-brand-700' : 'bg-gray-100 text-gray-600'}`}>
                {r.current ? 'Latest for this domain' : 'Superseded by a later scan'}
              </span>
              {r.scan_id && <Link to={`/scans/${encodeURIComponent(r.scan_id)}`} className="text-xs text-brand-700 hover:underline">Scan details</Link>}
            </li>
          ))}
        </ul>
      )}
      {open && state.more && <p className="text-xs text-gray-500 mt-2">Showing the latest 100 snapshots.</p>}
    </section>
  )
}
