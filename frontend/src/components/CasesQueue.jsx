// Minimum shared cross-domain managed-case presentation. Renders the universal
// /cases queue for a workspace, folding every case_type onto its canonical phase
// via the shared caseDisplay descriptor. Read-only: it displays server-provided
// state and NEVER decides which transitions are legal — that is enforced by the
// backend universal validator. A single presentation for all eight Cyber MOT
// domains, replacing per-page hardcoded state maps for the cross-domain view.
import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import { phaseMeta, phaseClass, domainKeyLabel, DOMAIN_KEY_LABELS } from '../lib/caseDisplay'

export default function CasesQueue({ workspaceId }) {
  const navigate = useNavigate()
  const [cases, setCases] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [domainFilter, setDomainFilter] = useState('')

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    api.getCases(workspaceId, domainFilter ? { domain_key: domainFilter, limit: 100 } : { limit: 100 })
      .then((res) => { if (!cancelled) { setCases(res.cases || []); setError(null) } })
      .catch(() => { if (!cancelled) setError('Could not load managed cases.') })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [workspaceId, domainFilter])

  // Filter options come from the canonical eight domains, NOT from the currently
  // loaded (already-filtered) rows — otherwise picking one domain collapses the
  // dropdown to that domain alone and you can't move to another without resetting.
  const domainKeys = Object.keys(DOMAIN_KEY_LABELS)

  return (
    <section className="rounded-xl border border-slate-200 bg-white p-5">
      <div className="flex items-center justify-between gap-3 mb-4">
        <div>
          <h3 className="text-sm font-semibold text-slate-800">Managed cases — all services</h3>
          <p className="text-xs text-slate-500">One queue across every Cyber MOT domain. Verification is performed by CyberMeters.</p>
        </div>
        <select
          className="text-xs border border-slate-200 rounded-md px-2 py-1 text-slate-600"
          value={domainFilter}
          onChange={(e) => setDomainFilter(e.target.value)}
        >
          <option value="">All services</option>
          {domainKeys.map((k) => <option key={k} value={k}>{domainKeyLabel(k)}</option>)}
        </select>
      </div>

      {loading && <p className="text-xs text-slate-400">Loading…</p>}
      {error && <p className="text-xs text-red-600">{error}</p>}
      {!loading && !error && cases.length === 0 && (
        <p className="text-xs text-slate-400">No managed cases yet. Cases open automatically when a service detects an issue that needs remediation.</p>
      )}

      {!loading && !error && cases.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-slate-400 border-b border-slate-100">
                <th className="py-2 pr-3 font-medium">Service</th>
                <th className="py-2 pr-3 font-medium">Case</th>
                <th className="py-2 pr-3 font-medium">Owner</th>
                <th className="py-2 pr-3 font-medium">Phase</th>
                <th className="py-2 pr-3 font-medium">Severity</th>
                <th className="py-2 pr-3 font-medium">Updated</th>
              </tr>
            </thead>
            <tbody>
              {cases.map((c) => {
                const meta = phaseMeta(c.canonical_phase, c.verification_support)
                return (
                  <tr
                    key={c.case_id}
                    className="border-b border-slate-50 hover:bg-slate-50 cursor-pointer"
                    onClick={() => navigate(`/ws/cases/${encodeURIComponent(c.case_id)}`)}
                    tabIndex={0}
                    role="link"
                    onKeyDown={(e) => { if (e.key === 'Enter') navigate(`/ws/cases/${encodeURIComponent(c.case_id)}`) }}
                  >
                    <td className="py-2 pr-3 text-slate-600">{domainKeyLabel(c.domain_key)}</td>
                    <td className="py-2 pr-3 text-slate-700">
                      <span className="font-medium">{c.title || c.source_finding_type || c.case_id}</span>
                      {c.domain ? <span className="text-slate-400"> · {c.domain}</span> : null}
                    </td>
                    <td className="py-2 pr-3 text-slate-600">{c.owner_ref || <span className="text-slate-400">Unassigned</span>}</td>
                    <td className="py-2 pr-3">
                      <span className={`inline-block rounded-full border px-2 py-0.5 text-xs ${phaseClass(c.canonical_phase, c.verification_support)}`}>
                        {meta.label}
                      </span>
                    </td>
                    <td className="py-2 pr-3 text-slate-500 capitalize">{c.severity || '—'}</td>
                    <td className="py-2 pr-3 text-slate-400 text-xs">{c.updated_at ? c.updated_at.slice(0, 10) : '—'}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
