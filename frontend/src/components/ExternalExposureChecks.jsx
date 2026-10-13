import { Link } from 'react-router-dom'
import { severityMeta, toneClass } from '../lib/websiteSecurityDisplay'

const COVERAGE = [
  ['completed', 'Completed'], ['pending', 'Waiting'], ['blocked', 'Blocked'],
  ['not_applicable', 'Not applicable'], ['budget_exhausted', 'Budget reached'], ['uncertain', 'Not determined'],
]
const date = (value) => value ? String(value).slice(0, 16).replace('T', ' ') : 'Not recorded'

// Render only the receipt's safe evidence projection, as text. Never render response
// bodies, arbitrary HTML, raw headers, query parameters or credential values.
export default function ExternalExposureChecks({ exposure, domain, scanId }) {
  const available = exposure?.source === 'external_exposure'
  const findings = available && Array.isArray(exposure.findings) ? exposure.findings : []
  return <section aria-label="Public content and management surfaces" className="mt-6 border-t border-gray-200 pt-6">
    <h3 className="text-lg font-semibold text-gray-900">Public content and management surfaces</h3>
    <p className="mt-2 text-base leading-relaxed text-gray-600">Checks for exposed configuration, development files, backups and operational information. A visible sign-in screen is not proof of unauthorised access.</p>
    {!available || !exposure.coverage ? <p className="mt-3 text-base text-gray-600">These checks were not recorded in this scan. No conclusion is available.</p> : <>
      <dl className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-3">
        {COVERAGE.map(([key, label]) => <div key={key} className="rounded-lg border border-gray-200 p-3">
          <dt className="text-sm text-gray-600">{label}</dt>
          <dd className="mt-1 text-base font-semibold">{Number.isInteger(exposure.coverage[key]) && exposure.coverage[key] >= 0 ? exposure.coverage[key] : 'Not recorded'}</dd>
        </div>)}
      </dl>
      {exposure.coverage.pending_assets > 0 && <p className="mt-3 text-sm text-gray-600">{exposure.coverage.pending_assets} additional assets are waiting for their turn in the rotating scan schedule.</p>}
      <p className="mt-3 text-sm text-gray-600">Observed: {date(exposure.observed_at)}. Waiting, blocked and incomplete checks cannot confirm that a previous finding was fixed.</p>
      {!findings.length && <p className="mt-3 text-base text-gray-600">No exposure findings in the recorded checks. Coverage above shows what was and was not assessed; this is not a guarantee that the site is secure.</p>}
      {findings.map((finding) => {
        const item = finding.exposure
        if (!item) return null
        const severity = severityMeta(finding.severity)
        return <details key={finding.id} className="mt-4 rounded-lg border border-gray-200 bg-white p-4">
          <summary className="cursor-pointer text-base font-semibold text-gray-900">{finding.title}</summary>
          <div className="mt-4 space-y-3 text-base leading-relaxed text-gray-700">
            <p className="break-all"><strong>Affected address:</strong> {item.affected_url}</p>
            <p>{item.observation}</p>
            <p><span className={`mr-2 inline-block rounded-full border px-2.5 py-1 text-sm ${toneClass(severity.tone)}`}>{severity.label}</span>{item.severity_rationale}</p>
            <div><p className="font-semibold">Recorded evidence</p><ul className="mt-1 list-disc space-y-1 pl-5">{(item.indicators || []).map((indicator) => <li key={indicator}>{indicator.replace(/_/g, ' ')}</li>)}</ul><p className="mt-1 text-sm">{date(item.observed_at)} · Response content and secret values are not stored.</p></div>
            {item.recommended_action && <p><strong>How to address it:</strong> {item.recommended_action}</p>}
            <p><strong>Latest check:</strong> {finding.finding_type === 'observation' ? 'Observation only; no vulnerability is asserted.' : 'The condition was observed in this scan.'}</p>
            <p><strong>Recheck:</strong> {item.retest_requirement}</p>
            <div className="flex flex-wrap gap-3">
              <Link className="btn-secondary" to={`/scans/new?domain=${encodeURIComponent(domain || '')}`}>Recheck this website</Link>
              {scanId && <Link className="btn-secondary" to={`/scans/${encodeURIComponent(scanId)}?view=technical#website-evidence`}>View scan evidence</Link>}
            </div>
          </div>
        </details>
      })}
      <details className="mt-4 text-sm text-gray-600"><summary className="cursor-pointer font-medium">Recorded request cost</summary><p className="mt-2">Requests: {exposure.costs?.requests ?? 'Not recorded'} · Redirects: {exposure.costs?.redirects ?? 'Not recorded'} · Retries: {exposure.costs?.retries ?? 'Not recorded'} · Response bytes: {exposure.costs?.bytes_decoded ?? 'Not recorded'} · Duration: {exposure.costs?.duration_ms != null ? `${exposure.costs.duration_ms} ms` : 'Not recorded'}</p></details>
    </>}
  </section>
}
