import { Link } from 'react-router-dom'
import { severityMeta, toneClass } from '../lib/websiteSecurityDisplay'
import { formatDate } from '../utils/dates'

const date = (value) => formatDate(value, 'Not recorded')

export function exposureCoverageSentence(coverage, checks = null) {
  const count = key => Number.isInteger(coverage?.[key]) && coverage[key] >= 0 ? coverage[key] : 0
  // The receipt's omitted checks are outside its recorded check total. Keep
  // all three customer counts on the recorded-check basis.
  const total = Number.isInteger(coverage?.recorded_total) && coverage.recorded_total >= 0 ? coverage.recorded_total
    : Array.isArray(checks) && checks.length > 0 ? checks.length
    : ['completed', 'blocked', 'not_applicable', 'pending', 'budget_exhausted', 'uncertain'].reduce((sum, key) => sum + count(key), 0)
  const completed = Math.min(count('completed'), total)
  const blocked = Math.min(count('blocked'), total - completed)
  const incomplete = total - completed - blocked
  return `${completed} checks completed · ${blocked} blocked · ${incomplete} not completed this scan (of ${total} recorded checks)`
}

export function hostRotationSentence(coverage) {
  const total = coverage?.hosts_total
  const checked = coverage?.hosts_checked
  if (!Number.isInteger(total) || !Number.isInteger(checked) || total <= 0 || checked < 0 || checked >= total) return null
  return `${checked} of ${total} hosts checked this scan; the rest rotate on the next scans`
}

// The backend owns the host evidence state; this only words it. A name with no
// DNS address or a server that kept failing was observed this scan, but its
// content was not assessed, so neither reads as a plain "checked".
export function hostCoverageLabel(host) {
  if (host?.evidence_state === 'host_does_not_resolve') return 'No DNS address this scan; content not assessed'
  if (host?.evidence_state === 'target_unavailable') return 'Server unavailable this scan; content not assessed'
  if (host?.checked_this_scan) return 'Checked this scan'
  return 'Awaiting rotation; no current verdict'
}

// Render only the receipt's safe evidence projection, as text. Never render response
// bodies, arbitrary HTML, raw headers, query parameters or credential values.
export default function ExternalExposureChecks({ exposure, domain, scanId }) {
  const available = exposure?.source === 'external_exposure'
  const findings = available && Array.isArray(exposure.findings) ? exposure.findings : []
  return <section aria-label="Public content and management surfaces" className="mt-6 border-t border-gray-200 pt-6">
    <h3 className="text-lg font-semibold text-gray-900">Public content and management surfaces</h3>
    <p className="mt-2 text-base leading-relaxed text-gray-600">Checks for exposed configuration, development files, backups and operational information. A visible sign-in screen is not proof of unauthorised access.</p>
    {!available || !exposure.coverage ? <p className="mt-3 text-base text-gray-600">These checks were not recorded in this scan. No conclusion is available.</p> : <>
      <p className="mt-4 text-base font-semibold text-gray-900">{exposureCoverageSentence(exposure.coverage, exposure.checks)}</p>
      {exposure.coverage.omitted_checks > 0 && <p className="mt-2 text-sm text-gray-600">{exposure.coverage.omitted_checks} additional checks were outside this scan’s recorded set.</p>}
      {hostRotationSentence(exposure.coverage) && <p className="mt-3 text-sm font-medium text-gray-700">{hostRotationSentence(exposure.coverage)}. Unchecked hosts have no current security verdict.</p>}
      {Array.isArray(exposure.host_coverage) && exposure.host_coverage.length > 0 && <details className="mt-3 text-sm text-gray-700">
        <summary className="cursor-pointer font-medium">Host coverage and last checked</summary>
        <ul className="mt-2 space-y-1">{exposure.host_coverage.map(host => <li key={host.hostname} className="break-words">
          <strong>{host.hostname}</strong> · {hostCoverageLabel(host)} · Last checked: {date(host.last_checked_at)}
        </li>)}</ul>
      </details>}
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
    </>}
  </section>
}
