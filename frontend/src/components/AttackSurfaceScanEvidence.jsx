// Attack Surface — what the latest scan recorded about the domain itself:
// registration (RDAP), public content and management surfaces, the deep TLS
// assessment, and the check pack's position on outside vulnerability data.
// Every value is the stored module's own field or the backend's own sentence;
// this file lays them out and never derives a state, a severity or a verdict.
// Full detail stays on the scan page; the links point there.
import { Link } from 'react-router-dom'
import { parseServerDate } from '../utils/dates'
import { severityMeta, scanQualityMeta, toneClass } from '../lib/websiteSecurityDisplay'
import { isNotInCheckPack, isPhase5EvidenceAvailable, phase5KnownCount } from '../lib/phase5EvidencePresentation'
import ExternalExposureChecks from './ExternalExposureChecks'

const date = (value) => value ? String(value).slice(0, 16).replace('T', ' ') : 'Not recorded'
const day = (value) => {
  if (!value) return 'Not recorded'
  const d = parseServerDate(value)
  return Number.isFinite(d?.getTime()) ? d.toLocaleDateString(undefined, { dateStyle: 'medium' }) : 'Not recorded'
}
const count = (value) => Number.isInteger(value) && value >= 0 ? value : 'Not recorded'
const words = (value) => String(value || '').replace(/_/g, ' ')

/** Names the deterministic critical-prefix pass found in DNS (backend list, verbatim). */
export function criticalNamesFromReport(report) {
  const module = report?.modules?.critical_prefix_discovery
  const items = Array.isArray(module?.items) ? module.items : []
  return new Set(items.filter((h) => typeof h === 'string').map((h) => h.toLowerCase()))
}

/** One sentence about the critical-prefix pass, from its own counters. */
export function criticalPrefixCoverageText(report) {
  const module = report?.modules?.critical_prefix_discovery
  if (!module || typeof module !== 'object') return null
  const checked = count(module.checked)
  const requested = count(module.requested)
  const found = count(module.found)
  const base = `Critical names: ${found} found among ${checked} of ${requested} checked`
  if (module.incomplete === true) return `${base}; the check did not finish (${words(module.incomplete_reason || module.reason || 'incomplete')}).`
  return `${base}.`
}

// ── Domain registration (RDAP) ───────────────────────────────────────────────

function registrationAge(days) {
  if (!Number.isInteger(days) || days < 0) return 'Not recorded'
  if (days >= 365) { const y = Math.floor(days / 365); return `${y} year${y === 1 ? '' : 's'}` }
  return `${days} day${days === 1 ? '' : 's'}`
}

function registrationState(whois) {
  if (!whois || typeof whois !== 'object') return { kind: 'absent', text: 'Registration data was not recorded in this scan.' }
  if (whois.unavailable === true || whois.outcome === 'unavailable') {
    return { kind: 'unavailable', text: `The registry did not answer this scan (${words(whois.reason || 'unavailable')}). Registration notes are left out; no other result changes.` }
  }
  if (whois.executed === false || whois.incomplete === true) {
    return { kind: 'deferred', text: `The registration lookup did not run within the scan budget (${words(whois.reason || whois.incomplete_reason || 'not run')}).` }
  }
  if (whois.error) return { kind: 'error', text: 'The registration lookup did not complete in this scan.' }
  if (!whois.registrar && !whois.expiration_date && !whois.creation_date) return { kind: 'empty', text: 'The registry answered without registrar or date fields; nothing is assumed from that.' }
  return { kind: 'recorded', text: null }
}

export function DomainRegistrationCard({ whois, domain }) {
  const state = registrationState(whois)
  const findings = state.kind === 'recorded' && Array.isArray(whois.findings)
    ? whois.findings.filter((f) => f && f.id !== 'whois_registrar_info')
    : []
  return (
    <section aria-label="Domain registration" className="card p-5">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="text-base font-semibold text-gray-900">Domain registration</h3>
        {domain && <span className="text-xs text-gray-500 break-all">{domain}</span>}
      </div>
      <p className="mt-1 text-xs text-gray-500">Read from the registry's RDAP service when the scan ran. Registration data is optional: it never changes any other result or the score.</p>
      {state.kind !== 'recorded' ? (
        <p className="mt-3 text-sm text-gray-600">{state.text}</p>
      ) : (
        <>
          <dl className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div className="rounded-lg border border-gray-200 p-3">
              <dt className="text-xs text-gray-500">Registrar</dt>
              <dd className="mt-1 text-sm font-semibold text-gray-900 break-words">{whois.registrar || 'Not recorded'}</dd>
            </div>
            <div className="rounded-lg border border-gray-200 p-3">
              <dt className="text-xs text-gray-500">Expires</dt>
              <dd className="mt-1 text-sm font-semibold text-gray-900">{day(whois.expiration_date)}</dd>
              {Number.isInteger(whois.days_until_expiry) && (
                <dd className="text-xs text-gray-500 mt-0.5">{whois.days_until_expiry < 0 ? `${Math.abs(whois.days_until_expiry)} days ago` : `in ${whois.days_until_expiry} days`}</dd>
              )}
            </div>
            <div className="rounded-lg border border-gray-200 p-3">
              <dt className="text-xs text-gray-500">Registered for</dt>
              <dd className="mt-1 text-sm font-semibold text-gray-900">{registrationAge(whois.domain_age_days)}</dd>
              {whois.creation_date && <dd className="text-xs text-gray-500 mt-0.5">since {day(whois.creation_date)}</dd>}
            </div>
          </dl>
          {whois.registration_status && <p className="mt-2 text-xs text-gray-500">Registry status: {words(whois.registration_status)}</p>}
          {findings.length > 0 ? (
            <ul className="mt-4 space-y-2" aria-label="Registration findings">
              {findings.map((f) => {
                const sev = severityMeta(String(f.severity || '').toLowerCase())
                return (
                  <li key={f.id} className="rounded-lg border border-gray-200 p-3">
                    <p className="text-sm font-semibold text-gray-900">
                      <span className={`mr-2 inline-block rounded-full border px-2 py-0.5 text-xs ${toneClass(sev.tone)}`}>{sev.label}</span>
                      {f.title || words(f.id)}
                    </p>
                    {f.description && <p className="mt-1 text-xs text-gray-600 leading-relaxed">{f.description}</p>}
                    {f.recommendation && <p className="mt-1 text-xs text-gray-600"><span className="font-semibold">Recommended:</span> {f.recommendation}</p>}
                  </li>
                )
              })}
            </ul>
          ) : (
            <p className="mt-3 text-xs text-gray-500">No registration finding was recorded in this scan.</p>
          )}
        </>
      )}
    </section>
  )
}

// ── Deep TLS assessment ──────────────────────────────────────────────────────

const TLS_QUALITY = {
  complete: 'Complete for the recorded scope',
  partial: 'Partial — some checks remain unresolved or outside this scan budget',
  not_run: 'Not run',
  unavailable: 'Result unavailable for this scan',
}
const TLS_COVERAGE = [
  ['planned', 'Planned'], ['completed', 'Completed'], ['uncertain', 'Uncertain'], ['unexecutable', 'Could not execute'],
  ['not_authorized', 'Not authorized'], ['not_applicable', 'Not applicable'], ['omitted_checks', 'Outside scan budget'], ['endpoint_gaps', 'Endpoint gaps'],
]

export function TlsAssessmentSummary({ assessment, findings, scanId }) {
  const recorded = assessment?.source === 'tls_assessment'
  const endpoints = recorded && Array.isArray(assessment.endpoints) ? assessment.endpoints : []
  const coverage = recorded ? (assessment.coverage || {}) : {}
  const tlsFindings = Array.isArray(findings) ? findings.filter((f) => /^tls_/.test(String(f?.id || ''))) : []
  return (
    <section aria-label="TLS security assessment" className="card p-5">
      <h3 className="text-base font-semibold text-gray-900">TLS security assessment</h3>
      <p className="mt-1 text-xs text-gray-500">Protocol, cipher and key-exchange measurements on the recorded endpoints. Findings from it are tracked under Certificates &amp; Trust; the full measurement stays on the scan page.</p>
      {!recorded ? (
        <p className="mt-3 text-sm text-gray-600">Deep TLS checks were not recorded in this scan. Their status is unknown.</p>
      ) : (
        <>
          <p className="mt-3 text-sm font-semibold text-gray-800">{TLS_QUALITY[assessment.quality] || 'Coverage not established'}</p>
          <ul className="mt-2 flex flex-wrap gap-2 text-xs text-gray-600" aria-label="TLS check coverage">
            {TLS_COVERAGE.map(([key, label]) => <li key={key} className="rounded-sm border border-gray-200 px-2 py-0.5">{label}: {count(coverage[key])}</li>)}
          </ul>
          <p className="mt-2 text-xs text-gray-500">{endpoints.length} endpoint{endpoints.length === 1 ? '' : 's'} recorded · {tlsFindings.length} TLS finding{tlsFindings.length === 1 ? '' : 's'} in this scan{assessment.observed_at ? ` · ${date(assessment.observed_at)}` : ''}</p>
          <div className="mt-3 flex flex-wrap gap-3">
            {scanId && <Link className="btn-secondary text-sm" to={`/scans/${encodeURIComponent(scanId)}?view=technical`}>View TLS measurement</Link>}
            <Link className="btn-secondary text-sm" to="/ws/certificates?tab=findings">Open Certificates &amp; Trust</Link>
          </div>
        </>
      )}
    </section>
  )
}

// ── Outside vulnerability data ───────────────────────────────────────────────
// The backend states whether outside vulnerability data is part of the check
// pack; the page repeats that statement. A stored scan that did use such data
// keeps its recorded counts, labelled as recorded under that scan's checks.

export function OutsideVulnerabilityDataCard({ cve, kev, checkPack }) {
  const statements = [cve?.customer_message, kev?.customer_message].filter(Boolean)
  const notInPack = isNotInCheckPack(cve) || isNotInCheckPack(kev)
  const kevCount = phase5KnownCount(kev, kev?.matched)
  const cveHigh = phase5KnownCount(cve, cve?.high_count)
  const cveCritical = phase5KnownCount(cve, cve?.critical_count)
  const legacyRecorded = !notInPack && (isPhase5EvidenceAvailable(kev) || isPhase5EvidenceAvailable(cve))
  return (
    <section aria-label="Outside vulnerability data" className="card p-5">
      <h3 className="text-base font-semibold text-gray-900">Outside vulnerability data</h3>
      {notInPack ? (
        <>
          {statements.length > 0
            ? statements.map((text) => <p key={text} className="mt-2 text-sm text-gray-600 leading-relaxed">{text}</p>)
            : <p className="mt-2 text-sm text-gray-600">Outside vulnerability databases and exploited-vulnerability lists are not part of this scan's check pack.</p>}
          {(cve?.check_pack_version || checkPack?.version) && <p className="mt-2 text-xs text-gray-400">Check version {cve?.check_pack_version || checkPack?.version}</p>}
        </>
      ) : legacyRecorded ? (
        <>
          <p className="mt-2 text-sm text-gray-600">This stored scan recorded outside vulnerability data under the checks in force when it ran. Those records keep their meaning and are not re-evaluated.</p>
          <p className="mt-2 text-sm text-gray-800 font-semibold">
            {kevCount == null ? 'Exploited-vulnerability matches: not recorded' : `${kevCount} exploited-vulnerability match${kevCount === 1 ? '' : 'es'}`}
            {' · '}
            {cveCritical == null || cveHigh == null ? 'CVE counts: not recorded' : `${cveCritical} critical and ${cveHigh} high CVE records`}
          </p>
        </>
      ) : (
        <p className="mt-2 text-sm text-gray-600">No outside vulnerability data is recorded for this scan.</p>
      )}
      <Link className="mt-3 inline-block text-sm font-semibold text-brand-600 hover:text-brand-700" to="/intelligence">Open the intelligence page</Link>
    </section>
  )
}

// ── The section the Attack Surface Findings tab renders ───────────────────────

export default function AttackSurfaceScanEvidence({ latest, selectedDomain = '', onSelectDomain = null }) {
  const { loading, error, scan, domains, report, reportError, reportPending, boundedHistory } = latest
  const quality = scanQualityMeta(report?.scan_quality?.status || (scan && ['completed', 'partial'].includes(scan.status) ? scan.scan_quality : null))
  const modules = report?.modules || {}
  return (
    <section aria-label="Latest scan evidence" className="space-y-4" data-testid="attack-surface-scan-evidence">
      <div className="card p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <h2 className="section-title">What the latest scan recorded for the domain</h2>
            <p className="mt-1 text-sm text-gray-600">Registration, public content and management surfaces, the deep TLS assessment and the check pack's position on outside vulnerability data.</p>
          </div>
          {domains.length > 1 && onSelectDomain && (
            <label className="max-w-full text-sm text-gray-600">Scanned domain
              <select className="input mt-1 block max-w-full text-base" value={scan?.domain || ''} onChange={(event) => onSelectDomain(event.target.value)}>
                {domains.map((d) => <option key={d} value={d}>{d}</option>)}
              </select>
            </label>
          )}
        </div>
        {loading ? <p className="mt-3 text-sm text-gray-600">Loading recent scans…</p>
          : error ? <p role="alert" className="mt-3 text-sm text-red-700">Recent scans could not be loaded. Refresh to try again; this is not an empty scan history.</p>
            : !scan ? <p className="mt-3 text-sm text-gray-600">No scan has run for this workspace yet, so nothing is recorded here. <Link className="underline" to="/scans/new">Run a scan</Link>.</p>
              : (
                <div className="mt-3 flex flex-wrap items-center gap-3 text-sm text-gray-600">
                  <span className="font-semibold text-gray-900 break-all">{scan.domain}</span>
                  <span>Latest scan: {date(scan.created_at)} · {words(scan.status)}</span>
                  <span className={`rounded-full border px-3 py-1 text-xs ${toneClass(quality.tone)}`}>{quality.label}</span>
                  <Link className="ml-auto text-sm font-semibold text-brand-600 hover:text-brand-700" to={`/scans/${encodeURIComponent(scan.id)}?view=technical`}>Open the scan report</Link>
                </div>
              )}
        {reportPending && <p className="mt-3 text-sm text-gray-600">Loading recorded checks…</p>}
        {reportError && <p role="alert" className="mt-3 text-sm text-amber-800">The latest report could not be loaded. Its checks are not confirmed here.</p>}
        {scan && !['completed', 'partial'].includes(scan.status) && <p className="mt-3 text-sm text-amber-800">The latest scan has not produced a completed assessment. Earlier results have not been substituted.</p>}
        {boundedHistory && <p className="mt-3 text-xs text-gray-500">Domain selection uses this workspace's 20 most recent scan records. <Link className="underline" to="/scans">View scan history</Link></p>}
      </div>
      {report && (
        <>
          <DomainRegistrationCard whois={modules.whois_intelligence} domain={scan?.domain} />
          <div className="card px-5 pb-5">
            <ExternalExposureChecks exposure={modules.external_exposure} domain={scan?.domain} scanId={scan?.id} />
          </div>
          <TlsAssessmentSummary assessment={modules.tls_assessment} findings={report.findings} scanId={scan?.id} />
          <OutsideVulnerabilityDataCard cve={modules.cve_intelligence} kev={modules.known_exploited_vulnerabilities} checkPack={report.check_pack} />
        </>
      )}
    </section>
  )
}
