import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import { parseServerDate } from '../utils/dates'
import { scanQualityMeta, toneClass } from '../lib/websiteSecurityDisplay'
import { SERVICE_COLORS } from '../theme/serviceColors'
import ExternalExposureChecks from './ExternalExposureChecks'

const colors = SERVICE_COLORS.website

const date = (value) => value ? String(value).slice(0, 16).replace('T', ' ') : 'Not recorded'
const count = (value) => Number.isInteger(value) && value >= 0

function checkModule(report, key) {
  const module = report?.modules?.[key]
  if (!module || module.error || module.incomplete || report?.scan_quality?.modules_skipped?.includes(key)
      || report?.scan_quality?.modules_incomplete?.some((entry) => entry.module === key)) return null
  return module
}

function observations(report) {
  const ssl = checkModule(report, 'ssl')
  const headers = checkModule(report, 'headers')
  const cookies = checkModule(report, 'domain_security_enrichment')?.cookies
  const redirect = ssl?.http_redirect_chain?.http_redirect_validated === true ? ssl.http_redirects_to_https : null
  const headerData = headers?.accessible === true && headers.headers_assessed !== false
    && Array.isArray(headers.present) && Array.isArray(headers.missing)
  const cookieData = headers?.accessible === true && cookies && !cookies.error && ['found', 'insecure_count', 'no_httponly', 'no_samesite'].every((key) => count(cookies[key]))
  return [
    { title: 'HTTPS access',
      value: ssl?.https_probe_executed === false ? 'Not confirmed' : ssl?.https_available === true ? 'Response observed' : ssl?.https_available === false ? 'Not reachable in this scan' : 'Not confirmed',
      note: ssl?.www_fallback_used ? 'Response came from the www host. See the report for the exact endpoint.' : 'HTTPS availability at the time of this scan.' },
    { title: 'HTTP → HTTPS',
      value: redirect === true ? 'Redirect observed' : redirect === false ? 'No redirect observed' : 'Not confirmed',
      note: 'Whether the HTTP request moved to HTTPS.' },
    { title: 'Security headers',
      value: headerData ? `${headers.present.length} present · ${headers.missing.length} missing` : 'Not confirmed',
      note: 'Presence alone does not prove a strong policy. See the recorded values.' },
    { title: 'Cookie attributes',
      value: cookieData ? (cookies.found ? `${cookies.found} cookies observed` : 'No cookies observed') : 'Not confirmed',
      note: cookieData && cookies.found ? `Without Secure: ${cookies.insecure_count} · HttpOnly: ${cookies.no_httponly} · SameSite: ${cookies.no_samesite}` : 'Checks Secure, HttpOnly and SameSite on observed cookies; absence does not prove a fix.' },
  ]
}

export default function WebsiteScanOverview({ workspaceId, refresh = 0 }) {
  const [scans, setScans] = useState([])
  const [selectedDomain, setSelectedDomain] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)
  const [result, setResult] = useState(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true); setError(false); setScans([]); setResult(null)
    api.getWorkspaceScans(workspaceId)
      .then((data) => { if (!cancelled) setScans(Array.isArray(data?.scans) ? data.scans : []) })
      .catch(() => { if (!cancelled) setError(true) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [workspaceId, refresh])

  // The endpoint is bounded to 20 recent scans. Keep the latest ATTEMPT per
  // domain, including failures, instead of falling back to an older success.
  const latest = new Map()
  for (const scan of [...scans].sort((a, b) => parseServerDate(b.created_at) - parseServerDate(a.created_at))) {
    if (scan.id && scan.domain && !latest.has(scan.domain)) latest.set(scan.domain, scan)
  }
  const scan = latest.get(selectedDomain) || latest.values().next().value

  useEffect(() => {
    let cancelled = false
    setResult(null)
    if (scan && ['completed', 'partial'].includes(scan.status)) {
      api.getScanReport(scan.id)
        .then((report) => {
          if (report?.scan_id && report.scan_id !== scan.id) throw new Error('Unexpected scan report')
          if (!cancelled) setResult({ scanId: scan.id, report })
        })
        .catch(() => { if (!cancelled) setResult({ scanId: scan.id, error: true }) })
    }
    return () => { cancelled = true }
  }, [scan?.id, scan?.status, workspaceId, refresh])

  const current = result?.scanId === scan?.id ? result : null
  const report = current?.report
  const quality = scanQualityMeta(report?.scan_quality?.status || (['completed', 'partial'].includes(scan?.status) ? scan?.scan_quality : null))
  const reportPending = scan && ['completed', 'partial'].includes(scan.status) && !current
  const domainState = report?.cyber_mot_domains?.find((entry) => entry.domain_key === 'website_security')
  const evidenceUrl = scan ? `/scans/${encodeURIComponent(scan.id)}?view=technical#website-evidence` : null

  return (
    <section id="website-observations" aria-label="Website scan overview" className="card mb-8 overflow-hidden scroll-mt-28">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-gray-100 px-6 py-5">
        <div><p className="text-sm font-semibold" style={{ color: colors.text }}>Website protection overview</p><h2 className="section-title mt-1">What did the latest scan observe?</h2></div>
        {latest.size > 1 && <label className="max-w-full text-sm text-gray-600">Recent scan site
          <select className="input mt-1 block max-w-full text-base" value={scan.domain} onChange={(event) => setSelectedDomain(event.target.value)}>
            {[...latest.keys()].map((domain) => <option key={domain} value={domain}>{domain}</option>)}
          </select>
        </label>}
      </div>
      <div className="px-6 py-5">
        {loading ? <p className="text-base text-gray-600">Loading recent website scans…</p>
          : error ? <p role="alert" className="text-base text-red-700">Recent scans could not be loaded. Refresh to try again; this is not an empty scan history.</p>
            : !scan ? <div><h3 className="text-lg font-semibold">No website scan available yet</h3><p className="mt-2 text-base text-gray-600">Run a scan to see HTTPS, header and cookie observations here. An empty finding list is not a security assessment.</p><Link className="btn-primary mt-4" to="/scans/new">Run a website scan</Link></div>
              : <>
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="min-w-0"><p className="text-lg font-semibold break-all">{scan.domain}</p><p className="mt-1 text-sm text-gray-600">Latest scan: {date(scan.created_at)} · {String(scan.status).replace(/_/g, ' ')}</p></div>
                  <span className={`rounded-full border px-3 py-1 text-sm ${toneClass(quality.tone)}`}>{quality.label}</span>
                </div>
                {reportPending && <p className="mt-4 text-base text-gray-600">Loading recorded checks…</p>}
                {current?.error && <p role="alert" className="mt-4 text-base text-brand-700">The latest report could not be loaded. Its checks are not confirmed here.</p>}
                {!['completed', 'partial'].includes(scan.status) && <p className="mt-4 text-base text-brand-700">The latest scan has not produced a completed assessment. Earlier results have not been substituted.</p>}
                {domainState?.conclusion_label && <p className="mt-4 text-base font-medium text-gray-700">{domainState.conclusion_label}</p>}
              </>}
        <div className="mt-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {observations(report).map(({ title, value, note }) => <div key={title} className="rounded-xl border border-gray-200 bg-gray-50/60 p-4">
            <h3 className="text-base font-semibold text-gray-900">{title}</h3>
            <p className="mt-3 text-base font-semibold text-gray-800">{loading || reportPending ? 'Loading…' : value}</p>
            <p className="mt-2 text-sm leading-relaxed text-gray-600">{note}</p>
          </div>)}
        </div>
        {scan && <div className="mt-5 flex flex-wrap gap-3">
          <Link className="btn-secondary" to={evidenceUrl}>View latest scan evidence</Link>
          <Link className="btn-primary" to={`/scans/new?domain=${encodeURIComponent(scan.domain)}`}>Recheck this website</Link>
        </div>}
        <div id="exposure-checks" className="scroll-mt-28">
          {report
            ? <ExternalExposureChecks exposure={report.modules?.external_exposure} domain={scan?.domain} scanId={scan?.id} />
            : <section aria-label="Exposure checks" className="mt-6 border-t border-gray-200 pt-6">
                <h3 className="text-lg font-semibold text-gray-900">Exposure checks</h3>
                <p className="mt-2 text-base text-gray-600">{reportPending || loading ? 'Loading recorded checks…' : 'No exposure check result is available from the latest scan.'}</p>
              </section>}
        </div>
        {scans.length >= 20 && <p className="mt-4 text-sm text-gray-500">Site selection uses this workspace’s 20 most recent scan records. <Link className="underline" to="/scans">View scan history</Link></p>}
      </div>
    </section>
  )
}
