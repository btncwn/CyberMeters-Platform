import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import { formatDate, parseServerDate } from '../utils/dates'
import { scanQualityMeta, toneClass } from '../lib/websiteSecurityDisplay'
import { SERVICE_COLORS } from '../theme/serviceColors'
import ExternalExposureChecks from './ExternalExposureChecks'

const colors = SERVICE_COLORS.website

// Human dates through the product's one formatter (no raw timestamps on screen).
const date = (value) => formatDate(value, 'Not recorded')
const count = (value) => Number.isInteger(value) && value >= 0

function checkModule(report, key) {
  const module = report?.modules?.[key]
  if (!module || module.error || module.incomplete || report?.scan_quality?.modules_skipped?.includes(key)
      || report?.scan_quality?.modules_incomplete?.some((entry) => entry.module === key)) return null
  return module
}

// Every tile carries a key; the Website Summary shows HTTPS, headers, HSTS and
// CSP as its figures (S1-SHELL-V2b) and this overview keeps the rest.
export function websiteObservations(report) {
  const ssl = checkModule(report, 'ssl')
  const headers = checkModule(report, 'headers')
  const cookies = checkModule(report, 'domain_security_enrichment')?.cookies
  const redirect = ssl?.http_redirect_chain?.http_redirect_validated === true ? ssl.http_redirects_to_https : null
  const headerData = headers?.accessible === true && headers.headers_assessed !== false
    && Array.isArray(headers.present) && Array.isArray(headers.missing)
  const cookieData = headers?.accessible === true && cookies && !cookies.error && ['found', 'insecure_count', 'no_httponly', 'no_samesite'].every((key) => count(cookies[key]))
  return [
    { key: 'https', title: 'HTTPS access',
      value: ssl?.https_probe_executed === false ? 'Not confirmed' : ssl?.https_available === true ? 'Response observed' : ssl?.https_available === false ? 'Not reachable in this scan' : 'Not confirmed',
      note: ssl?.www_fallback_used ? 'Response came from the www host. See the report for the exact endpoint.' : 'HTTPS availability at the time of this scan.' },
    { key: 'redirect', title: 'HTTP → HTTPS',
      value: redirect === true ? 'Redirect observed' : redirect === false ? 'No redirect observed' : 'Not confirmed',
      note: 'Whether the HTTP request moved to HTTPS.' },
    { key: 'headers', title: 'Security headers',
      value: headerData ? `${headers.present.length} present · ${headers.missing.length} missing` : 'Not confirmed',
      note: 'Presence alone does not prove a strong policy. See the recorded values.' },
    { key: 'cookies', title: 'Cookie attributes',
      value: cookieData ? (cookies.found ? `${cookies.found} cookies observed` : 'No cookies observed') : 'Not confirmed',
      note: cookieData && cookies.found ? `Without Secure: ${cookies.insecure_count} · HttpOnly: ${cookies.no_httponly} · SameSite: ${cookies.no_samesite}` : 'Checks Secure, HttpOnly and SameSite on observed cookies; absence does not prove a fix.' },
    hstsTile(headers, headerData),
    headerTile('csp', 'Content Security Policy', 'content-security-policy', headers, headerData),
  ]
}

// One header's tile from the headers module's own result: missing, or its
// strength class with the module's details sentence. Not assessed → "Not confirmed".
const STRENGTH_WORD = { valid: 'Sent', weak: 'Sent, weak', malformed: 'Sent, malformed', unknown: 'Sent, not classified' }
// A header in `missing` is only "Not sent" when the response could prove its
// absence — the same gates scoring.js uses before it scores header_missing_*
// (HTTPS response, no protection layer, a real 200, and not seen on another
// checked path). Otherwise absence is not confirmed (Executive 08:08; #911 class).
const hostOf = (url) => { try { return new URL(url).hostname.toLowerCase() } catch { return null } }
export function headerAbsenceUncertain(headers, name) {
  if (!headers) return true
  // Only a header seen on the SAME host is page variation; another host's header
  // (www sending HSTS after an apex redirect) says nothing about this response (C-40b).
  const responseHost = hostOf(headers.response_url)
  const variedByPath = (headers.checked_paths || []).some((p) => p?.headers_observed?.[name]
    && (!responseHost || hostOf(p.final_url || p.requested_url) === responseHost))
  return headers.validation_uncertain === true || headers.final_https === false
    // scoring.js reads a missing status code as 0 (not a real 200), so it cannot prove absence either.
    || headers.status_code !== 200 || variedByPath
}
function headerTile(key, title, name, headers, headerData) {
  if (!headerData) return { key, title, value: 'Not confirmed', note: 'The headers were not assessed in this scan.' }
  if (headers.missing.includes(name) && headerAbsenceUncertain(headers, name)) {
    return { key, title, value: 'Not validated', note: 'The site answered through a protection layer or varied by page; absence is not confirmed.' }
  }
  if (headers.missing.includes(name)) return { key, title, value: 'Not sent', note: `The site did not send ${title === 'HSTS' ? 'an HSTS' : 'a Content-Security-Policy'} header.` }
  const strength = headers.header_strength?.[name]
  return { key, title, value: STRENGTH_WORD[strength?.status] || 'Sent', note: strength?.details || 'Sent; strength not recorded.' }
}

// HSTS from the engine's host-scoped policy (item 15 B2, hsts_policy): an STS
// policy binds to the host that sent it, so the apex's own HTTPS answer decides,
// never "not in missing" (C-40b). Results recorded before hsts_policy keep the
// header-based tile.
export function hstsTile(headers, headerData) {
  const key = 'hsts', title = 'HSTS'
  const policy = headers?.hsts_policy
  if (!headerData || !policy?.state) return headerTile(key, title, 'strict-transport-security', headers, headerData)
  const apex = policy.apex_host || 'the apex'
  const other = policy.final_host && policy.final_host !== policy.apex_host ? policy.final_host : null
  if (policy.state === 'not_observed') {
    return { key, title, value: 'Not observed', note: 'The apex did not answer over HTTPS this scan; its HSTS policy was not observed.' }
  }
  if (policy.state === 'absent') {
    // "Not validated" is the module's own uncertainty flag (protection layer, path variation) only.
    if (headers.validation_uncertain === true) {
      return { key, title, value: 'Not validated', note: 'The site answered through a protection layer or varied by page; absence is not confirmed.' }
    }
    if (other && policy.final_value) {
      return { key, title, value: 'Not sent by the apex', note: `${apex} answered over HTTPS without HSTS. ${other} sends its own policy, which does not cover ${apex}.` }
    }
    return { key, title, value: 'Not sent', note: `${apex} answered over HTTPS without an HSTS header.` }
  }
  if (policy.state === 'present') {
    const strength = headers.header_strength?.['strict-transport-security']
    const details = strength?.details || 'Sent; strength not recorded.'
    const scope = other && policy.final_covered === false
      ? (policy.include_subdomains ? ` Set on ${apex}; it does not cover ${other}.` : ` Set on ${apex} without includeSubDomains, so it does not cover ${other}.`)
      : ''
    return { key, title, value: STRENGTH_WORD[strength?.status] || 'Sent', note: `${details}${scope}` }
  }
  return { key, title, value: 'Not confirmed', note: 'The HSTS policy was not assessed in this scan.' }
}

// The tiles the Website Summary lifts into "What we observed".
export const WEBSITE_FIGURE_KEYS = Object.freeze(['https', 'headers', 'hsts', 'csp'])

export default function WebsiteScanOverview({ workspaceId, refresh = 0, onReport = null }) {
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
  // The page lifts the headline tiles into "What we observed"; this card keeps the others.
  useEffect(() => { onReport?.({ report: report || null, pending: Boolean(loading || reportPending) }) }, [report, loading, reportPending, onReport])
  const observations = websiteObservations(report).filter((o) => !(onReport && WEBSITE_FIGURE_KEYS.includes(o.key)))

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
          {/* Each tile is a named anchor the sidebar can open (#website-security-headers, …). */}
          {observations.map(({ title, value, note }) => <div key={title} className="rounded-xl border border-gray-200 bg-gray-50/60 p-4">
            <h3 className="text-base font-semibold text-gray-900">{title}</h3>
            <p className="mt-3 text-base font-semibold text-gray-800">{loading || reportPending ? 'Loading…' : value}</p>
            <p className="mt-2 text-sm leading-relaxed text-gray-600">{note}</p>
          </div>)}
        </div>
        {scan && <div className="mt-5 flex flex-wrap gap-3">
          {/* The page's one scan control is "Scan now" at the top (design standard §1). */}
          <Link className="btn-secondary" to={evidenceUrl}>View latest scan evidence</Link>
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
