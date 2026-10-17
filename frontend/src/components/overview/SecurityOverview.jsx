// SecurityOverview — the ONE eight-area overview, rendered for a direct
// customer (/dashboard) and for an MSP-selected customer (/ws/dashboard) from
// the same props. No second implementation exists.
//
// Presentation only. Every state shown here is a backend value mapped to the
// common vocabulary by lib/statusVocabulary.js; counts are shown as
// observations, never turned into a verdict. A request that is still loading,
// failed, or came back malformed is shown as exactly that — eight areas still
// render, none of them settled.
import { Link } from 'react-router-dom'
import { api } from '../../api'
import { resolveDisplayDomains } from '../../lib/cyberMotDisplay'
import { customerEvidenceText } from '../../lib/evidenceStrengthDisplay'
import { MODULES, guidePathForDomainKey, casesPathForDomainKey, moduleTheme } from '../../lib/moduleRegistry'
import { domainStatus, summariseCases } from '../../lib/statusVocabulary'
import StatusChip from '../StatusChip'

// A request helper for callers whose API surface may not carry the function
// (older bundles, partial mocks): a missing function is a failed request, which
// the vocabulary shows as Error — never as an empty, settled list.
export function requestManagedCases(workspaceId, params = { limit: 200 }) {
  return Promise.resolve().then(() => api.getCases(workspaceId, params))
}

export function requestDomainStates(workspaceId) {
  return Promise.resolve().then(() => api.getCyberMotDomains(workspaceId))
}

// Only a valid eight-entry backend set is "ok"; anything else is a failed read.
export function domainsRequestState(domains, request) {
  if (request === 'loading' || request === 'error') return request
  const valid = Array.isArray(domains) && domains.length === 8
    && domains.every((d) => d && typeof d === 'object' && typeof d.domain_key === 'string' && typeof d.state === 'string')
  return valid ? 'ok' : 'error'
}

function titleCase(s) { return s ? String(s).charAt(0).toUpperCase() + String(s).slice(1) : '' }

// Observations from the scorecard and the latest report — the same counts the
// dashboard showed before, grouped under the area they describe. Numbers only;
// the chip above them carries the state.
export function moduleObservations(domainKey, { scorecard, critical = 0, high = 0, hasCompletedScan = false } = {}) {
  const sc = scorecard || null
  if (domainKey === 'attack_surface' && hasCompletedScan) {
    return [
      { label: 'Critical findings', value: critical, tone: critical > 0 ? 'bad' : '' },
      { label: 'High findings', value: high, tone: high > 0 ? 'warn' : '' },
      ...(sc?.active_assets != null ? [{ label: 'Active assets', value: sc.active_assets }] : []),
    ]
  }
  if (domainKey === 'certificates_trust') {
    const cr = sc?.certificate_risks?.risk_level
    if (!cr) return []
    return [
      { label: 'Certificate risk', value: titleCase(cr), tone: ['high', 'critical'].includes(cr) ? 'bad' : cr === 'medium' ? 'warn' : '' },
      ...(sc?.certificate_risks?.expiring_soon != null ? [{ label: 'Expiring soon', value: sc.certificate_risks.expiring_soon, tone: sc.certificate_risks.expiring_soon > 0 ? 'warn' : '' }] : []),
    ]
  }
  if (domainKey === 'brand_protection') {
    const brand = sc?.brand_risks
    if (!brand || (brand.active == null && brand.high == null)) return []
    return [
      { label: 'High-risk lookalikes', value: brand.high ?? 0, tone: (brand.high ?? 0) > 0 ? 'bad' : '' },
      { label: 'Active candidates', value: brand.active ?? 0 },
    ]
  }
  return []
}

// The next thing to do, from real signals only — the same ladder the dashboard
// used, now in one place so both overview surfaces say the same thing.
export function recommendedNextAction({ domainCount, hasCompletedScan, scorecard, critical = 0 } = {}) {
  const cr = scorecard?.certificate_risks?.risk_level
  const brand = scorecard?.brand_risks
  if (domainCount === 0) return { text: 'Add your first domain so CyberMeters can start monitoring it.', cta: 'Add a domain', to: '/ws/domains' }
  if (!hasCompletedScan) return { text: 'Run your first external scan to discover exposed assets and email posture.', cta: 'Run a scan', to: '/scans/new' }
  if (cr && ['high', 'critical'].includes(cr)) return { text: 'Certificate trust needs attention — review expiry and HTTPS posture.', cta: 'Review certificates', to: '/ws/certificates' }
  if (brand && (brand.high ?? 0) > 0) return { text: 'High-risk lookalike domains detected — review brand candidates.', cta: 'Review brand candidates', to: '/ws/brand-monitoring' }
  if (critical > 0) return { text: 'Critical findings on your attack surface — review and remediate.', cta: 'Review attack surface', to: '/assets' }
  return { text: 'Connect Email Protection to measure impersonation exposure and receive DMARC reports.', cta: 'Open Email Protection', to: '/ws/email-protection' }
}

/** The "Recommended next action" strip — one component for the home screen and the workspace overview. */
export function NextActionCard({ signals = {} }) {
  const rec = recommendedNextAction(signals)
  return (
    <div className="card p-5 border-brand-100 bg-brand-50/40 flex flex-col sm:flex-row sm:items-center gap-4" data-testid="next-action">
      <div className="flex-1 min-w-0">
        <p className="text-xs font-semibold text-brand-700 uppercase tracking-wide">Recommended next action</p>
        <p className="text-sm text-gray-800 mt-0.5 leading-relaxed">{rec.text}</p>
      </div>
      <Link to={rec.to} className="btn-primary text-sm shrink-0">{rec.cta}</Link>
    </div>
  )
}

const KPI_TONE = { bad: 'text-red-700', warn: 'text-brand-700', '': 'text-gray-800' }

function ModuleCard({ module, entry, request, caseSummary, casesRequest, observations }) {
  const theme = moduleTheme(module.domainKey)
  const status = domainStatus(entry, request)
  const summary = request === 'ok' && entry ? customerEvidenceText(entry.summary || entry.description) : null
  const openCases = caseSummary?.open ?? 0
  const guide = guidePathForDomainKey(module.domainKey)
  return (
    <article
      data-domain-key={module.domainKey}
      className="card p-5 flex flex-col gap-3 border-t-4"
      style={theme ? { borderTopColor: theme.icon } : undefined}
      aria-labelledby={`overview-${module.domainKey}`}
    >
      <div className="flex flex-col items-start gap-2">
        <h3 id={`overview-${module.domainKey}`} className="text-sm font-bold leading-snug" style={theme ? { color: theme.text } : undefined}>
          {module.title}
        </h3>
        <StatusChip status={status} />
      </div>
      <p className="text-xs text-gray-600 leading-relaxed">
        {request === 'loading' ? 'Reading the latest assessment…'
          : request === 'error' ? 'The latest assessment could not be read. Refresh to try again; nothing is assumed in the meantime.'
          : (summary || module.fallback)}
      </p>
      {request === 'ok' && entry?.freshness_reason && (
        <p className="text-xs text-gray-500">{entry.freshness_reason}</p>
      )}
      {observations.length > 0 && (
        <dl className="grid grid-cols-2 gap-x-3 gap-y-1">
          {observations.map((k) => (
            <div key={k.label} className="min-w-0">
              <dt className="text-xs text-gray-500 truncate">{k.label}</dt>
              <dd className={`text-sm font-bold tabular-nums ${KPI_TONE[k.tone || '']}`}>{k.value}</dd>
            </div>
          ))}
        </dl>
      )}
      <p className="text-xs text-gray-500">
        {request === 'ok' && typeof entry?.finding_count === 'number'
          ? `${entry.finding_count} finding${entry.finding_count === 1 ? '' : 's'}`
          : 'Findings not read'}
        {' · '}
        {casesRequest === 'ok'
          ? <Link to={casesPathForDomainKey(module.domainKey)} className="font-semibold text-gray-700 hover:text-brand-800">{openCases} open case{openCases === 1 ? '' : 's'}</Link>
          : casesRequest === 'loading' ? 'cases loading' : 'cases not read'}
      </p>
      <div className="mt-auto flex flex-wrap items-center gap-x-4 gap-y-1 pt-1">
        <Link to={module.to} className="text-sm font-semibold text-brand-700 hover:text-brand-800">{module.cta}</Link>
        {guide && <Link to={guide} className="text-sm font-semibold text-gray-500 hover:text-gray-800">Field Guide</Link>}
      </div>
    </article>
  )
}

/**
 * SecurityOverview
 *   workspaceName    — shown in the heading
 *   domains          — backend cyber_mot_domains array (any shape; validated here)
 *   domainsRequest   — 'loading' | 'error' | 'ok'
 *   cases            — backend managed cases for this workspace (any shape)
 *   casesRequest     — 'loading' | 'error' | 'ok'
 *   signals          — { domainCount, hasCompletedScan, scorecard, critical, high }
 */
export default function SecurityOverview({ workspaceName, domains, domainsRequest = 'ok', cases, casesRequest = 'ok', signals = {} }) {
  const request = domainsRequestState(domains, domainsRequest)
  const list = request === 'ok' ? resolveDisplayDomains(domains) : []
  const byKey = new Map(list.map((d) => [d.domain_key, d]))
  const caseList = casesRequest === 'ok' && Array.isArray(cases) ? cases : []
  const casesState = casesRequest === 'ok' && !Array.isArray(cases) ? 'error' : casesRequest
  const casesByKey = new Map(MODULES.map((m) => [m.domainKey, summariseCases(caseList.filter((c) => c?.domain_key === m.domainKey))]))
  const sc = signals.scorecard
  const brand = sc?.brand_risks
  const cr = sc?.certificate_risks?.risk_level
  const critical = signals.critical ?? 0
  const high = signals.high ?? 0
  const posture = [
    { label: 'Brand candidates', value: brand ? `${brand.active ?? 0} active${(brand.high ?? 0) > 0 ? `, ${brand.high} high-risk` : ''}` : 'Unknown', tone: brand && (brand.high ?? 0) > 0 ? 'bad' : 'na' },
    { label: 'Open findings', value: signals.hasCompletedScan ? `${critical} critical, ${high} high` : 'No completed scan', tone: critical > 0 ? 'bad' : high > 0 ? 'warn' : 'na' },
    { label: 'Certificate risk', value: cr ? titleCase(cr) : 'Unknown', tone: cr && ['high', 'critical'].includes(cr) ? 'bad' : cr === 'medium' ? 'warn' : 'na' },
  ]
  const pTone = (t) => t === 'bad' ? 'text-red-700' : t === 'warn' ? 'text-brand-700' : 'text-gray-400'

  return (
    <div className="space-y-6" data-testid="security-overview">
      <section aria-labelledby="overview-domains-heading">
        <div className="section-head">
          <div>
            <h2 id="overview-domains-heading" className="section-title">Your Cyber MOT domains</h2>
            <p className="text-xs text-gray-500 mt-1">
              Every area for {workspaceName || 'the selected workspace'}, each with what the latest assessment could establish.
            </p>
          </div>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          {MODULES.map((m) => (
            <ModuleCard
              key={m.domainKey}
              module={m}
              entry={byKey.get(m.domainKey) || null}
              request={request}
              caseSummary={casesByKey.get(m.domainKey)}
              casesRequest={casesState}
              observations={moduleObservations(m.domainKey, signals)}
            />
          ))}
        </div>
      </section>

      <NextActionCard signals={signals} />

      <div className="card p-5">
        <h3 className="section-title mb-3">Posture overview</h3>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {posture.map((p) => (
            <div key={p.label} className="rounded-xl border border-gray-200 bg-white px-4 py-3">
              <p className="text-sm font-semibold text-gray-900 leading-snug">{p.label}</p>
              <p className={`text-[14px] font-bold mt-1 ${pTone(p.tone)}`}>{p.value}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
