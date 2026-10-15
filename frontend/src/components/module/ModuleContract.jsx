// ModuleContract — the page contract every one of the eight area pages
// follows, in this order:
//
//   1 Scope → 2 Evidence state → 3 Risk → 4 Findings → 5 Recommended action
//   → 6 Managed case → 7 Verification → 8 Field Guide
//
// The page keeps its own findings body (section 4, passed as children); the
// contract renders the seven framing sections around it from backend values
// only: the area's resolver row (GET /workspaces/:id/cyber-mot-domains) and
// its managed cases (GET /workspaces/:id/managed-cases?domain_key=…). The
// words are the common vocabulary (lib/statusVocabulary.js); nothing here
// derives a state, and a read that fails or is still pending is shown as that.
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { customerEvidenceText } from '../../lib/evidenceStrengthDisplay'
import { ATTESTED_LABEL, EXTERNAL_EVIDENCE_LABEL } from '../../lib/caseDisplay'
import { moduleForDomainKey, moduleTheme, guidePathForDomainKey, casesPathForDomainKey } from '../../lib/moduleRegistry'
import { domainStatus, caseStatus, summariseCases } from '../../lib/statusVocabulary'
import StatusChip from '../StatusChip'
import { requestDomainStates, requestManagedCases, domainsRequestState } from '../overview/SecurityOverview'

export const MODULE_CONTRACT_SECTIONS = Object.freeze([
  { id: 'module-scope',          n: 1, label: 'Scope' },
  { id: 'module-evidence-state', n: 2, label: 'Evidence state' },
  { id: 'module-risk',           n: 3, label: 'Risk' },
  { id: 'module-findings',       n: 4, label: 'Findings' },
  { id: 'module-recommended',    n: 5, label: 'Recommended action' },
  { id: 'module-cases',          n: 6, label: 'Managed case' },
  { id: 'module-verification',   n: 7, label: 'Verification' },
  { id: 'module-guide',          n: 8, label: 'Field Guide' },
])

const SEVERITY_TONE = { critical: 'text-red-700', high: 'text-orange-700', medium: 'text-amber-700', low: 'text-blue-700', info: 'text-gray-600' }

function formatDay(value) {
  if (!value) return null
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? null : d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })
}

/** Reads the area's resolver row and its cases. Missing API functions and failed reads are errors, never empty success. */
export function useModuleContract(workspaceId, domainKey) {
  const [state, setState] = useState({ domainsRequest: 'loading', entry: null, casesRequest: 'loading', cases: [] })
  useEffect(() => {
    if (!workspaceId) return undefined
    let cancelled = false
    setState({ domainsRequest: 'loading', entry: null, casesRequest: 'loading', cases: [] })
    requestDomainStates(workspaceId).then(
      (res) => {
        if (cancelled) return
        const list = res?.cyber_mot_domains
        const ok = domainsRequestState(list, 'ok') === 'ok'
        setState((s) => ({ ...s, domainsRequest: ok ? 'ok' : 'error', entry: ok ? list.find((d) => d.domain_key === domainKey) || null : null }))
      },
      () => { if (!cancelled) setState((s) => ({ ...s, domainsRequest: 'error', entry: null })) },
    )
    requestManagedCases(workspaceId, { domain_key: domainKey, limit: 100 }).then(
      (res) => {
        if (cancelled) return
        const list = Array.isArray(res?.cases) ? res.cases : null
        setState((s) => ({ ...s, casesRequest: list ? 'ok' : 'error', cases: list || [] }))
      },
      () => { if (!cancelled) setState((s) => ({ ...s, casesRequest: 'error', cases: [] })) },
    )
    return () => { cancelled = true }
  }, [workspaceId, domainKey])
  return state
}

function SectionHeading({ section, theme }) {
  return (
    <h2 id={`${section.id}-heading`} className="section-title flex items-baseline gap-2">
      <span className="text-sm font-bold tabular-nums" style={theme ? { color: theme.text } : undefined}>{section.n}</span>
      {section.label}
    </h2>
  )
}

function Section({ section, theme, children, className = '' }) {
  return (
    <section id={section.id} aria-labelledby={`${section.id}-heading`} className={`scroll-mt-28 ${className}`}>
      <SectionHeading section={section} theme={theme} />
      <div className="mt-3">{children}</div>
    </section>
  )
}

const S = Object.fromEntries(MODULE_CONTRACT_SECTIONS.map((s) => [s.id, s]))

/**
 * ModuleContract
 *   domainKey          — one of the eight canonical keys
 *   workspaceId, workspaceName
 *   recommendedAction  — optional node the page already derives from its own backend data (shown in section 5)
 *   children           — the page's findings body (section 4)
 */
export default function ModuleContract({ domainKey, workspaceId, workspaceName, recommendedAction = null, children }) {
  const module = moduleForDomainKey(domainKey)
  const theme = moduleTheme(domainKey)
  const { domainsRequest, entry, casesRequest, cases } = useModuleContract(workspaceId, domainKey)
  const evidenceStatus = domainStatus(entry, domainsRequest === 'ok' && !entry ? 'error' : domainsRequest)
  const read = domainsRequest === 'ok' && entry
  const summary = read ? customerEvidenceText(entry.summary || entry.description) : null
  const caseSummary = summariseCases(cases)
  const guide = guidePathForDomainKey(domainKey)
  const casesPath = casesPathForDomainKey(domainKey)
  const limitations = read ? (entry.limitations || []).map(customerEvidenceText).filter(Boolean) : []
  const assessed = read ? formatDay(entry.last_assessed_at || entry.freshness) : null
  const open = cases.filter((c) => ['action_required', 'in_progress', 'ready_to_verify', 'recurring'].includes(caseStatus(c)))
  const shown = (open.length ? open : cases).slice(0, 5)

  return (
    <div className="space-y-8" data-testid="module-contract" data-domain-key={domainKey}>
      <nav aria-label="On this page" className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-gray-500">
        {MODULE_CONTRACT_SECTIONS.map((s) => (
          <a key={s.id} href={`#${s.id}`} className="hover:text-gray-900"><span className="tabular-nums">{s.n}</span> {s.label}</a>
        ))}
      </nav>

      <div className="card p-5 grid grid-cols-1 md:grid-cols-3 gap-6">
        <Section section={S['module-scope']} theme={theme}>
          <p className="text-sm font-semibold text-gray-900">{module?.title || domainKey}</p>
          <p className="text-xs text-gray-600 mt-1 leading-relaxed">{workspaceName ? `Workspace: ${workspaceName}.` : 'Selected workspace.'}{' '}{read && entry.description ? customerEvidenceText(entry.description) : ''}</p>
          {limitations.length > 0 && (
            <ul className="mt-2 space-y-1 text-xs text-gray-500 list-disc pl-4">
              {limitations.map((l, i) => <li key={i}>{l}</li>)}
            </ul>
          )}
        </Section>

        <Section section={S['module-evidence-state']} theme={theme}>
          <StatusChip status={evidenceStatus} size="md" />
          <p className="text-xs text-gray-600 mt-2 leading-relaxed">
            {domainsRequest === 'loading' ? 'Reading the latest assessment…'
              : domainsRequest === 'error' || !entry ? 'The latest assessment could not be read. Nothing is assumed in the meantime.'
              : (summary || 'No summary was recorded for this area.')}
          </p>
          {read && (
            <p className="text-xs text-gray-500 mt-1">
              {entry.freshness_reason || (assessed ? `Last assessed ${assessed}.` : 'No assessment date recorded.')}
              {entry.coverage ? ` Coverage: ${entry.coverage}.` : ''}
            </p>
          )}
        </Section>

        <Section section={S['module-risk']} theme={theme}>
          {read ? (
            <dl className="grid grid-cols-2 gap-x-4 gap-y-1">
              <dt className="text-xs text-gray-500">Highest severity</dt>
              <dd className={`text-sm font-bold ${entry.highest_severity ? 'capitalize' : ''} ${SEVERITY_TONE[String(entry.highest_severity || '').toLowerCase()] || 'text-gray-600'}`}>{entry.highest_severity || 'None recorded'}</dd>
              <dt className="text-xs text-gray-500">Findings</dt>
              <dd className="text-sm font-bold tabular-nums text-gray-900">{typeof entry.finding_count === 'number' ? entry.finding_count : '—'}</dd>
              <dt className="text-xs text-gray-500">Open cases</dt>
              <dd className="text-sm font-bold tabular-nums text-gray-900">{casesRequest === 'ok' ? caseSummary.open : '—'}</dd>
            </dl>
          ) : (
            <p className="text-xs text-gray-600 leading-relaxed">Risk is stated only from a read assessment. {domainsRequest === 'loading' ? 'Reading…' : 'Not available right now.'}</p>
          )}
        </Section>
      </div>

      <Section section={S['module-findings']} theme={theme}>
        {children}
      </Section>

      <Section section={S['module-recommended']} theme={theme}>
        <div className="card p-5 space-y-2">
          {recommendedAction}
          <p className="text-xs text-gray-600 leading-relaxed">
            {read
              ? `${entry.recommendation_count ?? 0} recommendation${(entry.recommendation_count ?? 0) === 1 ? '' : 's'} recorded in the latest assessment. Each finding above carries the registry's recommended action, owner type and verification method; an unmapped finding says so rather than inventing one.`
              : 'Recommended actions come from the canonical remediation registry for each finding; none can be shown until the area has been read.'}
          </p>
        </div>
      </Section>

      <Section section={S['module-cases']} theme={theme}>
        <div className="card p-5">
          {casesRequest === 'loading' && <p className="text-xs text-gray-500">Reading managed cases…</p>}
          {casesRequest === 'error' && <p className="text-xs text-gray-600"><StatusChip status="error" /> <span className="ml-2">Managed cases could not be read.</span></p>}
          {casesRequest === 'ok' && cases.length === 0 && (
            <p className="text-xs text-gray-600 leading-relaxed">No managed case exists for this area in this workspace. A case opens when a finding needs ownership, action and verification.</p>
          )}
          {casesRequest === 'ok' && cases.length > 0 && (
            <>
              <p className="text-xs text-gray-600 mb-3">{caseSummary.open} open of {caseSummary.total} case{caseSummary.total === 1 ? '' : 's'}.</p>
              <ul className="divide-y divide-gray-100">
                {shown.map((c) => (
                  <li key={c.case_id || c.id} className="flex items-start justify-between gap-3 py-2">
                    <div className="min-w-0">
                      <p className="text-sm font-semibold text-gray-900 truncate">{c.title || c.source_finding_type || c.case_type || 'Case'}</p>
                      {c.domain && <p className="text-xs text-gray-500 truncate">{c.domain}</p>}
                    </div>
                    <StatusChip status={caseStatus(c)} className="shrink-0" />
                  </li>
                ))}
              </ul>
            </>
          )}
          <div className="mt-3">
            <Link to={casesPath} className="text-sm font-semibold text-brand-600 hover:text-brand-700">Open Operations for this area</Link>
          </div>
        </div>
      </Section>

      <Section section={S['module-verification']} theme={theme}>
        <div className="card p-5 space-y-2 text-xs text-gray-600 leading-relaxed">
          {casesRequest === 'ok' && cases.length > 0 ? (
            <>
              <p>
                Of {caseSummary.total} case{caseSummary.total === 1 ? '' : 's'}: {caseSummary.support.automated} can be verified by CyberMeters re-observing the fix,
                {' '}{caseSummary.support.manual} rest{caseSummary.support.manual === 1 ? 's' : ''} on the customer's word
                {caseSummary.support.external > 0 ? `, ${caseSummary.support.external} need${caseSummary.support.external === 1 ? 's' : ''} independent third-party evidence` : ''}
                {caseSummary.support.unsupported > 0 ? `, ${caseSummary.support.unsupported} cannot be verified by any method` : ''}.
              </p>
              <ul className="flex flex-wrap gap-2">
                {(caseSummary.byWord.verified || 0) > 0 && <li><StatusChip status="verified" /> <span className="ml-1">{caseSummary.byWord.verified}</span></li>}
                {(caseSummary.byWord.attested || 0) > 0 && <li><StatusChip status="attested" /> <span className="ml-1">{caseSummary.byWord.attested}</span></li>}
                {(caseSummary.byWord.external || 0) > 0 && <li><StatusChip status="external" /> <span className="ml-1">{caseSummary.byWord.external}</span></li>}
                {(caseSummary.byWord.ready_to_verify || 0) > 0 && <li><StatusChip status="ready_to_verify" /> <span className="ml-1">{caseSummary.byWord.ready_to_verify}</span></li>}
                {(caseSummary.byWord.recurring || 0) > 0 && <li><StatusChip status="recurring" /> <span className="ml-1">{caseSummary.byWord.recurring}</span></li>}
              </ul>
            </>
          ) : (
            <p>{casesRequest === 'loading' ? 'Reading managed cases…' : casesRequest === 'error' ? 'Verification status could not be read.' : 'No managed case exists for this area yet, so there is nothing to verify.'}</p>
          )}
          <p className="text-gray-500">
            "Verified" is used only when CyberMeters re-observed the fix itself. A fix the product cannot observe is shown as "{ATTESTED_LABEL}"; one that needs a certification body or auditor is shown as "{EXTERNAL_EVIDENCE_LABEL}".
          </p>
        </div>
      </Section>

      <Section section={S['module-guide']} theme={theme}>
        <div className="card p-5 flex flex-col sm:flex-row sm:items-center gap-3">
          <p className="text-xs text-gray-600 leading-relaxed flex-1">What this area covers, what CyberMeters checks and why, how to read these results and what to do next.</p>
          {guide
            ? <Link to={guide} className="btn-secondary text-sm shrink-0">Open the Field Guide</Link>
            : <Link to="/guide" className="btn-secondary text-sm shrink-0">Open the Field Guide</Link>}
        </div>
      </Section>
    </div>
  )
}
