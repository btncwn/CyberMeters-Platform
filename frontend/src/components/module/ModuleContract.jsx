// ModuleContract — the page contract every area page follows. The area page
// (founder, 16 Oct 2026) opens with a serif title, the area's description, the
// backend evidence word and a filter box, then four tabs:
//
//   Overview    — the area's sub-page tiles, the page's own summary blocks
//                 (statistic cards, coverage honesty, open-case panel — the
//                 `overview` prop) and the summary: Scope, Evidence state and
//                 Risk. Lists never live here (Executive, 16 Oct 2026).
//   Findings    — the page's own findings body (the lists) and the recommended
//                 action
//   Cases       — the managed cases and verification
//   Field Guide — the Field Guide section
//
// The eight contract sections keep their order and ids (MODULE_CONTRACT_SECTIONS);
// each is reached through exactly one tab.
//
// The page keeps its own findings body (passed as children); the contract
// renders the framing sections from backend values only: the area's resolver
// row (GET /workspaces/:id/cyber-mot-domains) and its managed cases
// (GET /workspaces/:id/managed-cases?domain_key=…). The words are the common
// vocabulary (lib/statusVocabulary.js); nothing here derives a state, and a
// read that fails or is still pending is shown as that. The filter box narrows
// the tiles and the case list by text; it does not search anything else and
// its placeholder says so.
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useLocation, useNavigate, useSearchParams } from 'react-router-dom'
import { ChevronRight, Search } from 'lucide-react'
import { customerEvidenceText } from '../../lib/evidenceStrengthDisplay'
import { ATTESTED_LABEL, EXTERNAL_EVIDENCE_LABEL } from '../../lib/caseDisplay'
import { moduleForDomainKey, moduleTheme, guidePathForDomainKey, casesPathForDomainKey } from '../../lib/moduleRegistry'
import { domainStatus, caseStatus, summariseCases } from '../../lib/statusVocabulary'
import StatusChip from '../StatusChip'
import { requestDomainStates, requestManagedCases, domainsRequestState } from '../overview/SecurityOverview'
import { subpagesForDomainKey } from '../WorkspaceNav'
import { moduleIcon } from '../shell/moduleIcons'

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

export const MODULE_TABS = Object.freeze([
  { id: 'overview', label: 'Overview' },
  { id: 'findings', label: 'Findings' },
  { id: 'cases',    label: 'Cases' },
  { id: 'guide',    label: 'Field Guide' },
])
const TAB_IDS = MODULE_TABS.map((t) => t.id)

/**
 * Which tab a URL opens. An explicit `?tab=` wins; otherwise a deep link into the
 * page body — an anchor (`#dmarc-setup`, the sub-page tiles) or any other query
 * parameter (`?lifecycle=…`, `?condition=…`, the alert links) — opens Findings,
 * because that is where the body lives; a bare URL opens Overview.
 */
export function tabForLocation(params, hash) {
  const explicit = params.get('tab')
  if (TAB_IDS.includes(explicit)) return explicit
  if (hash || [...params.keys()].some((k) => k !== 'tab')) return 'findings'
  return 'overview'
}

const SEVERITY_TONE = { critical: 'text-red-700', high: 'text-red-600', medium: 'text-brand-700', low: 'text-blue-700', info: 'text-gray-600' }

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

/**
 * For a page's own "go to" buttons: scroll to the element when it is on the
 * current tab, otherwise open the tab that holds it at that anchor — Findings
 * by default (the body lives there), or `{ tab: 'overview' }` for a summary
 * block; the contract then scrolls once it has rendered.
 */
export function useAreaAnchor() {
  const navigate = useNavigate()
  const { pathname, search } = useLocation()
  return useCallback((id, { tab = 'findings' } = {}) => {
    const el = document.getElementById(id)
    if (el) { if (typeof el.scrollIntoView === 'function') el.scrollIntoView({ behavior: 'smooth', block: 'start' }); return }
    const next = new URLSearchParams(search)
    next.set('tab', TAB_IDS.includes(tab) ? tab : 'findings')
    navigate({ pathname, search: `?${next.toString()}`, hash: `#${id}` })
  }, [navigate, pathname, search])
}

/** Case-insensitive text match used by the area filter box. */
export function matchesFilter(text, query) {
  const q = String(query || '').trim().toLowerCase()
  if (!q) return true
  return String(text || '').toLowerCase().includes(q)
}

function SectionHeading({ section, theme }) {
  return (
    <h2 id={`${section.id}-heading`} className="section-title" style={theme ? { color: theme.text } : undefined}>
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

function SubpageTiles({ domainKey, tiles, theme }) {
  const Icon = moduleIcon(moduleForDomainKey(domainKey)?.colourKey)
  if (tiles.length === 0) return null
  return (
    <nav aria-label="Pages in this area" data-testid="module-tiles">
      <ul className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {tiles.map((t) => (
          <li key={t.to}>
            <Link to={t.to} className="card card-hover p-4 flex items-center gap-3">
              <span className="inline-flex items-center justify-center w-10 h-10 rounded-full shrink-0" style={theme ? { backgroundColor: theme.chip, color: theme.text } : undefined}>
                <Icon className="w-5 h-5" aria-hidden="true" />
              </span>
              <span className="min-w-0 flex-1">
                <span className="block text-[15px] font-semibold text-gray-900">{t.label}</span>
                {t.desc && <span className="block text-xs text-gray-500 truncate">{t.desc}</span>}
              </span>
              <ChevronRight className="w-4 h-4 text-gray-400 shrink-0" aria-hidden="true" />
            </Link>
          </li>
        ))}
      </ul>
    </nav>
  )
}

/**
 * ModuleContract
 *   domainKey          — one of the canonical area keys
 *   workspaceId, workspaceName
 *   description        — the page's one-paragraph description under the title
 *   actions            — the page's own actions (buttons/links), shown under the filter box
 *   aside              — an optional page-specific block shown under the header (e.g. questionnaire progress)
 *   overview           — the page's own summary blocks for the Overview tab: statistic cards,
 *                        coverage honesty and open-case panels, rendered between the tiles and
 *                        the Scope/Evidence/Risk summary. Never a list — lists are Findings.
 *   recommendedAction  — optional node the page already derives from its own backend data (shown in section 5)
 *   children           — the page's findings body (section 4)
 */
export default function ModuleContract({ domainKey, workspaceId, workspaceName, description = null, actions = null, aside = null, overview = null, recommendedAction = null, children }) {
  const module = moduleForDomainKey(domainKey)
  const theme = moduleTheme(domainKey)
  const [params, setParams] = useSearchParams()
  const { hash } = useLocation()
  const tab = tabForLocation(params, hash)
  const [query, setQuery] = useState('')
  // An anchor in the URL scrolls to its element once the tab that holds it has rendered.
  useEffect(() => {
    if (!hash) return
    const el = document.getElementById(hash.slice(1))
    if (el && typeof el.scrollIntoView === 'function') el.scrollIntoView({ block: 'start' })
  }, [hash, tab])
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
  const filteredCases = cases.filter((c) => matchesFilter(`${c.title || ''} ${c.domain || ''} ${c.source_finding_type || ''} ${c.case_type || ''}`, query))
  const filteredOpen = open.filter((c) => filteredCases.includes(c))
  const shown = (filteredOpen.length ? filteredOpen : filteredCases).slice(0, tab === 'cases' ? 50 : 5)
  const tiles = useMemo(() => subpagesForDomainKey(domainKey).filter((t) => matchesFilter(`${t.label} ${t.desc}`, query)), [domainKey, query])

  function selectTab(id) {
    const next = new URLSearchParams(params)
    if (id === 'overview') next.delete('tab'); else next.set('tab', id)
    setParams(next, { replace: true })
  }

  function onTabKeyDown(event, currentId) {
    const index = TAB_IDS.indexOf(currentId)
    const target = event.key === 'ArrowRight' ? (index + 1) % TAB_IDS.length
      : event.key === 'ArrowLeft' ? (index - 1 + TAB_IDS.length) % TAB_IDS.length
        : event.key === 'Home' ? 0
          : event.key === 'End' ? TAB_IDS.length - 1 : -1
    if (target < 0) return
    event.preventDefault()
    selectTab(TAB_IDS[target])
    event.currentTarget.parentElement.querySelectorAll('[role="tab"]')[target]?.focus()
  }

  const scopeSection = (
    <Section section={S['module-scope']} theme={theme}>
      <p className="text-sm font-semibold text-gray-900">{module?.title || domainKey}</p>
      <p className="text-xs text-gray-600 mt-1 leading-relaxed">{workspaceName ? `Workspace: ${workspaceName}.` : 'Selected workspace.'}{' '}{read && entry.description ? customerEvidenceText(entry.description) : ''}</p>
      {limitations.length > 0 && (
        <ul className="mt-2 space-y-1 text-xs text-gray-500 list-disc pl-4">
          {limitations.map((l, i) => <li key={i}>{l}</li>)}
        </ul>
      )}
    </Section>
  )
  const evidenceSection = (
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
  )
  const riskSection = (
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
  )
  const findingsSection = (
    <Section section={S['module-findings']} theme={theme}>
      {children}
    </Section>
  )
  const recommendedSection = (
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
  )
  const casesSection = (
    <Section section={S['module-cases']} theme={theme}>
      <div className="card p-5">
        {casesRequest === 'loading' && <p className="text-xs text-gray-500">Reading managed cases…</p>}
        {casesRequest === 'error' && <p className="text-xs text-gray-600"><StatusChip status="error" /> <span className="ml-2">Managed cases could not be read.</span></p>}
        {casesRequest === 'ok' && cases.length === 0 && (
          <p className="text-xs text-gray-600 leading-relaxed">No managed case exists for this area in this workspace. A case opens when a finding needs ownership, action and verification.</p>
        )}
        {casesRequest === 'ok' && cases.length > 0 && filteredCases.length === 0 && (
          <p className="text-xs text-gray-600 leading-relaxed">No case in this area matches the filter.</p>
        )}
        {casesRequest === 'ok' && filteredCases.length > 0 && (
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
          <Link to={casesPath} className="text-sm font-semibold text-brand-700 hover:text-brand-800">Open Operations for this area</Link>
        </div>
      </div>
    </Section>
  )
  const verificationSection = (
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
  )
  const guideSection = (
    <Section section={S['module-guide']} theme={theme}>
      <div className="card p-5 flex flex-col sm:flex-row sm:items-center gap-3">
        <p className="text-xs text-gray-600 leading-relaxed flex-1">What this area covers, what CyberMeters checks and why, how to read these results and what to do next.</p>
        {guide
          ? <Link to={guide} className="btn-secondary text-sm shrink-0">Open the Field Guide</Link>
          : <Link to="/guide" className="btn-secondary text-sm shrink-0">Open the Field Guide</Link>}
      </div>
    </Section>
  )

  return (
    <div className="space-y-6" data-testid="module-contract" data-domain-key={domainKey}>
      <header className="cm-module-head">
        <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4">
          <div className="min-w-0 flex-1">
            <h1 className="cm-hero-title text-left" style={theme ? { color: theme.text } : undefined}>{module?.title || domainKey}</h1>
            <p className="text-[15px] text-gray-600 mt-2 max-w-2xl leading-relaxed">{description || module?.fallback}</p>
            <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-gray-500" data-testid="module-head-status">
              <StatusChip status={evidenceStatus} size="md" />
              <span>
                {domainsRequest === 'loading' ? 'Reading the latest assessment…'
                  : domainsRequest === 'error' || !entry ? 'The latest assessment could not be read.'
                  : (entry.freshness_reason || (assessed ? `Last assessed ${assessed}.` : 'No assessment date recorded.'))}
              </span>
              {workspaceName && <span>· {workspaceName}</span>}
            </div>
          </div>
          <div className="flex flex-col items-stretch lg:items-end gap-3 shrink-0">
            <label className="cm-area-search">
              <Search className="w-4 h-4 text-gray-400 shrink-0" aria-hidden="true" />
              <input
                type="search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                aria-label="Filter pages and cases in this area"
                placeholder="Filter pages and cases in this area"
              />
            </label>
            {actions && <div className="flex flex-wrap items-center gap-2 lg:justify-end">{actions}</div>}
          </div>
        </div>
        {aside}
        <div role="tablist" aria-label="Area sections" className="cm-tabs mt-5">
          {MODULE_TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              role="tab"
              id={`module-tab-${t.id}`}
              aria-selected={tab === t.id}
              aria-controls="module-tabpanel"
              tabIndex={tab === t.id ? 0 : -1}
              onClick={() => selectTab(t.id)}
              onKeyDown={event => onTabKeyDown(event, t.id)}
              className="cm-tab"
            >
              {t.label}
            </button>
          ))}
        </div>
      </header>

      <div id="module-tabpanel" role="tabpanel" aria-labelledby={`module-tab-${tab}`} tabIndex={0} className="space-y-8">
        {tab === 'overview' && (
          <>
            <SubpageTiles domainKey={domainKey} tiles={tiles} theme={theme} />
            {overview && <div className="space-y-6" data-testid="module-overview">{overview}</div>}
            <div className="card p-5 grid grid-cols-1 md:grid-cols-3 gap-6" data-testid="module-summary">
              {scopeSection}
              {evidenceSection}
              {riskSection}
            </div>
          </>
        )}
        {tab === 'findings' && (
          <>
            {findingsSection}
            {recommendedSection}
          </>
        )}
        {tab === 'cases' && (
          <>
            {casesSection}
            {verificationSection}
          </>
        )}
        {tab === 'guide' && guideSection}
      </div>
    </div>
  )
}
