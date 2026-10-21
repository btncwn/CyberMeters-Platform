import { formatDay } from '../../utils/dates'
import ScanNowButton from '../ScanNowButton'
// ModuleContract — the ONE template every /ws/<area> page renders (founder,
// 18 Oct 2026), in this order:
//
//   1. Header — serif title · one-sentence scope · evidence-state badge ·
//      "Last assessed" (and the page's own header controls).
//   2. "What we observed" — 3–4 key figures at most: the page's `figures`, or
//      the area row's own counts (findings, evidence observed, highest
//      severity, coverage). Never invented.
//   3. "Do this next" — ONE recommended action card with ONE button: the page's
//      `nextAction`, or the first mapped finding's canonical remediation
//      (title + recommended action from the registry). No repeated CTAs.
//   4. Findings · Open cases · Verification — three clickable counts that open
//      the Findings and Cases tabs.
//   5. Tabs: Overview · Findings · Cases · Settings · Field Guide. Settings holds
//      anything configurable (the page's `settings` prop).
//   6. Scope & limits — small, at the bottom.
//
// Lists never live on Overview (Executive, 16 Oct 2026).
//
// The page keeps its own findings body (passed as children); the contract
// renders the framing sections from backend values only: the area's resolver
// row (GET /workspaces/:id/security-domains) and its managed cases
// (GET /workspaces/:id/cases?domain_key=…, the same query as Operations). The words are the common
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
import { OWNER_LABELS } from '../../data/remediation'

export const MODULE_CONTRACT_SECTIONS = Object.freeze([
  { id: 'module-observed',       n: 1, label: 'What we observed' },
  { id: 'module-next',           n: 2, label: 'Do this next' },
  { id: 'module-counts',         n: 3, label: 'Findings, cases and verification' },
  { id: 'module-findings',       n: 4, label: 'Findings' },
  { id: 'module-recommended',    n: 5, label: 'Recommended action' },
  { id: 'module-cases',          n: 6, label: 'Managed case' },
  { id: 'module-verification',   n: 7, label: 'Verification' },
  { id: 'module-settings',       n: 8, label: 'Settings' },
  { id: 'module-guide',          n: 9, label: 'Field Guide' },
  { id: 'module-scope',          n: 10, label: 'Scope & limits' },
])

export const MODULE_TABS = Object.freeze([
  { id: 'overview', label: 'Overview' },
  { id: 'findings', label: 'Findings' },
  { id: 'cases',    label: 'Cases' },
  { id: 'settings', label: 'Settings' },
  { id: 'guide',    label: 'Field Guide' },
])

const COVERAGE_WORDS = { complete: 'Complete', partial: 'Partial', degraded: 'Degraded' }
const STILL_TO_ASSESS = new Set(['not_yet_assessed', 'not_assessed', 'evidence_insufficient', 'unavailable', 'unknown'])

/**
 * The default "What we observed" figures from the area row — the backend's own
 * counts, nothing derived. A page may pass its own (max 4) instead.
 */
export function defaultFigures(entry) {
  if (!entry) return []
  const severity = String(entry.highest_severity || '').toLowerCase()
  return [
    { key: 'findings', label: 'Findings', value: typeof entry.finding_count === 'number' ? entry.finding_count : '—', explanation: 'In the latest assessment' },
    { key: 'evidence', label: 'Evidence observed', value: typeof entry.evidence_count === 'number' ? entry.evidence_count : '—', explanation: 'Checks that returned usable evidence' },
    { key: 'severity', label: 'Highest severity', value: severity ? severity[0].toUpperCase() + severity.slice(1) : 'None recorded', explanation: 'Across this area’s findings', tone: SEVERITY_TONE[severity] },
    { key: 'coverage', label: 'Coverage', value: COVERAGE_WORDS[String(entry.coverage || '').toLowerCase()] || 'Not recorded', explanation: 'How much of this area the scan could check' },
  ]
}

/**
 * The ONE "Do this next" action. A page's own `nextAction` wins; otherwise the
 * first finding the canonical remediation registry maps (its title and its
 * recommended action), then honest fallbacks. Always exactly one button.
 */
export function resolveNextAction({ nextAction = null, entry = null, request = 'loading', guide = '/guide' } = {}) {
  if (nextAction) return nextAction
  if (request === 'loading') return { title: 'Reading the latest assessment…', body: null, label: null }
  if (request !== 'ok' || !entry) return { title: 'The latest assessment could not be read', body: 'Nothing is assumed in the meantime. A new scan reads this area again.', label: 'Run a scan', to: '/scans/new' }
  const mapped = (entry.finding_details || []).find((d) => d?.status === 'resolved' && d.recommended_action)
  if (mapped) return { title: mapped.customer_title, body: mapped.recommended_action, label: 'Review this finding', tab: 'findings', source: 'registry' }
  if ((entry.finding_count ?? 0) > 0) return { title: 'Review the findings in the latest assessment', body: 'No registered remediation is mapped for these findings yet, so none is invented here.', label: 'Review findings', tab: 'findings' }
  if (STILL_TO_ASSESS.has(String(entry.state || '').toLowerCase())) return { title: 'Run a scan to assess this area', body: 'The latest assessment could not establish this area yet.', label: 'Run a scan', to: '/scans/new' }
  // No finding is only an all-clear when the scan could check the whole area.
  if (String(entry.coverage || '').toLowerCase() !== 'complete') return { title: 'No issue found in what could be checked', body: 'Coverage was not complete, so this is not an all-clear. A new scan checks the rest.', label: 'Run a scan', to: '/scans/new' }
  return { title: 'Nothing to fix from the latest assessment', body: 'CyberMeters keeps monitoring and will raise anything new.', label: 'Open the Field Guide', to: guide }
}
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

const SEVERITY_TONE = { critical: 'text-red-700', high: 'text-red-700', medium: 'text-brand-700', low: 'text-blue-700', info: 'text-gray-600' }

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
    requestManagedCases(workspaceId, { domain_key: domainKey, limit: 200 }).then(
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

function SubpageTiles({ domainKey, tiles, theme, summaries = null }) {
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
                {/* A page may add one honest line of its own data under a tile (e.g. the
                    network-assets count); the backend's numbers, never derived here. */}
                {summaries?.[t.to] ?? null}
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
 *   scanDomain         — the domain the page is showing; "Scan now" (top right) scans it
 *   aside              — an optional page-specific block shown under the header (e.g. questionnaire progress)
 *   overview           — the page's own summary blocks for the Overview tab: statistic cards,
 *                        coverage honesty and open-case panels, rendered between the tiles and
 *                        the Scope/Evidence/Risk summary. Never a list — lists are Findings.
 *   tileSummaries      — optional { [tile.to]: node } adding one line of the page's own backend data
 *                        under that sub-page tile on Overview
 *   recommendedAction  — optional node the page already derives from its own backend data (shown in section 5)
 *   children           — the page's findings body (section 4)
 */
export default function ModuleContract({ domainKey, workspaceId, workspaceName, description = null, actions = null, aside = null, overview = null, tileSummaries = null, recommendedAction = null, figures = null, nextAction = null, settings = null, scanDomain = null, children }) {
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
  const assessed = read ? formatDay(entry.last_assessed_at || entry.freshness, null) : null
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
    <section id="module-scope" aria-labelledby="module-scope-heading" className="border-t border-gray-100 pt-4" data-testid="module-scope">
      <h2 id="module-scope-heading" className="text-xs font-semibold text-gray-600">Scope &amp; limits</h2>
      <p className="text-xs text-gray-600 mt-1 leading-relaxed">
        {workspaceName ? `Workspace: ${workspaceName}.` : 'Selected workspace.'}{' '}
        {read && entry.description ? customerEvidenceText(entry.description) : (module?.fallback || '')}
        {read && entry.coverage ? ` Coverage: ${COVERAGE_WORDS[String(entry.coverage).toLowerCase()] || customerEvidenceText(entry.coverage)}.` : ''}
      </p>
      {limitations.length > 0 && (
        <ul className="mt-1 space-y-0.5 text-xs text-gray-600 list-disc pl-4">
          {limitations.map((l, i) => <li key={i}>{l}</li>)}
        </ul>
      )}
    </section>
  )
  const shownFigures = (Array.isArray(figures) && figures.length ? figures : (read ? defaultFigures(entry) : [])).slice(0, 4)
  const observedSection = (
    <section id="module-observed" aria-labelledby="module-observed-heading" data-testid="module-observed">
      <h2 id="module-observed-heading" className="section-title" style={theme ? { color: theme.text } : undefined}>What we observed</h2>
      {shownFigures.length ? (
        <dl className="mt-3 grid grid-cols-2 lg:grid-cols-4 gap-3">
          {shownFigures.map((f) => (
            <div key={f.key || f.label} className="card p-4" data-testid="module-figure">
              <dt className="text-sm font-semibold text-gray-900 leading-snug">{f.label}</dt>
              {f.explanation && <dd className="text-xs text-gray-600 mt-0.5 leading-snug">{f.explanation}</dd>}
              <dd className={`text-lg font-bold mt-1 tabular-nums ${f.tone || 'text-gray-900'}`}>{f.value ?? '—'}</dd>
            </div>
          ))}
        </dl>
      ) : (
        <p className="text-sm text-gray-600 mt-2">{domainsRequest === 'loading' ? 'Reading the latest assessment…' : 'The latest assessment could not be read. Nothing is assumed in the meantime.'}</p>
      )}
    </section>
  )
  const next = resolveNextAction({ nextAction, entry, request: domainsRequest === 'ok' && !entry ? 'error' : domainsRequest, guide: guide || '/guide' })
  const nextSection = (
    <section id="module-next" aria-labelledby="module-next-heading" className="card p-5 border-l-4" style={theme ? { borderLeftColor: theme.icon } : undefined} data-testid="module-next">
      <h2 id="module-next-heading" className="text-xs font-semibold text-gray-600">Do this next</h2>
      <div className="mt-1 flex flex-col sm:flex-row sm:items-center gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-[15px] font-semibold text-gray-900" data-testid="module-next-title">{next.title}</p>
          {next.body && <p className="text-sm text-gray-700 mt-1 leading-relaxed">{customerEvidenceText(next.body)}</p>}
        </div>
        {next.label && (next.to
          ? <Link to={next.to} className="btn-primary shrink-0" data-testid="module-next-action">{next.label}</Link>
          : <button type="button" onClick={next.onClick || (() => selectTab(next.tab || 'findings'))} className="btn-primary shrink-0" data-testid="module-next-action">{next.label}</button>)}
      </div>
    </section>
  )
  const awaitingVerification = (caseSummary.byWord?.ready_to_verify || 0)
  const countsSection = (
    <section id="module-counts" aria-label="Findings, open cases and verification" data-testid="module-counts">
      <ul className="grid grid-cols-3 gap-3">
        {[
          { key: 'findings', label: 'Findings', value: read && typeof entry.finding_count === 'number' ? entry.finding_count : '—', tab: 'findings', hint: 'Open the Findings tab' },
          { key: 'cases', label: 'Open cases', value: casesRequest === 'ok' ? caseSummary.open : '—', tab: 'cases', hint: 'Open the Cases tab' },
          { key: 'verification', label: 'Verification', value: casesRequest === 'ok' ? awaitingVerification : '—', tab: 'cases', hint: 'Cases ready to verify — open the Cases tab' },
        ].map((c) => (
          <li key={c.key}>
            <button type="button" onClick={() => selectTab(c.tab)} className="card card-hover w-full p-4 text-left" aria-label={`${c.label}: ${c.value}. ${c.hint}`} data-testid={`module-count-${c.key}`}>
              <span className="block text-sm font-semibold text-gray-900">{c.label}</span>
              <span className="block text-lg font-bold tabular-nums text-gray-900 mt-0.5">{c.value}</span>
            </button>
          </li>
        ))}
      </ul>
    </section>
  )
  const findingsSection = (
    <Section section={S['module-findings']} theme={theme}>
      <div className="card p-5 mb-5" data-testid="latest-assessment-findings">
        <h3 className="text-sm font-semibold text-gray-900">Findings in the latest assessment</h3>
        {!read && <p className="text-sm text-gray-600 mt-2">{domainsRequest === 'loading' ? 'Reading the latest assessment…' : 'Findings could not be read.'}</p>}
        {read && (!Array.isArray(entry.finding_ids) || entry.finding_ids.length === 0) && (
          <p className="text-sm text-gray-600 mt-2">No finding IDs were recorded for this area in the latest assessment.</p>
        )}
        {read && Array.isArray(entry.finding_ids) && entry.finding_ids.length > 0 && (
          <ul className="mt-3 space-y-3">
            {entry.finding_ids.map((id) => {
              const detail = entry.finding_details?.find((item) => item.finding_id === id)
              const title = detail?.status === 'resolved' ? detail.customer_title : 'Finding title unavailable'
              return <li key={id} className="border-t border-gray-100 pt-3 first:border-0 first:pt-0">
                <p className="text-sm font-medium text-gray-900">{title}</p>
                {detail?.status === 'resolved' && <>
                  {detail.recommended_action && <p className="text-sm text-gray-600 mt-1">{detail.recommended_action}</p>}
                  {detail.owner_type && <p className="text-xs text-gray-500 mt-1">Owner: {OWNER_LABELS[detail.owner_type] || detail.owner_type.replaceAll('_', ' ')}</p>}
                  {detail.verification_method && <p className="text-xs text-gray-500">Verification: {detail.verification_method.replaceAll('_', ' ')}</p>}
                </>}
                {entry.source_scan_id && <Link className="text-xs font-medium text-brand-600 hover:underline" to={`/scans/${encodeURIComponent(entry.source_scan_id)}?view=technical`}>Open technical scan →</Link>}
              </li>
            })}
          </ul>
        )}
      </div>
      {children}
    </Section>
  )
  const recommendedSection = (
    <Section section={S['module-recommended']} theme={theme}>
      <div className="card p-5 space-y-2">
        {recommendedAction}
        <p className="text-xs text-gray-600 leading-relaxed">
          {read
            ? `${entry.recommendation_count ?? 0} recommendation${(entry.recommendation_count ?? 0) === 1 ? '' : 's'} recorded in the latest assessment. Registered actions, owners and verification methods appear with the findings above; an unmapped finding has no invented advice.`
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
  const settingsSection = (
    <Section section={S['module-settings']} theme={theme}>
      {settings ? <div className="space-y-6" data-testid="module-settings-body">{settings}</div> : (
        <div className="card p-5 text-sm text-gray-600 leading-relaxed">
          Nothing to configure in this area. Where alerts go is set per workspace under{' '}
          <Link to="/ws/alerts" className="font-semibold text-brand-700 hover:text-brand-800">Alert channels</Link>.
        </div>
      )}
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
                  : (entry.freshness_reason ? customerEvidenceText(entry.freshness_reason) : (assessed ? `Last assessed ${assessed}.` : 'No assessment date recorded.'))}
              </span>
            </div>
          </div>
          <div className="flex flex-col items-stretch lg:items-end gap-3 shrink-0">
            {workspaceId && <ScanNowButton workspaceId={workspaceId} domain={scanDomain} />}
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
      </header>

      {/* 2–4: what we observed, the one next action, the three counts — above the tabs, on every tab. */}
      <div className="space-y-4" data-testid="module-first-screen">
        {observedSection}
        {nextSection}
        {countsSection}
      </div>

      <div>
        <div role="tablist" aria-label="Area sections" className="cm-tabs">
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
      </div>

      <div id="module-tabpanel" role="tabpanel" aria-labelledby={`module-tab-${tab}`} tabIndex={0} className="space-y-8">
        {tab === 'overview' && (
          <>
            {overview && <div className="space-y-6" data-testid="module-overview">{overview}</div>}
            <SubpageTiles domainKey={domainKey} tiles={tiles} theme={theme} summaries={tileSummaries} />
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
        {tab === 'settings' && settingsSection}
        {tab === 'guide' && guideSection}
      </div>

      {/* 6: scope & limits — small, at the bottom of every tab. */}
      {scopeSection}
    </div>
  )
}
