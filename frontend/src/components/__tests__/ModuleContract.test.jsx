import { render, screen, within, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import ModuleContract, { MODULE_CONTRACT_SECTIONS } from '../module/ModuleContract'
import { MODULES } from '../../lib/moduleRegistry'
import { api } from '../../api'
import { ATTESTED_LABEL } from '../../lib/caseDisplay'
import { laneCounts } from '../operations/OperationsBoard'

// Every area page renders ONE template (founder, 18 Oct 2026): header (title,
// scope, evidence badge, last assessed) → "What we observed" (3–4 figures) →
// "Do this next" (one card, one button) → Findings · Open cases · Verification
// counts → tabs Overview · Findings · Cases · Settings · Field Guide → Scope &
// limits at the bottom. The framing reads backend values only.

vi.mock('../../api', () => ({ api: { getSecurityCheckDomains: vi.fn(), getCases: vi.fn() } }))
vi.mock('../../utils/preload', () => ({ preloadComponent: vi.fn() }))
vi.mock('../../utils/preloadMap', () => ({ routePreloadMap: {} }))

const KEYS = MODULES.map((m) => m.domainKey)
const row = (domain_key, state, extra = {}) => ({ domain_key, display_name: domain_key, description: `${domain_key} description`, state, summary: `${domain_key} summary`, finding_count: 0, recommendation_count: 0, highest_severity: null, limitations: [], last_assessed_at: '2026-10-01T09:00:00Z', ...extra })
const eight = (over = {}) => KEYS.map((k) => over[k] || row(k, 'not_yet_assessed'))

function show(domainKey = 'website_security', props = {}, tab = null) {
  return render(
    <MemoryRouter initialEntries={[tab ? `/area?tab=${tab}` : '/area']}>
      <ModuleContract domainKey={domainKey} workspaceId="ws1" workspaceName="Example Ltd" {...props}>
        <p>page body</p>
      </ModuleContract>
    </MemoryRouter>,
  )
}
const headings = () => screen.getAllByRole('heading', { level: 2 }).map((h) => h.textContent.trim())
const section = (id) => document.getElementById(id)
const chip = (el) => el.querySelector('[data-status]').dataset.status
const headChip = () => chip(screen.getByTestId('module-head-status'))
const count = (key) => screen.getByTestId(`module-count-${key}`)
const figure = (label) => screen.getAllByTestId('module-figure').find((f) => f.querySelector('dt')?.textContent === label)
const FIRST = ['What we observed', 'Do this next']

beforeEach(() => { vi.clearAllMocks() })

describe('ModuleContract — the one area template', () => {
  it('matches Operations open-case counts and its cases query for every domain', async () => {
    const records = KEYS.flatMap((domain_key) => [
      { case_id: `${domain_key}-open`, domain_key, canonical_phase: 'assigned' },
      { case_id: `${domain_key}-closed`, domain_key, canonical_phase: 'verified', verification_support: 'automated' },
    ])
    api.getSecurityCheckDomains.mockResolvedValue({ cyber_mot_domains: eight() })
    api.getCases.mockImplementation(async (_wsId, params) => ({ cases: records.filter((c) => c.domain_key === params.domain_key) }))
    for (const key of KEYS) {
      const view = show(key)
      await waitFor(() => expect(count('cases')).toHaveTextContent('Open cases1'))
      const lanes = laneCounts(records.filter((c) => c.domain_key === key))
      expect(Number(count('cases').textContent.replace('Open cases', ''))).toBe(lanes.triage + lanes.in_progress + lanes.ready_to_verify)
      expect(api.getCases).toHaveBeenCalledWith('ws1', { domain_key: key, limit: 200 })
      view.unmount()
    }
  })

  it('renders the template in order: first screen on every tab, each tab its own sections, scope & limits last', async () => {
    api.getSecurityCheckDomains.mockResolvedValue({ cyber_mot_domains: eight() })
    api.getCases.mockResolvedValue({ cases: [] })
    expect(MODULE_CONTRACT_SECTIONS.map((s) => s.label)).toEqual(['What we observed', 'Do this next', 'Findings, cases and verification', 'Findings', 'Recommended action', 'Managed case', 'Verification', 'Settings', 'Field Guide', 'Scope & limits'])
    const perTab = { overview: [], findings: ['Findings', 'Recommended action'], cases: ['Managed case', 'Verification'], settings: ['Settings'], guide: ['Field Guide'] }
    for (const [tab, expected] of Object.entries(perTab)) {
      const { unmount } = show('website_security', {}, tab === 'overview' ? null : tab)
      expect(headings()).toEqual([...FIRST, ...expected, 'Scope & limits'])
      expect(screen.getByTestId('module-counts')).toBeInTheDocument()
      // Scope & limits is the last thing in the template.
      const contract = screen.getByTestId('module-contract')
      expect(contract.lastElementChild).toBe(screen.getByTestId('module-scope'))
      unmount()
    }
  })

  it('Overview carries no page body, cases or guide; scope names the workspace', async () => {
    api.getSecurityCheckDomains.mockResolvedValue({ cyber_mot_domains: eight() })
    api.getCases.mockResolvedValue({ cases: [] })
    show()
    await waitFor(() => expect(headChip()).toBe('not_assessed'))
    expect(within(section('module-scope')).getByText(/Workspace: Example Ltd/)).toBeInTheDocument()
    expect(screen.queryByText('page body')).not.toBeInTheDocument()
    expect(section('module-cases')).toBeNull()
    expect(section('module-guide')).toBeNull()
    expect(api.getSecurityCheckDomains).toHaveBeenCalledWith('ws1')
    expect(api.getCases).toHaveBeenCalledWith('ws1', { domain_key: 'website_security', limit: 200 })
  })

  it('Findings carries the page body; Cases links to Operations for the area; Field Guide links to the guide', async () => {
    api.getSecurityCheckDomains.mockResolvedValue({ cyber_mot_domains: eight() })
    api.getCases.mockResolvedValue({ cases: [] })
    let r = show('website_security', {}, 'findings')
    expect(within(section('module-findings')).getByText('page body')).toBeInTheDocument()
    r.unmount()
    r = show('website_security', {}, 'cases')
    await waitFor(() => expect(within(section('module-cases')).getByRole('link', { name: 'Open Operations for this area' })).toHaveAttribute('href', '/ws/cases?domain_key=website_security'))
    r.unmount()
    show('website_security', {}, 'guide')
    expect(within(section('module-guide')).getByRole('link', { name: 'Open the Field Guide' })).toHaveAttribute('href', '/guide/website-security')
  })

  it('every one of the eight areas resolves to its own Field Guide page and names itself in the header', async () => {
    api.getSecurityCheckDomains.mockResolvedValue({ cyber_mot_domains: eight() })
    api.getCases.mockResolvedValue({ cases: [] })
    for (const m of MODULES) {
      let r = show(m.domainKey, {}, 'guide')
      expect(within(section('module-guide')).getByRole('link', { name: 'Open the Field Guide' }).getAttribute('href')).toMatch(/^\/guide\/[a-z-]+$/)
      r.unmount()
      r = show(m.domainKey)
      expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(m.title)
      r.unmount()
    }
  })

  it('shows Loading before the reads return, then the backend word, the observed figures and freshness', async () => {
    let resolveDomains
    api.getSecurityCheckDomains.mockReturnValue(new Promise((r) => { resolveDomains = r }))
    api.getCases.mockResolvedValue({ cases: [] })
    show('email_protection')
    expect(headChip()).toBe('loading')
    expect(within(section('module-observed')).getByText('Reading the latest assessment…')).toBeInTheDocument()
    expect(screen.getByTestId('module-next-title')).toHaveTextContent('Reading the latest assessment…')
    expect(within(section('module-next')).queryByRole('button')).toBeNull()
    const resolved = { cyber_mot_domains: eight({ email_protection: row('email_protection', 'issue_detected', { finding_count: 4, evidence_count: 9, recommendation_count: 2, highest_severity: 'high', coverage: 'complete', evidence_freshness: 'current', freshness_reason: 'Last assessed 3 days ago.', last_assessed_at: new Date(Date.now() - 3 * 86400000).toISOString(), limitations: ['DKIM is checked against common selectors only.'] }) }) }
    resolveDomains(resolved)
    await waitFor(() => expect(headChip()).toBe('action_required'))
    expect(screen.getByTestId('module-head-status')).toHaveTextContent(/Last assessed 3 days ago\./)
    expect(screen.getAllByTestId('module-figure')).toHaveLength(4)
    expect(figure('Findings')).toHaveTextContent('4')
    expect(figure('Evidence observed')).toHaveTextContent('9')
    expect(figure('Highest severity')).toHaveTextContent('High')
    expect(figure('Coverage')).toHaveTextContent('Complete')
    expect(count('findings')).toHaveTextContent('4')
    expect(within(section('module-scope')).getByText('DKIM is checked against common selectors only.')).toBeInTheDocument()
    // The recommendation count is stated on the Findings tab.
    api.getSecurityCheckDomains.mockResolvedValue(resolved)
    show('email_protection', {}, 'findings')
    await waitFor(() => expect(within(section('module-recommended')).getByText(/2 recommendations recorded/)).toBeInTheDocument())
  })

  it('a page may supply its own figures — never more than four are shown', async () => {
    api.getSecurityCheckDomains.mockResolvedValue({ cyber_mot_domains: eight() })
    api.getCases.mockResolvedValue({ cases: [] })
    show('certificates_trust', { figures: [1, 2, 3, 4, 5].map((n) => ({ key: `f${n}`, label: `Figure ${n}`, value: n })) })
    await waitFor(() => expect(screen.getAllByTestId('module-figure')).toHaveLength(4))
    expect(screen.queryByText('Figure 5')).toBeNull()
  })

  it('Do this next: the first registry-mapped finding, one card, one button that opens Findings', async () => {
    api.getSecurityCheckDomains.mockResolvedValue({ cyber_mot_domains: eight({ website_security: row('website_security', 'issue_detected', { finding_count: 2, finding_ids: ['unmapped_x', 'header_missing_hsts'], finding_details: [
      { finding_id: 'unmapped_x', status: 'unmapped' },
      { finding_id: 'header_missing_hsts', status: 'resolved', customer_title: 'Send the HSTS header', recommended_action: 'Add Strict-Transport-Security with max-age of at least six months.' },
    ] }) }) })
    api.getCases.mockResolvedValue({ cases: [] })
    show('website_security')
    await waitFor(() => expect(screen.getByTestId('module-next-title')).toHaveTextContent('Send the HSTS header'))
    const card = section('module-next')
    expect(within(card).getByText('Add Strict-Transport-Security with max-age of at least six months.')).toBeInTheDocument()
    expect(within(card).getAllByRole('button')).toHaveLength(1)
    expect(within(card).queryAllByRole('link')).toHaveLength(0)
    fireEvent.click(screen.getByTestId('module-next-action'))
    expect(within(section('module-findings')).getByText('page body')).toBeInTheDocument()
  })

  it('Do this next fallbacks never invent remediation: unmapped findings, not yet assessed, nothing to fix, failed read', async () => {
    const cases = [
      [row('website_security', 'issue_detected', { finding_count: 1, finding_details: [{ finding_id: 'x', status: 'unmapped' }] }), 'Review the findings in the latest assessment', 'Review findings'],
      [row('website_security', 'not_yet_assessed'), 'Run a scan to assess this area', 'Run a scan'],
      [row('website_security', 'assessed_healthy', { coverage: 'complete' }), 'Nothing to fix from the latest assessment', 'Open the Field Guide'],
      // No finding with incomplete coverage is never presented as an all-clear.
      [row('website_security', 'provisional', { coverage: 'partial' }), 'No issue found in what could be checked', 'Run a scan'],
    ]
    api.getCases.mockResolvedValue({ cases: [] })
    for (const [entry, title, label] of cases) {
      api.getSecurityCheckDomains.mockResolvedValue({ cyber_mot_domains: eight({ website_security: entry }) })
      const r = show('website_security')
      await waitFor(() => expect(screen.getByTestId('module-next-title')).toHaveTextContent(title))
      expect(screen.getByTestId('module-next-action')).toHaveTextContent(label)
      r.unmount()
    }
    api.getSecurityCheckDomains.mockRejectedValue(new Error('boom'))
    show('website_security')
    await waitFor(() => expect(screen.getByTestId('module-next-title')).toHaveTextContent('The latest assessment could not be read'))
    expect(screen.getByTestId('module-next-action')).toHaveAttribute('href', '/scans/new')
  })

  it('a page’s own next action replaces the resolver, still one button', async () => {
    api.getSecurityCheckDomains.mockResolvedValue({ cyber_mot_domains: eight() })
    api.getCases.mockResolvedValue({ cases: [] })
    show('cyber_essentials_readiness', { nextAction: { title: 'Answer the readiness questionnaire', body: '0 of 20 answered.', label: 'Start questionnaire', to: '/ws/cyber-essentials?tab=findings#questionnaire' } })
    expect(screen.getByTestId('module-next-title')).toHaveTextContent('Answer the readiness questionnaire')
    expect(within(section('module-next')).getAllByRole('link')).toHaveLength(1)
    expect(screen.getByTestId('module-next-action')).toHaveTextContent('Start questionnaire')
  })

  it('the three counts open their tabs', async () => {
    api.getSecurityCheckDomains.mockResolvedValue({ cyber_mot_domains: eight() })
    api.getCases.mockResolvedValue({ cases: [{ case_id: 'c1', domain_key: 'website_security', canonical_phase: 'awaiting_verification', verification_support: 'automated', title: 'HSTS' }] })
    show('website_security')
    await waitFor(() => expect(count('verification')).toHaveTextContent('Verification1'))
    fireEvent.click(count('findings'))
    expect(section('module-findings')).not.toBeNull()
    fireEvent.click(count('verification'))
    expect(section('module-verification')).not.toBeNull()
    fireEvent.click(count('cases'))
    expect(section('module-cases')).not.toBeNull()
  })

  it('Settings shows the page’s configurable blocks, or says there is nothing to configure', async () => {
    api.getSecurityCheckDomains.mockResolvedValue({ cyber_mot_domains: eight() })
    api.getCases.mockResolvedValue({ cases: [] })
    let r = show('certificates_trust', { settings: <form aria-label="TLS scan permissions" /> }, 'settings')
    expect(within(section('module-settings')).getByRole('form', { name: 'TLS scan permissions' })).toBeInTheDocument()
    r.unmount()
    show('website_security', {}, 'settings')
    expect(within(section('module-settings')).getByText(/Nothing to configure in this area/)).toBeInTheDocument()
    expect(within(section('module-settings')).getByRole('link', { name: 'Alert channels' })).toHaveAttribute('href', '/ws/alerts')
  })

  it('backend-stale evidence reads Stale in the header', async () => {
    api.getSecurityCheckDomains.mockResolvedValue({ cyber_mot_domains: eight({ certificates_trust: row('certificates_trust', 'assessed_healthy', { evidence_freshness: 'stale', freshness_reason: 'Last assessed 70 days ago — this evidence is stale.' }) }) })
    api.getCases.mockResolvedValue({ cases: [] })
    show('certificates_trust')
    await waitFor(() => expect(headChip()).toBe('stale'))
    expect(screen.getByTestId('module-head-status')).toHaveTextContent(/this evidence is stale/)
  })

  it('a failed eight-domain read is Error with no figures; a failed case read says so on every tab that shows cases', async () => {
    api.getSecurityCheckDomains.mockRejectedValue(new Error('boom'))
    api.getCases.mockRejectedValue(new Error('boom'))
    let r = show()
    await waitFor(() => expect(headChip()).toBe('error'))
    expect(within(section('module-observed')).getByText(/could not be read/)).toBeInTheDocument()
    expect(screen.queryAllByTestId('module-figure')).toHaveLength(0)
    expect(count('findings')).toHaveTextContent('—')
    await waitFor(() => expect(count('cases')).toHaveTextContent('—'))
    r.unmount()
    r = show('website_security', {}, 'cases')
    await waitFor(() => expect(within(section('module-cases')).getByText('Managed cases could not be read.')).toBeInTheDocument())
    expect(within(section('module-verification')).getByText('Verification status could not be read.')).toBeInTheDocument()
    r.unmount()
    show('website_security', {}, 'findings')
    await waitFor(() => expect(within(section('module-recommended')).getByText(/none can be shown until the area has been read/)).toBeInTheDocument())
  })

  it('a bundle whose API has no case function shows Error for cases, not an empty settled list', async () => {
    api.getSecurityCheckDomains.mockResolvedValue({ cyber_mot_domains: eight() })
    const saved = api.getCases
    delete api.getCases
    try {
      show('website_security', {}, 'cases')
      await waitFor(() => expect(within(section('module-cases')).getByText('Managed cases could not be read.')).toBeInTheDocument())
      expect(screen.queryByText(/No managed case exists/)).not.toBeInTheDocument()
    } finally {
      api.getCases = saved
    }
  })

  it('a malformed or seven-entry backend set is an Error, never a state', async () => {
    api.getSecurityCheckDomains.mockResolvedValue({ cyber_mot_domains: eight().slice(0, 7) })
    api.getCases.mockResolvedValue({ cases: [] })
    show()
    await waitFor(() => expect(api.getSecurityCheckDomains).toHaveBeenCalled())
    await waitFor(() => expect(headChip()).toBe('error'))
  })

  it('managed cases: open cases first with the case word; verification splits observed from attested; the count shows the open cases', async () => {
    api.getSecurityCheckDomains.mockResolvedValue({ cyber_mot_domains: eight() })
    api.getCases.mockResolvedValue({ cases: [
      { case_id: 'c1', domain_key: 'email_protection', canonical_phase: 'awaiting_verification', verification_support: 'automated', title: 'DMARC policy missing', domain: 'example.co.uk' },
      { case_id: 'c2', domain_key: 'email_protection', canonical_phase: 'verified', verification_support: 'manual', title: 'Hosted record rolled back', domain: 'example.co.uk' },
      { case_id: 'c3', domain_key: 'email_protection', canonical_phase: 'verified', verification_support: 'automated', title: 'SPF fixed', domain: 'example.co.uk' },
      { case_id: 'c4', domain_key: 'email_protection', canonical_phase: 'reopened', verification_support: 'automated', title: 'DKIM selector gone', domain: 'example.co.uk' },
      { case_id: 'c5', domain_key: 'email_protection', canonical_phase: 'closed_no_action', verification_support: 'manual', title: 'Old', domain: 'example.co.uk' },
    ] })
    const r = show('email_protection', {}, 'cases')
    const cases = section('module-cases')
    await waitFor(() => expect(within(cases).getByText('2 open of 5 cases.')).toBeInTheDocument())
    const items = within(cases).getAllByRole('listitem')
    expect(items).toHaveLength(2)
    expect(items.map((li) => li.querySelector('[data-status]').dataset.status)).toEqual(['ready_to_verify', 'recurring'])
    expect(within(cases).queryByText('Old')).not.toBeInTheDocument()

    const v = section('module-verification')
    expect(within(v).getByText(/3 can be verified by CyberMeters re-observing the fix, 2 rest on the customer's word/)).toBeInTheDocument()
    expect(within(v).getByText('Verified')).toHaveAttribute('data-status', 'verified')
    expect(within(v).getByText(ATTESTED_LABEL)).toHaveAttribute('data-status', 'attested')
    // The customer-attested case is never shown as Verified anywhere on the page.
    expect(screen.getAllByText('Verified')).toHaveLength(1)
    r.unmount()

    show('email_protection')
    await waitFor(() => expect(count('cases')).toHaveTextContent('Open cases2'))
    expect(count('verification')).toHaveTextContent('Verification1')
  })

  it('no cases: says there is nothing to verify, without claiming anything is verified', async () => {
    api.getSecurityCheckDomains.mockResolvedValue({ cyber_mot_domains: eight() })
    api.getCases.mockResolvedValue({ cases: [] })
    show('website_security', {}, 'cases')
    await waitFor(() => expect(within(section('module-cases')).getByText(/No managed case exists for this area/)).toBeInTheDocument())
    expect(within(section('module-verification')).getByText(/nothing to verify/)).toBeInTheDocument()
    expect(screen.queryByText('Verified')).not.toBeInTheDocument()
  })

  it('a page may add its own backend-derived recommended action above the registry note', async () => {
    api.getSecurityCheckDomains.mockResolvedValue({ cyber_mot_domains: eight() })
    api.getCases.mockResolvedValue({ cases: [] })
    show('certificates_trust', { recommendedAction: <p>Renew the expired certificate.</p> }, 'findings')
    await waitFor(() => expect(api.getCases).toHaveBeenCalled())
    expect(within(section('module-recommended')).getByText('Renew the expired certificate.')).toBeInTheDocument()
  })
})
