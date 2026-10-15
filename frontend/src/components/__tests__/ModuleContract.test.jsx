import { render, screen, within, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import ModuleContract, { MODULE_CONTRACT_SECTIONS } from '../module/ModuleContract'
import { MODULES } from '../../lib/moduleRegistry'
import { api } from '../../api'
import { ATTESTED_LABEL } from '../../lib/caseDisplay'

// Every area page follows the same contract: Scope → Evidence state → Risk →
// Findings → Recommended action → Managed case → Verification → Field Guide.
// The framing sections read backend values only.

vi.mock('../../api', () => ({ api: { getCyberMotDomains: vi.fn(), getManagedCases: vi.fn() } }))

const KEYS = MODULES.map((m) => m.domainKey)
const row = (domain_key, state, extra = {}) => ({ domain_key, display_name: domain_key, description: `${domain_key} description`, state, summary: `${domain_key} summary`, finding_count: 0, recommendation_count: 0, highest_severity: null, limitations: [], last_assessed_at: '2026-10-01T09:00:00Z', ...extra })
const eight = (over = {}) => KEYS.map((k) => over[k] || row(k, 'not_yet_assessed'))

function show(domainKey = 'website_security', props = {}) {
  return render(
    <MemoryRouter>
      <ModuleContract domainKey={domainKey} workspaceId="ws1" workspaceName="Example Ltd" {...props}>
        <p>page body</p>
      </ModuleContract>
    </MemoryRouter>,
  )
}
const headings = () => screen.getAllByRole('heading', { level: 2 }).map((h) => h.textContent.replace(/^\d/, '').trim())
const section = (id) => document.getElementById(id)
const chip = (el) => el.querySelector('[data-status]').dataset.status

beforeEach(() => { vi.clearAllMocks() })

describe('ModuleContract — the eight-section page contract', () => {
  it('renders the eight sections in order, with the page body as Findings', async () => {
    api.getCyberMotDomains.mockResolvedValue({ cyber_mot_domains: eight() })
    api.getManagedCases.mockResolvedValue({ cases: [] })
    show()
    await waitFor(() => expect(chip(section('module-evidence-state'))).toBe('not_assessed'))
    expect(MODULE_CONTRACT_SECTIONS.map((s) => s.label)).toEqual(['Scope', 'Evidence state', 'Risk', 'Findings', 'Recommended action', 'Managed case', 'Verification', 'Field Guide'])
    expect(headings()).toEqual(MODULE_CONTRACT_SECTIONS.map((s) => s.label))
    expect(within(section('module-findings')).getByText('page body')).toBeInTheDocument()
    expect(within(section('module-scope')).getByText('Website Security')).toBeInTheDocument()
    expect(within(section('module-scope')).getByText(/Workspace: Example Ltd/)).toBeInTheDocument()
    expect(within(section('module-guide')).getByRole('link', { name: 'Open the Field Guide' })).toHaveAttribute('href', '/guide/website-security')
    expect(within(section('module-cases')).getByRole('link', { name: 'Open Operations for this area' })).toHaveAttribute('href', '/ws/cases?domain_key=website_security')
    expect(api.getCyberMotDomains).toHaveBeenCalledWith('ws1')
    expect(api.getManagedCases).toHaveBeenCalledWith('ws1', { domain_key: 'website_security', limit: 100 })
  })

  it('every one of the eight areas resolves to its own Field Guide page', async () => {
    api.getCyberMotDomains.mockResolvedValue({ cyber_mot_domains: eight() })
    api.getManagedCases.mockResolvedValue({ cases: [] })
    for (const m of MODULES) {
      const { unmount } = show(m.domainKey)
      expect(within(section('module-guide')).getByRole('link', { name: 'Open the Field Guide' }).getAttribute('href')).toMatch(/^\/guide\/[a-z-]+$/)
      expect(within(section('module-scope')).getByText(m.title)).toBeInTheDocument()
      unmount()
    }
  })

  it('shows Loading before the reads return, then the backend word, risk figures and freshness', async () => {
    let resolveDomains
    api.getCyberMotDomains.mockReturnValue(new Promise((r) => { resolveDomains = r }))
    api.getManagedCases.mockResolvedValue({ cases: [] })
    show('email_protection')
    expect(chip(section('module-evidence-state'))).toBe('loading')
    expect(within(section('module-risk')).getByText(/Risk is stated only from a read assessment/)).toBeInTheDocument()
    resolveDomains({ cyber_mot_domains: eight({ email_protection: row('email_protection', 'issue_detected', { finding_count: 4, recommendation_count: 2, highest_severity: 'high', coverage: 'complete', evidence_freshness: 'current', freshness_reason: 'Last assessed 3 days ago.', limitations: ['DKIM is checked against common selectors only.'] }) }) })
    await waitFor(() => expect(chip(section('module-evidence-state'))).toBe('action_required'))
    expect(within(section('module-evidence-state')).getByText('email_protection summary')).toBeInTheDocument()
    expect(within(section('module-evidence-state')).getByText(/Last assessed 3 days ago\. Coverage: complete\./)).toBeInTheDocument()
    expect(within(section('module-risk')).getByText('high')).toBeInTheDocument()
    expect(within(section('module-risk')).getByText('4')).toBeInTheDocument()
    expect(within(section('module-recommended')).getByText(/2 recommendations recorded/)).toBeInTheDocument()
    expect(within(section('module-scope')).getByText('DKIM is checked against common selectors only.')).toBeInTheDocument()
  })

  it('backend-stale evidence reads Stale', async () => {
    api.getCyberMotDomains.mockResolvedValue({ cyber_mot_domains: eight({ certificates_trust: row('certificates_trust', 'assessed_healthy', { evidence_freshness: 'stale', freshness_reason: 'Last assessed 70 days ago — this evidence is stale and may no longer reflect the current posture.' }) }) })
    api.getManagedCases.mockResolvedValue({ cases: [] })
    show('certificates_trust')
    await waitFor(() => expect(chip(section('module-evidence-state'))).toBe('stale'))
    expect(within(section('module-evidence-state')).getByText(/this evidence is stale/)).toBeInTheDocument()
  })

  it('a failed eight-domain read is Error with no risk figures; a failed case read says so', async () => {
    api.getCyberMotDomains.mockRejectedValue(new Error('boom'))
    api.getManagedCases.mockRejectedValue(new Error('boom'))
    show()
    await waitFor(() => expect(chip(section('module-evidence-state'))).toBe('error'))
    expect(within(section('module-evidence-state')).getByText(/could not be read/)).toBeInTheDocument()
    expect(within(section('module-risk')).queryByText('Highest severity')).not.toBeInTheDocument()
    expect(within(section('module-cases')).getByText('Managed cases could not be read.')).toBeInTheDocument()
    expect(within(section('module-verification')).getByText('Verification status could not be read.')).toBeInTheDocument()
    expect(within(section('module-recommended')).getByText(/none can be shown until the area has been read/)).toBeInTheDocument()
  })

  it('a bundle whose API has no case function shows Error for cases, not an empty settled list', async () => {
    api.getCyberMotDomains.mockResolvedValue({ cyber_mot_domains: eight() })
    const saved = api.getManagedCases
    delete api.getManagedCases
    try {
      show()
      await waitFor(() => expect(within(section('module-cases')).getByText('Managed cases could not be read.')).toBeInTheDocument())
      expect(screen.queryByText(/No managed case exists/)).not.toBeInTheDocument()
    } finally {
      api.getManagedCases = saved
    }
  })

  it('a malformed or seven-entry backend set is an Error, never a state', async () => {
    api.getCyberMotDomains.mockResolvedValue({ cyber_mot_domains: eight().slice(0, 7) })
    api.getManagedCases.mockResolvedValue({ cases: [] })
    show()
    await waitFor(() => expect(api.getCyberMotDomains).toHaveBeenCalled())
    await waitFor(() => expect(chip(section('module-evidence-state'))).toBe('error'))
  })

  it('managed cases: open cases first with the case word; verification splits observed from attested', async () => {
    api.getCyberMotDomains.mockResolvedValue({ cyber_mot_domains: eight() })
    api.getManagedCases.mockResolvedValue({ cases: [
      { case_id: 'c1', domain_key: 'email_protection', canonical_phase: 'awaiting_verification', verification_support: 'automated', title: 'DMARC policy missing', domain: 'example.co.uk' },
      { case_id: 'c2', domain_key: 'email_protection', canonical_phase: 'verified', verification_support: 'manual', title: 'Hosted record rolled back', domain: 'example.co.uk' },
      { case_id: 'c3', domain_key: 'email_protection', canonical_phase: 'verified', verification_support: 'automated', title: 'SPF fixed', domain: 'example.co.uk' },
      { case_id: 'c4', domain_key: 'email_protection', canonical_phase: 'reopened', verification_support: 'automated', title: 'DKIM selector gone', domain: 'example.co.uk' },
      { case_id: 'c5', domain_key: 'email_protection', canonical_phase: 'closed_no_action', verification_support: 'manual', title: 'Old', domain: 'example.co.uk' },
    ] })
    show('email_protection')
    const cases = section('module-cases')
    await waitFor(() => expect(within(cases).getByText('2 open of 5 cases.')).toBeInTheDocument())
    const items = within(cases).getAllByRole('listitem')
    expect(items).toHaveLength(2)
    expect(items.map((li) => li.querySelector('[data-status]').dataset.status)).toEqual(['ready_to_verify', 'recurring'])
    expect(within(cases).queryByText('Old')).not.toBeInTheDocument()
    expect(within(section('module-risk')).getByText('2')).toBeInTheDocument()

    const v = section('module-verification')
    expect(within(v).getByText(/3 can be verified by CyberMeters re-observing the fix, 2 rest on the customer's word/)).toBeInTheDocument()
    expect(within(v).getByText('Verified')).toHaveAttribute('data-status', 'verified')
    expect(within(v).getByText(ATTESTED_LABEL)).toHaveAttribute('data-status', 'attested')
    // The customer-attested case is never shown as Verified anywhere on the page.
    expect(screen.getAllByText('Verified')).toHaveLength(1)
  })

  it('no cases: says there is nothing to verify, without claiming anything is verified', async () => {
    api.getCyberMotDomains.mockResolvedValue({ cyber_mot_domains: eight() })
    api.getManagedCases.mockResolvedValue({ cases: [] })
    show()
    await waitFor(() => expect(within(section('module-cases')).getByText(/No managed case exists for this area/)).toBeInTheDocument())
    expect(within(section('module-verification')).getByText(/nothing to verify/)).toBeInTheDocument()
    expect(screen.queryByText('Verified')).not.toBeInTheDocument()
  })

  it('a page may add its own backend-derived recommended action above the registry note', async () => {
    api.getCyberMotDomains.mockResolvedValue({ cyber_mot_domains: eight() })
    api.getManagedCases.mockResolvedValue({ cases: [] })
    show('certificates_trust', { recommendedAction: <p>Renew the expired certificate.</p> })
    await waitFor(() => expect(api.getManagedCases).toHaveBeenCalled())
    expect(within(section('module-recommended')).getByText('Renew the expired certificate.')).toBeInTheDocument()
  })
})
