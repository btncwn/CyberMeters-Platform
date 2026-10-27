// CE "Do this next" (P2, 27 Oct 2026): with all 20 answers saved and a
// self-declared gap, the job is reviewing that answer — not a scan, which
// cannot see an internal answer, and never an all-clear. A finding or a case
// keeps priority; loading, failed, incomplete and gap-free states stay honest.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import WorkspaceCyberEssentialsPage from '../WorkspaceCyberEssentialsPage'
import { api } from '../../../api'
import { useWorkspace } from '../../../hooks/useWorkspace'
import { MODULES } from '../../../lib/moduleRegistry'

vi.mock('../../../api', () => ({
  api: {
    getWorkspaceCyberEssentialsAnswers: vi.fn(), getWorkspaceCyberEssentialsReadiness: vi.fn(),
    getCyberEssentialsControls: vi.fn(), saveWorkspaceCyberEssentialsAnswers: vi.fn(),
    getSecurityCheckDomains: vi.fn(), getCases: vi.fn(),
  },
}))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: vi.fn() }))

const CE = 'cyber_essentials_readiness'
const row = (domain_key, extra = {}) => ({ domain_key, display_name: domain_key, state: 'not_assessed', coverage: 'partial', finding_count: 0, finding_details: [], ...extra })
const domains = (ce = {}) => ({ cyber_mot_domains: MODULES.map((m) => (m.domainKey === CE ? row(CE, ce) : row(m.domainKey))) })
// 20 questions across two controls, as the real set is shaped.
const QUESTIONS = [
  { control_key: 'firewalls', label: 'Firewalls', questions: Array.from({ length: 10 }, (_, i) => ({ key: `fw_${i}`, text: `Firewall question ${i}` })) },
  { control_key: 'secure_configuration', label: 'Secure configuration', questions: Array.from({ length: 10 }, (_, i) => ({ key: `sc_${i}`, text: `Configuration question ${i}` })) },
]
const allAnswered = { firewalls: Object.fromEntries(QUESTIONS[0].questions.map((q) => [q.key, 'yes'])), secure_configuration: Object.fromEntries(QUESTIONS[1].questions.map((q) => [q.key, 'yes'])) }
const readiness = (gaps) => ({
  score: null, status: 'not_assessed', assessable: false, questionnaire: { complete: true },
  self_assessment: { controls: [{ control_key: 'firewalls', label: 'Firewalls', self_attestation: { answered: 10, total: 10, gaps } }] },
})
const TITLE = 'Review your self-declared answers'
const next = async () => {
  const heading = await screen.findByRole('heading', { name: 'Do this next' })
  return heading.closest('section') || heading.parentElement
}

beforeEach(() => {
  vi.clearAllMocks()
  useWorkspace.mockReturnValue({ wsId: 'ws-1', wsName: 'Example Ltd', loading: false })
  api.getWorkspaceCyberEssentialsAnswers.mockResolvedValue({ questions: QUESTIONS, answers: allAnswered })
  api.getWorkspaceCyberEssentialsReadiness.mockResolvedValue(readiness(['default_inbound_block']))
  api.getCyberEssentialsControls.mockResolvedValue({ items: [], pagination: { total: 0 } })
  api.getSecurityCheckDomains.mockResolvedValue(domains())
  api.getCases.mockResolvedValue({ cases: [] })
})
const mount = (path = '/ws/cyber-essentials') => render(<MemoryRouter initialEntries={[path]}><WorkspaceCyberEssentialsPage /></MemoryRouter>)

describe('CE Do this next', () => {
  it('20/20 saved with a self-declared gap: one self-declared review action, no scan, no all-clear, no assurance claim', async () => {
    mount()
    const card = within(await next())
    expect(await card.findByText(TITLE, { selector: 'h3, p, strong, span, div' })).toBeInTheDocument()
    const action = card.getByRole('link', { name: TITLE })
    expect(action).toHaveAttribute('href', '/ws/cyber-essentials?tab=findings#questionnaire')
    expect(card.queryByText(/Run a scan to assess this area/)).toBeNull()
    expect(card.queryByText(/Nothing to fix/)).toBeNull()
    const text = (await next()).textContent
    expect(text).toMatch(/1 of your saved answers shows a gap/)
    expect(text).toMatch(/your own answers/)
    expect(text).not.toMatch(/verif|certif|assur|confirmed/i)
  })
  it('20/20 saved with no gap: the generic honest ending, never the self-declared review', async () => {
    api.getWorkspaceCyberEssentialsReadiness.mockResolvedValue(readiness([]))
    mount()
    const card = within(await next())
    expect(await card.findByText('Run a scan to assess this area')).toBeInTheDocument()
    expect(card.queryByText(TITLE)).toBeNull()
  })
  it('an incomplete questionnaire keeps "Finish the readiness questionnaire"', async () => {
    api.getWorkspaceCyberEssentialsAnswers.mockResolvedValue({ questions: QUESTIONS, answers: { firewalls: allAnswered.firewalls } })
    mount()
    const card = within(await next())
    expect(await card.findByText('Finish the readiness questionnaire')).toBeInTheDocument()
    expect(card.queryByText(TITLE)).toBeNull()
  })
  it('a failed readiness load never offers the self-declared review', async () => {
    api.getWorkspaceCyberEssentialsReadiness.mockRejectedValue(new Error('network'))
    mount()
    await screen.findByText(/network|could not|try again/i)
    expect(screen.queryByText(TITLE)).toBeNull()
  })
  it('an external finding and an open case keep priority over the self-declared review', async () => {
    api.getSecurityCheckDomains.mockResolvedValue(domains({ state: 'issue_detected', finding_count: 1, finding_details: [{ finding_id: 'x', status: 'resolved', customer_title: 'Fix the external thing', recommended_action: 'Do the registered thing.' }] }))
    const first = mount()
    expect(await within(await next()).findByText('Fix the external thing')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: TITLE })).toBeNull()
    first.unmount()
    api.getSecurityCheckDomains.mockResolvedValue(domains())
    api.getCases.mockResolvedValue({ cases: [{ id: 'c1', case_id: 'c1', domain_key: CE, status: 'action_required' }] })
    mount()
    expect(await within(await next()).findByText(/case from earlier is still open/)).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: TITLE })).toBeNull()
  })
  it('an unsaved final answer never shows the review; a failed save keeps it hidden; a successful save that reads complete shows it (R1 #1024)', async () => {
    const nineteen = { firewalls: allAnswered.firewalls, secure_configuration: Object.fromEntries(QUESTIONS[1].questions.slice(0, 9).map((q) => [q.key, 'yes'])) }
    api.getWorkspaceCyberEssentialsAnswers.mockResolvedValue({ questions: QUESTIONS, answers: nineteen })
    api.getWorkspaceCyberEssentialsReadiness.mockResolvedValue({ ...readiness(['default_inbound_block']), questionnaire: { complete: false } })
    mount('/ws/cyber-essentials?tab=findings')
    expect(await within(await next()).findByText('Finish the readiness questionnaire')).toBeInTheDocument()
    // Tick the 20th answer without saving.
    const last = (await screen.findByText('Configuration question 9')).closest('.rounded-2xl')
    fireEvent.click(within(last).getByRole('button', { name: /^Yes/ }))
    await waitFor(() => expect(screen.queryByText('Finish the readiness questionnaire')).toBeNull())
    expect(screen.queryByRole('link', { name: TITLE })).toBeNull()
    expect(api.saveWorkspaceCyberEssentialsAnswers).toHaveBeenCalledTimes(0)
    // A failed save changes nothing.
    api.saveWorkspaceCyberEssentialsAnswers.mockRejectedValueOnce(new Error('save failed'))
    fireEvent.click(screen.getByRole('button', { name: 'Save answers' }))
    await waitFor(() => expect(api.saveWorkspaceCyberEssentialsAnswers).toHaveBeenCalledTimes(1))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Save answers' })).toBeEnabled())
    expect(screen.queryByRole('link', { name: TITLE })).toBeNull()
    // A successful save whose refreshed readiness reads complete shows it.
    api.saveWorkspaceCyberEssentialsAnswers.mockResolvedValueOnce({ questions: QUESTIONS, answers: allAnswered })
    api.getWorkspaceCyberEssentialsReadiness.mockResolvedValue(readiness(['default_inbound_block']))
    fireEvent.click(screen.getByRole('button', { name: 'Save answers' }))
    expect(await screen.findByRole('link', { name: TITLE })).toHaveAttribute('href', '/ws/cyber-essentials?tab=findings#questionnaire')
    expect(api.saveWorkspaceCyberEssentialsAnswers).toHaveBeenCalledTimes(2)
  })
})
