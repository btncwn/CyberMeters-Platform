import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from '../../../api'
import WorkspaceCaseDetailPage from '../WorkspaceCaseDetailPage'

// Design standard (founder, 21 Oct 2026), case page: one vocabulary with the
// list, human event labels, no dead end, and an Attack Surface case can be
// closed as a false positive from its own page.

vi.mock('../../../api', () => ({
  api: { getCase: vi.fn(), transitionCase: vi.fn(), transitionManagedCase: vi.fn(), getWorkspaceMembers: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({
  useWorkspace: () => ({ wsId: 'ws1', wsName: 'WS', workspaces: [{ id: 'ws1', role: 'admin' }], loading: false }),
}))

function renderCase() {
  return render(
    <MemoryRouter initialEntries={['/ws/cases/mc-1']}>
      <Routes><Route path="/ws/cases/:caseId" element={<WorkspaceCaseDetailPage />} /></Routes>
    </MemoryRouter>,
  )
}

const asmCase = {
  case_id: 'mc-1', workspace_id: 'ws1', domain_key: 'attack_surface', case_type: 'asm_exposure',
  status: 'triage', canonical_phase: 'triaged', verification_support: 'automated',
  title: 'Admin interface exposed', summary: 'An admin interface answered on admin.example.com.',
  severity: 'high', source_finding_type: 'asset_exposure_admin_interface', remediation_id: 'asm.exposure.admin',
  asset_ref: 'admin.example.com', reopened_count: 0, created_at: '2026-10-21T15:23:00Z', updated_at: '2026-10-21T15:23:00Z',
}
const asm = (target_status, label, extra = {}) => ({ target_status, label, endpoint: 'attack_surface', requires_owner: false, requires_note: false, requires_expiry: false, requires_attestation: false, ...extra })

beforeEach(() => {
  vi.clearAllMocks()
  api.getWorkspaceMembers.mockResolvedValue({ members: [] })
  api.transitionManagedCase.mockResolvedValue({ case: asmCase })
})

describe('case page design standard', () => {
  it('the status badge uses the list vocabulary ("Action required", not "Detected")', async () => {
    api.getCase.mockResolvedValue({ case: { ...asmCase, status: 'open', canonical_phase: 'detected' }, events: [], can_manage: true, available_transitions: [asm('triage', 'Begin triage')] })
    renderCase()
    await screen.findByRole('heading', { level: 1, name: 'Admin interface exposed' })
    expect(screen.getAllByText('Action required').length).toBeGreaterThan(0)
    expect(screen.queryByText('Detected')).toBeNull()
  })

  it('an Attack Surface case can be marked false positive here, with a required reason, through its own endpoint', async () => {
    api.getCase.mockResolvedValue({ case: asmCase, events: [], can_manage: true, available_transitions: [asm('owner_assigned', 'Move to Assigned', { requires_owner: true }), asm('false_positive', 'Mark false positive', { requires_note: true })] })
    renderCase()
    fireEvent.click(await screen.findByRole('button', { name: 'Mark false positive' }))
    const submit = await screen.findByRole('button', { name: 'Mark false positive' })
    expect(submit).toBeDisabled()
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'This is our own staging admin, not exposed to customers.' } })
    fireEvent.click(submit)
    await waitFor(() => expect(api.transitionManagedCase).toHaveBeenCalledWith('ws1', 'mc-1', { status: 'false_positive', reason: 'This is our own staging admin, not exposed to customers.' }))
    expect(api.transitionCase).not.toHaveBeenCalled()
  })

  it('a direct Attack Surface move (Begin triage) also uses the Attack Surface endpoint', async () => {
    api.getCase.mockResolvedValue({ case: { ...asmCase, status: 'open', canonical_phase: 'detected' }, events: [], can_manage: true, available_transitions: [asm('triage', 'Begin triage')] })
    renderCase()
    fireEvent.click(await screen.findByRole('button', { name: 'Begin triage' }))
    await waitFor(() => expect(api.transitionManagedCase).toHaveBeenCalledWith('ws1', 'mc-1', { status: 'triage' }))
  })

  it('the first move is the one primary button; the rest are secondary', async () => {
    api.getCase.mockResolvedValue({ case: asmCase, events: [], can_manage: true, available_transitions: [asm('owner_assigned', 'Move to Assigned'), asm('false_positive', 'Mark false positive', { requires_note: true })] })
    renderCase()
    await screen.findByRole('button', { name: 'Move to Assigned' })
    expect(document.querySelectorAll('[data-primary="true"]')).toHaveLength(1)
  })

  it('history events read as sentences, never raw keys', async () => {
    api.getCase.mockResolvedValue({ case: asmCase, events: [
      { id: 'e1', action: 'case_created', actor_type: 'system', created_at: '2026-10-21T15:23:00Z' },
      { id: 'e2', action: 'monitoring_changed', actor_type: 'system', created_at: '2026-10-21T15:24:00Z' },
    ], can_manage: false, available_transitions: [] })
    renderCase()
    const history = within(await screen.findByTestId('case-history'))
    expect(history.getByText(/^Monitoring changed/)).toBeInTheDocument()
    expect(history.getByText(/^Case opened/)).toBeInTheDocument()
    expect(screen.getByTestId('case-history').textContent).not.toMatch(/[a-z]+_[a-z]+/)
  })

  it('no internal key reaches the body (finding key, remediation id, case id)', async () => {
    api.getCase.mockResolvedValue({ case: asmCase, events: [], can_manage: false, available_transitions: [] })
    renderCase()
    await screen.findByRole('heading', { level: 1 })
    const body = screen.getByTestId('case-detail').textContent
    for (const key of ['asset_exposure_admin_interface', 'asm.exposure.admin', 'mc-1']) expect(body).not.toContain(key)
  })
})

describe('case page re-check fixes (founder, 21 Oct 21:35)', () => {
  it('two system moves with one action read as two meanings, not the same label twice', async () => {
    api.getCase.mockResolvedValue({ case: { ...asmCase, status: 'false_positive', canonical_phase: 'false_positive' }, events: [
      { id: 'e1', action: 'claim_withdrawn', actor_type: 'system', from_status: 'open', to_status: 'triage', created_at: '2026-10-21T21:01:00Z' },
      { id: 'e2', action: 'claim_withdrawn', actor_type: 'system', from_status: 'triage', to_status: 'false_positive', created_at: '2026-10-21T21:01:00Z' },
    ], can_manage: true, available_transitions: [] })
    renderCase()
    const history = within(await screen.findByTestId('case-history'))
    expect(history.getByText(/^Claim withdrawn — moved to review/)).toBeInTheDocument()
    expect(history.getByText(/^Claim withdrawn — closed as false positive/)).toBeInTheDocument()
  })

  it('a closed case shows the owner read-only, with no Assign control', async () => {
    api.getCase.mockResolvedValue({ case: { ...asmCase, status: 'false_positive', canonical_phase: 'false_positive' }, events: [], can_manage: true, available_transitions: [] })
    renderCase()
    expect(await screen.findByText('No owner was assigned')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Assign' })).toBeNull()
    expect(screen.queryByRole('combobox', { name: 'Assign owner' })).toBeNull()
  })
})
