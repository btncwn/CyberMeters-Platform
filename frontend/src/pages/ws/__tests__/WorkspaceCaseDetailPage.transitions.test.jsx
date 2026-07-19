// ── Universal Case Detail — Next-action transition controls ───────────────────
// The base managed-case backend + api.transitionCase existed but had no caller in
// the universal case UI. These tests prove the new "Next action" section renders
// ONLY from the backend's available_transitions, sends the correct target_status
// + payload, enforces required note/attestation input, refreshes on success,
// never fakes success on failure, is manager-gated, and keeps verification
// honesty (customer attestation is never "Verified by CyberMeters").
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from '../../../api'
import WorkspaceCaseDetailPage from '../WorkspaceCaseDetailPage'

vi.mock('../../../api', () => ({
  api: { getCase: vi.fn(), transitionCase: vi.fn(), getWorkspaceMembers: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({
  useWorkspace: () => ({ wsId: 'ws1', wsName: 'WS', workspaces: [{ id: 'ws1', role: 'admin' }], loading: false }),
}))

function renderCase(caseId = 'c1') {
  return render(
    <MemoryRouter initialEntries={[`/ws/cases/${caseId}`]}>
      <Routes><Route path="/ws/cases/:caseId" element={<WorkspaceCaseDetailPage />} /></Routes>
    </MemoryRouter>,
  )
}

const baseCase = {
  case_id: 'c1', workspace_id: 'ws1', domain_key: 'shadow_it_unmanaged_technology',
  case_type: 'shadow_it_case', status: 'detected', canonical_phase: 'detected',
  title: 'Unmanaged SaaS observed', severity: 'medium',
  source_finding_type: 'shadow_it_service', asset_ref: 'app.example.com',
  reopened_count: 0, created_at: '2026-07-01T10:00:00Z', updated_at: '2026-07-02T10:00:00Z',
  verification_support: 'manual', owner_ref: 'Beta',
}
const T = (over) => ({ requires_owner: false, requires_note: false, requires_expiry: false, requires_attestation: false, verification_mode: null, ...over })

beforeEach(() => {
  api.getCase.mockReset(); api.transitionCase.mockReset(); api.getWorkspaceMembers.mockReset()
  api.getWorkspaceMembers.mockResolvedValue({ members: [] })
})

describe('WorkspaceCaseDetailPage — Next action transitions', () => {
  it('renders ONLY the transitions the backend advertised (no invented controls)', async () => {
    api.getCase.mockResolvedValue({
      case: baseCase, events: [], can_manage: true,
      available_transitions: [T({ target_status: 'triaged', label: 'Begin triage' })],
    })
    renderCase()
    expect(await screen.findByRole('button', { name: 'Begin triage' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Approve to act' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Record customer attestation' })).toBeNull()
  })

  it('a manager can transition: sends the correct target_status and refreshes on success', async () => {
    api.getCase
      .mockResolvedValueOnce({ case: baseCase, events: [], can_manage: true, available_transitions: [T({ target_status: 'triaged', label: 'Begin triage' })] })
      .mockResolvedValueOnce({ case: { ...baseCase, status: 'triaged', canonical_phase: 'triaged' }, events: [], can_manage: true, available_transitions: [] })
    api.transitionCase.mockResolvedValue({ case: { ...baseCase, status: 'triaged' } })
    renderCase()
    fireEvent.click(await screen.findByRole('button', { name: 'Begin triage' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(api.transitionCase).toHaveBeenCalledWith('ws1', 'c1', { target_status: 'triaged' }))
    // Success refreshes case + history (getCase called again).
    await waitFor(() => expect(api.getCase).toHaveBeenCalledTimes(2))
  })

  it('a viewer/non-manager sees no transition controls', async () => {
    api.getCase.mockResolvedValue({
      case: baseCase, events: [], can_manage: false, available_transitions: [],
    })
    renderCase()
    // The page still renders (History present) but there is no Next action section.
    expect(await screen.findByText('History')).toBeInTheDocument()
    expect(screen.queryByText('Next action')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Begin triage' })).toBeNull()
  })

  it('requires a note before a reason-gated transition can be confirmed', async () => {
    api.getCase.mockResolvedValue({
      case: { ...baseCase, status: 'triaged', canonical_phase: 'triaged' }, events: [], can_manage: true,
      available_transitions: [T({ target_status: 'rejected', label: 'Reject case', requires_note: true })],
    })
    renderCase()
    fireEvent.click(await screen.findByRole('button', { name: 'Reject case' }))
    const confirm = await screen.findByRole('button', { name: 'Confirm' })
    expect(confirm).toBeDisabled()
    fireEvent.change(screen.getByPlaceholderText(/Why is this the right outcome/i), { target: { value: 'Duplicate of existing case.' } })
    expect(confirm).toBeEnabled()
    fireEvent.click(confirm)
    await waitFor(() => expect(api.transitionCase).toHaveBeenCalledWith('ws1', 'c1', { target_status: 'rejected', reason: 'Duplicate of existing case.' }))
  })

  it('records a manual verification as a customer attestation — honest wording, structured payload, never "Verified by CyberMeters"', async () => {
    api.getCase.mockResolvedValue({
      case: { ...baseCase, status: 'awaiting_verification', canonical_phase: 'awaiting_verification' }, events: [], can_manage: true,
      available_transitions: [T({ target_status: 'verified', label: 'Record customer attestation', requires_attestation: true, verification_mode: 'manual' })],
    })
    api.transitionCase.mockResolvedValue({ case: baseCase })
    renderCase()
    fireEvent.click(await screen.findByRole('button', { name: 'Record customer attestation' }))
    // Honest wording present (also appears in the explainer — hence findAllByText);
    // the reserved phrase never appears anywhere for a customer attestation.
    expect((await screen.findAllByText(/Attested by customer — not externally verifiable/i)).length).toBeGreaterThan(0)
    expect(screen.queryByText('Verified by CyberMeters')).toBeNull()

    const confirm = screen.getByRole('button', { name: 'Confirm' })
    expect(confirm).toBeDisabled()
    fireEvent.change(screen.getByPlaceholderText(/Describe what you changed/i), { target: { value: 'Removed the unmanaged app.' } })
    expect(confirm).toBeEnabled()
    fireEvent.click(confirm)
    await waitFor(() => expect(api.transitionCase).toHaveBeenCalled())
    const [, , payload] = api.transitionCase.mock.calls[0]
    expect(payload.target_status).toBe('verified')
    expect(payload.evidence.verification_method).toBe('manual_attestation')
    expect(payload.evidence.verification_result).toBe('fixed')
    expect(payload.evidence.attestation.statement).toBe('Removed the unmanaged app.')
  })

  it('does not falsely show success when the transition fails', async () => {
    api.getCase.mockResolvedValue({
      case: baseCase, events: [], can_manage: true,
      available_transitions: [T({ target_status: 'triaged', label: 'Begin triage' })],
    })
    api.transitionCase.mockRejectedValue(new Error('boom'))
    renderCase()
    fireEvent.click(await screen.findByRole('button', { name: 'Begin triage' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Confirm' }))
    expect(await screen.findByText(/Could not complete this action/i)).toBeInTheDocument()
    // No reload occurred (getCase still called once) — failure never fakes success.
    expect(api.getCase).toHaveBeenCalledTimes(1)
  })

  it('the transition button row wraps (no horizontal overflow)', async () => {
    api.getCase.mockResolvedValue({
      case: baseCase, events: [], can_manage: true,
      available_transitions: [T({ target_status: 'triaged', label: 'Begin triage' }), T({ target_status: 'false_positive', label: 'Mark false positive', requires_note: true })],
    })
    renderCase()
    const btn = await screen.findByRole('button', { name: 'Begin triage' })
    expect(btn.parentElement.className).toMatch(/flex-wrap/)
  })
})
