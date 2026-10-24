// ── Universal Case Detail — Next-action transition controls ───────────────────
// UX correction (founder public-beta blocker): an input-free transition must
// execute on ONE click — no redundant empty Confirm panel. A transition that
// requires a reason / expiry / attestation still opens an inline form that
// collects only those fields. These tests pin: direct one-click execution for
// input-free moves, no empty Confirm panel, disable-while-submitting +
// no-duplicate, real forms for input-required moves, honest attestation wording,
// no false success, success refresh, and viewer gating.
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
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
  case_type: 'shadow_it_case', status: 'action_in_progress', canonical_phase: 'action_in_progress',
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

describe('WorkspaceCaseDetailPage — input-free transitions execute on one click', () => {
  const DIRECT = [
    { target_status: 'triaged', label: 'Begin triage' },
    { target_status: 'assigned', label: 'Move to Assigned' },
    { target_status: 'approved', label: 'Approve to act' },
    { target_status: 'action_in_progress', label: 'Start remediation' },
    { target_status: 'awaiting_verification', label: 'Submit for verification' },
    { target_status: 'monitoring', label: 'Move to monitoring' },
    { target_status: 'reopened', label: 'Reopen case' },
  ]

  it.each(DIRECT)('"$label" transitions on a single click with no Confirm panel', async ({ target_status, label }) => {
    api.getCase
      .mockResolvedValueOnce({ case: baseCase, events: [], can_manage: true, available_transitions: [T({ target_status, label })] })
      .mockResolvedValueOnce({ case: { ...baseCase, status: target_status }, events: [], can_manage: true, available_transitions: [] })
    api.transitionCase.mockResolvedValue({ case: { ...baseCase, status: target_status } })
    renderCase()
    fireEvent.click(await screen.findByRole('button', { name: label }))
    await waitFor(() => expect(api.transitionCase).toHaveBeenCalledWith('ws1', 'c1', { target_status, expected_status: 'action_in_progress' }))
    // No empty Confirm/Cancel panel ever appeared.
    expect(screen.queryByRole('button', { name: 'Confirm' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Cancel' })).toBeNull()
    // Success refreshes case + history.
    await waitFor(() => expect(api.getCase).toHaveBeenCalledTimes(2))
  })

  it('a double-click cannot create a duplicate transition request', async () => {
    api.getCase.mockResolvedValue({ case: baseCase, events: [], can_manage: true, available_transitions: [T({ target_status: 'awaiting_verification', label: 'Submit for verification' })] })
    let resolveFn
    api.transitionCase.mockReturnValue(new Promise((res) => { resolveFn = res }))
    renderCase()
    const btn = await screen.findByRole('button', { name: 'Submit for verification' })
    fireEvent.click(btn)   // starts the request; button becomes disabled/busy
    fireEvent.click(btn)   // ignored — busy
    await waitFor(() => expect(btn).toBeDisabled())
    expect(api.transitionCase).toHaveBeenCalledTimes(1)
    resolveFn({ case: baseCase }) // cleanup
  })

  it('shows a generic error and does NOT refresh when a direct transition fails', async () => {
    api.getCase.mockResolvedValue({ case: baseCase, events: [], can_manage: true, available_transitions: [T({ target_status: 'awaiting_verification', label: 'Submit for verification' })] })
    api.transitionCase.mockRejectedValue(new Error('boom'))
    renderCase()
    fireEvent.click(await screen.findByRole('button', { name: 'Submit for verification' }))
    expect(await screen.findByText(/Could not complete this action/i)).toBeInTheDocument()
    expect(api.getCase).toHaveBeenCalledTimes(1) // no reload → no false success
  })
})

describe('WorkspaceCaseDetailPage — input-required transitions still open a form', () => {
  it('a reason-required transition (Reject case) opens a form and sends the reason', async () => {
    api.getCase.mockResolvedValue({
      case: { ...baseCase, status: 'triaged', canonical_phase: 'triaged' }, events: [], can_manage: true,
      available_transitions: [T({ target_status: 'rejected', label: 'Reject case', requires_note: true })],
    })
    api.transitionCase.mockResolvedValue({ case: baseCase })
    renderCase()
    fireEvent.click(await screen.findByRole('button', { name: 'Reject case' }))
    // The submit button names the action (verb + object), not "Confirm".
    const confirm = await screen.findByRole('button', { name: 'Reject case' })
    expect(confirm).toBeDisabled()
    fireEvent.change(screen.getByPlaceholderText(/Why is this the right outcome/i), { target: { value: 'Duplicate case.' } })
    expect(confirm).toBeEnabled()
    fireEvent.click(confirm)
    await waitFor(() => expect(api.transitionCase).toHaveBeenCalledWith('ws1', 'c1', { target_status: 'rejected', reason: 'Duplicate case.', expected_status: 'triaged' }))
  })

  it('risk acceptance requests both a reason and an expiry', async () => {
    api.getCase.mockResolvedValue({
      case: { ...baseCase, status: 'assigned', canonical_phase: 'assigned' }, events: [], can_manage: true,
      available_transitions: [T({ target_status: 'accepted_risk', label: 'Accept risk', requires_note: true, requires_expiry: true })],
    })
    api.transitionCase.mockResolvedValue({ case: baseCase })
    renderCase()
    fireEvent.click(await screen.findByRole('button', { name: 'Accept risk' }))
    // The submit button names the action (verb + object), not "Confirm".
    const confirm = await screen.findByRole('button', { name: 'Accept risk' })
    expect(confirm).toBeDisabled()
    fireEvent.change(screen.getByPlaceholderText(/Why is this the right outcome/i), { target: { value: 'Accepted by security.' } })
    expect(confirm).toBeDisabled() // still needs expiry
    fireEvent.change(document.querySelector('input[type="date"]'), { target: { value: '2026-12-31' } })
    expect(confirm).toBeEnabled()
    fireEvent.click(confirm)
    await waitFor(() => expect(api.transitionCase).toHaveBeenCalled())
    const [, , payload] = api.transitionCase.mock.calls[0]
    expect(payload.target_status).toBe('accepted_risk')
    expect(payload.reason).toBe('Accepted by security.')
    expect(payload.risk_accepted_until).toMatch(/^2026-12-31/)
  })

  it('a manual verification opens a structured attestation form — honest wording, never "Verified by CyberMeters"', async () => {
    api.getCase.mockResolvedValue({
      case: { ...baseCase, status: 'awaiting_verification', canonical_phase: 'awaiting_verification' }, events: [], can_manage: true,
      available_transitions: [T({ target_status: 'verified', label: 'Record customer attestation', requires_attestation: true, verification_mode: 'manual' })],
    })
    api.transitionCase.mockResolvedValue({ case: baseCase })
    renderCase()
    fireEvent.click(await screen.findByRole('button', { name: 'Record customer attestation' }))
    expect((await screen.findAllByText(/Attested by customer — not externally verifiable/i)).length).toBeGreaterThan(0)
    expect(screen.queryByText('Verified by CyberMeters')).toBeNull()
    const confirm = screen.getByRole('button', { name: 'Record customer attestation' })
    expect(confirm).toBeDisabled()
    fireEvent.change(screen.getByPlaceholderText(/Describe what you changed/i), { target: { value: 'Removed the unmanaged app.' } })
    fireEvent.click(confirm)
    await waitFor(() => expect(api.transitionCase).toHaveBeenCalled())
    const [, , payload] = api.transitionCase.mock.calls[0]
    expect(payload.evidence.verification_method).toBe('manual_attestation')
    expect(payload.evidence.attestation.statement).toBe('Removed the unmanaged app.')
  })

  it('an owner-required Move to Assigned opens the guidance form (not a direct move)', async () => {
    api.getCase.mockResolvedValue({
      case: { ...baseCase, status: 'triaged', canonical_phase: 'triaged', owner_ref: null }, events: [], can_manage: true,
      available_transitions: [T({ target_status: 'assigned', label: 'Move to Assigned', requires_owner: true })],
    })
    renderCase()
    fireEvent.click(await screen.findByRole('button', { name: 'Move to Assigned' }))
    // C-46 rank 4: the owner is chosen right in the Next action panel.
    expect(await screen.findByText(/This step needs an accountable owner/i)).toBeInTheDocument()
    expect(screen.getByTestId('next-action-owner')).toBeInTheDocument()
    // No direct transition fired (owner missing).
    expect(api.transitionCase).not.toHaveBeenCalled()
  })
})

describe('WorkspaceCaseDetailPage — viewer gating', () => {
  it('a non-manager sees no transition controls', async () => {
    api.getCase.mockResolvedValue({ case: baseCase, events: [], can_manage: false, available_transitions: [] })
    renderCase()
    expect(await screen.findByText('History')).toBeInTheDocument()
    expect(screen.queryByText('Next action')).toBeNull()
  })
})

// #912 stale-client guard: the page names the status it rendered; when the case
// has moved since, the server changes nothing, the page says so and reloads.
describe('WorkspaceCaseDetailPage — a case that moved since the page loaded', () => {
  it('a 409 case_status_changed shows a plain sentence and reloads the case; no generic error', async () => {
    api.getCase.mockResolvedValue({ case: baseCase, events: [], can_manage: true, available_transitions: [{ target_status: 'triaged', label: 'Begin triage' }] })
    api.transitionCase.mockRejectedValue(Object.assign(new Error('changed'), { status: 409, code: 'case_status_changed' }))
    renderCase()
    fireEvent.click(await screen.findByRole('button', { name: 'Begin triage' }))
    expect(await screen.findByText('This case changed since the page was loaded, so nothing was changed. It now shows its current status.')).toBeInTheDocument()
    expect(screen.queryByText('Could not complete this action. Please try again.')).toBeNull()
    await waitFor(() => expect(api.getCase).toHaveBeenCalledTimes(2))
  })
})

// Founder P1 #3 (23 Oct 2026): "What we saw" never shows a raw condition key (C-45 R01).
describe('WorkspaceCaseDetailPage — the affected line in words', () => {
  it('reads "sheshire.co.uk — HSTS header missing", never "sheshire.co.uk:header_missing_…"', async () => {
    api.getCase.mockResolvedValue({ case: { ...baseCase, resource: null, asset_ref: 'sheshire.co.uk:header_missing_strict_transport_security' }, events: [], can_manage: true, available_transitions: [] })
    renderCase()
    expect(await screen.findByText('sheshire.co.uk — HSTS header missing')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('header_missing_strict_transport_security')
  })
})
