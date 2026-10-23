import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../../api'
import WorkspaceCaseDetailPage, { presentTransitions, submittedForVerificationText } from '../WorkspaceCaseDetailPage'

// S1-CASE-STALE (Executive 00:00, 23 Oct 2026; Codex C-37): a backwards or
// consequential move is never the primary and says what it does; after a
// transition the controls stay disabled until the server's state is on screen.

vi.mock('../../../api', () => ({ api: { getCase: vi.fn(), transitionCase: vi.fn(), transitionManagedCase: vi.fn(), getWorkspaceMembers: vi.fn() } }))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: () => ({ wsId: 'ws1', wsName: 'WS', workspaces: [{ id: 'ws1', role: 'admin' }], loading: false }) }))

const T = (target_status, label, extra = {}) => ({ target_status, label, ...extra })
const view = (caseRecord, transitions) => presentTransitions(caseRecord, transitions).map(({ label, primary }) => `${primary ? '[P] ' : ''}${label}`)

describe('presentTransitions (C-37 rows)', () => {
  it('B06N awaiting verification (automated): no primary; the rollback says it reopens work', () => {
    expect(view({ status: 'awaiting_verification', canonical_phase: 'awaiting_verification', verification_support: 'automated' }, [T('action_in_progress', 'Start remediation')]))
      .toEqual(['Not fixed yet — reopen work'])
  })
  it('B06M awaiting verification (manual): the attestation stays primary; the rollback is relabelled', () => {
    expect(view({ status: 'awaiting_verification', canonical_phase: 'awaiting_verification', verification_support: 'manual' }, [T('verified', 'Record customer attestation'), T('action_in_progress', 'Start remediation')]))
      .toEqual(['[P] Record customer attestation', 'Not fixed yet — reopen work'])
  })
  it('B08 monitoring and B11 accepted risk: reopening or re-triaging is never the primary', () => {
    expect(view({ status: 'monitoring', canonical_phase: 'monitoring' }, [T('reopened', 'Reopen case'), T('closed_no_action', 'Close — no action needed')]))
      .toEqual(['Reopen case', '[P] Close — no action needed'])
    expect(view({ status: 'accepted_risk', canonical_phase: 'accepted_risk' }, [T('triaged', 'Begin triage')]))
      .toEqual(['Withdraw the risk acceptance and re-triage'])
  })
  it('Attack Surface A06/A07/A08/A09/A11: the running check, the close, the risk request and the retry say what they do', () => {
    expect(view({ status: 'verifying' }, [T('verification_requested', 'Request verification')])).toEqual(['Restart verification (cancels the running check)'])
    expect(view({ status: 'resolved' }, [T('closed', 'Close case')])).toEqual(['Close case'])
    expect(view({ status: 'risk_acceptance_requested' }, [T('risk_accepted', 'Accept risk'), T('remediation_in_progress', 'Start remediation')]))
      .toEqual(['[P] Accept risk', 'Withdraw the risk request and resume work'])
    expect(view({ status: 'risk_accepted' }, [T('triage', 'Begin triage')])).toEqual(['Withdraw the risk acceptance and re-triage'])
    expect(view({ status: 'verification_failed' }, [T('remediation_in_progress', 'Start remediation'), T('verification_requested', 'Request verification')]))
      .toEqual(['[P] Resume remediation', 'Request verification'])
  })
  it('forward moves keep their label and the first is the one primary', () => {
    expect(view({ status: 'approved', canonical_phase: 'approved' }, [T('action_in_progress', 'Start remediation'), T('accepted_risk', 'Accept risk')]))
      .toEqual(['[P] Start remediation', 'Accept risk'])
  })
  it('the waiting sentence names the submission date and who verifies; none for a manual case', () => {
    const c = { canonical_phase: 'awaiting_verification', verification_support: 'automated', updated_at: '2026-10-21T09:00:00Z' }
    expect(submittedForVerificationText(c, [{ to_status: 'awaiting_verification', created_at: '2026-10-22T12:00:00Z' }]))
      .toBe('Submitted for verification on 22 Oct 2026 — CyberMeters verifies this on the next complete scan.')
    expect(submittedForVerificationText({ ...c, verification_support: 'manual' }, [])).toBeNull()
    expect(submittedForVerificationText({ ...c, canonical_phase: 'action_in_progress' }, [])).toBeNull()
  })
})

const caseIn = (phase) => ({
  case_id: 'mc-1', workspace_id: 'ws1', domain_key: 'website_security', case_type: 'website_case', status: phase, canonical_phase: phase,
  verification_support: 'automated', title: 'Send the HSTS header', severity: 'medium', reopened_count: 0,
  created_at: '2026-10-21T10:00:00Z', updated_at: '2026-10-22T12:00:00Z',
})
const transitionsFor = { action_in_progress: [T('awaiting_verification', 'Submit for verification')], awaiting_verification: [T('action_in_progress', 'Start remediation')] }
const body = (phase) => ({ case: caseIn(phase), events: [], can_manage: true, available_transitions: transitionsFor[phase] || [] })

beforeEach(() => { vi.clearAllMocks(); api.getWorkspaceMembers.mockResolvedValue({ members: [] }) })

describe('the case page after a transition', () => {
  it('disables the clicked control in flight, applies the server state, and the old primary cannot take a second click', async () => {
    let phase = 'action_in_progress'
    let releaseReload
    api.getCase.mockImplementation(() => (phase === 'action_in_progress'
      ? Promise.resolve(body(phase))
      : new Promise((resolve) => { releaseReload = () => resolve(body(phase)) })))
    api.transitionCase.mockImplementation(async () => { phase = 'awaiting_verification'; return { ok: true } })
    render(<MemoryRouter initialEntries={['/ws/cases/mc-1']}><Routes><Route path="/ws/cases/:caseId" element={<WorkspaceCaseDetailPage />} /></Routes></MemoryRouter>)
    const submit = await screen.findByRole('button', { name: 'Submit for verification' })
    fireEvent.click(submit)
    // In flight and while the case reloads the control is disabled or gone; a second click does nothing.
    await waitFor(() => expect(api.getCase).toHaveBeenCalledTimes(2))
    for (const b of screen.queryAllByRole('button', { name: /Working…|Submit for verification/ })) {
      expect(b).toBeDisabled()
      fireEvent.click(b)
    }
    expect(api.transitionCase).toHaveBeenCalledTimes(1)
    await act(async () => { releaseReload() })
    // The server's state: waiting sentence, no primary, the rollback secondary and honest.
    expect(await screen.findByTestId('case-waiting-verification')).toHaveTextContent('Submitted for verification on 22 Oct 2026 — CyberMeters verifies this on the next complete scan.')
    expect(screen.queryByRole('button', { name: 'Submit for verification' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Start remediation' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Not fixed yet — reopen work' })).not.toHaveAttribute('data-primary')
    expect(document.querySelectorAll('[data-primary="true"]')).toHaveLength(0)
    expect(api.transitionCase).toHaveBeenCalledWith('ws1', 'mc-1', { target_status: 'awaiting_verification' })
  })
})
