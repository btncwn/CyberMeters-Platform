// ── Universal Case Detail — reopen honesty (manual vs automatic) ──────────────
// Founder defect: a manual/customer reopen was described as a system
// re-observation ("reopened 1 time after the condition was re-observed"). The
// persisted managed_case_events.actor_type already distinguishes the cause
// ('system' = automatic evidence-driven recurrence; 'customer' = manual reopen),
// so the Recurrence card + history are derived from it — no migration.
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from '../../../api'
import WorkspaceCaseDetailPage from '../WorkspaceCaseDetailPage'

vi.mock('../../../api', () => ({ api: { getCase: vi.fn(), transitionCase: vi.fn(), getWorkspaceMembers: vi.fn() } }))
vi.mock('../../../hooks/useWorkspace', () => ({
  useWorkspace: () => ({ wsId: 'ws1', wsName: 'WS', workspaces: [{ id: 'ws1', role: 'admin' }], loading: false }),
}))

function renderCase() {
  return render(
    <MemoryRouter initialEntries={['/ws/cases/c1']}>
      <Routes><Route path="/ws/cases/:caseId" element={<WorkspaceCaseDetailPage />} /></Routes>
    </MemoryRouter>,
  )
}

const c = (over) => ({
  case_id: 'c1', workspace_id: 'ws1', domain_key: 'certificates_trust', case_type: 'certificate_case',
  status: 'action_in_progress', canonical_phase: 'action_in_progress', title: 'Cert recurrence',
  severity: 'medium', verification_support: 'automated', reopened_count: 0,
  created_at: '2026-07-01T10:00:00Z', updated_at: '2026-07-02T10:00:00Z', ...over,
})

beforeEach(() => {
  api.getCase.mockReset(); api.getWorkspaceMembers.mockReset()
  api.getWorkspaceMembers.mockResolvedValue({ members: [] })
})

describe('WorkspaceCaseDetailPage — reopen cause honesty', () => {
  it('a MANUAL reopen is never described as a re-observation', async () => {
    api.getCase.mockResolvedValue({
      case: c({ status: 'reopened', canonical_phase: 'reopened', reopened_count: 1 }),
      events: [
        { id: 'e1', action: 'case_created', actor_type: 'system', to_status: 'detected', created_at: '2026-07-01T10:00:00Z' },
        { id: 'e2', action: 'transition_reopened', actor_type: 'customer', actor_id: 'u1', to_status: 'reopened', created_at: '2026-07-05T10:00:00Z' },
      ],
      can_manage: true, available_transitions: [],
    })
    renderCase()
    expect(await screen.findByText(/Manually reopened 1 time by a workspace member/i)).toBeInTheDocument()
    // The recurrence card must NOT claim re-observation for a manual reopen.
    expect(screen.queryByText(/Automatically reopened/i)).toBeNull()
    // History labels it honestly too.
    expect(screen.getByText(/Manually reopened by a workspace member/i)).toBeInTheDocument()
  })

  it('an AUTOMATIC (system) reopen is described as a re-observation', async () => {
    api.getCase.mockResolvedValue({
      case: c({ status: 'reopened', canonical_phase: 'reopened', reopened_count: 1 }),
      events: [
        { id: 'e1', action: 'case_created', actor_type: 'system', to_status: 'detected', created_at: '2026-07-01T10:00:00Z' },
        { id: 'e2', action: 'transition_reopened', actor_type: 'system', actor_id: null, to_status: 'reopened', created_at: '2026-07-05T10:00:00Z' },
      ],
      can_manage: true, available_transitions: [],
    })
    renderCase()
    expect(await screen.findByText(/Automatically reopened 1 time after the condition was re-observed/i)).toBeInTheDocument()
    expect(screen.queryByText(/Manually reopened/i)).toBeNull()
    expect(screen.getByText(/Reopened automatically after the condition was re-observed/i)).toBeInTheDocument()
  })

  it('a never-reopened case shows the neutral not-reopened copy', async () => {
    api.getCase.mockResolvedValue({ case: c(), events: [{ id: 'e1', action: 'case_created', actor_type: 'system', to_status: 'detected', created_at: '2026-07-01T10:00:00Z' }], can_manage: true, available_transitions: [] })
    renderCase()
    expect(await screen.findByText(/Not reopened\./i)).toBeInTheDocument()
    expect(screen.queryByText(/re-observed/i)).toBeNull()
  })
})
