// #921: a CE case in a workspace whose readiness is not assessed carries the
// backend's `assessment`; the case page shows its message and a "Not assessed"
// chip in place of "Action required". Nothing else changes.
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from '../../../api'
import WorkspaceCaseDetailPage from '../WorkspaceCaseDetailPage'
import { caseStatus } from '../../../lib/statusVocabulary'
import { caseChipStatus, caseAssessmentMessage } from '../../../lib/caseAssessment'

vi.mock('../../../api', () => ({
  api: { getCase: vi.fn(), transitionCase: vi.fn(), getWorkspaceMembers: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({
  useWorkspace: () => ({ wsId: 'ws1', wsName: 'WS', workspaces: [{ id: 'ws1', role: 'admin' }], loading: false }),
}))

const NOTE = 'Not assessed since 22 Oct 2026 — Cyber Essentials readiness is evaluated for single-domain workspaces only.'
const ceCase = {
  case_id: 'c1', workspace_id: 'ws1', domain_key: 'cyber_essentials_readiness', case_type: 'cyber_essentials_case',
  status: 'detected', canonical_phase: 'detected', title: 'Secure configuration evidence', severity: 'medium',
  reopened_count: 0, created_at: '2026-10-01T10:00:00Z', updated_at: '2026-10-02T10:00:00Z',
}
const withNote = { ...ceCase, assessment: { state: 'not_assessed', reason: 'workspace_multi_domain_not_aggregatable', since: '2026-10-22 11:16:52', message: NOTE } }

function renderCase() {
  return render(
    <MemoryRouter initialEntries={['/ws/cases/c1']}>
      <Routes><Route path="/ws/cases/:caseId" element={<WorkspaceCaseDetailPage />} /></Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  api.getCase.mockReset(); api.getWorkspaceMembers.mockReset()
  api.getWorkspaceMembers.mockResolvedValue({ members: [] })
})

describe('CE case assessment note', () => {
  it('helpers: chip reads not_assessed and the message is the backend sentence; status and lanes keep caseStatus', () => {
    expect(caseChipStatus(withNote)).toBe('not_assessed')
    expect(caseAssessmentMessage(withNote)).toBe(NOTE)
    expect(caseStatus(withNote)).toBe('action_required')
    expect(caseChipStatus(ceCase)).toBe('action_required')
    expect(caseAssessmentMessage(ceCase)).toBeNull()
    expect(caseAssessmentMessage({ ...ceCase, assessment: { state: 'assessed', message: 'x' } })).toBeNull()
  })
  it('the case page shows the note and "Not assessed", never "Action required"', async () => {
    api.getCase.mockResolvedValue({ case: withNote, events: [], can_manage: true, available_transitions: [] })
    renderCase()
    expect(await screen.findByTestId('case-assessment')).toHaveTextContent(NOTE)
    expect(screen.getByText('Not assessed')).toBeInTheDocument()
    expect(screen.queryByText('Action required')).toBeNull()
  })
  it('without assessment the page is unchanged (Action required, no note)', async () => {
    api.getCase.mockResolvedValue({ case: ceCase, events: [], can_manage: true, available_transitions: [] })
    renderCase()
    expect(await screen.findByText('Action required')).toBeInTheDocument()
    expect(screen.queryByTestId('case-assessment')).toBeNull()
  })
})
