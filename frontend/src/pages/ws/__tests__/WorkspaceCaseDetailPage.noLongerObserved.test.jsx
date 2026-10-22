import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../../api'
import WorkspaceCaseDetailPage, { noLongerObservedText } from '../WorkspaceCaseDetailPage'

// Executive 16:20 (product decision, no auto-close): when CyberMeters no longer
// observes the condition but the case has not been moved on, the page says so
// and the one primary action stays the next transition.

vi.mock('../../../api', () => ({ api: { getCase: vi.fn(), transitionCase: vi.fn(), transitionManagedCase: vi.fn(), getWorkspaceMembers: vi.fn() } }))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: () => ({ wsId: 'ws1', wsName: 'WS', workspaces: [{ id: 'ws1', role: 'admin' }], loading: false }) }))

const base = {
  case_id: 'mc-1', workspace_id: 'ws1', domain_key: 'website_security', case_type: 'website_case', status: 'detected', canonical_phase: 'detected',
  verification_support: 'automated', title: 'Send the HSTS header', summary: 'HSTS was not sent.', severity: 'medium', reopened_count: 0,
  created_at: '2026-10-21T10:00:00Z', updated_at: '2026-10-22T10:00:00Z',
}
beforeEach(() => { vi.clearAllMocks(); api.getWorkspaceMembers.mockResolvedValue({ members: [] }) })

describe('noLongerObservedText', () => {
  it('says so with the last check date, for a case not yet ready to verify', () => {
    expect(noLongerObservedText({ ...base, condition_state: 'no_longer_observed', last_observed_absent_at: '2026-10-22T11:16:00Z' }))
      .toBe('CyberMeters no longer observes this issue (last check 22 Oct 2026). Mark the case ready to verify and the next scan will confirm it.')
  })
  it('without a date it still says so, without inventing one', () => {
    expect(noLongerObservedText({ ...base, canonical_phase: 'triaged', condition_state: 'no_longer_observed' }))
      .toBe('CyberMeters no longer observes this issue. Mark the case ready to verify and the next scan will confirm it.')
  })
  it('nothing until the API carries the field; nothing for another state or a case already ready or closed', () => {
    expect(noLongerObservedText(base)).toBeNull()
    expect(noLongerObservedText({ ...base, condition_state: 'observed' })).toBeNull()
    expect(noLongerObservedText({ ...base, condition_state: 'no_longer_observed', canonical_phase: 'awaiting_verification' })).toBeNull()
    expect(noLongerObservedText({ ...base, condition_state: 'no_longer_observed', canonical_phase: 'verified' })).toBeNull()
  })
})

describe('the case page', () => {
  it('shows the sentence above the guidance; the next transition stays the one primary action', async () => {
    api.getCase.mockResolvedValue({ case: { ...base, condition_state: 'no_longer_observed', last_observed_absent_at: '2026-10-22T11:16:00Z' }, events: [], can_manage: true,
      available_transitions: [{ target_status: 'triaged', label: 'Begin triage' }] })
    render(<MemoryRouter initialEntries={['/ws/cases/mc-1']}><Routes><Route path="/ws/cases/:caseId" element={<WorkspaceCaseDetailPage />} /></Routes></MemoryRouter>)
    expect(await screen.findByTestId('case-no-longer-observed')).toHaveTextContent('CyberMeters no longer observes this issue (last check 22 Oct 2026).')
    expect(document.querySelectorAll('[data-primary="true"]')).toHaveLength(1)
  })
})
