import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import WorkspaceCaseDetailPage from '../WorkspaceCaseDetailPage'
import { api } from '../../../api'
import { resolutionEventWords } from '../../../lib/caseEventWords'
import { formatLocalDateTime } from '../../../utils/dates'

// KALAN 10c (founder live proof 23 Oct): History said "Resolution observed —
// moved to detected" (a contradiction) and showed times in a different
// convention from the scan pages.
vi.mock('../../../api', () => ({ api: { getCase: vi.fn(), getWorkspaceMembers: vi.fn() } }))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: () => ({ wsId: 'ws1', wsName: 'Example Ltd', workspaces: [], loading: false }) }))
afterEach(cleanup)

describe('resolution event words', () => {
  it('resolution_observed says the condition is gone and the case stays open until submitted', () => {
    expect(resolutionEventWords({ action: 'resolution_observed', to_status: 'detected' }))
      .toBe('CyberMeters no longer observes this condition. The case stays open until you submit it for verification.')
  })
  it('resolution_observed_not_verifying says why it is not a fix, from the recorded reason', () => {
    expect(resolutionEventWords({ action: 'resolution_observed_not_verifying', detail_json: JSON.stringify({ reason: 'detecting_module_not_proven_complete' }) }))
      .toMatch(/check that detects it did not complete, so this does not count as a fix\.$/)
    expect(resolutionEventWords({ action: 'resolution_observed_not_verifying', detail_json: JSON.stringify({ reason: 'registry_method_is_not_externally_observable' }) }))
      .toMatch(/cannot verify this fix from outside\.$/)
    expect(resolutionEventWords({ action: 'resolution_observed_not_verifying', detail_json: 'not json' }))
      .toBe('CyberMeters did not see the condition, but this does not verify the fix.')
  })
  it('other events are untouched', () => {
    expect(resolutionEventWords({ action: 'case_created' })).toBeNull()
  })
})

it('the case page History uses the words and the app-wide local time rule', async () => {
  api.getWorkspaceMembers.mockResolvedValue({ members: [] })
  const at = '2026-10-23 23:24:00'
  api.getCase.mockResolvedValue({ can_manage: true, case: {
    case_id: 'mc1', case_type: 'website_case', domain_key: 'website_security', domain: 'example.org',
    display_title: 'Add or strengthen HSTS', status: 'detected', canonical_phase: 'detected', verification_support: 'automated',
  }, events: [{ id: 'e1', action: 'resolution_observed', actor_type: 'system', from_status: 'detected', to_status: 'detected', detail_json: '{"reason":"case_not_awaiting_verification"}', created_at: at }],
  available_transitions: [] })
  render(<MemoryRouter initialEntries={['/ws/cases/mc1']}><Routes><Route path="/ws/cases/:caseId" element={<WorkspaceCaseDetailPage />} /></Routes></MemoryRouter>)
  expect(await screen.findByText('CyberMeters no longer observes this condition. The case stays open until you submit it for verification.')).toBeInTheDocument()
  expect(document.body.textContent).not.toMatch(/Resolution observed — moved to/)
  expect(document.body.textContent).toContain(formatLocalDateTime(at))
})
