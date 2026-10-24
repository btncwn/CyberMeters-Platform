// Codex C-46 rank 1, flipped: a case waiting for CyberMeters' automated verification
// shows one visible next step — run the next scan of its domain.
import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { afterEach, expect, it, vi } from 'vitest'
import WorkspaceCaseDetailPage from '../WorkspaceCaseDetailPage'
import { api } from '../../../api'
vi.mock('../../../api', () => ({ api: { getCase: vi.fn(), getWorkspaceMembers: vi.fn() } }))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: () => ({ wsId: 'ws1', wsName: 'Workspace A', workspaces: [], loading: false }) }))
afterEach(cleanup)
const mount = () => render(<MemoryRouter initialEntries={['/ws/cases/mc1']}><Routes><Route path="/ws/cases/:caseId" element={<WorkspaceCaseDetailPage/>}/></Routes></MemoryRouter>)
const waiting = (over) => ({ can_manage: true, case: {
  case_id: 'mc1', case_type: 'website_case', domain_key: 'website_security', domain: 'example.org',
  display_title: 'Add or strengthen HSTS', status: 'awaiting_verification', canonical_phase: 'awaiting_verification',
  verification_support: 'automated', ...over,
}, events: [], available_transitions: [{ target_status: 'action_in_progress', label: 'Start remediation', requires_owner: false }] })

it('rank 1: an automated awaiting-verification case offers "Run the next scan" for its domain', async () => {
  api.getWorkspaceMembers.mockResolvedValue({ members: [] })
  api.getCase.mockResolvedValue(waiting())
  mount()
  expect(await screen.findByText(/CyberMeters verifies this on the next complete scan/)).toBeInTheDocument()
  const next = screen.getByRole('link', { name: 'Run the next scan' })
  expect(next).toHaveAttribute('href', '/scans/new?domain=example.org')
  expect(next).toHaveClass('btn-primary')
  expect(screen.getByRole('button', { name: 'Not fixed yet — reopen work' })).not.toHaveAttribute('data-primary', 'true')
})

it('a manual (attested) case does not offer a scan as its next step', async () => {
  api.getWorkspaceMembers.mockResolvedValue({ members: [] })
  api.getCase.mockResolvedValue(waiting({ verification_support: 'manual' }))
  mount()
  await screen.findByRole('heading', { name: 'Add or strengthen HSTS' })
  expect(screen.queryByRole('link', { name: 'Run the next scan' })).toBeNull()
})
