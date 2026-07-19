import { render, screen } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from '../../../api'
import WorkspaceCaseDetailPage from '../WorkspaceCaseDetailPage'

vi.mock('../../../api', () => ({ api: { getCase: vi.fn(), getWorkspaceMembers: vi.fn() } }))
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
  case_id: 'c1', workspace_id: 'ws1', domain_key: 'identity_exposure',
  case_type: 'identity_case', status: 'awaiting_verification', canonical_phase: 'awaiting_verification',
  title: 'Exposed admin login', summary: 'An admin login surface was observed.',
  severity: 'high', source_finding_type: 'identity_exposed_login', asset_ref: 'admin.example.com',
  remediation_id: 'identity.exposed_login.remove', reopened_count: 0,
  created_at: '2026-07-01T10:00:00Z', updated_at: '2026-07-02T10:00:00Z',
}

beforeEach(() => {
  api.getCase.mockReset()
  api.getWorkspaceMembers.mockReset()
  api.getWorkspaceMembers.mockResolvedValue({ members: [] })
})

describe('WorkspaceCaseDetailPage — verification honesty', () => {
  it('a MANUAL verified case reads as ATTESTED, never "Verified by CyberMeters"', async () => {
    api.getCase.mockResolvedValue({
      case: { ...baseCase, status: 'verified', canonical_phase: 'verified', verification_support: 'manual' },
      events: [],
    })
    renderCase()
    expect(await screen.findAllByText(/Attested by customer — not externally verifiable/i)).not.toHaveLength(0)
    expect(screen.queryByText('Verified by CyberMeters')).toBeNull()
  })

  it('an AUTOMATED verified case reads as "Verified by CyberMeters"', async () => {
    api.getCase.mockResolvedValue({
      case: { ...baseCase, domain_key: 'website_security', status: 'verified', canonical_phase: 'verified', verification_support: 'automated' },
      events: [],
    })
    renderCase()
    expect(await screen.findAllByText('Verified by CyberMeters')).not.toHaveLength(0)
    expect(screen.queryByText(/Attested by customer/i)).toBeNull()
  })

  it('renders evidence source, affected resource and canonical remediation', async () => {
    api.getCase.mockResolvedValue({ case: { ...baseCase, verification_support: 'manual' }, events: [] })
    renderCase()
    expect(await screen.findByText('identity_exposed_login')).toBeInTheDocument()
    expect(screen.getByText('admin.example.com')).toBeInTheDocument()
    expect(screen.getByText('identity.exposed_login.remove')).toBeInTheDocument()
  })

  it('does not use a green "settled" tone for an automated case that is not yet verified', async () => {
    api.getCase.mockResolvedValue({
      case: { ...baseCase, domain_key: 'website_security', status: 'action_in_progress', canonical_phase: 'action_in_progress', verification_support: 'automated' },
      events: [],
    })
    renderCase()
    const explainer = await screen.findByText(/CyberMeters re-observes this fix itself/i)
    // The informational panel must not read as "settled" (green) before the case is verified.
    expect(explainer.closest('div').className).not.toMatch(/bg-green/)
  })

  it('states completion is an assertion that never reaches a verified state', async () => {
    api.getCase.mockResolvedValue({ case: { ...baseCase, verification_support: 'manual' }, events: [] })
    renderCase()
    expect(await screen.findByText(/completion is an assertion/i)).toBeInTheDocument()
  })

  it('shows recurrence/reopen count and honest history', async () => {
    api.getCase.mockResolvedValue({
      case: { ...baseCase, verification_support: 'manual', reopened_count: 2 },
      events: [
        { id: 'e1', action: 'case_created', actor_type: 'system', to_status: 'detected', created_at: '2026-07-01T10:00:00Z' },
        { id: 'e2', action: 'assignment_changed', actor_type: 'customer', actor_id: 'u1', created_at: '2026-07-01T11:00:00Z' },
      ],
    })
    renderCase()
    expect(await screen.findByText(/reopened/i)).toBeInTheDocument()
    expect(screen.getByText('Case opened')).toBeInTheDocument()
    expect(screen.getByText('Owner assigned')).toBeInTheDocument()
  })

  it('links out to the domain-specific workflow (coexist, not replace)', async () => {
    api.getCase.mockResolvedValue({ case: { ...baseCase, verification_support: 'manual' }, events: [] })
    renderCase()
    const link = await screen.findByRole('link', { name: /Identity Exposure workflow/i })
    expect(link).toHaveAttribute('href', '/ws/identity-exposure')
  })
})
