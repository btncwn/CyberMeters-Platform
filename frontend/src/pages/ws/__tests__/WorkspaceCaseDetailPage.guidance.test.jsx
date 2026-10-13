import { render, screen } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from '../../../api'
import WorkspaceCaseDetailPage from '../WorkspaceCaseDetailPage'

vi.mock('../../../api', () => ({ api: { getCase: vi.fn(), getWorkspaceMembers: vi.fn() } }))
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

const exposureCase = {
  case_id: 'c1', workspace_id: 'ws1', domain_key: 'attack_surface', case_type: 'asm_exposure',
  status: 'verification_requested', canonical_phase: 'awaiting_verification', verification_support: 'automated',
  title: 'Sensitive Management Tool Exposed', severity: 'high',
  source_finding_type: 'asset_exposure_sensitive_tool', asset_ref: 'admin.example.com', domain: 'example.com',
  remediation_id: 'asm.exposure.sensitive_tool', reopened_count: 0,
  created_at: '2026-10-01T09:00:00Z', updated_at: '2026-10-04T12:00:00Z',
}

beforeEach(() => {
  api.getCase.mockReset()
  api.getWorkspaceMembers.mockReset()
  api.getWorkspaceMembers.mockResolvedValue({ members: [] })
})

describe('WorkspaceCaseDetailPage — what to do and how the fix is checked', () => {
  it('shows the backend guidance: the action, the re-check rule and why the last re-check did not close the case', async () => {
    api.getCase.mockResolvedValue({
      case: {
        ...exposureCase,
        guidance: {
          version: 'case-guidance-v1',
          remediation: {
            title: 'Restrict exposed management tools',
            explanation: 'Sensitive management tools were reachable directly from the public internet.',
            business_impact: 'Exposed management tooling can leak configuration or provide a foothold for attackers.',
            recommended_action: 'Firewall or VPN-protect the affected interfaces and allow only trusted IP ranges.',
            effort: 'medium', owner_label: 'Your IT, DNS or hosting administrator',
          },
          recheck: {
            method: 'rescan',
            label: 'The next complete scan re-checks the affected host itself.',
            fixed_when: 'The tool is no longer publicly reachable on a fresh scan.',
            rule: "A timeout, a refused or blocked connection, or a filter's 401, 403 or 429 never closes the case.",
          },
          last_recheck: {
            outcome: 'waiting', label: 'Not confirmed yet', at: '2026-10-04T12:00:00.000Z',
            reason: 'The affected host refused or dropped the connection. A blocked connection is not proof the problem is gone.',
            hosts: [{ hostname: 'admin.example.com', outcome: 'no_answer', label: 'admin.example.com refused or dropped the connection.' }],
          },
          closure: null,
        },
      },
      events: [],
    })
    renderCase()
    const todo = await screen.findByRole('region', { name: 'What to do' })
    expect(todo).toHaveTextContent('Firewall or VPN-protect the affected interfaces')
    const check = screen.getByRole('region', { name: 'How the fix is checked' })
    expect(check).toHaveTextContent('Not confirmed yet')
    expect(check).toHaveTextContent('A blocked connection is not proof the problem is gone.')
    expect(check).toHaveTextContent('admin.example.com refused or dropped the connection.')
    expect(screen.queryByText('Verified by CyberMeters')).toBeNull()
  })

  it('renders as before when the backend sends no guidance', async () => {
    api.getCase.mockResolvedValue({ case: exposureCase, events: [] })
    renderCase()
    expect(await screen.findByText('Sensitive Management Tool Exposed')).toBeInTheDocument()
    expect(screen.queryByRole('region', { name: 'What to do' })).toBeNull()
    expect(screen.queryByRole('region', { name: 'How the fix is checked' })).toBeNull()
  })
})
