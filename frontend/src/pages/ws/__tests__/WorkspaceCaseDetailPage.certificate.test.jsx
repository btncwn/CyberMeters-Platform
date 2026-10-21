import { render, screen, within } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from '../../../api'
import WorkspaceCaseDetailPage from '../WorkspaceCaseDetailPage'

// Founder, 20 Oct 2026 (case mc-67d95f496ac6): the title froze "(owner
// missing)", Affected resource and Source scan were empty, and history showed a
// raw user id. Every value below comes from the case API.

vi.mock('../../../api', () => ({ api: { getCase: vi.fn(), getWorkspaceMembers: vi.fn() } }))
vi.mock('../../../hooks/useWorkspace', () => ({
  useWorkspace: () => ({ wsId: 'ws1', wsName: 'WS', workspaces: [{ id: 'ws1', role: 'admin' }], loading: false }),
}))

const certCase = {
  case_id: 'mc-67d95f496ac6', workspace_id: 'ws1', domain_key: 'certificates_trust', case_type: 'certificate_case',
  status: 'awaiting_verification', canonical_phase: 'awaiting_verification', verification_support: 'automated',
  title: 'Certificate follow-up: shop.example.com (owner missing)',
  display_title: 'Certificate follow-up: shop.example.com — expiring soon', reason_label: 'expiring soon',
  resource: 'shop.example.com', source_scan_id: 'scan_123', owner_ref: 'Turhan Acar',
  source_finding_type: 'certificate_expiring_soon', severity: 'medium', reopened_count: 0,
  created_at: '2026-10-19T09:00:00Z', updated_at: '2026-10-20T12:00:00Z',
}
const events = [
  { id: 'e1', actor_type: 'system', actor_id: null, actor_name: null, action: 'case_created', created_at: '2026-10-19T09:00:00Z' },
  { id: 'e2', actor_type: 'customer', actor_id: 'usr_abc123', actor_name: 'Turhan Acar', action: 'assignment_changed', created_at: '2026-10-19T10:00:00Z' },
  { id: 'e3', actor_type: 'customer', actor_id: 'usr_gone99', actor_name: 'A former workspace member', from_status: 'assigned', to_status: 'approved', action: 'transition_approved', created_at: '2026-10-19T11:00:00Z' },
]

function renderCase() {
  return render(
    <MemoryRouter initialEntries={['/ws/cases/mc-67d95f496ac6']}>
      <Routes><Route path="/ws/cases/:caseId" element={<WorkspaceCaseDetailPage />} /></Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  api.getCase.mockReset()
  api.getWorkspaceMembers.mockReset()
  api.getWorkspaceMembers.mockResolvedValue({ members: [] })
})

describe('certificate case detail', () => {
  it('shows the backend title, the certificate host and a link to the source scan', async () => {
    api.getCase.mockResolvedValue({ case: certCase, events, can_manage: false, available_transitions: [] })
    renderCase()
    expect(await screen.findByRole('heading', { level: 1, name: 'Certificate follow-up: shop.example.com — expiring soon' })).toBeInTheDocument()
    expect(screen.queryByText(/owner missing/i)).toBeNull()
    expect(screen.getByText(/^Affected:/)).toHaveTextContent('Affected: shop.example.com')
    expect(screen.getByRole('link', { name: 'Open the scan that observed this' })).toHaveAttribute('href', '/scans/scan_123')
  })

  it('history names people, never a raw user id', async () => {
    api.getCase.mockResolvedValue({ case: certCase, events, can_manage: false, available_transitions: [] })
    renderCase()
    await screen.findByRole('heading', { name: 'History' })
    const history = within(screen.getByTestId('case-history'))
    expect(history.getByText(/Turhan Acar/)).toBeInTheDocument()
    expect(history.getByText(/A former workspace member/)).toBeInTheDocument()
    expect(history.getByText(/CyberMeters/)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/usr_/)
  })

  it('a field the backend does not have reads "Not recorded", never blank', async () => {
    api.getCase.mockResolvedValue({ case: { ...certCase, resource: null, asset_ref: null, domain: null, source_scan_id: null }, events: [], can_manage: false, available_transitions: [] })
    renderCase()
    await screen.findByRole('heading', { level: 1 })
    expect(screen.getByText(/^Affected:/)).toHaveTextContent('Affected: not recorded')
    expect(screen.getByText('The observing scan was not recorded.')).toBeInTheDocument()
  })
})
