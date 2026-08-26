import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import AdminSurfacesPage from '../AdminSurfacesPage'
import { api } from '../../../api'
import { useWorkspace } from '../../../hooks/useWorkspace'

vi.mock('../../../api', () => ({
  api: { getWorkspaceAdminSurfaces: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: vi.fn() }))

const WS_ID = 'ws_admin_contract_1'

function mount() {
  return render(
    <MemoryRouter initialEntries={['/ws/admin-surfaces']}>
      <Routes>
        <Route path="/ws/admin-surfaces" element={<AdminSurfacesPage />} />
      </Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  useWorkspace.mockReturnValue({ wsId: WS_ID, wsName: 'Contract workspace' })
})

describe('AdminSurfacesPage — API contract and evidence honesty', () => {
  it('renders the canonical services payload and never infers authentication state', async () => {
    api.getWorkspaceAdminSurfaces.mockResolvedValue({
      workspace_id: WS_ID,
      evidence_status: 'issue_detected',
      services: [{
        url: 'https://admin.example.com',
        hostname: 'admin.example.com',
        product: 'Jenkins',
        category: 'admin_panel',
        severity: 'critical',
        confidence: 'confirmed',
        domain: 'example.com',
      }],
    })

    mount()

    expect(await screen.findByText('Jenkins')).toBeInTheDocument()
    expect(screen.getByText('admin panel')).toBeInTheDocument()
    expect(screen.getByText('example.com')).toBeInTheDocument()
    expect(screen.getByText('Confirmed')).toBeInTheDocument()
    expect(screen.queryByText('Unauthenticated')).not.toBeInTheDocument()
    expect(screen.queryByText('Open')).not.toBeInTheDocument()
    expect(api.getWorkspaceAdminSurfaces).toHaveBeenCalledWith(WS_ID)
  })

  it.each([
    ['not_assessed', 'Admin surfaces not assessed'],
    ['unavailable', 'Admin-surface evidence unavailable'],
    ['assessed_healthy', 'No admin surfaces observed'],
  ])('renders %s as its own evidence state', async (evidenceStatus, expectedCopy) => {
    api.getWorkspaceAdminSurfaces.mockResolvedValue({
      workspace_id: WS_ID,
      services: [],
      evidence_status: evidenceStatus,
    })

    mount()

    expect(await screen.findByText(expectedCopy)).toBeInTheDocument()
    if (evidenceStatus !== 'assessed_healthy') {
      expect(screen.queryByText('No admin surfaces observed')).not.toBeInTheDocument()
    }
  })

  it('fails closed to not assessed when an older response omits the evidence status', async () => {
    api.getWorkspaceAdminSurfaces.mockResolvedValue({ services: [] })

    mount()

    expect(await screen.findByText('Admin surfaces not assessed')).toBeInTheDocument()
    expect(screen.queryByText('No admin surfaces observed')).not.toBeInTheDocument()
  })

  it('does not call the API while no workspace is selected', async () => {
    useWorkspace.mockReturnValue({ wsId: null, wsName: null })

    mount()

    expect(await screen.findByText('No workspace selected')).toBeInTheDocument()
    await waitFor(() => expect(api.getWorkspaceAdminSurfaces).not.toHaveBeenCalled())
  })
})
