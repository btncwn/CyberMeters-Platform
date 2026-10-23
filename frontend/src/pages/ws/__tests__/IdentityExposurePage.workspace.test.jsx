// ── Identity Exposure — workspace comes from context, never a route param ─────
// Regression: the page read `useParams().workspaceId`, but the /ws/* routes
// declare no :workspaceId — so it was always undefined and the page called
// /api/workspaces/undefined/... → 403. It now resolves the workspace from
// useWorkspace(). These tests render on the REAL paramless route and prove the
// API gets the context wsId, never undefined, and is not called before the
// workspace resolves.
// The page body lives on the Findings tab of the area contract (16 Oct 2026); these tests open it there.
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { beforeEach, describe, it, expect, vi } from 'vitest'
import IdentityExposurePage from '../IdentityExposurePage'
import { api } from '../../../api'
import { useWorkspace } from '../../../hooks/useWorkspace'

vi.mock('../../../api', () => ({
  api: { getIdentitySurfaces: vi.fn(), getIdentitySurface: vi.fn(), identitySurfaceVerify: vi.fn(), identitySurfaceAction: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: vi.fn() }))

const WS_ID = 'ws_real_identity_1'

// Rendered on the paramless production route — there is no :workspaceId to read.
function mount() {
  return render(
    <MemoryRouter initialEntries={['/ws/identity-exposure?tab=findings']}>
      <Routes><Route path="/ws/identity-exposure" element={<IdentityExposurePage />} /></Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('IdentityExposurePage — workspace resolution', () => {
  it('shows server observation fields and loads event history with the linked case', async () => {
    useWorkspace.mockReturnValue({ wsId: WS_ID, loading: false })
    api.getIdentitySurfaces.mockResolvedValue({ items: [{
      identity_exposure_id: 'surface_1', primary_hostname: 'login.example.test',
      first_seen_at: '2026-10-01', last_seen_at: '2026-10-16',
      measured_endpoints: ['https://login.example.test/'],
      monitoring_status: 'reappeared', monitoring_reason: 'retired_surface_reappeared',
      allowed_actions: [],
    }], counts: {} })
    api.getIdentitySurface.mockResolvedValue({
      events: [{ id: 'event_1', event_type: 'monitoring_changed', actor_type: 'system', created_at: '2026-10-16' }],
      linked_case: { id: 'case_1', status: 'open' },
    })
    mount()
    expect(await screen.findByText('First seen: 2026-10-01')).toBeInTheDocument()
    expect(screen.getByText('Last seen: 2026-10-16')).toBeInTheDocument()
    expect(screen.getByText('Measured: https://login.example.test/')).toBeInTheDocument()
    expect(screen.getByText('Monitoring: reappeared')).toBeInTheDocument()
    expect(screen.getByText('Reason: retired_surface_reappeared')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'History' }))
    expect(api.getIdentitySurface).toHaveBeenCalledWith(WS_ID, 'surface_1')
    expect(await screen.findByText(/monitoring changed/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'case_1' })).toHaveAttribute('href', '/ws/cases/case_1')
  })

  it('keeps a failed detail read visible as an error', async () => {
    useWorkspace.mockReturnValue({ wsId: WS_ID, loading: false })
    api.getIdentitySurfaces.mockResolvedValue({ items: [{ identity_exposure_id: 'surface_1', allowed_actions: [] }], counts: {} })
    api.getIdentitySurface.mockRejectedValue({ status: 403 })
    mount()
    fireEvent.click(await screen.findByRole('button', { name: 'History' }))
    expect(await screen.findByRole('alert')).toHaveTextContent("Could not load this surface's history")
  })
  it('calls the API with the context wsId (never undefined) on a paramless route', async () => {
    useWorkspace.mockReturnValue({ wsId: WS_ID, loading: false })
    api.getIdentitySurfaces.mockResolvedValue({ items: [], counts: {}, actions: [] })
    mount()
    await waitFor(() => expect(api.getIdentitySurfaces).toHaveBeenCalled())
    // The unfiltered load asks for the backend's maximum page (the summary counts read it).
    expect(api.getIdentitySurfaces).toHaveBeenCalledWith(WS_ID, { limit: 500 })
    for (const call of api.getIdentitySurfaces.mock.calls) expect(call[0]).toBe(WS_ID)
    expect(screen.getByRole('heading', { name: 'Login-surface review' })).toBeInTheDocument()
    expect(screen.queryByText(/known.address breach|saved address.check|LeakCheck/i)).not.toBeInTheDocument()
  })

  it('renders an empty state (not an error) for an empty 200 response', async () => {
    useWorkspace.mockReturnValue({ wsId: WS_ID, loading: false })
    api.getIdentitySurfaces.mockResolvedValue({ items: [], counts: {}, actions: [] })
    mount()
    expect(await screen.findByText(/No managed identity evidence yet/i)).toBeInTheDocument()
  })

  it('renders the generic failure state on a backend 403', async () => {
    useWorkspace.mockReturnValue({ wsId: WS_ID, loading: false })
    api.getIdentitySurfaces.mockRejectedValue({ status: 403 })
    mount()
    expect(await screen.findByText(/Could not load managed identity surfaces/i)).toBeInTheDocument()
  })

  it('does NOT call the API while the workspace is unresolved (null wsId, loading)', async () => {
    useWorkspace.mockReturnValue({ wsId: null, loading: true })
    api.getIdentitySurfaces.mockResolvedValue({ items: [], counts: {}, actions: [] })
    mount()
    await Promise.resolve()
    expect(api.getIdentitySurfaces).not.toHaveBeenCalled()
  })

  it('shows "No workspace selected" (no API call) when resolution finishes with no workspace', async () => {
    useWorkspace.mockReturnValue({ wsId: null, loading: false })
    mount()
    expect(await screen.findByText(/No workspace selected/i)).toBeInTheDocument()
    expect(api.getIdentitySurfaces).not.toHaveBeenCalled()
  })
})
