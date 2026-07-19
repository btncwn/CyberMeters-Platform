// ── Identity Exposure — workspace comes from context, never a route param ─────
// Regression: the page read `useParams().workspaceId`, but the /ws/* routes
// declare no :workspaceId — so it was always undefined and the page called
// /api/workspaces/undefined/... → 403. It now resolves the workspace from
// useWorkspace(). These tests render on the REAL paramless route and prove the
// API gets the context wsId, never undefined, and is not called before the
// workspace resolves.
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { beforeEach, describe, it, expect, vi } from 'vitest'
import IdentityExposurePage from '../IdentityExposurePage'
import { api } from '../../../api'
import { useWorkspace } from '../../../hooks/useWorkspace'

vi.mock('../../../api', () => ({
  api: { getIdentitySurfaces: vi.fn(), identitySurfaceVerify: vi.fn(), identitySurfaceAction: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: vi.fn() }))

const WS_ID = 'ws_real_identity_1'

// Rendered on the paramless production route — there is no :workspaceId to read.
function mount() {
  return render(
    <MemoryRouter initialEntries={['/ws/identity-exposure']}>
      <Routes><Route path="/ws/identity-exposure" element={<IdentityExposurePage />} /></Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => { vi.clearAllMocks() })

describe('IdentityExposurePage — workspace resolution', () => {
  it('calls the API with the context wsId (never undefined) on a paramless route', async () => {
    useWorkspace.mockReturnValue({ wsId: WS_ID, loading: false })
    api.getIdentitySurfaces.mockResolvedValue({ items: [], counts: {}, actions: [] })
    mount()
    await waitFor(() => expect(api.getIdentitySurfaces).toHaveBeenCalled())
    expect(api.getIdentitySurfaces).toHaveBeenCalledWith(WS_ID, {})
    for (const call of api.getIdentitySurfaces.mock.calls) expect(call[0]).toBe(WS_ID)
  })

  it('renders an empty state (not an error) for an empty 200 response', async () => {
    useWorkspace.mockReturnValue({ wsId: WS_ID, loading: false })
    api.getIdentitySurfaces.mockResolvedValue({ items: [], counts: {}, actions: [] })
    mount()
    expect(await screen.findByText(/No managed identity surfaces yet/i)).toBeInTheDocument()
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
