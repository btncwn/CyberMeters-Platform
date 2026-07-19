// ── Shadow IT inventory — workspace comes from context, never a route param ───
// Regression: read `useParams().workspaceId` on a paramless /ws/* route →
// undefined → /api/workspaces/undefined/... → 403. Now uses useWorkspace().
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { beforeEach, describe, it, expect, vi } from 'vitest'
import ShadowItInventoryPage from '../ShadowItInventoryPage'
import { api } from '../../../api'
import { useWorkspace } from '../../../hooks/useWorkspace'

vi.mock('../../../api', () => ({
  api: { getShadowItInventory: vi.fn(), shadowItAction: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: vi.fn() }))

const WS_ID = 'ws_real_shadowit_1'

function mount() {
  return render(
    <MemoryRouter initialEntries={['/ws/shadow-it']}>
      <Routes><Route path="/ws/shadow-it" element={<ShadowItInventoryPage />} /></Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => { vi.clearAllMocks() })

describe('ShadowItInventoryPage — workspace resolution', () => {
  it('calls the API with the context wsId (never undefined) on a paramless route', async () => {
    useWorkspace.mockReturnValue({ wsId: WS_ID, loading: false })
    api.getShadowItInventory.mockResolvedValue({ items: [], counts: {}, actions: [] })
    mount()
    await waitFor(() => expect(api.getShadowItInventory).toHaveBeenCalled())
    expect(api.getShadowItInventory).toHaveBeenCalledWith(WS_ID, {})
    for (const call of api.getShadowItInventory.mock.calls) expect(call[0]).toBe(WS_ID)
  })

  it('renders an empty state (not an error) for an empty 200 response', async () => {
    useWorkspace.mockReturnValue({ wsId: WS_ID, loading: false })
    api.getShadowItInventory.mockResolvedValue({ items: [], counts: {}, actions: [] })
    mount()
    expect(await screen.findByText(/No externally observed technology recorded yet/i)).toBeInTheDocument()
  })

  it('renders the generic failure state on a backend 403', async () => {
    useWorkspace.mockReturnValue({ wsId: WS_ID, loading: false })
    api.getShadowItInventory.mockRejectedValue({ status: 403 })
    mount()
    expect(await screen.findByText(/Could not load the technology inventory/i)).toBeInTheDocument()
  })

  it('does NOT call the API while the workspace is unresolved (null wsId, loading)', async () => {
    useWorkspace.mockReturnValue({ wsId: null, loading: true })
    api.getShadowItInventory.mockResolvedValue({ items: [], counts: {}, actions: [] })
    mount()
    await Promise.resolve()
    expect(api.getShadowItInventory).not.toHaveBeenCalled()
  })

  it('shows "No workspace selected" (no API call) when resolution finishes with no workspace', async () => {
    useWorkspace.mockReturnValue({ wsId: null, loading: false })
    mount()
    expect(await screen.findByText(/No workspace selected/i)).toBeInTheDocument()
    expect(api.getShadowItInventory).not.toHaveBeenCalled()
  })
})
