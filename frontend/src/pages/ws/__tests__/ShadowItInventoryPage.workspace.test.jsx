// ── Shadow IT inventory — workspace comes from context, never a route param ───
// Regression: read `useParams().workspaceId` on a paramless /ws/* route →
// undefined → /api/workspaces/undefined/... → 403. Now uses useWorkspace().
// The page body lives on the Findings tab of the area contract (16 Oct 2026); these tests open it there.
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { beforeEach, describe, it, expect, vi } from 'vitest'
import ShadowItInventoryPage from '../ShadowItInventoryPage'
import { api } from '../../../api'
import { useWorkspace } from '../../../hooks/useWorkspace'

vi.mock('../../../api', () => ({
  api: { getShadowItInventory: vi.fn(), getShadowItItem: vi.fn(), shadowItAction: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: vi.fn() }))

const WS_ID = 'ws_real_shadowit_1'

function mount() {
  return render(
    <MemoryRouter initialEntries={['/ws/shadow-it?tab=findings']}>
      <Routes><Route path="/ws/shadow-it" element={<ShadowItInventoryPage />} /></Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => { vi.clearAllMocks() })

describe('ShadowItInventoryPage — workspace resolution', () => {
  it('shows only server-provided source evidence and loads item history', async () => {
    useWorkspace.mockReturnValue({ wsId: WS_ID, loading: false })
    api.getShadowItInventory.mockResolvedValue({ items: [{
      inventory_item_id: 'item_1', display_name: 'Mail provider',
      source_type: 'email_sender,cloud_asset', observed_identifiers: ['mx.example.test'], evidence_age_days: 5,
      classification: 'unreviewed', ownership_status: 'missing', monitoring_status: 'observed',
    }], counts: {}, actions: [] })
    api.getShadowItItem.mockResolvedValue({ events: [{ id: 'event_1', event_type: 'material_change', created_at: '2026-10-16' }], linked_case: { id: 'case_1', status: 'open' } })
    mount()
    expect(await screen.findByText('Mail provider')).toBeInTheDocument()
    expect(screen.getByText('Observed via DMARC report')).toBeInTheDocument()
    expect(screen.getByText('Observed via Cloud asset')).toBeInTheDocument()
    expect(screen.getByText('Observed identifiers: mx.example.test')).toBeInTheDocument()
    expect(screen.getByText('Evidence age: 5 days')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'History' }))
    expect(api.getShadowItItem).toHaveBeenCalledWith(WS_ID, 'item_1')
    expect(await screen.findByText('material change')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'case_1' })).toHaveAttribute('href', '/ws/cases/case_1')
  })

  it('shows a failed detail read as an error', async () => {
    useWorkspace.mockReturnValue({ wsId: WS_ID, loading: false })
    api.getShadowItInventory.mockResolvedValue({ items: [{ inventory_item_id: 'item_1', display_name: 'Mail provider', classification: 'unreviewed' }], counts: {}, actions: [] })
    api.getShadowItItem.mockRejectedValue({ status: 403 })
    mount()
    fireEvent.click(await screen.findByRole('button', { name: 'History' }))
    expect(await screen.findByRole('alert')).toHaveTextContent("Could not load this item's history")
  })
  it('calls the API with the context wsId (never undefined) on a paramless route', async () => {
    useWorkspace.mockReturnValue({ wsId: WS_ID, loading: false })
    api.getShadowItInventory.mockResolvedValue({ items: [], counts: {}, actions: [] })
    mount()
    await waitFor(() => expect(api.getShadowItInventory).toHaveBeenCalled())
    // The unfiltered load asks for the backend's maximum page (the Summary lists read it).
    expect(api.getShadowItInventory).toHaveBeenCalledWith(WS_ID, { limit: 500 })
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
