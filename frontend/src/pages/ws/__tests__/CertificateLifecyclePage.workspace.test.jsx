// ── Certificate lifecycle — workspace comes from context, never a route param ─
// Latent fourth case of the same defect: read `useParams().workspaceId` on a
// paramless /ws/* route → undefined → /api/workspaces/undefined/... → 403.
// Now uses useWorkspace().
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { beforeEach, describe, it, expect, vi } from 'vitest'
import CertificateLifecyclePage from '../CertificateLifecyclePage'
import { api } from '../../../api'
import { useWorkspace } from '../../../hooks/useWorkspace'

vi.mock('../../../api', () => ({
  api: { getCertificateLifecycle: vi.fn(), certificateLifecycleVerify: vi.fn(), certificateLifecycleAction: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: vi.fn() }))

const WS_ID = 'ws_real_cert_1'

function mount() {
  return render(
    <MemoryRouter initialEntries={['/ws/certificate-lifecycle']}>
      <Routes><Route path="/ws/certificate-lifecycle" element={<CertificateLifecyclePage />} /></Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => { vi.clearAllMocks() })

describe('CertificateLifecyclePage — workspace resolution', () => {
  it('calls the API with the context wsId (never undefined) on a paramless route', async () => {
    useWorkspace.mockReturnValue({ wsId: WS_ID, loading: false })
    api.getCertificateLifecycle.mockResolvedValue({ items: [], counts: {}, actions: [] })
    mount()
    await waitFor(() => expect(api.getCertificateLifecycle).toHaveBeenCalled())
    expect(api.getCertificateLifecycle).toHaveBeenCalledWith(WS_ID, {})
    for (const call of api.getCertificateLifecycle.mock.calls) expect(call[0]).toBe(WS_ID)
  })

  it('renders an empty state (not an error) for an empty 200 response', async () => {
    useWorkspace.mockReturnValue({ wsId: WS_ID, loading: false })
    api.getCertificateLifecycle.mockResolvedValue({ items: [], counts: {}, actions: [] })
    mount()
    expect(await screen.findByText(/No certificates under management yet/i)).toBeInTheDocument()
  })

  it('renders the generic failure state on a backend 403', async () => {
    useWorkspace.mockReturnValue({ wsId: WS_ID, loading: false })
    api.getCertificateLifecycle.mockRejectedValue({ status: 403 })
    mount()
    expect(await screen.findByText(/Could not load the certificate lifecycle/i)).toBeInTheDocument()
  })

  it('does NOT call the API while the workspace is unresolved (null wsId, loading)', async () => {
    useWorkspace.mockReturnValue({ wsId: null, loading: true })
    api.getCertificateLifecycle.mockResolvedValue({ items: [], counts: {}, actions: [] })
    mount()
    await Promise.resolve()
    expect(api.getCertificateLifecycle).not.toHaveBeenCalled()
  })

  it('shows "No workspace selected" (no API call) when resolution finishes with no workspace', async () => {
    useWorkspace.mockReturnValue({ wsId: null, loading: false })
    mount()
    expect(await screen.findByText(/No workspace selected/i)).toBeInTheDocument()
    expect(api.getCertificateLifecycle).not.toHaveBeenCalled()
  })
})
