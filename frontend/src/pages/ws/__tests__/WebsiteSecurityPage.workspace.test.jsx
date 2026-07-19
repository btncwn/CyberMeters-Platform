// ── Website Security — workspace from context; alert deep-link preserved ──────
// Regression: read `useParams().workspaceId` on a paramless /ws/* route →
// undefined → /api/workspaces/undefined/... → 403. Now uses useWorkspace().
// This page ALSO keeps useSearchParams for the ?condition=<id> alert deep link,
// so these tests prove both: the list + condition-detail APIs get the context
// wsId, and the deep-link still expands and loads that condition.
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { beforeEach, describe, it, expect, vi } from 'vitest'
import WebsiteSecurityPage from '../WebsiteSecurityPage'
import { api } from '../../../api'
import { useWorkspace } from '../../../hooks/useWorkspace'

vi.mock('../../../api', () => ({
  api: { getWebsiteSecurityConditions: vi.fn(), getWebsiteSecurityCondition: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: vi.fn() }))

const WS_ID = 'ws_real_websec_1'

const ITEM = {
  id: 'cond_1', condition_key: 'mixed_content', monitoring_status: 'observed',
  severity: 'medium', last_scan_quality: 'complete', domain: 'example.com',
  first_seen_at: '2026-07-01T00:00:00Z',
}

function mount(entry = '/ws/website-security') {
  return render(
    <MemoryRouter initialEntries={[entry]}>
      <Routes><Route path="/ws/website-security" element={<WebsiteSecurityPage />} /></Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  // jsdom does not implement scrollIntoView; the deep-link effect calls it.
  if (!Element.prototype.scrollIntoView) Element.prototype.scrollIntoView = () => {}
})

describe('WebsiteSecurityPage — workspace resolution', () => {
  it('calls the conditions API with the context wsId (never undefined) on a paramless route', async () => {
    useWorkspace.mockReturnValue({ wsId: WS_ID, loading: false })
    api.getWebsiteSecurityConditions.mockResolvedValue({ items: [], pagination: { total: 0 } })
    mount()
    await waitFor(() => expect(api.getWebsiteSecurityConditions).toHaveBeenCalled())
    expect(api.getWebsiteSecurityConditions).toHaveBeenCalledWith(WS_ID, {})
    for (const call of api.getWebsiteSecurityConditions.mock.calls) expect(call[0]).toBe(WS_ID)
  })

  it('renders an empty state (not an error) for an empty 200 response', async () => {
    useWorkspace.mockReturnValue({ wsId: WS_ID, loading: false })
    api.getWebsiteSecurityConditions.mockResolvedValue({ items: [], pagination: { total: 0 } })
    mount()
    expect(await screen.findByText(/No website security conditions recorded yet/i)).toBeInTheDocument()
  })

  it('renders the generic failure state on a backend 403', async () => {
    useWorkspace.mockReturnValue({ wsId: WS_ID, loading: false })
    api.getWebsiteSecurityConditions.mockRejectedValue({ status: 403 })
    mount()
    expect(await screen.findByText(/Could not load website security conditions/i)).toBeInTheDocument()
  })

  it('preserves the ?condition=<id> deep link: loads that condition detail with the context wsId', async () => {
    useWorkspace.mockReturnValue({ wsId: WS_ID, loading: false })
    api.getWebsiteSecurityConditions.mockResolvedValue({ items: [ITEM], pagination: { total: 1 } })
    api.getWebsiteSecurityCondition.mockResolvedValue({ id: 'cond_1', history: [] })
    mount('/ws/website-security?condition=cond_1')
    await waitFor(() => expect(api.getWebsiteSecurityCondition).toHaveBeenCalled())
    expect(api.getWebsiteSecurityCondition).toHaveBeenCalledWith(WS_ID, 'cond_1')
    for (const call of api.getWebsiteSecurityCondition.mock.calls) expect(call[0]).toBe(WS_ID)
  })

  it('does NOT call any API while the workspace is unresolved (null wsId, loading)', async () => {
    useWorkspace.mockReturnValue({ wsId: null, loading: true })
    api.getWebsiteSecurityConditions.mockResolvedValue({ items: [], pagination: { total: 0 } })
    mount('/ws/website-security?condition=cond_1')
    await Promise.resolve()
    expect(api.getWebsiteSecurityConditions).not.toHaveBeenCalled()
    expect(api.getWebsiteSecurityCondition).not.toHaveBeenCalled()
  })

  it('shows "No workspace selected" (no API call) when resolution finishes with no workspace', async () => {
    useWorkspace.mockReturnValue({ wsId: null, loading: false })
    mount()
    expect(await screen.findByText(/No workspace selected/i)).toBeInTheDocument()
    expect(api.getWebsiteSecurityConditions).not.toHaveBeenCalled()
  })
})
