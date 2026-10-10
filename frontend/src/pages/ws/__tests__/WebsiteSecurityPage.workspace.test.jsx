// ── Website Security — workspace from context; alert deep-link preserved ──────
// Regression: read `useParams().workspaceId` on a paramless /ws/* route →
// undefined → /api/workspaces/undefined/... → 403. Now uses useWorkspace().
// This page ALSO keeps useSearchParams for the ?condition=<id> alert deep link,
// so these tests prove both: the list + condition-detail APIs get the context
// wsId, and the deep-link still expands and loads that condition.
import { render, screen, waitFor, fireEvent, within, act } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { beforeEach, describe, it, expect, vi } from 'vitest'
import WebsiteSecurityPage from '../WebsiteSecurityPage'
import { api } from '../../../api'
import { useWorkspace } from '../../../hooks/useWorkspace'

vi.mock('../../../api', () => ({
  api: { getWebsiteSecurityConditions: vi.fn(), getWebsiteSecurityCondition: vi.fn(), getWorkspaceScans: vi.fn(), getScanReport: vi.fn() },
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
  api.getWorkspaceScans.mockResolvedValue({ scans: [] })
  // jsdom does not implement scrollIntoView; the deep-link effect calls it.
  if (!Element.prototype.scrollIntoView) Element.prototype.scrollIntoView = () => {}
})

describe('WebsiteSecurityPage — workspace resolution', () => {
  it('calls the conditions API with the context wsId (never undefined) on a paramless route', async () => {
    useWorkspace.mockReturnValue({ wsId: WS_ID, loading: false })
    api.getWebsiteSecurityConditions.mockResolvedValue({ items: [], pagination: { total: 0 } })
    mount()
    await waitFor(() => expect(api.getWebsiteSecurityConditions).toHaveBeenCalled())
    expect(api.getWebsiteSecurityConditions).toHaveBeenCalledWith(WS_ID, { limit: 50, offset: 0 })
    for (const call of api.getWebsiteSecurityConditions.mock.calls) expect(call[0]).toBe(WS_ID)
  })

  it('renders an empty state (not an error) for an empty 200 response', async () => {
    useWorkspace.mockReturnValue({ wsId: WS_ID, loading: false })
    api.getWebsiteSecurityConditions.mockResolvedValue({ items: [], pagination: { total: 0 } })
    mount()
    expect(await screen.findByText(/No website security conditions recorded yet/i)).toBeInTheDocument()
  })

  it('keeps recorded checks visible when this workspace has no tracked findings', async () => {
    useWorkspace.mockReturnValue({ wsId: WS_ID, wsName: 'CyberMeters', loading: false })
    api.getWebsiteSecurityConditions.mockResolvedValue({ items: [], pagination: { total: 0 } })
    api.getWorkspaceScans.mockResolvedValue({ scans: [{ id: 'latest', domain: 'example.com', status: 'completed', created_at: '2026-10-10T10:00:00Z' }] })
    api.getScanReport.mockResolvedValue({ scan_id: 'latest', modules: { ssl: { https_available: true, https_probe_executed: true } } })
    mount()
    expect(await screen.findByText(/No website security conditions recorded yet/i)).toBeInTheDocument()
    expect(await screen.findByText('Response observed')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'View latest scan evidence' })).toHaveAttribute('href', '/scans/latest?view=technical#website-evidence')
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


describe('WebsiteSecurityPage — actionable, compact findings', () => {
  beforeEach(() => {
    useWorkspace.mockReturnValue({ wsId: WS_ID, loading: false })
    api.getWebsiteSecurityConditions.mockResolvedValue({ items: [ITEM], pagination: { total: 1 } })
    api.getWebsiteSecurityCondition.mockResolvedValue({ item: ITEM, events: [], linked_case: { id: 'case_1' } })
  })

  it('keeps evidence and case actions inside the expanded finding', async () => {
    const item = { ...ITEM, last_scan_id: 'scan_1', last_seen_at: '2026-10-10T10:00:00Z' }
    api.getWebsiteSecurityConditions.mockResolvedValue({ items: [item], pagination: { total: 1 } })
    mount()
    const row = await screen.findByRole('button', { name: /Mixed content/ })
    expect(screen.queryByRole('link', { name: 'Open managed case' })).toBeNull()
    fireEvent.click(row)
    expect(await screen.findByRole('link', { name: 'Open managed case' })).toHaveAttribute('href', '/ws/cases/case_1')
    expect(screen.getByRole('link', { name: 'View scan evidence' })).toHaveAttribute('href', '/scans/scan_1?view=technical#website-evidence')
    expect(screen.getByRole('link', { name: 'Recheck domain' })).toHaveAttribute('href', '/scans/new?domain=example.com')
    expect(screen.getByText('History and scan details').closest('details')).not.toHaveAttribute('open')
  })

  it('does not present an unknown historical Critical rating as a current red finding', async () => {
    const item = { ...ITEM, severity: 'critical', monitoring_status: 'unknown', last_scan_quality: 'degraded' }
    api.getWebsiteSecurityConditions.mockResolvedValue({ items: [item], pagination: { total: 1 } })
    mount()
    const row = await screen.findByRole('button', { name: /Mixed content/ })
    expect(within(row).queryByText('Critical')).toBeNull()
    expect(within(row).getByText('Not determined')).toBeInTheDocument()
    fireEvent.click(row)
    expect(await screen.findByText('Critical')).toBeInTheDocument()
    expect(screen.getByText(/historical rating, not a confirmed current issue/)).toBeInTheDocument()
    expect(within(row).queryByText('No longer seen')).toBeNull()
  })

  it('pages past the first 50 results and resets the page when filtering', async () => {
    api.getWebsiteSecurityConditions.mockImplementation((ws, params) => Promise.resolve({
      items: [{ ...ITEM, id: params.offset ? 'cond_51' : 'cond_1', title: params.offset ? 'Second page finding' : 'First page finding' }],
      pagination: { total: 51 },
    }))
    mount()
    await screen.findByText('First page finding')
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    await screen.findByText('Second page finding')
    expect(api.getWebsiteSecurityConditions).toHaveBeenLastCalledWith(WS_ID, { limit: 50, offset: 50 })
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled()
    fireEvent.change(screen.getByLabelText('State'), { target: { value: 'unknown' } })
    await waitFor(() => expect(api.getWebsiteSecurityConditions).toHaveBeenLastCalledWith(WS_ID, { limit: 50, offset: 0, monitoring_status: 'unknown' }))
  })

  it('opens an alert-linked condition even when it is beyond the loaded page', async () => {
    api.getWebsiteSecurityConditions.mockResolvedValue({ items: [], pagination: { total: 80 } })
    api.getWebsiteSecurityCondition.mockResolvedValue({ item: { ...ITEM, id: 'cond_51', title: 'Linked old finding' }, events: [] })
    mount('/ws/website-security?condition=cond_51')
    expect(await screen.findByText('Linked old finding')).toBeInTheDocument()
    expect(screen.getByText(/outside this page/)).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Open managed case' })).toBeNull()
  })

  it('ignores a late detail response after selecting a different condition', async () => {
    let resolveFirst
    api.getWebsiteSecurityConditions.mockResolvedValue({ items: [{ ...ITEM, title: 'First condition' }, { ...ITEM, id: 'cond_2', title: 'Second condition' }], pagination: { total: 2 } })
    api.getWebsiteSecurityCondition.mockImplementation((ws, id) => id === 'cond_1'
      ? new Promise((resolve) => { resolveFirst = resolve })
      : Promise.resolve({ item: { ...ITEM, id: 'cond_2' }, events: [], linked_case: { id: 'case_2' } }))
    mount()
    fireEvent.click(await screen.findByRole('button', { name: /First condition/ }))
    fireEvent.click(screen.getByRole('button', { name: /Second condition/ }))
    expect(await screen.findByRole('link', { name: 'Open managed case' })).toHaveAttribute('href', '/ws/cases/case_2')
    await act(async () => resolveFirst({ item: ITEM, events: [], linked_case: { id: 'wrong_case' } }))
    expect(screen.getByRole('link', { name: 'Open managed case' })).toHaveAttribute('href', '/ws/cases/case_2')
  })
})
