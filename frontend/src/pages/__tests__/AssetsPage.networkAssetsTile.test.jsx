import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import AssetsPage from '../AssetsPage'
import { api } from '../../api'

// Attack Surface Overview: the "Network assets" page tile (the area item in
// WorkspaceNav) carries an honest one-liner from the network panel's API and
// opens the Findings tab at #network-assets, where the panel lives.

vi.mock('../../api', () => ({
  api: {
    getSecurityCheckDomains: vi.fn(), getManagedCases: vi.fn(), getWorkspaceAssetsSummary: vi.fn(), getWorkspaceAssets: vi.fn(),
    getWorkspaceAssetsTimeline: vi.fn(), getWorkspaceScans: vi.fn(), getScanReport: vi.fn(),
    getNetworkTargets: vi.fn(), getNetworkAssets: vi.fn(), getNetworkScans: vi.fn(),
  },
}))
vi.mock('../../components/CasesQueue', () => ({ default: () => null }))
vi.mock('../../components/AttackSurfaceAssurance', () => ({ default: () => null }))
vi.mock('../../components/HostnameListPanel', () => ({ default: () => null }))
vi.mock('../../components/NetworkAssetsPanel', () => ({ default: () => <section id="network-assets" data-testid="network-panel">Network assets panel</section> }))

function renderAt(path) {
  return render(<MemoryRouter initialEntries={[path]}><AssetsPage /></MemoryRouter>)
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.setItem('cybermeters_workspace_id', 'ws-1')
  localStorage.setItem('cybermeters_workspace_name', 'Acme')
  api.getSecurityCheckDomains.mockResolvedValue({ cyber_mot_domains: [] })
  api.getManagedCases.mockResolvedValue({ cases: [] })
  api.getWorkspaceAssetsSummary.mockResolvedValue({ total_assets: 2, lifecycle_counts: { observed: 2 } })
  api.getWorkspaceAssets.mockResolvedValue({ assets: [] })
  api.getWorkspaceAssetsTimeline.mockResolvedValue({ timeline: [] })
  api.getWorkspaceScans.mockResolvedValue({ scans: [] })
  api.getNetworkTargets.mockResolvedValue({ targets: [{ id: 't1' }, { id: 't2' }] })
  api.getNetworkAssets.mockResolvedValue({ assets: [{ state: 'open', last_scan_id: 'ns1' }, { state: 'open', last_scan_id: 'ns1' }, { state: 'closed', last_scan_id: 'ns1' }], next_cursor: null })
  api.getNetworkScans.mockResolvedValue({ scans: [{ id: 'ns1', status: 'completed', completed_at: '2026-10-16T08:00:00Z' }] })
})

describe('Attack Surface — Network assets tile', () => {
  it('shows the tile on Overview with the honest summary and the Findings anchor, and opens Findings on click', async () => {
    renderAt('/assets')
    const tiles = await screen.findByTestId('module-tiles')
    const tile = within(tiles).getByRole('link', { name: /Network assets/ })
    expect(tile).toHaveAttribute('href', '/assets#network-assets')
    expect(within(tile).getByText('Open ports and services on addresses you are authorised to test')).toBeInTheDocument()
    await waitFor(() => expect(within(tile).getByTestId('network-assets-summary')).toHaveTextContent('2 targets · 2 open ports in the latest network scan'))
    expect(screen.queryByTestId('network-panel')).toBeNull()
    fireEvent.click(tile)
    expect(await screen.findByTestId('network-panel')).toBeInTheDocument()
    expect(screen.getByTestId('network-panel')).toHaveAttribute('id', 'network-assets')
    expect(screen.queryByTestId('module-tiles')).toBeNull()
  })

  it('the empty state asks for an authorised target instead of a number', async () => {
    api.getNetworkTargets.mockResolvedValue({ targets: [] })
    api.getNetworkAssets.mockResolvedValue({ assets: [] })
    api.getNetworkScans.mockResolvedValue({ scans: [] })
    renderAt('/assets')
    const tiles = await screen.findByTestId('module-tiles')
    await waitFor(() => expect(within(tiles).getByTestId('network-assets-summary')).toHaveTextContent('Add an IP or network you are authorised to test to see open ports'))
  })

  it('a deep link to #network-assets opens Findings with the panel', async () => {
    renderAt('/assets#network-assets')
    expect(await screen.findByTestId('network-panel')).toBeInTheDocument()
    expect(screen.queryByTestId('module-tiles')).toBeNull()
  })
})
