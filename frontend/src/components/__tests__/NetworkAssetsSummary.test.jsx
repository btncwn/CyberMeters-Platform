import { render, screen, waitFor } from '@testing-library/react'
import NetworkAssetsSummary, { networkAssetsSummary, NETWORK_ASSETS_TILE_TO } from '../NetworkAssetsSummary'
import { api } from '../../api'

// The one-liner on the Attack Surface "Network assets" tile uses only what the
// network panel's API returns and never invents a number.

vi.mock('../../api', () => ({ api: { getNetworkTargets: vi.fn(), getNetworkAssets: vi.fn(), getNetworkScans: vi.fn() } }))

const targets = [{ id: 't1', target: '203.0.113.0/28' }, { id: 't2', target: '198.51.100.7' }]
const scans = [{ id: 'ns0', status: 'completed', completed_at: '2026-10-10T08:00:00Z' }, { id: 'ns1', status: 'completed', completed_at: '2026-10-16T08:00:00Z' }, { id: 'ns2', status: 'pending', completed_at: null }]
const assets = [
  { address: '203.0.113.5', port: 443, state: 'open', last_scan_id: 'ns1' },
  { address: '203.0.113.5', port: 80, state: 'open', last_scan_id: 'ns1' },
  { address: '203.0.113.9', port: 22, state: 'open', last_scan_id: 'ns0' },   // observed open by an older scan only
  { address: '198.51.100.7', port: 22, state: 'closed', last_scan_id: 'ns1' },
]

beforeEach(() => { vi.clearAllMocks() })

describe('networkAssetsSummary', () => {
  it('counts targets and the open ports the latest completed scan observed', () => {
    expect(networkAssetsSummary({ targets, assets, scans })).toEqual({ text: '2 targets · 2 open ports in the latest network scan', state: 'measured' })
    expect(networkAssetsSummary({ targets: [targets[0]], assets: assets.slice(0, 1), scans })).toEqual({ text: '1 target · 1 open port in the latest network scan', state: 'measured' })
    expect(networkAssetsSummary({ targets, assets, scans, nextCursor: '256' }).text).toBe('2 targets · at least 2 open ports in the latest network scan')
  })
  it('says so when no scan has completed, when there are no targets, and when nothing could be read', () => {
    expect(networkAssetsSummary({ targets, assets: [], scans: [scans[2]] })).toEqual({ text: '2 targets · no completed network scan yet', state: 'no_scan' })
    expect(networkAssetsSummary({ targets: [], assets: [], scans: [] })).toEqual({ text: 'Add an IP or network you are authorised to test to see open ports', state: 'empty' })
    expect(networkAssetsSummary({})).toEqual({ text: 'Network inventory could not be read', state: 'unavailable' })
  })
  it('the tile target is the Findings anchor', () => {
    expect(NETWORK_ASSETS_TILE_TO).toBe('/assets#network-assets')
  })
})

describe('<NetworkAssetsSummary>', () => {
  it('renders the measured summary after reading the panel\'s three endpoints', async () => {
    api.getNetworkTargets.mockResolvedValue({ targets, capabilities: {} })
    api.getNetworkAssets.mockResolvedValue({ assets, total: 4, next_cursor: null })
    api.getNetworkScans.mockResolvedValue({ scans })
    render(<NetworkAssetsSummary workspaceId="ws1" />)
    expect(screen.getByTestId('network-assets-summary')).toHaveTextContent('Reading the network inventory…')
    await waitFor(() => expect(screen.getByTestId('network-assets-summary')).toHaveTextContent('2 targets · 2 open ports in the latest network scan'))
    expect(screen.getByTestId('network-assets-summary')).toHaveAttribute('data-state', 'measured')
    expect(api.getNetworkTargets).toHaveBeenCalledWith('ws1', expect.objectContaining({ signal: expect.anything() }))
  })
  it('renders the empty-state sentence without inventing a number', async () => {
    api.getNetworkTargets.mockResolvedValue({ targets: [] })
    api.getNetworkAssets.mockResolvedValue({ assets: [] })
    api.getNetworkScans.mockResolvedValue({ scans: [] })
    render(<NetworkAssetsSummary workspaceId="ws1" />)
    await waitFor(() => expect(screen.getByTestId('network-assets-summary')).toHaveAttribute('data-state', 'empty'))
    expect(screen.getByTestId('network-assets-summary')).toHaveTextContent('Add an IP or network you are authorised to test to see open ports')
    expect(screen.getByTestId('network-assets-summary').textContent).not.toMatch(/\d/)
  })
  it('a failed read says so, and a client without the methods never crashes', async () => {
    api.getNetworkTargets.mockRejectedValue(new Error('boom'))
    api.getNetworkAssets.mockResolvedValue({ assets: [] })
    api.getNetworkScans.mockResolvedValue({ scans: [] })
    const { unmount } = render(<NetworkAssetsSummary workspaceId="ws1" />)
    await waitFor(() => expect(screen.getByTestId('network-assets-summary')).toHaveTextContent('Network inventory could not be read'))
    unmount()
    api.getNetworkTargets.mockImplementation(undefined)
    api.getNetworkTargets = undefined
    render(<NetworkAssetsSummary workspaceId="ws1" />)
    await waitFor(() => expect(screen.getByTestId('network-assets-summary')).toHaveAttribute('data-state', 'unavailable'))
  })
  it('renders nothing without a workspace', () => {
    render(<NetworkAssetsSummary workspaceId={null} />)
    expect(screen.queryByTestId('network-assets-summary')).toBeNull()
  })
})
