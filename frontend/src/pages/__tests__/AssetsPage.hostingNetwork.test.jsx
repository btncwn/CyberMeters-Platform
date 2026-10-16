// The page body lives on the Findings tab of the area contract (16 Oct 2026); these tests open it there.
import { fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api'
import AssetsPage from '../AssetsPage'

vi.mock('../../api', () => ({
  api: {
    getManagedCases: vi.fn(),
    getWorkspaceAssetsSummary: vi.fn(),
    getWorkspaceAssets: vi.fn(),
    getWorkspaceAssetsTimeline: vi.fn(),
    getWorkspaceAsset: vi.fn(),
  },
}))

vi.mock('../../components/CasesQueue', () => ({ default: () => null }))
vi.mock('../../components/AttackSurfaceAssurance', () => ({ default: () => null }))
vi.mock('../../components/HostnameListPanel', () => ({ default: () => null }))
vi.mock('../../components/NetworkAssetsPanel', () => ({ default: () => null }))
vi.mock('../../components/AssetEvidence', () => ({ default: () => null }))

const CLOUD_LIMIT = 'The address is in a range the provider publishes for its cloud. It does not show whose account runs the server.'
const cloud = {
  status: 'attributed', list_version: '2026-10-14.1', providers: ['aws'],
  networks: [{ address: '52.94.5.10', provider: 'aws', provider_label: 'Amazon Web Services', kind: 'cloud', region: 'eu-west-2', service: 'EC2', range: '52.94.5.0/24' }],
  limitations: [CLOUD_LIMIT],
}
const assets = [
  { id: 'a1', hostname: 'app.example.com', asset_type: 'subdomain', status: 'active', source: 'dns_discovery', last_seen: '2026-10-12T10:00:00Z', risk_level: 'low', lifecycle_state: 'observed', lifecycle_state_label: 'Observed', ip_addresses: '["52.94.5.10"]', hosting_network: cloud },
  { id: 'a2', hostname: 'mail.example.com', asset_type: 'subdomain', status: 'active', source: 'dns_discovery', last_seen: '2026-10-12T10:00:00Z', risk_level: 'low', lifecycle_state: 'observed', lifecycle_state_label: 'Observed', hosting_network: { status: 'unattributed', networks: [], providers: [], limitations: [] } },
  { id: 'a3', hostname: 'old.example.com', asset_type: 'subdomain', status: 'active', source: 'dns_discovery', last_seen: '2026-10-12T10:00:00Z', risk_level: 'low', lifecycle_state: 'observed', lifecycle_state_label: 'Observed', hosting_network: { status: 'unavailable', networks: [], providers: [], limitations: [] } },
]

async function renderPage() {
  api.getWorkspaceAssetsSummary.mockResolvedValue({ total_assets: 3, lifecycle_counts: { observed: 3 } })
  api.getWorkspaceAssets.mockResolvedValue({
    assets,
    hosting_summary: { assets: 3, by_provider: [{ provider: 'aws', provider_label: 'Amazon Web Services', kind: 'cloud', count: 1 }], other_networks: 1, no_address: 0, unavailable: 1 },
  })
  api.getWorkspaceAssetsTimeline.mockResolvedValue({ timeline: [] })
  api.getManagedCases.mockResolvedValue({ cases: [] })
  api.getWorkspaceAsset.mockResolvedValue({ asset: assets[0], events: [], evidence: null })
  render(<MemoryRouter initialEntries={['/assets?tab=findings']}><AssetsPage /></MemoryRouter>)
  await screen.findByText('app.example.com')
}

beforeEach(() => {
  localStorage.setItem('cybermeters_workspace_id', 'ws-1')
  localStorage.setItem('cybermeters_workspace_name', 'Acme')
  vi.clearAllMocks()
})

describe('AssetsPage hosting network', () => {
  it('shows the provider the backend matched in each row, and nothing when it was not checked', async () => {
    await renderPage()
    expect(within(screen.getByText('app.example.com').closest('tr')).getByText('Amazon Web Services')).toBeInTheDocument()
    expect(within(screen.getByText('mail.example.com').closest('tr')).getByText('Other network')).toBeInTheDocument()
    expect(within(screen.getByText('old.example.com').closest('tr')).getByText('—')).toBeInTheDocument()
  })

  it('summarises where the listed assets answer from, without overclaiming ownership', async () => {
    await renderPage()
    const summary = screen.getByLabelText('Hosting networks')
    expect(within(summary).getByText(/Where these assets answer from/)).toBeInTheDocument()
    expect(within(summary).getByText(/Other networks/)).toBeInTheDocument()
    expect(within(summary).getByText(/does not show whose account runs the server/)).toBeInTheDocument()
  })

  it('lists the matched address, region and service in the detail panel with the backend limit', async () => {
    await renderPage()
    fireEvent.click(screen.getByText('app.example.com'))
    expect(await screen.findByText('Hosting network')).toBeInTheDocument()
    expect(screen.getByText(/eu-west-2 · EC2 compute/)).toBeInTheDocument()
    expect(screen.getByText(CLOUD_LIMIT)).toBeInTheDocument()
  })
})
