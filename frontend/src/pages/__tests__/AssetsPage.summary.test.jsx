// S1-SHELL-V2b (Attack Surface): each figure is a named anchor; the "takeover"
// count is labelled by what the backend counts; ?type= opens the filtered inventory.
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api'
import AssetsPage from '../AssetsPage'

vi.mock('../../api', () => ({
  api: {
    getManagedCases: vi.fn(), getWorkspaceAssetsSummary: vi.fn(), getWorkspaceAssets: vi.fn(),
    getWorkspaceAssetsTimeline: vi.fn(), getWorkspaceScans: vi.fn(), getScanReport: vi.fn(),
  },
}))
vi.mock('../../components/CasesQueue', () => ({ default: () => null }))
vi.mock('../../components/AttackSurfaceAssurance', () => ({ default: () => null }))
vi.mock('../../components/HostnameListPanel', () => ({ default: () => null }))

const assets = [
  { id: 'a1', hostname: 'app.example.com', asset_type: 'subdomain', status: 'active', lifecycle_state: 'observed', lifecycle_state_label: 'Observed' },
  { id: 'a2', hostname: 'ssh.example.com', asset_type: 'exposed_service', status: 'active', lifecycle_state: 'observed', lifecycle_state_label: 'Observed' },
]

function renderAt(url, summary = { total_assets: 2, exposed_services: 1, takeover_risks: 3, lifecycle_counts: { observed: 2, confirmed_removed: 0 } }) {
  api.getWorkspaceAssetsSummary.mockResolvedValue(summary)
  api.getWorkspaceAssets.mockResolvedValue({ assets })
  api.getWorkspaceAssetsTimeline.mockResolvedValue({ timeline: [] })
  api.getManagedCases.mockResolvedValue({ cases: [] })
  api.getWorkspaceScans.mockResolvedValue({ scans: [] })
  return render(<MemoryRouter initialEntries={[url]}><AssetsPage /></MemoryRouter>)
}

beforeEach(() => { vi.clearAllMocks(); localStorage.setItem('cybermeters_workspace_id', 'ws1') })

describe('Attack Surface Summary', () => {
  it('names the risk figure by what it counts, never "takeover"; every figure is an anchor', async () => {
    renderAt('/assets')
    await waitFor(() => expect(document.getElementById('asm-high-risk')).not.toBeNull())
    expect(document.getElementById('asm-high-risk')).toHaveTextContent('High or critical risk assets')
    expect(document.getElementById('asm-high-risk')).toHaveTextContent('3')
    expect(screen.queryByText(/Takeover risks|Possible subdomain takeovers/)).toBeNull()
    for (const id of ['asm-seen', 'asm-no-longer-observed', 'asm-exposed-services']) expect(document.getElementById(id)).not.toBeNull()
  })
  it('reads high_risk_assets (takeover_risks is only the deprecated alias)', async () => {
    renderAt('/assets', { total_assets: 2, exposed_services: 1, high_risk_assets: 4, takeover_risks: 4, lifecycle_counts: { observed: 2, confirmed_removed: 0 } })
    await waitFor(() => expect(document.getElementById('asm-high-risk')).not.toBeNull())
    expect(document.getElementById('asm-high-risk')).toHaveTextContent('4')
  })
  it('?type=exposed_service opens the inventory filtered to exposed services', async () => {
    renderAt('/assets?type=exposed_service#asset-inventory')
    expect(await screen.findByText('ssh.example.com')).toBeInTheDocument()
    expect(screen.queryByText('app.example.com')).toBeNull()
  })
})
