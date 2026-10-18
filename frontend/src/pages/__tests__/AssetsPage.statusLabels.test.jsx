// The page body lives on the Findings tab of the area contract (16 Oct 2026); these tests open it there.
import { fireEvent, render, screen, within, waitFor } from '@testing-library/react'
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
    getWorkspaceScans: vi.fn(),
    getScanReport: vi.fn(),
  },
}))

vi.mock('../../components/CasesQueue', () => ({ default: () => null }))
vi.mock('../../components/AttackSurfaceAssurance', () => ({ default: () => null }))
vi.mock('../../components/HostnameListPanel', () => ({ default: () => null }))

const assets = [
  {
    id: 'a1', hostname: 'app.example.com', asset_type: 'subdomain', status: 'active',
    source: 'customer_list', last_seen: '2026-10-12T10:00:00Z',
    lifecycle_state: 'observed', lifecycle_state_label: 'Observed',
  },
  {
    id: 'a2', hostname: 'old.example.com', asset_type: 'subdomain', status: 'inactive',
    source: 'dns_bruteforce', last_seen: '2026-09-01T10:00:00Z',
    lifecycle_state: 'confirmed_removed', lifecycle_state_label: 'No longer externally observed',
  },
  {
    id: 'a3', hostname: 'quiet.example.com', asset_type: 'subdomain', status: 'active',
    source: 'dns_bruteforce', last_seen: '2026-09-01T10:00:00Z',
  },
]

async function renderPage(tab = 'findings') {
  api.getWorkspaceAssetsSummary.mockResolvedValue({
    total_assets: 3, active_assets: 2, inactive_assets: 1,
    lifecycle_counts: { observed: 1, not_observed: 0, confirmed_removed: 1, not_assessed: 1 },
  })
  api.getWorkspaceAssets.mockResolvedValue({ assets })
  api.getWorkspaceAssetsTimeline.mockResolvedValue({ timeline: [] })
  api.getManagedCases.mockResolvedValue({ cases: [] })
  api.getWorkspaceScans.mockResolvedValue({ scans: [] })
  render(<MemoryRouter initialEntries={[`/assets?tab=${tab}`]}><AssetsPage /></MemoryRouter>)
  if (tab === 'findings') await screen.findByText('app.example.com')
  else await waitFor(() => expect(screen.getAllByTestId('module-figure')).toHaveLength(4))
}

beforeEach(() => {
  localStorage.setItem('cybermeters_workspace_id', 'ws-1')
  localStorage.setItem('cybermeters_workspace_name', 'Acme')
  vi.clearAllMocks()
})

describe('AssetsPage status wording', () => {
  it('shows backend lifecycle labels and never the legacy status words', async () => {
    await renderPage()
    expect(within(screen.getByText('app.example.com').closest('tr')).getByText('Observed')).toBeInTheDocument()
    expect(within(screen.getByText('old.example.com').closest('tr')).getByText('No longer externally observed')).toBeInTheDocument()
    expect(within(screen.getByText('quiet.example.com').closest('tr')).getByText('Not assessed')).toBeInTheDocument()
    expect(screen.queryByText(/Legacy/)).not.toBeInTheDocument()
  })

  it('counts lifecycle states, not the legacy active flag — in "What we observed"', async () => {
    await renderPage('overview')
    const figures = screen.getAllByTestId('module-figure')
    const seen = figures.find((f) => f.querySelector('dt').textContent === 'Seen in latest scan')
    const gone = figures.find((f) => f.querySelector('dt').textContent === 'No longer observed')
    expect(seen).toHaveTextContent('1')
    expect(gone).toHaveTextContent('1')
    expect(gone).toHaveTextContent('not proof it was removed')
    expect(screen.queryByText('Active inventory across this workspace')).not.toBeInTheDocument()
    // Overview carries the summary, never the asset list; Findings the reverse.
    expect(screen.queryByText('app.example.com')).not.toBeInTheDocument()
  })

  it('shows at most four figures (the old seven-card grid is gone) and one reading guide above the lifecycle table', async () => {
    await renderPage()
    expect(screen.queryByTestId('attack-surface-stats')).not.toBeInTheDocument()
    expect(screen.getAllByTestId('module-figure')).toHaveLength(4)
    expect(screen.getByText('Asset Timeline')).toBeInTheDocument()
    expect(screen.getAllByTestId('asset-lifecycle-howto')).toHaveLength(1)
    expect(screen.getByText('How to read this')).toBeInTheDocument()
    const headers = screen.getAllByRole('columnheader').map((th) => th.textContent)
    expect(headers.slice(0, 4)).toEqual(['Hostname', 'Lifecycle state', 'Latest evidence', 'Last seen'])
  })

  it('filters the table by lifecycle state', async () => {
    await renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'No longer observed' }))
    expect(screen.getByText('old.example.com')).toBeInTheDocument()
    expect(screen.queryByText('app.example.com')).not.toBeInTheDocument()
    expect(screen.queryByText('quiet.example.com')).not.toBeInTheDocument()
  })

  it('does not claim a 30-day window the timeline does not apply', async () => {
    await renderPage()
    expect(screen.queryByText(/last 30 days/)).not.toBeInTheDocument()
  })
})
