import { render, screen, within } from '@testing-library/react'
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
  },
}))

vi.mock('../../components/CasesQueue', () => ({ default: () => null }))
vi.mock('../../components/AttackSurfaceAssurance', () => ({ default: () => null }))

const projectionV1 = {
  version: 'asset-lifecycle-claim-projection-v1',
  coverage: 'complete',
}

function timelineResponse(projection) {
  return {
    timeline: [{
      day: '2026-08-07',
      new_asset_discovered: 0,
      asset_reappeared: 0,
      no_longer_observed_assets: 7,
      takeover_risk_detected: 0,
      wildcard_dns_detected: 0,
      cloud_storage_detected: 0,
    }],
    ...(projection === undefined ? {} : { lifecycle_claim_projection: projection }),
  }
}

async function renderPage(projection) {
  api.getWorkspaceAssetsSummary.mockResolvedValue(null)
  api.getWorkspaceAssets.mockResolvedValue({ assets: [] })
  api.getWorkspaceAssetsTimeline.mockResolvedValue(timelineResponse(projection))
  api.getManagedCases.mockResolvedValue({ cases: [] })
  render(<MemoryRouter><AssetsPage /></MemoryRouter>)
  await screen.findByText('Asset Timeline')
  return screen.getByText('2026-08-07').closest('tr')
}

beforeEach(() => {
  localStorage.setItem('cybermeters_workspace_id', 'ws-1')
  localStorage.setItem('cybermeters_workspace_name', 'Acme')
  vi.clearAllMocks()
})

describe('AssetsPage lifecycle count projection', () => {
  it.each([
    ['missing', undefined],
    ['unknown-version', { version: 'asset-lifecycle-claim-projection-v2', coverage: 'complete' }],
  ])('fails a %s projection closed even when the row contains a number', async (_label, projection) => {
    const row = await renderPage(projection)
    expect(within(row).getByText('Not evaluated')).toBeInTheDocument()
    expect(within(row).queryByText('7')).not.toBeInTheDocument()
  })

  it('renders an exact count only for the recognised complete projection', async () => {
    const row = await renderPage(projectionV1)
    expect(within(row).getByText('7')).toBeInTheDocument()
    expect(within(row).queryByText('Not evaluated')).not.toBeInTheDocument()
  })
})
