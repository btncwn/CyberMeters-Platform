import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import WorkspaceDashboard from '../WorkspaceDashboard'
import { api } from '../../../api'

vi.mock('../../../api', () => ({
  api: {
    getWorkspaceScorecard: vi.fn(),
    getWorkspacePostureTimeline: vi.fn(),
    getWorkspaceSummary: vi.fn(),
    getWorkspaceHealth: vi.fn(),
    getWorkspaceDomains: vi.fn(),
    getCyberMotDomains: vi.fn(),
  },
}))
vi.mock('../../../hooks/useWorkspace', () => ({
  useWorkspace: () => ({ wsId: 'ws-founder', wsName: 'Founder workspace' }),
}))
vi.mock('../../../context/AuthContext', () => ({ useAuth: () => ({ user: { id: 'owner' } }) }))
vi.mock('../../../components/WorkspaceMembersPanel', () => ({ default: () => null }))
vi.mock('../../../components/ActivityTimeline', () => ({ default: () => null }))
vi.mock('../../../components/CyberMotDomains', () => ({ default: () => null }))

// Keep the page's data selection visible without relying on jsdom chart layout.
vi.mock('recharts', () => ({
  ResponsiveContainer: ({ children }) => <>{children}</>,
  AreaChart: ({ data, children }) => <div data-testid="asset-chart" data-points={JSON.stringify(data)}>{children}</div>,
  Area: ({ dataKey }) => <span data-testid="asset-series">{dataKey}</span>,
  XAxis: ({ dataKey, tickFormatter }) => <span data-testid="asset-axis" data-key={dataKey}>{tickFormatter('2026-10-08')}</span>,
  YAxis: () => null,
  CartesianGrid: () => null,
  Tooltip: () => null,
}))

const established = (score = 82) => ({
  display_score: score, display_rating: 'good', state: 'established',
  quality: 'complete', provisional: false, authoritative: true, comparable: true,
})
const provisional = (score = 90) => ({
  display_score: score, display_rating: null, state: 'provisional',
  quality: 'partial', provisional: true, authoritative: false, comparable: false,
  message: 'Some checks were not completed. This score is provisional.',
})
const timeline = [
  { day: '2026-10-07', asset_count: 5, new_assets: 1, removed_assets: 0, critical_findings: 0 },
  { day: '2026-10-08', asset_count: 7, new_assets: 2, removed_assets: 0, critical_findings: 0 },
]

async function dashboard(posture) {
  api.getWorkspaceScorecard.mockResolvedValue({
    // These legacy fields must not override the canonical evidence decision.
    security_score: 100, risk_rating: 'excellent', current_posture: posture,
    last_scan_at: '2026-10-08T20:15:21Z',
  })
  api.getWorkspacePostureTimeline.mockResolvedValue({ timeline })
  api.getWorkspaceSummary.mockResolvedValue({ domains: 1, latest_score: 100 })
  api.getWorkspaceHealth.mockResolvedValue({ workspace_status: 'active', monitoring_health: 'healthy' })
  api.getWorkspaceDomains.mockResolvedValue({ domains: [{ domain: 'cybermeters.com', verification_status: 'verified' }] })
  api.getCyberMotDomains.mockResolvedValue({ cyber_mot_domains: [] })
  render(<MemoryRouter><WorkspaceDashboard /></MemoryRouter>)
  return within(await screen.findByRole('region', { name: 'Security score' }))
}

describe('WorkspaceDashboard evidence presentation', () => {
  beforeEach(() => vi.clearAllMocks())

  it('renders the actual asset timeline contract without inventing a numeric score trend', async () => {
    await dashboard({ state: 'not_established', authoritative: null, latest_provisional: provisional() })

    expect(screen.queryByText(/NaN|Invalid Date/)).not.toBeInTheDocument()
    expect(screen.getByText('Score history is not available.')).toBeInTheDocument()
    expect(JSON.parse(screen.getByTestId('asset-chart').dataset.points)).toEqual(timeline)
    expect(screen.getByTestId('asset-series')).toHaveTextContent('asset_count')
    expect(screen.getByTestId('asset-axis')).toHaveAttribute('data-key', 'day')
    expect(screen.getByTestId('asset-axis')).not.toHaveTextContent('Invalid Date')
    expect(api.getWorkspacePostureTimeline).toHaveBeenCalledWith('ws-founder')
  })

  it('labels partial 90 separately from current posture and scopes the monitoring badge', async () => {
    const score = await dashboard({ state: 'not_established', authoritative: null, latest_provisional: provisional() })

    expect(score.getByText('Current posture not yet established.')).toBeInTheDocument()
    const latest = within(score.getByRole('region', { name: 'Latest assessment' }))
    expect(latest.getByText('90')).toBeInTheDocument()
    expect(latest.getByText('Provisional')).toBeInTheDocument()
    expect(latest.getByText(/Some checks were not completed/)).toBeInTheDocument()
    expect(score.queryByText('Excellent')).not.toBeInTheDocument()
    expect(score.queryByText('100')).not.toBeInTheDocument()
    expect(screen.getByText('Monitoring: recent')).toBeInTheDocument()
    expect(screen.queryByText('healthy')).not.toBeInTheDocument()
  })

  it('preserves an authoritative score separately from a newer provisional assessment', async () => {
    const score = await dashboard({
      state: 'established',
      authoritative: { ...established(), label: 'Last authoritative posture' },
      latest_provisional: provisional(),
    })

    expect(score.getByLabelText('Established score 82')).toBeInTheDocument()
    expect(score.getByText('Good')).toBeInTheDocument()
    expect(score.getByText('Last authoritative posture')).toBeInTheDocument()
    expect(within(score.getByRole('region', { name: 'Latest assessment' })).getByText('90')).toBeInTheDocument()
    expect(score.getByText('Provisional')).toBeInTheDocument()
    expect(score.queryByText('100')).not.toBeInTheDocument()
  })

  it('shows a complete assessment without adding a provisional state', async () => {
    const score = await dashboard({ state: 'established', authoritative: established(), latest_provisional: null })

    expect(score.getByLabelText('Established score 82')).toBeInTheDocument()
    expect(score.getByText('Good')).toBeInTheDocument()
    expect(score.queryByText('Provisional')).not.toBeInTheDocument()
    expect(score.queryByRole('region', { name: 'Latest assessment' })).not.toBeInTheDocument()
  })

  it.each([null, NaN, Infinity])('keeps an invalid authoritative score (%s) neutral despite legacy numeric fields', async (value) => {
    const score = await dashboard({ state: 'established', authoritative: established(value), latest_provisional: null })

    expect(score.getByText('Current posture not yet established.')).toBeInTheDocument()
    expect(score.getByText('—')).toBeInTheDocument()
    expect(score.queryByText(/NaN|Infinity|Excellent|Good/)).not.toBeInTheDocument()
    expect(score.queryByText('100')).not.toBeInTheDocument()
  })

  it('does not use legacy scores when the canonical posture envelope is absent', async () => {
    const score = await dashboard(undefined)

    expect(score.getByText('Current posture not yet established.')).toBeInTheDocument()
    expect(score.getByText('—')).toBeInTheDocument()
    expect(score.queryByText('100')).not.toBeInTheDocument()
    expect(score.queryByText('Excellent')).not.toBeInTheDocument()
  })
})
