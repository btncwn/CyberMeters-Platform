import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import Dashboard, { deriveInsights } from '../Dashboard'
import { api } from '../../api'

vi.mock('../../api', () => ({
  api: {
    getWorkspaceScans: vi.fn(), getWorkspaceDomains: vi.fn(),
    getWorkspaceScorecard: vi.fn(), getCyberMotDomains: vi.fn(),
    getScanReport: vi.fn(),
  },
}))
vi.mock('../../components/OnboardingProgress', () => ({ default: () => null }))
vi.mock('../../components/FirstResultsGuide', () => ({ default: () => null }))
vi.mock('../../components/TeamOnboardingCard', () => ({ default: () => null }))
vi.mock('../../components/RecentChangesCard', () => ({ default: () => null }))
vi.mock('../../components/CyberMotDomains', () => ({ default: () => null }))

const scans = [
  { id: 'tls-partial', domain: 'cybermeters.com', status: 'completed', score: 100,
    rating: 'excellent', scan_quality: 'partial', created_at: '2026-10-14 01:48:00' },
  { id: 'earlier-complete', domain: 'cybermeters.com', status: 'completed', score: 82,
    rating: 'good', scan_quality: 'complete', created_at: '2026-10-12 22:32:00' },
]

describe('Dashboard TLS quality honesty', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    localStorage.setItem('cybermeters_workspace_id', 'founder-workspace')
    api.getWorkspaceScans.mockResolvedValue({ scans })
    api.getWorkspaceDomains.mockResolvedValue({ domains: [{ domain: 'cybermeters.com' }] })
    api.getWorkspaceScorecard.mockResolvedValue({})
    api.getCyberMotDomains.mockResolvedValue({ cyber_mot_domains: [] })
    api.getScanReport.mockResolvedValue({ status: 'completed', scan_id: 'tls-partial',
      cyber_metrics_score: 100, findings: [], cyber_mot_domains: [] })
  })

  it('does not let an older complete scan make the newest partial TLS result authoritative or comparable', () => {
    const result = deriveInsights(scans, null)
    expect(result).toMatchObject({ score: 100, riskLevel: null,
      postureProvisional: true, postureEstablished: false, scanQuality: 'partial' })
    expect(result.trend.map(point => point.value)).toEqual([82])
  })

  it('shows the latest score as provisional and unrated throughout the live dashboard', async () => {
    render(<MemoryRouter><Dashboard /></MemoryRouter>)
    expect(await screen.findByText('Provisional Score')).toBeInTheDocument()
    expect(screen.getByText('Unrated')).toBeInTheDocument()
    expect(screen.getByText('Some checks were not completed. This score is provisional.')).toBeInTheDocument()
    expect(screen.queryByText('Excellent')).not.toBeInTheDocument()
    const recent = within(screen.getByText('Recent Scans').closest('.card'))
    expect(recent.getByText('100 provisional')).toBeInTheDocument()
    expect(recent.getByText('Partial results')).toBeInTheDocument()
    expect(screen.getByText('Cyber Metrics Score across fully assessed scans')).toBeInTheDocument()
  })
})
