import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import PortfolioPage from '../PortfolioPage'
import { api } from '../../api'

vi.mock('../../api', () => ({
  api: {
    getPortfolioOverview: vi.fn(),
    getPortfolioWorkspaces: vi.fn(),
    getPortfolioAlerts: vi.fn(),
    getPortfolioTrends: vi.fn(),
    getPortfolioExecutiveSummary: vi.fn(),
    getPortfolioMaturity: vi.fn(),
    getPortfolioDomains: vi.fn(),
  },
}))

const gate = () => Object.assign(new Error('Feature requires upgrade: portfolio_monitoring'), {
  error: 'plan_feature_required', feature: 'portfolio_monitoring', required_plan: 'business',
})
const renderPage = () => render(<MemoryRouter><PortfolioPage /></MemoryRouter>)

beforeEach(() => vi.resetAllMocks())

describe('Portfolio page plan response', () => {
  it('shows one upgrade card, never a raw feature key or a Retry per section', async () => {
    for (const fn of Object.values(api)) fn.mockRejectedValue(gate())
    renderPage()

    expect(await screen.findByRole('heading', { name: 'Portfolio Risk Monitoring requires an upgrade' })).toBeInTheDocument()
    expect(screen.getAllByRole('heading', { name: /requires an upgrade/ })).toHaveLength(1)
    expect(screen.queryByText(/Feature requires upgrade:/)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Upgrade to Business' })).toBeInTheDocument()
  })

  it('keeps a real service failure retryable per section', async () => {
    api.getPortfolioOverview.mockRejectedValue(new Error('Service unavailable'))
    api.getPortfolioWorkspaces.mockResolvedValue({ workspaces: [] })
    api.getPortfolioAlerts.mockResolvedValue({ alerts: [] })
    api.getPortfolioTrends.mockResolvedValue({ trend: [] })
    api.getPortfolioExecutiveSummary.mockResolvedValue({ executive_summary: 'No customers yet.', top_attention: [] })
    api.getPortfolioMaturity.mockResolvedValue({ portfolio_state: 'no_workspaces', domains: [] })
    api.getPortfolioDomains.mockResolvedValue({ domains: [], portfolio_state: 'no_workspaces', portfolio_state_reason: 'No customer environments are being monitored yet.', pagination: { limit: 25, offset: 0, total: 0 } })
    renderPage()

    expect(await screen.findByText('Service unavailable')).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: 'Retry' }).length).toBeGreaterThan(0)
    expect(screen.queryByRole('heading', { name: /requires an upgrade/ })).not.toBeInTheDocument()
  })
})
