import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import PortfolioRiskPage from '../PortfolioRiskPage'
import { api } from '../../api'

// Drives the real page against the real API shapes the risk engine returns.
//
// The engine used to send `portfolio_score: null` with an executive summary reading
// "showing serious overall risk (portfolio score: null/100)", and this page rendered
// that sentence verbatim inside a green Executive Summary card. There was no page test
// at all — no assertion anywhere covered the badge ladder, the `/100`, or RiskBadge's
// `?? 'badge-low'` fallback. Unit-testing the helpers would not have caught it either;
// the bug only exists once something renders. So this test renders.

vi.mock('../../api', () => ({
  api: { getPortfolioRisk: vi.fn() },
}))

const base = {
  workspace_count: 2,
  high_risk_workspaces: 0,
  critical_workspaces: 0,
  risk_rankings: [],
  trending: { improving: [], deteriorating: [] },
  portfolio_alerts: [],
  shared_dependencies: [],
  calculated_at: '2026-07-16T00:00:00.000Z',
}

const renderPage = async (payload) => {
  api.getPortfolioRisk.mockResolvedValue(payload)
  render(<MemoryRouter><PortfolioRiskPage /></MemoryRouter>)
  await waitFor(() => expect(api.getPortfolioRisk).toHaveBeenCalled())
}

const bodyText = () => document.body.textContent || ''

beforeEach(() => vi.clearAllMocks())

describe('PortfolioRiskPage — absent evidence must not render as a verdict', () => {
  describe('workspaces exist but nothing has been assessed', () => {
    const payload = {
      ...base,
      portfolio_score: null,
      portfolio_score_band: null,
      portfolio_score_state: 'evidence_insufficient',
      portfolio_score_reason:
        'No completed business risk assessment exists for any of the 2 monitored customer environments yet, so a portfolio score cannot be calculated.',
      portfolio_score_basis: { scored_workspaces: 0, total_workspaces: 2 },
      executive_summary:
        'A portfolio risk score is not available for your 2 customer environments yet. No completed business risk assessment exists for any of the 2 monitored customer environments yet, so a portfolio score cannot be calculated.',
    }

    it('never prints null/100, undefined/100 or NaN/100', async () => {
      await renderPage(payload)
      await waitFor(() => expect(bodyText()).not.toMatch(/null\/100|undefined\/100|NaN\/100/))
    })

    it('renders no risk verdict word for a score that does not exist', async () => {
      await renderPage(payload)
      await waitFor(() => expect(screen.queryByText('Serious')).not.toBeInTheDocument())
      expect(screen.queryByText('Healthy')).not.toBeInTheDocument()
      expect(screen.queryByText('Moderate')).not.toBeInTheDocument()
      expect(screen.queryByText('Elevated')).not.toBeInTheDocument()
    })

    // The reason appears twice by design — once on the score card, once in the
    // executive summary — so whichever the reader looks at, they get the why.
    it('states explicitly that evidence is insufficient, and why', async () => {
      await renderPage(payload)
      await waitFor(() => expect(screen.getByText('Insufficient evidence')).toBeInTheDocument())
      expect(screen.getAllByText(/cannot be calculated/i).length).toBeGreaterThan(0)
    })

    it('does not hide the missing evidence behind a benign colour', async () => {
      await renderPage(payload)
      const chip = await screen.findByText('Insufficient evidence')
      expect(chip.className).toMatch(/slate/)
      expect(chip.className).not.toMatch(/brand|green|red/)
    })
  })

  describe('no workspaces at all', () => {
    it('is neither healthy nor at risk', async () => {
      await renderPage({
        ...base,
        workspace_count: 0,
        portfolio_score: null,
        portfolio_score_band: null,
        portfolio_score_state: 'no_workspaces',
        portfolio_score_reason: 'No customer environments are being monitored yet.',
        portfolio_score_basis: { scored_workspaces: 0, total_workspaces: 0 },
        executive_summary: 'No customer environments are currently monitored. Add workspaces to begin portfolio risk tracking.',
      })
      await waitFor(() => expect(screen.getByText('Nothing monitored')).toBeInTheDocument())
      expect(bodyText()).not.toMatch(/null\/100/)
      expect(screen.queryByText('Healthy')).not.toBeInTheDocument()
      expect(screen.queryByText('Serious')).not.toBeInTheDocument()
    })
  })

  describe('partial coverage — a real score that speaks for only part of the portfolio', () => {
    it('shows the score AND discloses what it excludes', async () => {
      await renderPage({
        ...base,
        portfolio_score: 90,
        portfolio_score_band: 'healthy',
        portfolio_score_state: 'partial',
        portfolio_score_reason: 'Based on 1 of 2 monitored customer environments; 1 environment has no completed assessment and is not represented in this score.',
        portfolio_score_basis: { scored_workspaces: 1, total_workspaces: 2 },
        executive_summary: 'Your portfolio of 2 customer environments is showing healthy overall risk (portfolio score: 90/100). Based on 1 of 2 monitored customer environments; 1 environment has no completed assessment and is not represented in this score.',
      })
      await waitFor(() => expect(screen.getByText('Healthy')).toBeInTheDocument())
      expect(screen.getByText('Partial coverage')).toBeInTheDocument()
      // Disclosed on the score card AND inside the summary sentence — a 90 drawn from
      // 1 of 2 customers must not read as a 90 for the portfolio in either place.
      expect(screen.getAllByText(/not represented in this score/i).length).toBeGreaterThan(0)
      expect(screen.getAllByText(/1 of 2/i).length).toBeGreaterThan(0)
    })
  })

  describe('a real, complete score', () => {
    it('renders the band and the score unchanged', async () => {
      await renderPage({
        ...base,
        portfolio_score: 60,
        portfolio_score_band: 'moderate',
        portfolio_score_state: 'available',
        portfolio_score_reason: 'Based on all 2 monitored customer environments.',
        portfolio_score_basis: { scored_workspaces: 2, total_workspaces: 2 },
        executive_summary: 'Your portfolio of 2 customer environments is showing moderate overall risk (portfolio score: 60/100).',
      })
      await waitFor(() => expect(screen.getByText('Moderate')).toBeInTheDocument())
      expect(screen.getByText('All environments assessed')).toBeInTheDocument()
      expect(bodyText()).toMatch(/60\/100/)
    })
  })

  describe('the rankings table', () => {
    const withRows = {
      ...base,
      portfolio_score: 90,
      portfolio_score_band: 'healthy',
      portfolio_score_state: 'partial',
      portfolio_score_reason: 'Based on 1 of 2 monitored customer environments; 1 environment has no completed assessment and is not represented in this score.',
      portfolio_score_basis: { scored_workspaces: 1, total_workspaces: 2 },
      executive_summary: 'ok',
      risk_rankings: [
        { workspace_id: 'w1', workspace_name: 'Assessed Ltd', brs_score: 90, risk_band: 'low', score_delta_30d: null, supply_chain_score: null, spof_count: 0, trend: 'no_data' },
        { workspace_id: 'w2', workspace_name: 'Unassessed Ltd', brs_score: null, risk_band: 'unknown', score_delta_30d: null, supply_chain_score: null, spof_count: 0, trend: 'no_data' },
      ],
    }

    it('shows "Not assessed" instead of a fraction with no numerator', async () => {
      await renderPage(withRows)
      await waitFor(() => expect(screen.getByText('Not assessed')).toBeInTheDocument())
      expect(bodyText()).not.toMatch(/—\/100/)
      expect(bodyText()).not.toMatch(/null\/100/)
    })

    it('renders an unassessed customer as unknown, not as low risk', async () => {
      await renderPage(withRows)
      const badge = await screen.findByText('unknown')
      expect(badge).toHaveClass('badge-unknown')
      expect(badge).not.toHaveClass('badge-low')
    })

    it('still renders the assessed customer normally', async () => {
      await renderPage(withRows)
      await waitFor(() => expect(screen.getByText('low')).toHaveClass('badge-low'))
      expect(bodyText()).toMatch(/90\/100/)
    })
  })

  describe('non-finite score (defensive — `!= null` let NaN through)', () => {
    it('does not render NaN or a red verdict', async () => {
      await renderPage({
        ...base,
        portfolio_score: NaN,
        portfolio_score_band: null,
        portfolio_score_state: 'evidence_insufficient',
        portfolio_score_reason: 'No completed business risk assessment exists yet.',
        portfolio_score_basis: { scored_workspaces: 0, total_workspaces: 2 },
        executive_summary: 'A portfolio risk score is not available yet.',
      })
      await waitFor(() => expect(screen.getByText('Insufficient evidence')).toBeInTheDocument())
      expect(bodyText()).not.toMatch(/NaN/)
      expect(screen.queryByText('Serious')).not.toBeInTheDocument()
    })
  })
})
