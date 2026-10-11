import React from 'react'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { PortfolioExecutiveSummary, PortfolioMaturity } from '../PortfolioSummaryCards'
import { api } from '../../api'

vi.mock('../../api', () => ({ api: { getPortfolioExecutiveSummary: vi.fn(), getPortfolioMaturity: vi.fn() } }))
beforeEach(() => { vi.resetAllMocks() })
const wrap = (el) => render(<MemoryRouter>{el}</MemoryRouter>)
const KEYS = ['identity_exposure', 'attack_surface', 'email_protection', 'website_security', 'shadow_it_unmanaged_technology', 'certificates_trust', 'brand_protection', 'cyber_essentials_readiness']

describe('PortfolioExecutiveSummary', () => {
  it('shows the backend sentence verbatim and why each customer needs attention', async () => {
    api.getPortfolioExecutiveSummary.mockResolvedValue({
      executive_summary: 'Across your 3 customers, average posture is 71/100. 1 needs attention, starting with Acme (2 critical findings).',
      partial_failure: false,
      top_attention: [{ workspace_id: 'w1', workspace_name: 'Acme', critical_findings: 2, customer_changes_7d_high: 1, latest_score: 55 }],
    })
    wrap(<PortfolioExecutiveSummary />)
    expect(await screen.findByText(/average posture is 71\/100/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Acme' })).toHaveAttribute('href', '/workspaces/w1')
    expect(screen.getByText(/2 critical findings, 1 new high-severity change this week, score 55\/100/)).toBeInTheDocument()
  })
  it('partial data is labelled; failure is an error; plan gate renders nothing', async () => {
    api.getPortfolioExecutiveSummary.mockResolvedValue({ executive_summary: 'x', partial_failure: true, top_attention: [] })
    const { unmount } = wrap(<PortfolioExecutiveSummary />)
    expect(await screen.findByText('Partial')).toBeInTheDocument()
    unmount()
    api.getPortfolioExecutiveSummary.mockRejectedValue(new Error('500'))
    const r2 = wrap(<PortfolioExecutiveSummary />)
    expect(await screen.findByRole('alert')).toHaveTextContent('could not be loaded')
    r2.unmount()
    api.getPortfolioExecutiveSummary.mockRejectedValue(Object.assign(new Error('gate'), { error: 'plan_feature_required' }))
    const { container } = wrap(<PortfolioExecutiveSummary />)
    await new Promise((r) => setTimeout(r, 0))
    expect(container.textContent).toBe('')
  })
})

describe('PortfolioMaturity', () => {
  it('renders the backend worst-case stage per domain with coverage and honest notes', async () => {
    api.getPortfolioMaturity.mockResolvedValue({ portfolio_state: 'assessed', domains: KEYS.map((k) => ({
      domain_key: k, display_name: k, portfolio_stage: k === 'email_protection' ? 'managed' : 'not_established',
      workspaces_established: k === 'email_protection' ? 2 : 0, workspaces_total: 2,
      regressed_count: k === 'email_protection' ? 1 : 0, attested_count: k === 'email_protection' ? 1 : 0, unmanaged_count: 0,
    })) })
    wrap(<PortfolioMaturity />)
    expect(await screen.findByText('Under management')).toBeInTheDocument()
    expect(screen.getByText('2 of 2 customers assessed')).toBeInTheDocument()
    expect(screen.getByText(/1 where an issue came back · 1 attested by the customer — not externally verified/)).toBeInTheDocument()
    expect(screen.getAllByText('Not established')).toHaveLength(7)
  })
  it('unavailable is an alert, never a clean zero', async () => {
    api.getPortfolioMaturity.mockResolvedValue({ portfolio_state: 'unavailable', domains: [] })
    wrap(<PortfolioMaturity />)
    expect(await screen.findByRole('alert')).toHaveTextContent('temporarily unavailable')
  })
})
