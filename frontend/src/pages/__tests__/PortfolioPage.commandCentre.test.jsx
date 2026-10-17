// Portfolio command centre — the per-customer eight-area view on /portfolio.
// These tests render: the page shows words the backend decided, in the founder
// order, for every customer, and never a settled word for something the backend
// did not say. Personas: MSP with entitlement and N customers (one just created
// with no scan, one with mixed evidence), MSP without entitlement, an empty
// portfolio, a failed read, an older bundle without the API function.
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
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

// Founder order, duplicated on purpose so the test fails if the registry drifts.
const FOUNDER_ORDER = [
  'email_protection', 'attack_surface', 'website_security', 'identity_exposure',
  'shadow_it_unmanaged_technology', 'certificates_trust', 'brand_protection', 'cyber_essentials_readiness',
]

const area = (k, over = {}) => ({
  domain_key: k, display_name: k, state: 'assessed_healthy', summary: `${k} summary`, coverage: 'complete',
  highest_severity: null, finding_count: 0, last_assessed_at: '2026-10-12T09:00:00Z',
  evidence_freshness: 'current', evidence_age_days: 3, freshness_reason: 'Last assessed 3 days ago.',
  trend: 'stable', trend_reason: 'No material issue observed in either assessment.', open_case_count: 0, limitations: [],
  ...over,
})
const eight = (over = {}) => FOUNDER_ORDER.map((k) => area(k, over[k] || {}))

const row = (o = {}) => ({
  workspace_id: 'ws_a', workspace_name: 'Customer A', domain_id: 'd_a', hostname: 'a.example.co.uk',
  overall_score: 72, overall_rating: 'fair', overall_state: 'established', overall_reason: 'ok',
  last_assessed_at: '2026-10-12T09:00:00Z', evidence_freshness: 'current', evidence_age_days: 3,
  freshness_reason: 'Last assessed 3 days ago.', priority: 'high', attention_required: true,
  attention_reasons: [], open_case_count: 2, cyber_mot_domains: eight(),
  drill_down: { workspace_id: 'ws_a', domain_id: 'd_a', scan_id: 'sc_a' },
  ...o,
})

// Workspace just created — no scan: the backend records every area as not yet assessed.
const FRESH = row({
  workspace_id: 'ws_new', workspace_name: 'New Customer', domain_id: 'd_new', hostname: 'new.example.co.uk',
  overall_score: null, overall_rating: null, overall_state: 'not_established', overall_reason: 'No completed assessment yet.',
  last_assessed_at: null, evidence_freshness: 'none', evidence_age_days: null, freshness_reason: 'No assessment has been recorded yet.',
  priority: 'unknown', open_case_count: 0,
  cyber_mot_domains: eight(Object.fromEntries(FOUNDER_ORDER.map((k) => [k, {
    state: 'not_yet_assessed', coverage: null, last_assessed_at: null, evidence_freshness: 'none', evidence_age_days: null,
    freshness_reason: 'No assessment has been recorded for this domain yet.',
    trend: 'insufficient_history', trend_reason: 'No assessment has been recorded for this domain yet.',
  }]))),
  drill_down: { workspace_id: 'ws_new', domain_id: 'd_new', scan_id: null },
})

const MIXED = row({
  cyber_mot_domains: eight({
    email_protection: { state: 'issue_detected', highest_severity: 'high', finding_count: 3, trend: 'worsening', trend_reason: 'Two new findings since the previous assessment.', open_case_count: 2 },
    attack_surface: { state: 'assessed_healthy', evidence_freshness: 'stale', evidence_age_days: 61, freshness_reason: 'Last assessed 61 days ago — stale.', trend: 'not_comparable', trend_reason: 'The most recent assessments did not both complete.' },
    website_security: { state: 'provisional', coverage: 'partial' },
    identity_exposure: { state: 'evidence_insufficient', trend: 'insufficient_history', trend_reason: 'Only one assessment has been recorded.' },
    shadow_it_unmanaged_technology: { state: 'monitoring_only', coverage: 'partial' },
    brand_protection: { state: 'customer_input_required' },
    cyber_essentials_readiness: { state: 'evidence_insufficient' },
  }),
})

const resp = (rows, o = {}) => ({
  domains: rows,
  summary: { total_domains: rows.length, total_customers: rows.length, assessed_domains: rows.length, by_domain: [], coverage_note: null },
  portfolio_state: 'available', portfolio_state_reason: `Based on all ${rows.length} monitored domains.`,
  pagination: { limit: 25, offset: 0, total: rows.length }, generated_at: '2026-10-15T10:00:00Z', ...o,
})

const gate = () => Object.assign(new Error('Feature requires upgrade: portfolio_monitoring'), {
  error: 'plan_feature_required', feature: 'portfolio_monitoring', required_plan: 'business',
})

function okEverythingElse() {
  api.getPortfolioOverview.mockResolvedValue({ total_workspaces: 2, total_domains: 2, total_assets: 0, new_assets_7d: 0, total_vendors: 0, new_reports_30d: 0, total_reports: 0, critical_findings: 0, high_findings: 0, average_score: null })
  api.getPortfolioWorkspaces.mockResolvedValue({ workspaces: [] })
  api.getPortfolioAlerts.mockResolvedValue({ alerts: [] })
  api.getPortfolioTrends.mockResolvedValue({ trend: [] })
  api.getPortfolioExecutiveSummary.mockResolvedValue({ executive_summary: 'Two customers are monitored.', top_attention: [] })
  api.getPortfolioMaturity.mockResolvedValue({ portfolio_state: 'no_evidence', domains: [] })
}

const renderPage = () => render(
  <MemoryRouter initialEntries={['/portfolio']}>
    <Routes>
      <Route path="/portfolio" element={<PortfolioPage />} />
      <Route path="/ws/dashboard" element={<div data-testid="ws-dashboard-probe">Workspace administration</div>} />
    </Routes>
  </MemoryRouter>,
)

const matrix = async () => { renderPage(); return within(await screen.findByTestId('customer-domain-matrix')) }
const rows = (m) => m.getAllByTestId('customer-row')
const chipWords = (r) => [...within(r).getByTestId('area-cells').querySelectorAll('[data-domain-key]')].map((c) => c.querySelector('[data-status]').getAttribute('data-status'))
const cellKeys = (r) => [...within(r).getByTestId('area-cells').querySelectorAll('[data-domain-key]')].map((c) => c.getAttribute('data-domain-key'))

beforeEach(() => {
  vi.resetAllMocks()
  localStorage.clear()
})

describe('Portfolio command centre — customers across the eight areas', () => {
  it('renders every customer with eight areas in founder order, words from the backend', async () => {
    okEverythingElse()
    api.getPortfolioDomains.mockResolvedValue(resp([MIXED, FRESH]))
    const m = await matrix()
    const rs = rows(m)
    expect(rs).toHaveLength(2)
    expect(cellKeys(rs[0])).toEqual(FOUNDER_ORDER)
    expect(cellKeys(rs[1])).toEqual(FOUNDER_ORDER)
    expect(api.getPortfolioDomains).toHaveBeenCalledWith({ limit: 25, offset: 0, sort: 'priority' })

    // Mixed customer: each word is the backend state (and backend freshness) mapped, nothing more.
    expect(chipWords(rs[0])).toEqual([
      'action_required',       // issue_detected
      'stale',                 // assessed_healthy + evidence_freshness stale
      'provisional',
      'evidence_insufficient',
      'provisional',           // monitoring_only with partial coverage
      'established',           // assessed_healthy, current
      'customer_input',        // customer_input_required
      'evidence_insufficient',
    ])
    expect(within(rs[0]).getByText('Customer A')).toBeInTheDocument()
    expect(within(rs[0]).getByText('2 open cases')).toBeInTheDocument()
    expect(within(rs[0]).getByRole('link', { name: 'Assessment' })).toHaveAttribute('href', '/scans/sc_a')

    // Just-created customer: eight × Not assessed, never Established, never a trend claim.
    expect(chipWords(rs[1])).toEqual(Array(8).fill('not_assessed'))
    expect(within(rs[1]).queryByText('Established')).not.toBeInTheDocument()
    expect(within(rs[1]).getAllByText(/not enough history for a trend/).length).toBe(8)
    expect(within(rs[1]).queryByText(/trend: stable/)).not.toBeInTheDocument()
    expect(within(rs[1]).queryByRole('link', { name: 'Assessment' })).not.toBeInTheDocument()
    expect(within(rs[1]).getByText('0 open cases')).toBeInTheDocument()
  })

  it('shows the backend trend per area, not a dash for everything', async () => {
    okEverythingElse()
    api.getPortfolioDomains.mockResolvedValue(resp([MIXED]))
    const m = await matrix()
    const r = rows(m)[0]
    expect(within(r).getByText(/trend: worsening/)).toBeInTheDocument()
    expect(within(r).getByText(/trend: not comparable/)).toBeInTheDocument()
    expect(within(r).getAllByText(/trend: stable/).length).toBe(5)
    expect(m.getByText('Full domain view')).toHaveAttribute('href', '/portfolio/domains')
  })

  it('a row whose eight-area set is malformed shows Error on all eight, never fewer, never settled', async () => {
    okEverythingElse()
    api.getPortfolioDomains.mockResolvedValue(resp([
      row({ cyber_mot_domains: eight().slice(0, 7) }),
      row({ workspace_id: 'ws_b', domain_id: 'd_b', workspace_name: 'Customer B', cyber_mot_domains: null }),
    ]))
    const m = await matrix()
    const rs = rows(m)
    expect(cellKeys(rs[0])).toEqual(FOUNDER_ORDER)
    expect(chipWords(rs[0])).toEqual(Array(8).fill('error'))
    expect(chipWords(rs[1])).toEqual(Array(8).fill('error'))
    expect(m.queryByText('Established')).not.toBeInTheDocument()
  })

  it('an empty portfolio shows the backend reason and a way to add a customer', async () => {
    okEverythingElse()
    api.getPortfolioDomains.mockResolvedValue(resp([], {
      portfolio_state: 'no_workspaces', portfolio_state_reason: 'No customer environments are being monitored yet.',
    }))
    const m = await matrix()
    expect(await m.findByTestId('customer-domain-matrix-empty')).toBeInTheDocument()
    expect(m.getByText('No customers are being monitored yet')).toBeInTheDocument()
    expect(m.getByText('No customer environments are being monitored yet.')).toBeInTheDocument()
    expect(m.getByRole('link', { name: 'Add a customer' })).toHaveAttribute('href', '/workspaces')
    expect(m.queryAllByTestId('customer-row')).toHaveLength(0)
  })

  it('MSP without entitlement: a plan gate on the domains read alone is one upgrade card, no Retry', async () => {
    okEverythingElse()
    api.getPortfolioDomains.mockRejectedValue(gate())
    renderPage()
    expect(await screen.findByRole('heading', { name: 'Portfolio Risk Monitoring requires an upgrade' })).toBeInTheDocument()
    expect(screen.getAllByRole('heading', { name: /requires an upgrade/ })).toHaveLength(1)
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
    expect(screen.queryByTestId('customer-domain-matrix')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Upgrade to Business' })).toBeInTheDocument()
  })

  it('a failed domains read shows Error with Retry and leaves the other sections alone', async () => {
    okEverythingElse()
    api.getPortfolioDomains.mockRejectedValueOnce(new Error('Service unavailable')).mockResolvedValueOnce(resp([MIXED]))
    const m = await matrix()
    const alert = await m.findByRole('alert')
    expect(within(alert).getByText('Error')).toBeInTheDocument()
    expect(within(alert).getByText(/could not be read/)).toBeInTheDocument()
    expect(m.queryAllByTestId('customer-row')).toHaveLength(0)
    expect(screen.queryByRole('heading', { name: /requires an upgrade/ })).not.toBeInTheDocument()
    expect(await screen.findByText('Two customers are monitored.')).toBeInTheDocument()

    fireEvent.click(within(alert).getByRole('button', { name: 'Retry' }))
    expect(await m.findByText('Customer A')).toBeInTheDocument()
    expect(api.getPortfolioDomains).toHaveBeenCalledTimes(2)
  })

  it('an older bundle without the API function shows Error, never an empty settled list', async () => {
    okEverythingElse()
    const saved = api.getPortfolioDomains
    api.getPortfolioDomains = undefined
    try {
      const m = await matrix()
      const alert = await m.findByRole('alert')
      expect(within(alert).getByText('Error')).toBeInTheDocument()
      expect(m.queryByTestId('customer-domain-matrix-empty')).not.toBeInTheDocument()
    } finally {
      api.getPortfolioDomains = saved
    }
  })

  it('Open customer selects that workspace and opens Workspace administration', async () => {
    okEverythingElse()
    api.getPortfolioDomains.mockResolvedValue(resp([MIXED]))
    const m = await matrix()
    fireEvent.click(within(rows(m)[0]).getByRole('button', { name: 'Open customer' }))
    expect(await screen.findByTestId('ws-dashboard-probe')).toBeInTheDocument()
    expect(localStorage.getItem('cybermeters_workspace_id')).toBe('ws_a')
    expect(localStorage.getItem('cybermeters_workspace_name')).toBe('Customer A')
  })

  it('shows loading on the matrix while the read is pending', async () => {
    okEverythingElse()
    api.getPortfolioDomains.mockReturnValue(new Promise(() => {}))
    const m = await matrix()
    expect(m.getByRole('status')).toHaveTextContent('Loading')
    expect(m.queryAllByTestId('customer-row')).toHaveLength(0)
  })
})
