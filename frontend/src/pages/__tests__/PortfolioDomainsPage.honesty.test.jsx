// ── MSP Portfolio per-domain — frontend honesty ──────────────────────────────
// These tests RENDER. #117's own post-mortem is the reason: unit-testing the helpers
// would not have caught the defect, because "the bug only exists once something
// renders" — a `?? 'badge-low'` fallback is invisible in a unit test of the map and
// fatal on the page.
//
// What must hold, on the surface an MSP reads to decide who to help first:
//   • a domain nobody assessed never renders as healthy, and never as low priority;
//   • "no history" never renders as "stable";
//   • stale evidence is visible on the row, not buried;
//   • a critical domain is never hidden behind a healthy overall score;
//   • no score never prints as —/100, null/100 or NaN/100;
//   • the page shows EIGHT domains, always.
import React from 'react'
import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import PortfolioDomainsPage from '../PortfolioDomainsPage'
import { CYBER_MOT_KEYS } from './portfolioDomainsFixtures'
import { api } from '../../api'

vi.mock('../../api', () => ({ api: { getPortfolioDomains: vi.fn() } }))

const eight = (over = {}) => CYBER_MOT_KEYS.map((k, i) => ({
  domain_key: k, display_name: k.replace(/_/g, ' '),
  state: 'assessed_healthy', summary: 'Assessed — no material issue observed.',
  coverage: 'complete', highest_severity: null, finding_count: 0, evidence_count: 1,
  last_assessed_at: '2026-07-15T00:00:00Z', evidence_freshness: 'current',
  evidence_age_days: 1, freshness_reason: 'Last assessed yesterday.',
  trend: 'stable', trend_reason: 'No material issue observed in either assessment.',
  trend_window_days: 7, compared_scan_id: 'sc_old', previous_state: 'assessed_healthy',
  new_finding_ids: [], resolved_finding_ids: [], source_scan_id: 'sc_new',
  resolver_version: '2026-07-16.1', open_case_count: 0, limitations: [],
  ...(over[k] || {}),
})

)
const mkRow = (o = {}) => ({
  workspace_id: 'ws1', workspace_name: 'Acme', domain_id: 'd1', hostname: 'acme.co.uk',
  domain_verification_status: 'verified', overall_score: 90, overall_rating: 'excellent',
  overall_state: 'established', overall_reason: 'ok',
  last_assessed_at: '2026-07-15T00:00:00Z', evidence_freshness: 'current',
  evidence_age_days: 1, freshness_reason: 'Last assessed yesterday.',
  evidence_completeness: 8, latest_scan_id: 'sc_new', latest_scan_quality: 'complete',
  priority: 'low', attention_required: false, highest_severity: null,
  attention_reasons: [], open_case_count: 0,
  domain_state_counts: { issue_detected: 0, worsening: 0, unknown: 0, stale: 0, customer_input_required: 0, assessed_healthy: 8 },
  cyber_mot_domains: eight(), drill_down: { workspace_id: 'ws1', domain_id: 'd1', scan_id: 'sc_new' },
  ...o,
})
const mkResp = (rows, o = {}) => ({
  domains: rows,
  summary: {
    total_domains: rows.length, total_customers: 1, assessed_domains: rows.length,
    unassessed_domains: 0, attention_required: rows.filter((r) => r.attention_required).length,
    stale_domains: 0, worsening_domains: 0, open_cases: 0,
    priority_distribution: { critical: 0, high: 0, medium: 0, low: rows.length, unknown: 0 },
    by_domain: [], coverage_note: null, ...(o.summary || {}),
  },
  portfolio_state: 'available', portfolio_state_reason: 'Based on all 1 monitored domain.',
  pagination: { limit: 25, offset: 0, total: rows.length },
  generated_at: '2026-07-16T10:00:00Z', ...o,
})

const renderPage = async (resp) => {
  api.getPortfolioDomains.mockResolvedValue(resp)
  render(<MemoryRouter><PortfolioDomainsPage /></MemoryRouter>)
  await screen.findByText('Domain state & trend')
}

beforeEach(() => vi.clearAllMocks())

describe('PortfolioDomainsPage — honesty', () => {
  it('renders all EIGHT domains for a row, never fewer', async () => {
    await renderPage(mkResp([mkRow()]))
    for (const k of CYBER_MOT_KEYS) {
      expect(screen.getAllByText(k.replace(/_/g, ' ')).length).toBeGreaterThan(0)
    }
  })

  it('a never-assessed domain renders as Not assessed, NEVER Healthy', async () => {
    const cells = eight(Object.fromEntries(CYBER_MOT_KEYS.map((k) => [k, {
      state: 'not_yet_assessed', trend: 'insufficient_history',
      trend_reason: 'No assessment has been recorded for this domain yet.',
      evidence_freshness: 'none', evidence_age_days: null,
      freshness_reason: 'No assessment has been recorded for this domain yet.',
      summary: 'Not yet assessed — no completed assessment has recorded a state for this domain.',
    }])))
    await renderPage(mkResp([mkRow({
      cyber_mot_domains: cells, overall_score: null, overall_rating: null,
      overall_reason: 'No completed assessment has established a posture for this domain yet.',
      priority: 'unknown', attention_required: true, evidence_freshness: 'none',
      evidence_age_days: null, freshness_reason: 'No assessment has been recorded for this domain yet.',
      domain_state_counts: { issue_detected: 0, worsening: 0, unknown: 8, stale: 0, customer_input_required: 0, assessed_healthy: 0 },
    })]))
    // Scoped to the ROWS, not the document: the legend legitimately contains the word
    // "Healthy" as a vocabulary explanation, and asserting document-wide would make this
    // test pass or fail on the legend's copy rather than on what the row claims.
    const rows = within(screen.getByTestId('portfolio-rows'))
    expect(rows.queryByText('Healthy')).toBeNull()
    expect(rows.getAllByText('Not assessed').length).toBe(8)
    // Never assessed must not read as a clean, low-priority customer.
    expect(rows.queryByText('Low priority')).toBeNull()
    expect(rows.getByText('Unknown priority')).toBeInTheDocument()
    expect(rows.getByText('Never assessed')).toBeInTheDocument()
  })

  it('NEVER prints a score placeholder when there is no score', async () => {
    await renderPage(mkResp([mkRow({
      overall_score: null, overall_rating: null,
      overall_reason: 'No completed assessment has established a posture for this domain yet.',
    })]))
    const html = document.body.innerHTML
    expect(html).not.toMatch(/null\/100|undefined\/100|NaN\/100|—\/100/)
    expect(screen.getByText(/No completed assessment has established a posture/)).toBeInTheDocument()
  })

  it('a NaN score is not renderable and cannot leak a rating', async () => {
    await renderPage(mkResp([mkRow({ overall_score: NaN, overall_rating: 'excellent', overall_reason: 'no posture' })]))
    expect(document.body.innerHTML).not.toMatch(/NaN/)
  })

  it('"no history" renders as No history, NEVER as Stable', async () => {
    const cells = eight({ email_protection: {
      trend: 'insufficient_history',
      trend_reason: 'Only one assessment has been recorded — a trend needs at least two comparable assessments.',
    } })
    await renderPage(mkResp([mkRow({ cyber_mot_domains: cells })]))
    const email = screen.getByTitle(/email protection[\s\S]*Trend: No history/i)
    expect(email).toBeInTheDocument()
    expect(email.getAttribute('title')).not.toMatch(/Trend: Stable/)
  })

  it('disappeared evidence renders Not comparable, never Recovered/Improving', async () => {
    const cells = eight({ email_protection: {
      state: 'evidence_insufficient', trend: 'not_comparable',
      trend_reason: 'This domain could not be assessed in the latest scan (evidence_insufficient); the previous result is not evidence that it has been resolved.',
      summary: 'Required evidence could not be collected this scan.',
    } })
    await renderPage(mkResp([mkRow({ cyber_mot_domains: cells })]))
    const t = screen.getByTitle(/email protection[\s\S]*not evidence that it has been resolved/i)
    expect(t.getAttribute('title')).toMatch(/Trend: Not comparable/)
    expect(t.getAttribute('title')).not.toMatch(/Recovered|Improving/)
  })

  it('a resolver-version change is never shown as the customer worsening', async () => {
    const cells = eight({ website_security: {
      trend: 'not_comparable',
      trend_reason: 'The way this domain is assessed changed between these two assessments, so the difference would not describe a change in your security posture.',
    } })
    await renderPage(mkResp([mkRow({ cyber_mot_domains: cells })]))
    const t = screen.getByTitle(/website security[\s\S]*would not describe a change in your security posture/i)
    expect(t.getAttribute('title')).toMatch(/Trend: Not comparable/)
    expect(t.getAttribute('title')).not.toMatch(/Worsening|New risk/)
  })

  it('stale evidence is visible on the row and on the domain cell', async () => {
    const cells = eight({ certificates_trust: {
      evidence_freshness: 'stale', evidence_age_days: 400,
      freshness_reason: 'Last assessed 400 days ago — this evidence is stale and may no longer reflect the current posture.',
    } })
    await renderPage(mkResp([mkRow({
      cyber_mot_domains: cells, evidence_freshness: 'stale', evidence_age_days: 400,
      freshness_reason: 'Last assessed 400 days ago — this evidence is stale and may no longer reflect the current posture.',
      priority: 'unknown', attention_required: true,
    })]))
    expect(screen.getByText('Stale')).toBeInTheDocument()
    expect(screen.getByText('stale evidence')).toBeInTheDocument()
    expect(screen.getAllByText(/400 days ago/).length).toBeGreaterThan(0)
  })

  it('a CRITICAL domain is not hidden behind a healthy overall score', async () => {
    const cells = eight({ email_protection: {
      state: 'issue_detected', highest_severity: 'critical', finding_count: 1,
      summary: '1 issue detected.', trend: 'new_risk',
      trend_reason: 'A new issue was detected that was not present in the previous assessment (dmarc_missing).',
    } })
    await renderPage(mkResp([mkRow({
      overall_score: 86, overall_rating: 'good', cyber_mot_domains: cells,
      priority: 'critical', attention_required: true, highest_severity: 'critical',
      attention_reasons: [{ domain_key: 'email_protection', kind: 'issue_detected', severity: 'critical', detail: 'Email Protection: 1 issue detected.' }],
      domain_state_counts: { issue_detected: 1, worsening: 1, unknown: 0, stale: 0, customer_input_required: 0, assessed_healthy: 7 },
    })]))
    // The favourable 86 is shown, AND the critical domain is on the same row.
    const rows = within(screen.getByTestId('portfolio-rows'))
    expect(rows.getByText('86')).toBeInTheDocument()
    expect(rows.getByText('Critical priority')).toBeInTheDocument()
    expect(rows.getByText('Issue detected')).toBeInTheDocument()
  })

  it('an unrecognised backend state renders as unknown (slate), never as benign', async () => {
    const cells = eight({ brand_protection: { state: 'some_new_state_we_do_not_know', trend: 'brand_new_trend' } })
    await renderPage(mkResp([mkRow({ cyber_mot_domains: cells })]))
    const cell = screen.getByTitle(/brand protection/i)
    expect(cell.className).toMatch(/slate/)
    expect(cell.className).not.toMatch(/emerald|green/)
  })

  it('an empty portfolio states why rather than implying all-clear', async () => {
    await renderPage(mkResp([], {
      portfolio_state: 'no_workspaces',
      portfolio_state_reason: 'No customer environments are being monitored yet.',
      summary: { total_domains: 0, total_customers: 0, assessed_domains: 0, unassessed_domains: 0, attention_required: 0, stale_domains: 0, worsening_domains: 0, open_cases: 0, priority_distribution: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }, by_domain: [], coverage_note: null },
      pagination: { limit: 25, offset: 0, total: 0 },
    }))
    const empty = screen.getByTestId('portfolio-empty')
    expect(within(empty).getByText('No domains in your portfolio yet')).toBeInTheDocument()
    expect(within(empty).getByText('No customer environments are being monitored yet.')).toBeInTheDocument()
    // The empty state itself must not reach for reassurance. Scoped to that element: the
    // legend below it explains the word "Healthy", which is vocabulary, not a verdict.
    expect(empty.textContent).not.toMatch(/all clear|no issues|healthy|secure|protected/i)
    // And no row is rendered at all, so nothing can imply a state.
    expect(screen.queryByTestId('portfolio-rows')).toBeNull()
  })

  it('a partial portfolio discloses its blind spot rather than averaging it away', async () => {
    await renderPage(mkResp([mkRow()], {
      portfolio_state: 'partial',
      summary: { total_domains: 3, total_customers: 2, assessed_domains: 1, unassessed_domains: 2, attention_required: 0, stale_domains: 0, worsening_domains: 0, open_cases: 0, priority_distribution: { critical: 0, high: 0, medium: 0, low: 1, unknown: 2 }, by_domain: [], coverage_note: '2 of 3 monitored domains have no completed assessment and are not represented in the state counts above.' },
    }))
    expect(screen.getByText(/not represented in the state counts above/)).toBeInTheDocument()
  })

  it('the plan gate renders for an un-entitled user rather than an empty portfolio', async () => {
    const err = Object.assign(new Error('plan_feature_required'), {
      error: 'plan_feature_required', feature: 'portfolio_monitoring', required_plan: 'business', upgrade_url: '/billing',
    })
    api.getPortfolioDomains.mockRejectedValue(err)
    render(<MemoryRouter><PortfolioDomainsPage /></MemoryRouter>)
    // The critical property: an un-entitled user must NOT see a zeroed portfolio, which
    // would read as "you have no problems" rather than "you cannot see this".
    expect((await screen.findAllByText(/upgrade|business|plan/i)).length).toBeGreaterThan(0)
    expect(screen.queryByText('Domain state & trend')).toBeNull()
    expect(screen.queryByTestId('portfolio-rows')).toBeNull()
    expect(screen.queryByTestId('portfolio-empty')).toBeNull()
  })

  it('drill-down targets the authorised scan id, not a hostname lookup', async () => {
    await renderPage(mkResp([mkRow()]))
    const link = screen.getByRole('link', { name: /View the assessment behind this/ })
    expect(link.getAttribute('href')).toBe('/scans/sc_new')
  })
})
