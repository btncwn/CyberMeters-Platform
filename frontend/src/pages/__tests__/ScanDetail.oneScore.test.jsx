import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import ScanDetail from '../ScanDetail'
import { api } from '../../api'

// Founder live run (24 Oct 2026): Technical Details showed "Cyber Metrics Score 0"
// while the same scan's Executive Report said 100 / 100. One score, one number.
vi.mock('../../api', () => ({
  api: {
    getScan: vi.fn(), getScanReport: vi.fn(), getExecutiveReportV2: vi.fn(), getScanReportPdf: vi.fn(),
    getFindingWaivers: vi.fn(), waiveFinding: vi.fn(), unwaiveFinding: vi.fn(),
  },
}))
vi.mock('../../components/ExecutiveReportV2', () => ({ default: () => <div>Executive report</div> }))

const ID = 'scan_one_score'
const scan = { id: ID, domain: 'example.com', status: 'completed', scan_quality: 'complete', created_at: '2026-10-24T09:59:05Z' }
// The technical report as the running placeholder left it: a zero, no assessment.
const placeholder = { scan_id: ID, domain: 'example.com', status: 'running', cyber_metrics_score: 0, risk_level: 'unknown',
  findings: [], recommendations: [], scan_quality: { status: 'complete' } }
const v2 = { cyber_metrics_score: { value: 100, rating: 'excellent', provisional: false, quality: 'complete', message: null } }

beforeEach(() => {
  vi.clearAllMocks()
  api.getScan.mockResolvedValue({ scan, report_availability: { status: 'report_ready', retryable: false } })
  api.getFindingWaivers.mockResolvedValue({ waivers: [] })
})
const open = async () => {
  render(<MemoryRouter initialEntries={[`/scans/${ID}`]}><Routes><Route path="/scans/:id" element={<ScanDetail />} /></Routes></MemoryRouter>)
  await waitFor(() => expect(api.getScanReport).toHaveBeenCalled())
  fireEvent.click(await screen.findByRole('button', { name: 'Technical Details' }))
}

it('Technical Details shows the Executive Report\'s score, never a different number', async () => {
  api.getScanReport.mockResolvedValue(placeholder)
  api.getExecutiveReportV2.mockResolvedValue(v2)
  await open()
  const hero = (await screen.findAllByText('Cyber Metrics Score')).map((n) => n.parentElement).find((el) => el.textContent.includes('/100'))
  expect(hero).toHaveTextContent('100/100')
  expect(hero.textContent).not.toMatch(/(^|\D)0\/100/)
})

it('without a canonical report, a running placeholder never shows its zero as a score', async () => {
  api.getScanReport.mockResolvedValue(placeholder)
  api.getExecutiveReportV2.mockRejectedValue(new Error('not available'))
  render(<MemoryRouter initialEntries={[`/scans/${ID}`]}><Routes><Route path="/scans/:id" element={<ScanDetail />} /></Routes></MemoryRouter>)
  await waitFor(() => expect(api.getScanReport).toHaveBeenCalled())
  await screen.findAllByText('Cyber Metrics Score')
  expect(document.body.textContent).not.toMatch(/(^|\D)0\/100/)
})

describe('Business Risk card shows the canonical indicator, never a second score', () => {
  const LOW = 'Business risk is low. No major gaps detected across email security, website trust, operational continuity, attack surface, or brand protection.'
  const HIGH = 'Business risk is high. The top risks are: Domain can be spoofed and Website certificate expired.'
  const complete = { scan_quality: 'complete', assessment_quality: 'complete', monitoring_state: 'monitoring_healthy', modules_skipped: [] }
  // The raw report disagrees on purpose: nothing from it may reach the card.
  const raw = { ...placeholder, status: 'completed', business_risk: { score: 37, band: 'Raw Band', summary: 'Raw summary sentence.',
    categories: { email_trust: { score: 41 }, website_trust: { score: 43 } }, top_business_risks: [{ title: 'Raw top risk' }] } }
  const canonical = (indicator, notAssessed = []) => ({ ...v2, business_risk_indicator: indicator,
    evidence_completeness: complete, executive_summary: { not_fully_assessed: notAssessed } })
  const gap = [{ domain_key: 'identity_exposure' }]
  const card = async () => {
    render(<MemoryRouter initialEntries={[`/scans/${ID}`]}><Routes><Route path="/scans/:id" element={<ScanDetail />} /></Routes></MemoryRouter>)
    return (await screen.findByRole('heading', { name: 'Business Risk Indicator' })).closest('.card')
  }
  const expectNoRawValues = (el) => {
    expect(document.body.textContent).not.toContain('Business Risk Score')
    for (const value of ['37', '41', '43', '/ 100', 'Raw Band', 'RAW BAND', 'Raw summary sentence', 'Raw top risk', 'Email Trust']) {
      expect(el.textContent).not.toContain(value)
    }
  }

  it('keeps the Cyber Metrics Score and shows only band + explanation', async () => {
    api.getScanReport.mockResolvedValue(raw)
    api.getExecutiveReportV2.mockResolvedValue(canonical({ band: 'High Business Risk', explanation: HIGH }))
    const el = await card()
    expect(el).toHaveTextContent('HIGH BUSINESS RISK')
    expect(el).toHaveTextContent('Domain can be spoofed')
    expect(el).not.toHaveTextContent('Coverage is incomplete')
    expectNoRawValues(el)
    fireEvent.click(await screen.findByRole('button', { name: 'Technical Details' }))
    const hero = (await screen.findAllByText('Cyber Metrics Score')).map((n) => n.parentElement).find((n) => n.textContent.includes('/100'))
    expect(hero).toHaveTextContent('100/100')
  })

  it('low band with incomplete coverage bounds the no-gaps sentence', async () => {
    api.getScanReport.mockResolvedValue(raw)
    api.getExecutiveReportV2.mockResolvedValue(canonical({ band: 'Low Business Risk', explanation: LOW }, gap))
    const el = await card()
    expect(el).toHaveTextContent('LOW BUSINESS RISK')
    expect(el).toHaveTextContent('No major gaps were identified in the evidence available')
    expect(el).toHaveTextContent('Coverage is incomplete')
    expect(document.body.textContent).not.toContain('No major gaps detected')
    expectNoRawValues(el)
  })

  it('high band with incomplete coverage keeps the named risks and adds the limit', async () => {
    api.getScanReport.mockResolvedValue(raw)
    api.getExecutiveReportV2.mockResolvedValue(canonical({ band: 'High Business Risk', explanation: HIGH }, gap))
    const el = await card()
    expect(el).toHaveTextContent('Domain can be spoofed')
    expect(el).toHaveTextContent('Coverage is incomplete')
    expect(el).not.toHaveTextContent('No major gaps')
  })

  it.each([
    ['null band', { band: null, explanation: 'Business Risk Indicator is not authoritative because monitoring evidence or scan coverage was incomplete.' }, 'not authoritative because monitoring'],
    ['provisional band', { band: 'Low Business Risk', provisional: true, explanation: 'Business Risk Indicator is not authoritative because monitoring evidence or scan coverage was incomplete.' }, 'not authoritative because monitoring'],
  ])('%s is not a final indicator', async (_name, indicator, sentence) => {
    api.getScanReport.mockResolvedValue(raw)
    api.getExecutiveReportV2.mockResolvedValue(canonical(indicator))
    const el = await card()
    expect(el).toHaveTextContent('Not available')
    expect(el).toHaveTextContent(sentence)
    expect(el).not.toHaveTextContent('LOW BUSINESS RISK')
    expectNoRawValues(el)
  })

  it('an unread canonical report never falls back to the raw band or score', async () => {
    api.getScanReport.mockResolvedValue(raw)
    api.getExecutiveReportV2.mockRejectedValue(new Error('not available'))
    const el = await card()
    expect(el).toHaveTextContent('Not available')
    expectNoRawValues(el)
  })
})
