import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import ScanDetail from '../ScanDetail'
import ExecutiveReportV2 from '../../components/ExecutiveReportV2'
import { api } from '../../api'

// R1 11:22: both tabs judge score completeness from the same source, in the same
// order (evidence_completeness.scan_quality ?? cyber_metrics_score.quality), so
// they can never disagree. The Executive Report here is the real component.
vi.mock('../../api', () => ({
  api: {
    getScan: vi.fn(), getScanReport: vi.fn(), getExecutiveReportV2: vi.fn(), getScanReportPdf: vi.fn(),
    getFindingWaivers: vi.fn(), waiveFinding: vi.fn(), unwaiveFinding: vi.fn(),
  },
}))

const ID = 'scan_both_tabs'
const scan = { id: ID, domain: 'example.com', status: 'completed', scan_quality: 'complete', created_at: '2026-10-24T09:59:05Z' }
const technical = { scan_id: ID, domain: 'example.com', status: 'completed', cyber_metrics_score: 100, risk_level: 'excellent',
  assessment: { display_score: 100, display_rating: 'excellent', provisional: false, quality: 'complete' },
  findings: [], recommendations: [], scan_quality: { status: 'complete' } }
const v2 = (evidenceQuality) => ({ cyber_metrics_score: { value: 100, rating: 'excellent', provisional: false, quality: 'complete', message: null },
  evidence_completeness: { scan_quality: evidenceQuality }, executive_summary: {}, cyber_mot_domains: [], remediation_actions: [] })

beforeEach(() => {
  vi.clearAllMocks()
  api.getScan.mockResolvedValue({ scan, report_availability: { status: 'report_ready', retryable: false } })
  api.getScanReport.mockResolvedValue(technical)
  api.getFindingWaivers.mockResolvedValue({ waivers: [] })
})
afterEach(cleanup)

async function technicalHeroShowsNumber(report) {
  api.getExecutiveReportV2.mockResolvedValue(report)
  render(<MemoryRouter initialEntries={[`/scans/${ID}`]}><Routes><Route path="/scans/:id" element={<ScanDetail />} /></Routes></MemoryRouter>)
  await waitFor(() => expect(api.getExecutiveReportV2).toHaveBeenCalled())
  fireEvent.click(await screen.findByRole('button', { name: 'Technical Details' }))
  // The Technical Details hero (the label sits above its ring or its withheld text).
  const labels = await screen.findAllByText('Cyber Metrics Score')
  const hero = labels.map((n) => n.parentElement).find((el) => el.querySelector('svg') || el.querySelector('[data-testid="hero-score-withheld"]'))
  const shows = /100\s*\/\s*100/.test(hero.textContent)
  cleanup()
  return shows
}
function reportShowsNumber(report) {
  render(<MemoryRouter><ExecutiveReportV2 report={report} /></MemoryRouter>)
  const shows = /100\s*\/\s*100/.test(document.body.textContent)
  cleanup()
  return shows
}

describe('both tabs agree on whether the score is shown', () => {
  it('complete evidence: both show 100 / 100', async () => {
    expect(reportShowsNumber(v2('complete'))).toBe(true)
    expect(await technicalHeroShowsNumber(v2('complete'))).toBe(true)
  })
  it('partial evidence (the score\'s own quality still says complete): both withhold the number', async () => {
    expect(reportShowsNumber(v2('partial'))).toBe(false)
    expect(await technicalHeroShowsNumber(v2('partial'))).toBe(false)
  })
})
