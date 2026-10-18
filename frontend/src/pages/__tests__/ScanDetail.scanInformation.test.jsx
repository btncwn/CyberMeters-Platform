import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import ScanDetail from '../ScanDetail'
import { api } from '../../api'
import { formatDate } from '../../utils/dates'

// Scan Information panel (founder, 17 Oct 2026): label | value grid whose value
// column has min-width 0 and wraps anywhere, so nothing is clipped at the right
// edge; the scan id is available only via a copy control and tooltip;
// status and band chips never break onto two lines.

vi.mock('../../api', () => ({
  api: {
    getScan: vi.fn(), getScanReport: vi.fn(), getExecutiveReportV2: vi.fn(), getScanReportPdf: vi.fn(),
    getFindingWaivers: vi.fn(), waiveFinding: vi.fn(), unwaiveFinding: vi.fn(),
  },
}))
vi.mock('../../components/ExecutiveReportV2', () => ({ default: () => <div>Executive report</div> }))

const FULL_ID = 'scan_bc7a4cd9-9b7e-4d2a-8c5f-0a1b2c3db732'
const scan = { id: FULL_ID, domain: 'a-rather-long-business-name-with-hyphens.co.uk', status: 'completed', score: 82, rating: 'good', scan_quality: 'complete', created_at: '2026-10-16T09:00:00Z' }
const report = {
  scan_id: FULL_ID, domain: scan.domain, status: 'completed', cyber_metrics_score: 82, risk_level: 'good',
  assessment: { quality: 'complete', provisional: false, authoritative: true, comparable: true, display_score: 82, display_rating: 'good' },
  findings: [], recommendations: [], modules: {}, scan_quality: { status: 'complete' }, cyber_mot_domains: [],
  started_at: '2026-10-16T09:00:01Z', completed_at: '2026-10-16T09:01:31Z',
}

async function renderPage() {
  api.getScan.mockResolvedValue({ scan, report_availability: { status: 'report_ready', retryable: false } })
  api.getScanReport.mockResolvedValue(report)
  api.getExecutiveReportV2.mockRejectedValue(new Error('not in this fixture'))
  api.getFindingWaivers.mockResolvedValue({ waivers: [] })
  render(<MemoryRouter initialEntries={[`/scans/${scan.id}`]}><Routes><Route path="/scans/:id" element={<ScanDetail />} /></Routes></MemoryRouter>)
  await screen.findByText('Scan Information')
  await waitFor(() => expect(api.getScanReport).toHaveBeenCalled())
  return screen.getByText('Scan Information').closest('.card')
}

beforeEach(() => { vi.clearAllMocks() })

describe('Scan Information panel', () => {
  it('titles the scan by date and keeps its ID only in copy controls and tooltips', async () => {
    const writeText = vi.fn().mockResolvedValue()
    Object.assign(navigator, { clipboard: { writeText } })
    const panel = await renderPage()
    expect(screen.getByRole('heading', { name: `Scan — ${formatDate(scan.created_at)}` })).toBeInTheDocument()
    const copy = within(panel).getByRole('button', { name: 'Copy scan ID' })
    expect(copy).toHaveAttribute('title', FULL_ID)
    fireEvent.click(copy)
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(FULL_ID))
    expect(await within(panel).findByText('Copied')).toBeInTheDocument()
    expect(within(panel).queryByText(FULL_ID)).toBeNull()
    expect(screen.queryByText(/scan_bc7a/)).toBeNull()
  })

  it('lays rows out as a label | value grid whose value wraps anywhere, and keeps chips on one line', async () => {
    const panel = await renderPage()
    const rows = within(panel).getAllByTestId('scan-info-row')
    expect(rows.length).toBeGreaterThan(4)
    for (const row of rows) {
      expect(row).toHaveClass('grid')
      expect(row.className).toMatch(/grid-cols-\[/)
      const value = within(row).getByTestId('scan-info-value')
      expect(value).toHaveClass('min-w-0', '[overflow-wrap:anywhere]')
      expect(value.className).not.toMatch(/truncate/)
      expect(row.firstElementChild.className).not.toMatch(/uppercase/)
    }
    expect(within(panel).getByText(scan.domain)).toBeInTheDocument()
    const statusChip = within(panel).getAllByText('Completed').find((el) => el.className.includes('rounded-full'))
    for (const chip of [statusChip, within(panel).getByTestId('scan-band-chip')]) {
      expect(chip).toHaveClass('whitespace-nowrap')
    }
    expect(within(panel).getByTestId('scan-band-chip')).toHaveTextContent('Good')
  })
})

// Score honesty (follow-up PR, 17 Oct 2026): a partial or band-withheld score is
// never a headline "100 / 100" — the backend's explanation reads first and the
// number follows, small and labelled provisional.
const withheldAssessment = { quality: 'partial', provisional: true, authoritative: false, comparable: false, display_score: 100, display_rating: null, message: 'The Cyber Metrics Score is withheld because attack surface did not complete this scan.' }
const establishedAssessment = { quality: 'complete', provisional: false, authoritative: true, comparable: true, display_score: 82, display_rating: 'good' }
const scoreScan = (over = {}) => ({ ...scan, score: 100, rating: 'excellent', scan_quality: 'partial', ...over })
const scoreReport = (assessment) => ({ ...report, cyber_metrics_score: assessment.display_score, risk_level: assessment.display_rating, assessment, scan_quality: { status: assessment.quality } })
async function renderScore(s, r) {
  api.getScan.mockResolvedValue({ scan: s, report_availability: { status: 'report_ready', retryable: false } })
  api.getScanReport.mockResolvedValue(r)
  api.getExecutiveReportV2.mockRejectedValue(new Error('not in this fixture'))
  api.getFindingWaivers.mockResolvedValue({ waivers: [] })
  render(<MemoryRouter initialEntries={[`/scans/${s.id}`]}><Routes><Route path="/scans/:id" element={<ScanDetail />} /></Routes></MemoryRouter>)
  await screen.findByText('Scan Information')
  await waitFor(() => expect(api.getScanReport).toHaveBeenCalled())
  return screen.getByText('Scan Information').closest('.card')
}

describe('Scan Information — score honesty', () => {
  it('partial + withheld: explanation first, no headline 100 / 100, the number small and labelled provisional', async () => {
    const panel = await renderScore(scoreScan(), scoreReport(withheldAssessment))
    expect(within(panel).queryByTestId('scan-score-headline')).toBeNull()
    expect(within(panel).queryByText('100 / 100', { selector: '.font-bold' })).toBeNull()
    const block = within(panel).getByTestId('scan-score-withheld')
    const explanation = within(block).getByText(withheldAssessment.message)
    const number = within(block).getByText('100 / 100')
    expect(explanation.compareDocumentPosition(number) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(number.parentElement).toHaveClass('text-xs')
    expect(number.parentElement).toHaveTextContent('provisional')
    expect(within(panel).getByText('Provisional Score')).toBeInTheDocument()
    expect(within(panel).getByTestId('scan-band-chip')).toHaveTextContent('Withheld until a complete scan')
    // The technical report hero follows the same rule.
    const hero = screen.getByTestId('hero-score-withheld')
    expect(hero).toHaveTextContent(withheldAssessment.message)
    expect(hero).toHaveTextContent('Provisional score 100 / 100')
    expect(screen.queryByText('/100')).toBeNull()
  })

  it('an established score stays a headline', async () => {
    const panel = await renderScore(scoreScan({ scan_quality: 'complete', score: 82, rating: 'good' }), scoreReport(establishedAssessment))
    expect(within(panel).getByTestId('scan-score-headline')).toHaveTextContent('82 / 100')
    expect(within(panel).queryByTestId('scan-score-withheld')).toBeNull()
    expect(within(panel).getByTestId('scan-band-chip')).toHaveTextContent('Good')
  })
})
