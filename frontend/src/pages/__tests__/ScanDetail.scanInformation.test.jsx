import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import ScanDetail, { shortScanId } from '../ScanDetail'
import { api } from '../../api'

// Scan Information panel: the scan id is shortened with a copy button that
// carries the full id; the domain wraps rather than truncates; status and band
// chips never break onto two lines; labels read in normal case and stack above
// their values on narrow widths. A partial / withheld score is never a
// headline "100 / 100".

vi.mock('../../api', () => ({
  api: {
    getScan: vi.fn(), getScanReport: vi.fn(), getExecutiveReportV2: vi.fn(), getScanReportPdf: vi.fn(),
    getFindingWaivers: vi.fn(), waiveFinding: vi.fn(), unwaiveFinding: vi.fn(), getWorkspaceScans: vi.fn(),
  },
}))
vi.mock('../../components/ExecutiveReportV2', () => ({ default: () => <div>Executive report</div> }))

const FULL_ID = 'scan_ea24c1f3-9b7e-4d2a-8c5f-0a1b2c3d80ff'
const scan = (over = {}) => ({ id: FULL_ID, domain: 'a-rather-long-business-name-with-hyphens.co.uk', status: 'completed', score: 100, rating: 'excellent', scan_quality: 'partial', created_at: '2026-10-16T09:00:00Z', ...over })
const withheld = { quality: 'partial', provisional: true, authoritative: false, comparable: false, display_score: 100, display_rating: null, message: 'The Cyber Metrics Score is withheld because attack surface did not complete this scan.' }
const established = { quality: 'complete', provisional: false, authoritative: true, comparable: true, display_score: 82, display_rating: 'good' }
const report = (assessment, over = {}) => ({ scan_id: FULL_ID, domain: 'a-rather-long-business-name-with-hyphens.co.uk', status: 'completed', cyber_metrics_score: assessment.display_score, risk_level: assessment.display_rating, assessment, findings: [], recommendations: [], modules: {}, scan_quality: { status: assessment.quality }, cyber_mot_domains: [], started_at: '2026-10-16T09:00:01Z', completed_at: '2026-10-16T09:01:31Z', ...over })

async function renderPage(s, r) {
  api.getScan.mockResolvedValue({ scan: s, report_availability: { status: 'report_ready', retryable: false } })
  api.getScanReport.mockResolvedValue(r)
  api.getExecutiveReportV2.mockRejectedValue(new Error('not in this fixture'))
  api.getFindingWaivers.mockResolvedValue({ waivers: [] })
  render(<MemoryRouter initialEntries={[`/scans/${s.id}`]}><Routes><Route path="/scans/:id" element={<ScanDetail />} /></Routes></MemoryRouter>)
  await screen.findByText('Scan Information')
  await waitFor(() => expect(api.getScanReport).toHaveBeenCalled())
  return screen.getByText('Scan Information').closest('.card')
}

beforeEach(() => { vi.clearAllMocks(); localStorage.clear() })

describe('shortScanId', () => {
  it('keeps the prefix and the tail, leaves short ids alone', () => {
    expect(shortScanId(FULL_ID)).toBe('scan_ea24…80ff')
    expect(shortScanId('scan_4f100e6d')).toBe('scan_4f100e6d')
    expect(shortScanId(null)).toBe('')
  })
})

describe('Scan Information panel', () => {
  it('shows the shortened id in monospace with the full id in the title and the copy payload; the raw id appears nowhere', async () => {
    const writeText = vi.fn().mockResolvedValue()
    Object.assign(navigator, { clipboard: { writeText } })
    const panel = await renderPage(scan(), report(established))
    const short = within(panel).getByTestId('scan-id-short')
    expect(short).toHaveTextContent('scan_ea24…80ff')
    expect(short).toHaveClass('mono')
    expect(short).toHaveAttribute('title', FULL_ID)
    const copy = within(panel).getByRole('button', { name: `Copy scan ID ${FULL_ID}` })
    expect(copy).toHaveAttribute('title', FULL_ID)
    fireEvent.click(copy)
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(FULL_ID))
    expect(await within(panel).findByText('Copied')).toBeInTheDocument()
    expect(screen.queryByText(FULL_ID)).toBeNull()
  })

  it('wraps the domain, keeps chips on one line, uses normal-case stacked labels and the short band label', async () => {
    const panel = await renderPage(scan(), report(established))
    const domain = within(panel).getByTestId('scan-info-domain')
    expect(domain).toHaveClass('break-words')
    expect(domain.className).not.toMatch(/truncate/)
    expect(screen.getByRole('heading', { level: 1 }).className).not.toMatch(/truncate/)
    for (const chip of [within(panel).getByText('Partial results'), within(panel).getByTestId('scan-band-chip')]) {
      expect(chip).toHaveClass('whitespace-nowrap')
    }
    expect(within(panel).getByText('Assessment band')).toBeInTheDocument()
    expect(within(panel).queryByText(/CyberMeters assessment band/)).toBeNull()
    const rows = within(panel).getAllByTestId('scan-info-row')
    expect(rows.length).toBeGreaterThan(4)
    for (const row of rows) {
      // Stacked by default (390 / 1024 / 1280 sidebars), side by side only from xl.
      expect(row).toHaveClass('flex-col')
      expect(row.className).not.toMatch(/(^|\s)flex-row/)
      const label = row.firstElementChild
      expect(label.className).not.toMatch(/uppercase/)
    }
  })

  it('partial + withheld: explanation first, no headline 100 / 100, the number small and labelled provisional', async () => {
    const panel = await renderPage(scan(), report(withheld))
    expect(within(panel).queryByTestId('scan-score-headline')).toBeNull()
    expect(within(panel).queryByText('100 / 100', { selector: '.font-bold' })).toBeNull()
    const block = within(panel).getByTestId('scan-score-withheld')
    const explanation = within(block).getByText(withheld.message)
    const number = within(block).getByText('100 / 100')
    expect(explanation.compareDocumentPosition(number) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(number.parentElement).toHaveClass('text-xs')
    expect(number.parentElement).toHaveTextContent('provisional')
    expect(within(panel).getByText('Provisional Score')).toBeInTheDocument()
    expect(within(panel).getByTestId('scan-band-chip')).toHaveTextContent('Withheld until a complete scan')
    // The technical report hero follows the same rule.
    const hero = screen.getByTestId('hero-score-withheld')
    expect(hero).toHaveTextContent(withheld.message)
    expect(hero).toHaveTextContent('Provisional score 100 / 100')
    expect(screen.queryByText('/100')).toBeNull()
  })

  it('an established score stays a headline', async () => {
    const panel = await renderPage(scan({ scan_quality: 'complete', score: 82, rating: 'good' }), report(established))
    expect(within(panel).getByTestId('scan-score-headline')).toHaveTextContent('82 / 100')
    expect(within(panel).queryByTestId('scan-score-withheld')).toBeNull()
    expect(within(panel).getByTestId('scan-band-chip')).toHaveTextContent('Good')
  })
})
