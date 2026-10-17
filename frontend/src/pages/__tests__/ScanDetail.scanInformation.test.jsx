import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import ScanDetail, { shortScanId } from '../ScanDetail'
import { api } from '../../api'

// Scan Information panel (founder, 17 Oct 2026): label | value grid whose value
// column has min-width 0 and wraps anywhere, so nothing is clipped at the right
// edge; the scan id is shortened on one line with a Copy button carrying the
// full id (tooltip too); status and band chips never break onto two lines.

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

describe('shortScanId', () => {
  it('keeps the prefix and the tail on one line, leaves short ids alone', () => {
    expect(shortScanId(FULL_ID)).toBe('scan_bc7a…b732')
    expect(shortScanId('scan_4f100e6d')).toBe('scan_4f100e6d')
    expect(shortScanId(null)).toBe('')
  })
})

describe('Scan Information panel', () => {
  it('shortens the id in monospace with the full id as tooltip and copy payload', async () => {
    const writeText = vi.fn().mockResolvedValue()
    Object.assign(navigator, { clipboard: { writeText } })
    const panel = await renderPage()
    const short = within(panel).getByTestId('scan-id-short')
    expect(short).toHaveTextContent('scan_bc7a…b732')
    expect(short).toHaveClass('mono', 'whitespace-nowrap')
    expect(short).toHaveAttribute('title', FULL_ID)
    const copy = within(panel).getByRole('button', { name: `Copy scan ID ${FULL_ID}` })
    expect(copy).toHaveAttribute('title', FULL_ID)
    fireEvent.click(copy)
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(FULL_ID))
    expect(await within(panel).findByText('Copied')).toBeInTheDocument()
    expect(within(panel).queryByText(FULL_ID)).toBeNull()
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
