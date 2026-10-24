import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, expect, it, vi } from 'vitest'
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
