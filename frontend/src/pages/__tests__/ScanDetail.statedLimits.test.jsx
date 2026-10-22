import React from 'react'
import { render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import ScanDetail from '../ScanDetail'
import { api } from '../../api'

vi.mock('../../api', () => ({ api: {
  getScan: vi.fn(), getScanReport: vi.fn(), getExecutiveReportV2: vi.fn(),
  getScanReportPdf: vi.fn(), getFindingWaivers: vi.fn(), waiveFinding: vi.fn(), unwaiveFinding: vi.fn(),
} }))
vi.mock('../../components/ExecutiveReportV2', () => ({ default: () => <div>Executive report</div> }))
const PARTIAL_ASSESSMENT = { raw_score: 85, display_score: 85, display_rating: null,
  quality: 'partial', provisional: true, authoritative: false, comparable: false,
  message: 'Some checks were not completed. This score is provisional.' }
const COMPLETE_ASSESSMENT = { raw_score: 82, display_score: 82, display_rating: 'good',
  quality: 'complete', provisional: false, authoritative: true, comparable: true, message: null }
const scanFixture = (overrides = {}) => ({ id: 'scan_checks', domain: 'cybermeters.com', status: 'completed',
  score: 85, rating: 'good', scan_quality: 'partial', created_at: '2026-10-16T08:55:00Z', ...overrides })
const reportFixture = (overrides = {}) => ({ scan_id: 'scan_checks', domain: 'cybermeters.com', status: 'completed',
  cyber_metrics_score: 85, risk_level: null, assessment: PARTIAL_ASSESSMENT,
  findings: [], recommendations: [], modules: {}, scan_quality: { status: 'partial', warnings: [] },
  cyber_mot_domains: [], started_at: '2026-10-16T09:00:00Z', completed_at: '2026-10-16T09:01:00Z', ...overrides })
async function renderFixture({ scan = scanFixture(), report = reportFixture() } = {}) {
  api.getScan.mockResolvedValue({ scan, report_availability: { status: 'report_ready', retryable: false } })
  api.getScanReport.mockResolvedValue(report)
  api.getExecutiveReportV2.mockRejectedValue(new Error('not in this fixture'))
  api.getFindingWaivers.mockResolvedValue({ waivers: [] })
  render(<MemoryRouter initialEntries={[`/scans/${scan.id}`]}><Routes><Route path="/scans/:id" element={<ScanDetail />} /></Routes></MemoryRouter>)
  await waitFor(() => expect(api.getScanReport).toHaveBeenCalledTimes(1))
  await screen.findByText('Scan Information')
}
const cardForHeading = text => screen.getByText(text).closest('.card')
beforeEach(() => { vi.clearAllMocks(); localStorage.clear() })

// 22 Oct 2026: a stated limit renders as the backend's sentence on the scan
// page, never as a reason key, and never as "coverage incomplete".
describe('stated limits of a complete scan', () => {
  const sentence = 'No web service observed on probe.cybermeters.com (ports 80/443 did not answer during this scan); the host is still recorded in your inventory.'
  it('shows the backend sentence and never the reason key', async () => {
    await renderFixture({ scan: scanFixture({ scan_quality: 'complete' }), report: reportFixture({ assessment: COMPLETE_ASSESSMENT,
      scan_quality: { status: 'complete', modules_skipped: [], warnings: [], modules_incomplete: [],
        stated_limits: [{ module: 'asset_exposure', reason: 'no_web_service_answered', hosts: ['probe.cybermeters.com'], message: sentence }] } }) })
    const block = await screen.findByTestId('scan-stated-limits')
    expect(block).toHaveTextContent('probe.cybermeters.com (ports 80/443 did not answer during this scan)')
    expect(document.body).not.toHaveTextContent('no_web_service_answered')
    expect(screen.queryByText('Scan coverage incomplete')).not.toBeInTheDocument()
  })
  it('renders nothing when there are no stated limits', async () => {
    await renderFixture({ scan: scanFixture({ scan_quality: 'complete' }), report: reportFixture({ assessment: COMPLETE_ASSESSMENT,
      scan_quality: { status: 'complete', modules_skipped: [], warnings: [] } }) })
    expect(screen.queryByTestId('scan-stated-limits')).not.toBeInTheDocument()
  })
})
