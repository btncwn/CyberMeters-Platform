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

describe('canonical Checks disclosure', () => {
  const emailReason = 'Email protection data could not be fully verified'
  const checksRow = () => within(cardForHeading('Scan Information')).getByText('Checks').closest('[data-testid="scan-info-row"]')
  const completeRawReport = (assessment) => reportFixture({ assessment,
    scan_quality: { status: 'complete', modules_skipped: [], warnings: [] } })

  it.each(['degraded', 'partial'])('shows the backend area when assessment is %s despite complete raw checks', async (quality) => {
    await renderFixture({ scan: scanFixture({ scan_quality: 'complete' }),
      report: completeRawReport({ ...PARTIAL_ASSESSMENT, quality, coverage: { monitoring_signals: {
        email_protection: { state: 'monitoring_degraded', message: emailReason },
        dns: { state: 'monitoring_healthy', message: 'DNS completed normally' },
      } } }) })
    await waitFor(() => expect(checksRow()).toHaveTextContent(emailReason))
    expect(checksRow()).not.toHaveTextContent('All completed')
    expect(checksRow()).not.toHaveTextContent('DNS completed normally')
    expect(within(cardForHeading('Scan Information')).getByText('Completed')).toBeInTheDocument()
  })

  it('keeps all-completed wording for a complete backend assessment', async () => {
    await renderFixture({ scan: scanFixture({ scan_quality: 'complete' }), report: completeRawReport(COMPLETE_ASSESSMENT) })
    await waitFor(() => expect(checksRow()).toHaveTextContent('All completed'))
    expect(screen.queryByText('Scan coverage incomplete')).not.toBeInTheDocument()
  })

  it.each([undefined, null])('does not invent a budget cause when an incomplete module has reason %s', async (incomplete_reason) => {
    await renderFixture({ report: reportFixture({
      modules: { email_security: { error: 'Email checks unavailable' } },
      scan_quality: { status: 'partial', modules_skipped: ['email_security'],
        modules_incomplete: [{ module: 'email_security', incomplete_reason }], warnings: [] },
    }) })
    const warning = screen.getByText('Scan coverage incomplete').parentElement
    expect(warning).toHaveTextContent('did not complete — not assessed')
    expect(warning).not.toHaveTextContent(/scan budget|timed out|timeout/i)
    expect(warning).not.toHaveTextContent('Checks not completed:')
    expect(checksRow()).not.toHaveTextContent('All completed')
  })

  it('preserves the recorded evidence reason instead of replacing it with noncompletion', async () => {
    await renderFixture({ report: reportFixture({
      scan_quality: { status: 'partial', modules_skipped: [],
        modules_incomplete: [{ module: 'subdomain_takeover', incomplete_reason: 'host_probe_unconfirmed' }], warnings: [] },
    }) })
    const warning = screen.getByText('Scan coverage incomplete').parentElement
    expect(warning).toHaveTextContent('subdomain takeover checks: ran, but evidence was insufficient — some hosts gave an answer that could not be confirmed')
    expect(warning).not.toHaveTextContent('did not complete — not assessed')
  })

  it('shows all backend degraded-area messages without inventing a cause', async () => {
    const dnsReason = 'DNS evidence was unavailable in this run'
    await renderFixture({ scan: scanFixture({ scan_quality: 'complete' }),
      report: completeRawReport({ ...PARTIAL_ASSESSMENT, quality: 'degraded', coverage: { monitoring_signals: {
        email_protection: { state: 'monitoring_degraded', message: emailReason },
        dns: { state: 'signal_unavailable', message: dnsReason },
      } } }) })
    await waitFor(() => expect(checksRow()).toHaveTextContent(emailReason))
    expect(checksRow()).toHaveTextContent(dnsReason)
    expect(checksRow()).not.toHaveTextContent('All completed')
  })

  it('uses report-quality warning when a canonical assessment is unavailable', async () => {
    await renderFixture({ scan: scanFixture({ scan_quality: 'complete' }),
      report: reportFixture({ assessment: null, scan_quality: { status: 'partial', warnings: [emailReason] } }) })
    await waitFor(() => expect(checksRow()).toHaveTextContent(emailReason))
    expect(checksRow()).not.toHaveTextContent('All completed')
  })

  it('stays incomplete without inventing an area when backend detail is missing', async () => {
    await renderFixture({ scan: scanFixture({ scan_quality: 'complete' }),
      report: completeRawReport({ ...PARTIAL_ASSESSMENT, quality: 'degraded' }) })
    await waitFor(() => expect(checksRow()).toHaveTextContent('Some did not complete'))
    expect(checksRow()).not.toHaveTextContent('All completed')
    expect(checksRow()).not.toHaveTextContent('Email protection')
  })
})
