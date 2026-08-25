import React from 'react'
import { render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import ScanDetail from '../ScanDetail'
import { api } from '../../api'

vi.mock('../../api', () => ({
  api: {
    getScan: vi.fn(),
    getScanReport: vi.fn(),
    getExecutiveReportV2: vi.fn(),
    getScanReportPdf: vi.fn(),
    getFindingWaivers: vi.fn(),
    waiveFinding: vi.fn(),
    unwaiveFinding: vi.fn(),
  },
}))

vi.mock('../../components/ExecutiveReportV2', () => ({
  default: () => <div>Executive report</div>,
}))

const REPORT_READY = {
  status: 'report_ready',
  retryable: false,
  snapshot_id: 'snapshot-honesty',
}

const PARTIAL_ASSESSMENT = {
  raw_score: 85,
  display_score: 85,
  display_rating: null,
  quality: 'partial',
  provisional: true,
  authoritative: false,
  comparable: false,
  message: 'Some checks were not completed. This score is provisional.',
}

const COMPLETE_ASSESSMENT = {
  raw_score: 82,
  display_score: 82,
  display_rating: 'good',
  quality: 'complete',
  provisional: false,
  authoritative: true,
  comparable: true,
  message: null,
}

const SUPPRESSED_ASSESSMENT = {
  raw_score: null,
  display_score: null,
  display_rating: null,
  quality: 'partial',
  provisional: true,
  authoritative: false,
  comparable: false,
  message: 'The Cyber Metrics Score is withheld because attack surface did not complete this scan.',
  suppression_reason: 'The Cyber Metrics Score is withheld because attack surface did not complete this scan.',
}

function historicalChanges(overrides = {}) {
  return {
    has_previous: true,
    previous_scan_id: 'scan-previous',
    previous_score: 82,
    current_score: 85,
    score_change: 3,
    comparable: false,
    new_subdomains: ['new.example.com'],
    removed_subdomains: ['old.example.com'],
    new_findings: [{ title: 'New comparative finding' }],
    resolved_findings: [{ title: 'Resolved comparative finding' }],
    new_takeover_risks: [{ host: 'takeover.example.com' }],
    new_exposed_assets: [{ host: 'admin.example.com' }],
    ...overrides,
  }
}

function scanFixture(overrides = {}) {
  return {
    id: 'scan_4f100e6d',
    domain: 'cybermeters.com',
    status: 'completed',
    score: 85,
    rating: 'good',
    scan_quality: 'partial',
    created_at: '2026-07-31T10:00:00Z',
    ...overrides,
  }
}

function reportFixture(overrides = {}) {
  return {
    scan_id: 'scan_4f100e6d',
    domain: 'cybermeters.com',
    status: 'completed',
    cyber_metrics_score: 85,
    risk_level: null,
    assessment: PARTIAL_ASSESSMENT,
    findings: [],
    recommendations: [],
    modules: {
      historical_changes: historicalChanges(),
    },
    scan_quality: {
      status: 'partial',
      modules_skipped: ['ssl', 'headers', 'subdomains'],
      warnings: ['Module incomplete: headers'],
    },
    cyber_mot_domains: [],
    started_at: '2026-07-31T10:00:01Z',
    completed_at: '2026-07-31T10:01:01Z',
    ...overrides,
  }
}

async function renderFixture({ scan = scanFixture(), report = reportFixture() } = {}) {
  api.getScan.mockResolvedValue({ scan, report_availability: REPORT_READY })
  api.getScanReport.mockResolvedValue(report)
  api.getExecutiveReportV2.mockRejectedValue(new Error('not available in focused fixture'))

  render(
    <MemoryRouter initialEntries={[`/scans/${scan.id}`]}>
      <Routes>
        <Route path="/scans/:id" element={<ScanDetail />} />
      </Routes>
    </MemoryRouter>,
  )

  await waitFor(() => expect(api.getScanReport).toHaveBeenCalledTimes(1))
  await screen.findByText('Scan Information')
}

function cardForHeading(text) {
  const heading = screen.getByText(text)
  const card = heading.closest('.card')
  expect(card).not.toBeNull()
  return card
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
})

describe('ScanDetail evidence honesty', () => {
  it('A: partial canonical score and null rating override divergent raw scan presentation', async () => {
    await renderFixture({ scan: scanFixture({ score: 99 }) })

    const scanInfo = cardForHeading('Scan Information')
    expect(within(scanInfo).getByText('Provisional Score')).toBeInTheDocument()
    expect(within(scanInfo).getByText('85 / 100')).toBeInTheDocument()
    expect(within(scanInfo).queryByText('99 / 100')).not.toBeInTheDocument()
    expect(within(scanInfo).queryByText('99')).not.toBeInTheDocument()
    expect(within(scanInfo).getByText('Not assessed')).toBeInTheDocument()
    expect(within(scanInfo).queryByText('Good')).not.toBeInTheDocument()
    expect(screen.queryByText('Excellent')).not.toBeInTheDocument()
  })

  it('reason A: canonical assessment message outranks skipped modules and warnings', async () => {
    const report = reportFixture({
      scan_quality: {
        status: 'partial',
        modules_skipped: ['headers'],
        warnings: ['Module incomplete: headers'],
      },
    })
    await renderFixture({ report })

    const changes = cardForHeading('Changes Since Last Scan')
    expect(within(changes).getByText('Not comparable')).toBeInTheDocument()
    expect(within(changes).getByText(PARTIAL_ASSESSMENT.message)).toBeInTheDocument()
    expect(within(changes).queryByText(/Headers evidence did not complete this scan/i)).not.toBeInTheDocument()
    expect(within(changes).queryByText('Module incomplete: headers')).not.toBeInTheDocument()
    expect(within(changes).queryByText('Score Comparison')).not.toBeInTheDocument()
    expect(within(changes).queryByText('82')).not.toBeInTheDocument()
    expect(within(changes).queryByText('+3')).not.toBeInTheDocument()
    expect(within(changes).queryByText('New Findings')).not.toBeInTheDocument()
    expect(within(changes).queryByText('Resolved Findings')).not.toBeInTheDocument()
    expect(within(changes).queryByText(/No changes detected/i)).not.toBeInTheDocument()
  })

  it('reason B: backend scan-quality warning is rendered verbatim without frontend causality', async () => {
    const warning = 'Coverage warning supplied by the Worker.'
    const report = reportFixture({
      assessment: { ...PARTIAL_ASSESSMENT, message: null },
      scan_quality: {
        status: 'partial',
        modules_skipped: ['headers'],
        warnings: [warning],
      },
    })
    await renderFixture({ report })

    const changes = cardForHeading('Changes Since Last Scan')
    expect(within(changes).getByText(warning)).toBeInTheDocument()
    expect(within(changes).queryByText(/Headers evidence did not complete this scan/i)).not.toBeInTheDocument()
    expect(within(changes).queryByText(/Changes cannot be compared reliably/i)).not.toBeInTheDocument()
  })

  it('reason C: missing canonical reason uses the bounded consequence-only fallback', async () => {
    const report = reportFixture({
      assessment: { ...PARTIAL_ASSESSMENT, message: null },
      scan_quality: {
        status: 'partial',
        modules_skipped: ['headers'],
        warnings: [],
      },
    })
    await renderFixture({ report })

    const changes = cardForHeading('Changes Since Last Scan')
    expect(within(changes).getByText(
      'This scan is not marked comparable. Historical changes are unavailable.',
    )).toBeInTheDocument()
    expect(within(changes).queryByText(/Headers evidence did not complete this scan/i)).not.toBeInTheDocument()
    expect(within(changes).queryByText(/because|therefore/i)).not.toBeInTheDocument()
  })

  it('C: missing comparable fails closed', async () => {
    const missing = historicalChanges()
    delete missing.comparable
    const report = reportFixture({ modules: { historical_changes: missing } })
    await renderFixture({ report })

    const changes = cardForHeading('Changes Since Last Scan')
    expect(within(changes).getByText('Not comparable')).toBeInTheDocument()
    expect(within(changes).queryByText('Score Comparison')).not.toBeInTheDocument()
    expect(within(changes).queryByText('New Findings')).not.toBeInTheDocument()
  })

  it('C: null comparable fails closed', async () => {
    const report = reportFixture({
      modules: { historical_changes: historicalChanges({ comparable: null }) },
    })
    await renderFixture({ report })

    const changes = cardForHeading('Changes Since Last Scan')
    expect(within(changes).getByText('Not comparable')).toBeInTheDocument()
    expect(within(changes).queryByText('Score Comparison')).not.toBeInTheDocument()
  })

  it('C: unknown comparable fails closed', async () => {
    const report = reportFixture({
      modules: { historical_changes: historicalChanges({ comparable: 'true' }) },
    })
    await renderFixture({ report })

    const changes = cardForHeading('Changes Since Last Scan')
    expect(within(changes).getByText('Not comparable')).toBeInTheDocument()
    expect(within(changes).queryByText('Score Comparison')).not.toBeInTheDocument()
  })

  it('D: complete canonical good rating and comparable history retain positive behavior', async () => {
    const report = reportFixture({
      cyber_metrics_score: 82,
      risk_level: 'good',
      assessment: COMPLETE_ASSESSMENT,
      modules: {
        historical_changes: historicalChanges({
          previous_score: 75,
          current_score: 82,
          score_change: 7,
          comparable: true,
          new_subdomains: [],
          removed_subdomains: [],
          new_findings: [],
          resolved_findings: [{ title: 'Security Headers Not Fully Observed' }],
          new_takeover_risks: [],
          new_exposed_assets: [],
        }),
      },
      scan_quality: { status: 'complete', modules_skipped: [], warnings: [] },
    })
    await renderFixture({
      scan: scanFixture({ score: 82, rating: 'good', scan_quality: 'complete' }),
      report,
    })

    const scanInfo = cardForHeading('Scan Information')
    const changes = cardForHeading('Changes Since Last Scan')
    expect(within(scanInfo).getByText('Good')).toBeInTheDocument()
    expect(within(scanInfo).getByText('82 / 100')).toBeInTheDocument()
    expect(within(changes).getByText('Score Comparison')).toBeInTheDocument()
    expect(within(changes).getByText('75')).toBeInTheDocument()
    expect(within(changes).getByText('82')).toBeInTheDocument()
    expect(within(changes).getByText(/\+7/)).toBeInTheDocument()
    expect(within(changes).getByText('Resolved Findings')).toBeInTheDocument()
    expect(within(changes).getByText('Security Headers Not Fully Observed')).toBeInTheDocument()
  })

  it('E: explicit first scan retains the no-history message', async () => {
    const report = reportFixture({
      modules: {
        historical_changes: historicalChanges({
          has_previous: false,
          comparable: false,
        }),
      },
    })
    await renderFixture({ report })

    const changes = cardForHeading('Changes Since Last Scan')
    expect(within(changes).getByText(/First scan for this domain/i)).toBeInTheDocument()
    expect(within(changes).queryByText('Not comparable')).not.toBeInTheDocument()
  })

  it('F: missing canonical assessment never falls back to raw score or rating', async () => {
    const report = reportFixture({ assessment: undefined })
    await renderFixture({ scan: scanFixture({ score: 99 }), report })

    const scanInfo = cardForHeading('Scan Information')
    expect(within(scanInfo).getByText('—')).toBeInTheDocument()
    expect(within(scanInfo).queryByText('99 / 100')).not.toBeInTheDocument()
    expect(within(scanInfo).queryByText('99')).not.toBeInTheDocument()
    expect(within(scanInfo).getByText('Not assessed')).toBeInTheDocument()
    expect(within(scanInfo).queryByText('Good')).not.toBeInTheDocument()
    expect(within(scanInfo).queryByText('Excellent')).not.toBeInTheDocument()
  })

  it('F: null canonical display score never falls back to the raw score', async () => {
    const report = reportFixture({
      assessment: { ...PARTIAL_ASSESSMENT, display_score: null },
    })
    await renderFixture({ scan: scanFixture({ score: 99 }), report })

    const scanInfo = cardForHeading('Scan Information')
    expect(within(scanInfo).getByText('Provisional Score')).toBeInTheDocument()
    expect(within(scanInfo).getByText('—')).toBeInTheDocument()
    expect(within(scanInfo).queryByText('99 / 100')).not.toBeInTheDocument()
    expect(within(scanInfo).queryByText('99')).not.toBeInTheDocument()
  })

  it('F: a suppressed score renders the backend reason in Scan Information', async () => {
    const report = reportFixture({
      cyber_metrics_score: null,
      risk_level: null,
      assessment: SUPPRESSED_ASSESSMENT,
    })
    await renderFixture({ scan: scanFixture({ score: 99, rating: 'good' }), report })

    const scanInfo = cardForHeading('Scan Information')
    expect(within(scanInfo).getByText('Provisional Score')).toBeInTheDocument()
    expect(within(scanInfo).getByText('—')).toBeInTheDocument()
    expect(within(scanInfo).getByText(SUPPRESSED_ASSESSMENT.suppression_reason)).toBeInTheDocument()
    expect(within(scanInfo).queryByText('99 / 100')).not.toBeInTheDocument()
    expect(within(scanInfo).queryByText('Good')).not.toBeInTheDocument()
  })

  it('F2: a withheld historical redirect conclusion renders no stale score, band or BRI', async () => {
    // P1-2 (R1): after the atomic historical invalidation the API sends a
    // non-authoritative withheld assessment and NO business risk. The real
    // render must show the reason and none of the stale 85/good conclusions.
    const WITHHELD =
      'The recorded HTTP hop did not serve a response, so whether this site ' +
      'redirected to HTTPS was never observed; the historical defect conclusion is withheld.'
    const report = reportFixture({
      cyber_metrics_score: null,
      risk_level: null,
      business_risk: null,
      assessment: {
        raw_score: null,
        display_score: null,
        display_rating: null,
        quality: 'complete',
        provisional: true,
        authoritative: false,
        comparable: false,
        message: WITHHELD,
        suppression_reason: WITHHELD,
      },
    })
    await renderFixture({ scan: scanFixture({ score: 85, rating: 'good' }), report })

    const scanInfo = cardForHeading('Scan Information')
    expect(within(scanInfo).getByText(WITHHELD)).toBeInTheDocument()
    expect(within(scanInfo).queryByText('85 / 100')).not.toBeInTheDocument()
    expect(within(scanInfo).queryByText('Good')).not.toBeInTheDocument()
    expect(screen.queryByText('Business Risk Score')).not.toBeInTheDocument()
  })

  it('G: observed partial finding stays visible without becoming a new-change claim', async () => {
    const observed = {
      id: 'finding-observed',
      title: 'Observed HTTPS Weakness',
      description: 'This condition was positively observed in the evidence that completed.',
      severity: 'medium',
      score_impact: -5,
      finding_type: 'finding',
    }
    const report = reportFixture({
      findings: [observed],
      modules: {
        historical_changes: historicalChanges({
          comparable: false,
          new_findings: [{ title: observed.title }],
        }),
      },
    })
    await renderFixture({ report })

    const findings = cardForHeading('Findings (1)')
    const changes = cardForHeading('Changes Since Last Scan')
    expect(within(findings).getByText(observed.title)).toBeInTheDocument()
    expect(within(changes).getByText('Not comparable')).toBeInTheDocument()
    expect(within(changes).queryByText('New Findings')).not.toBeInTheDocument()
    expect(within(changes).queryByText(observed.title)).not.toBeInTheDocument()
  })
})
