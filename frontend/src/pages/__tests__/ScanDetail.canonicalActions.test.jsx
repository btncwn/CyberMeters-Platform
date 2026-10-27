import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import ScanDetail from '../ScanDetail'
import { api } from '../../api'

vi.mock('../../api', () => ({ api: {
  getScan: vi.fn(), getScanReport: vi.fn(), getExecutiveReportV2: vi.fn(),
  getScanReportPdf: vi.fn(), getFindingWaivers: vi.fn(), waiveFinding: vi.fn(), unwaiveFinding: vi.fn(),
} }))

const ID = 'scan_canonical_actions'
const scan = { id: ID, domain: 'example.com', status: 'completed', scan_quality: 'complete', created_at: '2026-10-27T10:00:00Z' }
const technical = {
  scan_id: ID, domain: 'example.com', status: 'completed', cyber_metrics_score: 85, risk_level: 'good',
  assessment: { display_score: 85, display_rating: 'good', quality: 'complete' },
  findings: ['email_missing_dmarc', 'tls_legacy_protocol__one', 'tls_legacy_protocol__two'].map((id, i) => ({
    id, title: `Observed finding ${i + 1}`, severity: 'high', finding_type: 'finding',
    module: i ? 'tls_assessment' : 'email_security', score_impact: i ? 0 : -15,
  })),
  recommendations: [{ title: 'Legacy DMARC recommendation', description: 'Legacy advice', priority: 1 }],
  scan_quality: { status: 'complete' },
}
const actions = Object.freeze([
  Object.freeze({ remediation_id: 'email.dmarc.publish', title: 'Frozen DMARC action', action: 'Frozen DMARC steps.', priority: 'high', finding_ids: ['email_missing_dmarc'] }),
  Object.freeze({ remediation_id: 'tls.protocol.disable', title: 'Disable the observed legacy TLS version', action: 'Frozen TLS compatibility steps.', priority: 'high',
    finding_ids: Object.freeze(['tls_legacy_protocol__one', 'tls_legacy_protocol__two']),
    verification_ceiling: 'Can be verified by CyberMeters re-observation.', case_id: 'mc-tls' }),
])
const v2 = {
  cyber_metrics_score: { value: 85, rating: 'good', quality: 'complete' },
  evidence_completeness: { scan_quality: 'complete' }, executive_summary: {}, cyber_mot_domains: [],
  remediation_actions: actions,
}

beforeEach(() => {
  vi.clearAllMocks()
  api.getScan.mockResolvedValue({ scan, report_availability: { status: 'report_ready', retryable: false } })
  api.getScanReport.mockResolvedValue(technical)
  api.getExecutiveReportV2.mockResolvedValue(v2)
  api.getFindingWaivers.mockResolvedValue({ waivers: [] })
})
afterEach(cleanup)

function mount() {
  return render(<MemoryRouter initialEntries={[`/scans/${ID}`]}><Routes><Route path="/scans/:id" element={<ScanDetail />} /></Routes></MemoryRouter>)
}
async function openTechnical() {
  fireEvent.click(await screen.findByRole('button', { name: 'Technical Details', exact: true }))
}
function expectActionCount(count) {
  expect(screen.getByText('Actions').parentElement).toHaveTextContent(new RegExp(`^${count}Actions$`))
  expect(screen.getByRole('heading', { name: `Recommended Actions (${count})`, exact: true })).toBeInTheDocument()
}

describe('Technical Details uses the same frozen actions as Executive/PDF', () => {
  it('keeps the canonical grouping, instructions, verification ceiling and case link', async () => {
    mount()
    const executiveHeading = await screen.findByRole('heading', { name: 'Recommended Actions', exact: true })
    expect(executiveHeading.parentElement).toHaveTextContent('(2)')
    await openTechnical()
    expectActionCount(2)
    expect(screen.getByText('Frozen DMARC action', { exact: true })).toBeInTheDocument()
    expect(screen.getByText('Disable the observed legacy TLS version', { exact: true })).toBeInTheDocument()
    expect(screen.getByText('Frozen TLS compatibility steps.', { exact: true })).toBeInTheDocument()
    expect(screen.getByText('Resolves 2 related findings.', { exact: true })).toBeInTheDocument()
    expect(screen.getByText('Can be verified by CyberMeters re-observation.', { exact: true })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Open the case for this action/ })).toHaveAttribute('href', '/ws/cases/mc-tls')
    expect(screen.queryByText('Legacy DMARC recommendation')).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Findings (3)' })).toBeInTheDocument()
  })

  it('treats a canonical empty array as authoritative instead of reviving old advice', async () => {
    api.getExecutiveReportV2.mockResolvedValue({ ...v2, remediation_actions: [] })
    mount()
    await openTechnical()
    expectActionCount(0)
    expect(screen.getByText('No recommended actions for this assessment.')).toBeInTheDocument()
    expect(screen.queryByText('Legacy DMARC recommendation')).not.toBeInTheDocument()
  })

  it('keeps the legacy fallback when V2 has no canonical action array', async () => {
    api.getExecutiveReportV2.mockResolvedValue({ ...v2, remediation_actions: undefined })
    mount()
    await openTechnical()
    expectActionCount(1)
    expect(screen.getByText('Legacy DMARC recommendation')).toBeInTheDocument()
  })

  it('keeps the legacy fallback when the canonical report is unavailable', async () => {
    api.getExecutiveReportV2.mockRejectedValue(new Error('Snapshot unavailable'))
    mount()
    await waitFor(() => expect(screen.getByText('Legacy DMARC recommendation')).toBeInTheDocument())
    expectActionCount(1)
  })
})
