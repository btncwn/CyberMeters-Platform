import { render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import ScanDetail from '../ScanDetail'
import { api } from '../../api'

// Founder, 20 Oct 2026: the mail_transport results (MX STARTTLS and the
// certificate) appear on the scan's Technical Details tab, not only under
// Email Protection, from the same shared card and the same module.

vi.mock('../../api', () => ({
  api: {
    getScan: vi.fn(), getScanReport: vi.fn(), getExecutiveReportV2: vi.fn(), getScanReportPdf: vi.fn(),
    getFindingWaivers: vi.fn(), waiveFinding: vi.fn(), unwaiveFinding: vi.fn(),
  },
}))
vi.mock('../../components/ExecutiveReportV2', () => ({ default: () => <div>Executive report</div> }))

const scan = { id: 'scan_mt1', domain: 'example.co.uk', status: 'completed', score: 82, rating: 'good', scan_quality: 'complete', created_at: '2026-10-20T08:55:00Z' }
const TESTED = {
  source: 'mail_transport', state: 'partial', reason: null, coverage: { planned: 2, tested: 1, not_tested: 1 },
  hosts: [
    { host: 'mx1.mail-host.example', priority: 10, tested_address: '203.0.113.25', state: 'tested', starttls_offered: true,
      tls_version: 'tls1_3', cipher: 'TLS_AES_256_GCM_SHA384', cipher_class: 'not_flagged_weak',
      certificate_hostname_match: true, chain_validity: 'valid', certificate_expires_at: '2027-01-15T00:00:00.000Z' },
    { host: 'mx2.mail-host.example', priority: 20, state: 'not_offered', starttls_offered: false },
  ],
}

async function renderTechnical(modules) {
  const report = {
    scan_id: scan.id, domain: scan.domain, status: 'completed', cyber_metrics_score: 82, risk_level: 'good',
    assessment: { quality: 'complete', provisional: false, authoritative: true, comparable: true, display_score: 82, display_rating: 'good' },
    findings: [], recommendations: [], modules, scan_quality: { status: 'complete' }, cyber_mot_domains: [],
    started_at: '2026-10-20T09:00:01Z', completed_at: '2026-10-20T09:01:31Z',
  }
  api.getScan.mockResolvedValue({ scan, report_availability: { status: 'report_ready', retryable: false } })
  api.getScanReport.mockResolvedValue(report)
  api.getExecutiveReportV2.mockRejectedValue(new Error('not in this fixture'))
  api.getFindingWaivers.mockResolvedValue({ waivers: [] })
  render(<MemoryRouter initialEntries={[`/scans/${scan.id}?view=technical`]}><Routes><Route path="/scans/:id" element={<ScanDetail />} /></Routes></MemoryRouter>)
  await waitFor(() => expect(api.getScanReport).toHaveBeenCalled())
  return (await screen.findByText('Mail Transport (MX STARTTLS · Certificate)')).closest('.card')
}

beforeEach(() => { vi.clearAllMocks(); Element.prototype.scrollIntoView = vi.fn() })

describe('Technical Details: mail transport', () => {
  it('shows each MX host: STARTTLS, TLS version, cipher, certificate name, chain and expiry', async () => {
    const card = await renderTechnical({ mail_transport: TESTED, email_security: { mta_sts_detail: { policy_found: true, mode: 'enforce' }, tls_rpt_detail: { record_found: true } } })
    expect(within(card).getByText('mx1.mail-host.example')).toBeInTheDocument()
    expect(within(card).getByText('STARTTLS offered · TLS handshake completed')).toBeInTheDocument()
    expect(within(card).getByText(/TLS 1\.3 · TLS_AES_256_GCM_SHA384 · Hostname matched · Chain valid · Certificate expires/)).toBeInTheDocument()
    expect(within(card).getByText('mx2.mail-host.example')).toBeInTheDocument()
    expect(within(card).getByText('STARTTLS not offered')).toBeInTheDocument()
    expect(within(card).getByText(/MTA-STS: enforce policy observed/)).toBeInTheDocument()
    expect(within(card).getByText(/TLS-RPT: reporting record observed/)).toBeInTheDocument()
    // One heading: the section's, not the card's own as well.
    expect(within(card).queryByText('Mail transport encryption')).toBeNull()
  })

  it('says why nothing was tested, and never reads as encrypted', async () => {
    const card = await renderTechnical({ mail_transport: { source: 'mail_transport', state: 'not_tested', reason: 'verified_workspace_required', hosts: [] } })
    expect(within(card).getByText(/tested only for a domain verified in a workspace/)).toBeInTheDocument()
    expect(within(card).queryByText(/handshake completed/)).toBeNull()
    expect(within(card).getByText(/MTA-STS: enforcement not confirmed/)).toBeInTheDocument()
  })

  it('a scan from before the module existed shows the section without inventing a result', async () => {
    const card = await renderTechnical({})
    expect(within(card).getByText('Mail servers were not tested in this scan.')).toBeInTheDocument()
  })
})
