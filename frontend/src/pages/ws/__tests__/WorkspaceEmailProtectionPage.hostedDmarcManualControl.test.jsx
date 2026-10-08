import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { BecExposure, DmarcIngestionStatus, ManagedDmarcCard } from '../WorkspaceEmailProtectionPage'
import { api } from '../../../api'

vi.mock('../../../api', () => ({
  api: {
    getHostedDmarc: vi.fn(),
    setHostedDmarcPolicy: vi.fn(),
    rollbackHostedDmarc: vi.fn(),
    setHostedDmarcAutopilot: vi.fn(),
    getBecExposureScore: vi.fn(),
    getDmarcReportHistory: vi.fn(),
  },
  BASE: 'https://api.example.test/api',
}))

const WS_ID = 'ws_hosted_dmarc_1'
const DOMAIN = 'example.test'

function hostedDmarcResponse({
  automationStatus = 'suspended',
  policyAllowed = true,
  changePending = false,
} = {}) {
  return {
    record: {
      id: 'hosted_dmarc_1',
      status: 'connected',
      current_value: 'v=DMARC1; p=none; rua=mailto:rua@example.test',
      policy_step: { index: 0, policy: 'none', pct: 100 },
      next_step: { label: 'Quarantine 25%', policy: 'quarantine', pct: 25 },
      change_pending: changePending,
      autopilot: false,
      can_rollback: true,
    },
    policy_management_available: policyAllowed,
    compliance: { pass_rate: 100, total_messages: 42, window_days: 7 },
    readiness: { ready: true, reasons: [] },
    hosted_dmarc_interpretation: { automation_status: automationStatus },
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  api.setHostedDmarcPolicy.mockResolvedValue({})
  api.rollbackHostedDmarc.mockResolvedValue({})
  api.setHostedDmarcAutopilot.mockResolvedValue({})
})

const becResponse = (evidence = {}) => ({
  exposure_level: 'medium', exposure_score: 25, confidence: 'medium',
  evidence: {
    dmarc_policy: 'reject', pass_rate: 0, total_messages: 0,
    reports_received: false, cybermeters_rua_verified: false,
    last_report_received_at: '2026-10-06T00:00:00Z',
    known_senders: 0, unknown_senders: 0, suspicious_senders: 0,
    high_volume_failing_senders: 0, failed_messages: 0,
    ...evidence,
  },
  reasons: [{ code: 'no_dmarc_reports', severity: 'medium', label: 'No DMARC reports have been received' }],
  recommended_actions: [{ code: 'enable_dmarc_reporting', priority: 'high', label: 'Enable DMARC aggregate reporting' }],
})

describe('DMARC receipt and BEC assessment evidence scopes', () => {
  it('shows inbound receipt without promoting it into the BEC assessment or displaying an empty 0% rate', async () => {
    const bec = becResponse()
    api.getBecExposureScore.mockResolvedValue(bec)
    api.getDmarcReportHistory.mockResolvedValue({
      totals: { reports: 3, total_messages: 33, last_seen: 1791244800 },
      reports: [{ source: 'inbound_email', authoritative_eligible: false }],
    })
    render(<><BecExposure wsId={WS_ID} domain={DOMAIN} /><DmarcIngestionStatus wsId={WS_ID} domain={DOMAIN} /></>)

    expect(await screen.findByText('Reports received · DNS not verified')).toBeInTheDocument()
    expect(screen.getByText('Yes')).toBeInTheDocument()
    expect(screen.getByText('Not verified')).toBeInTheDocument()
    expect(screen.getByText('Pass rate: Not measured')).toBeInTheDocument()
    expect(screen.getByText('Not measured')).toBeInTheDocument()
    expect(screen.queryByText('Pass rate 0%')).not.toBeInTheDocument()
    expect(screen.queryByText('0%')).not.toBeInTheDocument()
    expect(screen.queryByText('No reports yet')).not.toBeInTheDocument()
    expect(screen.queryByText('No DMARC reports have been received')).not.toBeInTheDocument()
    expect(screen.getAllByText('No customer-submitted reports for this assessment')).toHaveLength(2)
    expect(screen.getByText('Add a report to this assessment')).toBeInTheDocument()
    expect(screen.getByText(/Score 25\/100/)).toBeInTheDocument()
    expect(bec.evidence.reports_received).toBe(false)
    expect(bec.reasons[0].label).toBe('No DMARC reports have been received')
    expect(api.getDmarcReportHistory).toHaveBeenCalledWith(WS_ID, DOMAIN, 1)
  })

  it('preserves a measured zero pass rate when eligible messages really failed', async () => {
    api.getBecExposureScore.mockResolvedValue(becResponse({ total_messages: 10, failed_messages: 10, reports_received: true }))
    api.getDmarcReportHistory.mockResolvedValue({ totals: { reports: 1, last_seen: 1791244800 } })
    render(<><BecExposure wsId={WS_ID} domain={DOMAIN} /><DmarcIngestionStatus wsId={WS_ID} domain={DOMAIN} /></>)

    expect(await screen.findByText('Pass rate 0%')).toBeInTheDocument()
    expect(await screen.findByText('Customer-submitted sender activity · BEC assessment')).toBeInTheDocument()
    expect(screen.queryByText('Not measured')).not.toBeInTheDocument()
    expect(screen.queryByText('Pass rate: Not measured')).not.toBeInTheDocument()
  })

  it('does not infer DMARC receipt from a shared endpoint date when DMARC history is empty', async () => {
    api.getBecExposureScore.mockResolvedValue(becResponse())
    api.getDmarcReportHistory.mockResolvedValue({ totals: { reports: 0, last_seen: null } })
    render(<DmarcIngestionStatus wsId={WS_ID} domain={DOMAIN} />)

    expect(await screen.findByText('No reports received yet')).toBeInTheDocument()
    expect(screen.getByText('No')).toBeInTheDocument()
    expect(screen.getByText('Not yet')).toBeInTheDocument()
    expect(screen.queryByText('Yes')).not.toBeInTheDocument()
  })

  it('keeps report-history failure unknown instead of calling it no reports', async () => {
    api.getBecExposureScore.mockResolvedValue(becResponse())
    api.getDmarcReportHistory.mockRejectedValue(new Error('unavailable'))
    render(<DmarcIngestionStatus wsId={WS_ID} domain={DOMAIN} />)

    expect(await screen.findByText('Report status unavailable')).toBeInTheDocument()
    const receivedTile = screen.getByText('Reports received').parentElement
    expect(within(receivedTile).getByText('Unknown')).toBeInTheDocument()
    expect(screen.queryByText('No reports received yet')).not.toBeInTheDocument()
    expect(screen.queryByText('No')).not.toBeInTheDocument()
  })

  it('reports receipt while keeping failed BEC/DNS evidence unknown', async () => {
    api.getBecExposureScore.mockRejectedValue(new Error('unavailable'))
    api.getDmarcReportHistory.mockResolvedValue({ totals: { reports: 1, last_seen: null } })
    render(<DmarcIngestionStatus wsId={WS_ID} domain={DOMAIN} />)

    expect(await screen.findByText('Reports received · DNS not verified')).toBeInTheDocument()
    const dnsTile = screen.getByText('DNS verification').parentElement
    expect(within(dnsTile).getByText('Unknown')).toBeInTheDocument()
    expect(screen.getByText('Yes')).toBeInTheDocument()
    expect(screen.queryByText('BEC assessment pass rate')).not.toBeInTheDocument()
  })
})

describe('ManagedDmarcCard — governed manual controls while automation is suspended', () => {
  it('renders governed manual advance and rollback without rendering Self-Driving DMARC', async () => {
    api.getHostedDmarc.mockResolvedValue(hostedDmarcResponse())

    render(<ManagedDmarcCard wsId={WS_ID} domain={DOMAIN} endpointReady />)

    expect(await screen.findByText('Managed policy automation is suspended')).toBeInTheDocument()
    expect(screen.getByText(/Automatic policy advancement and rollback from inbound DMARC \(RUA\) reports are suspended/i)).toBeInTheDocument()

    const advance = screen.getByRole('button', { name: 'Advance to Quarantine 25%' })
    expect(screen.getByRole('button', { name: 'Roll back last change' })).toBeInTheDocument()
    expect(screen.queryByText('Self-Driving DMARC')).not.toBeInTheDocument()
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()

    fireEvent.click(advance)
    await waitFor(() => {
      expect(api.setHostedDmarcPolicy).toHaveBeenCalledWith(
        WS_ID,
        DOMAIN,
        'quarantine',
        25,
      )
    })
    expect(api.setHostedDmarcAutopilot).not.toHaveBeenCalled()
  })

  it('keeps Self-Driving DMARC available only for a non-suspended interpretation', async () => {
    api.getHostedDmarc.mockResolvedValue(hostedDmarcResponse({ automationStatus: 'active' }))

    render(<ManagedDmarcCard wsId={WS_ID} domain={DOMAIN} endpointReady />)

    expect(await screen.findByText('Self-Driving DMARC')).toBeInTheDocument()
    expect(screen.getByRole('checkbox')).toBeInTheDocument()
    expect(screen.queryByText('Managed policy automation is suspended')).not.toBeInTheDocument()
  })

  it('preserves paid-plan and in-progress guards for manual tightening', async () => {
    api.getHostedDmarc.mockResolvedValue(hostedDmarcResponse({ policyAllowed: false }))
    const { unmount } = render(<ManagedDmarcCard wsId={WS_ID} domain={DOMAIN} endpointReady />)

    expect(await screen.findByText(/Managed policy-change tools are on paid plans/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Advance to/i })).not.toBeInTheDocument()
    expect(screen.queryByText('Self-Driving DMARC')).not.toBeInTheDocument()

    unmount()
    api.getHostedDmarc.mockResolvedValue(hostedDmarcResponse({ changePending: true }))
    render(<ManagedDmarcCard wsId={WS_ID} domain={DOMAIN} endpointReady />)

    expect(await screen.findByText(/A change is being confirmed/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Advance to/i })).not.toBeInTheDocument()
    expect(screen.queryByText('Self-Driving DMARC')).not.toBeInTheDocument()
  })
})
