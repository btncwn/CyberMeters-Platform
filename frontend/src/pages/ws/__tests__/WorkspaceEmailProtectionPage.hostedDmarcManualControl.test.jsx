import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { BecExposure, DmarcIngestionStatus, ManagedDmarcCard, complianceDetail } from '../WorkspaceEmailProtectionPage'
import { api } from '../../../api'

vi.mock('../../../api', () => ({
  api: {
    getHostedDmarc: vi.fn(),
    setHostedDmarcPolicy: vi.fn(),
    setHostedDmarcStep: vi.fn(),
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
      policy_step: { index: 0, policy: 'none', pct: 100, label: 'Monitor only' },
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
  api.setHostedDmarcStep.mockResolvedValue({})
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
    expect(screen.getByText('DMARC pass rate in reports you uploaded')).toBeInTheDocument()
    expect(screen.getByText('Not measured')).toBeInTheDocument()
    expect(screen.getByText('DMARC pass rate in reports you uploaded').nextElementSibling).toHaveTextContent('Not measured')
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

    expect(await screen.findByText('DMARC pass rate in reports you uploaded')).toBeInTheDocument()
    expect(screen.getByText('Pass rate in reports you uploaded: 0%')).toBeInTheDocument()
    expect(await screen.findByText('Customer-submitted sender activity · BEC assessment')).toBeInTheDocument()
    expect(screen.queryByText('Not measured')).not.toBeInTheDocument()
    expect(screen.getByText('DMARC pass rate in reports you uploaded').nextElementSibling).toHaveTextContent('0%')
  })

  it('does not infer DMARC receipt from a shared endpoint date when DMARC history is empty', async () => {
    api.getBecExposureScore.mockResolvedValue(becResponse())
    api.getDmarcReportHistory.mockResolvedValue({ totals: { reports: 0, last_seen: null } })
    render(<DmarcIngestionStatus wsId={WS_ID} domain={DOMAIN} />)

    expect(await screen.findByText('Waiting for first report')).toBeInTheDocument()
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
    expect(screen.queryByText('Waiting for first report')).not.toBeInTheDocument()
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
        false,
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

// The RFC 9989 ladder as the API sends it (#749): five keyed steps, no pct.
const LADDER = [
  ['none', 'none', false, 'Monitor only', 'No action is requested for mail that fails DMARC; reports keep arriving.'],
  ['quarantine_testing', 'quarantine', true, 'Quarantine (testing)', 'p=quarantine with t=y: receivers are asked to apply one level less, so still no action (RFC 9989 §4.7).'],
  ['quarantine', 'quarantine', false, 'Quarantine', 'Receivers are asked to quarantine mail that fails DMARC.'],
  ['reject_testing', 'reject', true, 'Reject (testing)', 'p=reject with t=y: receivers are asked to apply one level less, so quarantine (RFC 9989 §4.7).'],
  ['reject', 'reject', false, 'Reject', 'Receivers are asked to reject mail that fails DMARC.'],
].map(([key, policy, testing, label, description], index) => ({ index, key, policy, testing, label, description }))

function ladderResponse(index, { legacyPct = null, changePending = false, policyAllowed = true } = {}) {
  const base = hostedDmarcResponse({ automationStatus: 'active', policyAllowed, changePending })
  base.record = {
    ...base.record,
    current_value: `v=DMARC1; p=${LADDER[index].policy}${LADDER[index].testing ? '; t=y' : ''}; rua=mailto:rua@example.test`,
    ladder: LADDER,
    policy_step: LADDER[index],
    next_step: LADDER[index + 1] || null,
    previous_step: index > 0 ? LADDER[index - 1] : null,
    legacy_pct: legacyPct,
    can_rollback: false,
  }
  return base
}

describe('ManagedDmarcCard — RFC 9989 ladder from the API', () => {
  it('renders the steps the API sends and marks the current one, with no percentages', async () => {
    api.getHostedDmarc.mockResolvedValue(ladderResponse(4))
    render(<ManagedDmarcCard wsId={WS_ID} domain={DOMAIN} endpointReady />)

    const track = await screen.findByTestId('dmarc-ladder')
    expect([...track.children].map((c) => c.querySelector('p').textContent))
      .toEqual(['Monitor only', 'Quarantine (testing)', 'Quarantine', 'Reject (testing)', 'Reject'])
    const current = track.querySelector('[aria-current="step"]')
    expect(current).toHaveTextContent('Reject')
    expect(current).toHaveTextContent('You are here')
    expect(screen.getByText('Receivers are asked to reject mail that fails DMARC.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Advance to/ })).not.toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/\d+\s*%\s*of mail|Quarantine \d+%|Reject \d+%/)
  })

  it('advances by step key', async () => {
    api.getHostedDmarc.mockResolvedValue(ladderResponse(1))
    render(<ManagedDmarcCard wsId={WS_ID} domain={DOMAIN} endpointReady />)

    fireEvent.click(await screen.findByRole('button', { name: 'Advance to Quarantine' }))
    await waitFor(() => expect(api.setHostedDmarcStep).toHaveBeenCalledWith(WS_ID, DOMAIN, 'quarantine', false))
    expect(api.setHostedDmarcPolicy).not.toHaveBeenCalled()
  })

  it('steps back one level by key only after confirmation in the in-app dialog', async () => {
    api.getHostedDmarc.mockResolvedValue(ladderResponse(3))
    const nativeConfirm = vi.spyOn(window, 'confirm')
    render(<ManagedDmarcCard wsId={WS_ID} domain={DOMAIN} endpointReady />)
    const stepBack = await screen.findByRole('button', { name: 'Step back one level' })

    fireEvent.click(stepBack)
    let dialog = await screen.findByRole('dialog', { name: 'Step back to Quarantine?' })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(api.setHostedDmarcStep).not.toHaveBeenCalled()

    fireEvent.click(stepBack)
    dialog = await screen.findByRole('dialog', { name: 'Step back to Quarantine?' })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Step back to Quarantine' }))
    await waitFor(() => expect(api.setHostedDmarcStep).toHaveBeenCalledWith(WS_ID, DOMAIN, 'quarantine', false))
    expect(nativeConfirm).not.toHaveBeenCalled()
    nativeConfirm.mockRestore()
  })

  it('a not-ready advance asks in the in-app dialog, naming the override and the backend reasons', async () => {
    api.getHostedDmarc.mockResolvedValue(ladderResponse(3))
    const reason = 'Reports received by email or upload are not counted toward automation (39 arrived in the last 7 days), so neither the 50-message volume nor the 97% pass rate can be measured yet.'
    api.setHostedDmarcStep
      .mockRejectedValueOnce(Object.assign(new Error('Compliance is not ready for a stricter policy yet.'), { code: 'readiness_check_failed', readiness: { ready: false, reasons: [reason] } }))
      .mockResolvedValueOnce({})
    render(<ManagedDmarcCard wsId={WS_ID} domain={DOMAIN} endpointReady />)
    fireEvent.click(await screen.findByRole('button', { name: 'Advance to Reject' }))
    const dialog = await screen.findByRole('alertdialog', { name: 'Move to Reject anyway?' })
    expect(dialog).toHaveTextContent(reason)
    // useDialog moves focus in a passive effect after the dialog mounts, so the
    // dialog can be found a moment before it is focused: wait for that focus.
    await waitFor(() => expect(within(dialog).getByRole('button', { name: 'Stay at Reject (testing)' })).toHaveFocus())
    fireEvent.click(within(dialog).getByRole('button', { name: 'Move to Reject anyway' }))
    await waitFor(() => expect(api.setHostedDmarcStep).toHaveBeenLastCalledWith(WS_ID, DOMAIN, 'reject', true))
  })

  it('offers no step back at the bottom of the ladder, while a change is pending, or on a free plan', async () => {
    api.getHostedDmarc.mockResolvedValue(ladderResponse(0))
    const { unmount } = render(<ManagedDmarcCard wsId={WS_ID} domain={DOMAIN} endpointReady />)
    expect(await screen.findByTestId('dmarc-ladder')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Step back one level' })).not.toBeInTheDocument()
    unmount()

    api.getHostedDmarc.mockResolvedValue(ladderResponse(2, { changePending: true }))
    const second = render(<ManagedDmarcCard wsId={WS_ID} domain={DOMAIN} endpointReady />)
    expect(await screen.findByText(/A change is being confirmed/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Step back one level' })).not.toBeInTheDocument()
    second.unmount()

    api.getHostedDmarc.mockResolvedValue(ladderResponse(2, { policyAllowed: false }))
    render(<ManagedDmarcCard wsId={WS_ID} domain={DOMAIN} endpointReady />)
    expect(await screen.findByText(/Managed policy-change tools are on paid plans/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Step back one level' })).not.toBeInTheDocument()
  })

  it('shows the legacy pct notice from the API as a calm note', async () => {
    const message = 'This record still carries pct=50. RFC 9989 removed pct: receivers that follow it ignore the value and apply the policy as written. CyberMeters removes it on your next policy change.'
    api.getHostedDmarc.mockResolvedValue(ladderResponse(1, { legacyPct: { pct: '50', message } }))
    render(<ManagedDmarcCard wsId={WS_ID} domain={DOMAIN} endpointReady />)

    const notice = await screen.findByTestId('legacy-pct-notice')
    expect(notice).toHaveTextContent('Older DMARC tag on this record')
    expect(notice).toHaveTextContent(message)
  })

  it('without a ladder from the API, shows only the step the API names', async () => {
    api.getHostedDmarc.mockResolvedValue(hostedDmarcResponse())
    render(<ManagedDmarcCard wsId={WS_ID} domain={DOMAIN} endpointReady />)
    const track = await screen.findByTestId('dmarc-ladder')
    expect(track.children).toHaveLength(1)
    expect(track).toHaveTextContent('You are here')
    expect(screen.queryByRole('button', { name: 'Step back one level' })).not.toBeInTheDocument()
  })
})

// 21 Oct 2026: reports kept arriving by email while the card said "no reports
// yet" (the 7-day pass rate counts only reports automation may use). The API
// now says why the pass rate is absent; the card words it.
describe('7-day compliance line', () => {
  it('names arriving reports and why there is no pass rate, from the API', () => {
    const text = complianceDetail({ pass_rate: null, total_messages: 0, reports_received: 39, last_report_received_at: '2026-10-20 10:14:00', pass_rate_unavailable_reason: 'reports_not_used_for_pass_rate' })
    expect(text).toMatch(/^Reports are arriving \(last: .*10:14 UTC\)\. The pass rate is not calculated from these reports\.$/)
    expect(text).not.toMatch(/no reports/i)
  })

  it('says no reports only when the API says none arrived in the window', () => {
    expect(complianceDetail({ pass_rate: null, pass_rate_unavailable_reason: 'no_reports' })).toBe('No reports in the last 7 days')
    expect(complianceDetail({ pass_rate: null, pass_rate_unavailable_reason: 'unknown' })).toBe('Pass rate not calculated')
    expect(complianceDetail({ pass_rate: null })).toBe('Pass rate not calculated')
    expect(complianceDetail({ pass_rate: 98.5, total_messages: 1200 })).toBe('1,200 messages')
  })

  it('the card shows the API wording under the 7-day figure', async () => {
    const response = hostedDmarcResponse()
    response.compliance = { pass_rate: null, total_messages: 0, window_days: 7, reports_received: 39, last_report_received_at: '2026-10-20 10:14:00', pass_rate_unavailable_reason: 'reports_not_used_for_pass_rate' }
    api.getHostedDmarc.mockResolvedValue(response)
    render(<ManagedDmarcCard wsId={WS_ID} domain={DOMAIN} endpointReady />)
    const line = await screen.findByTestId('compliance-detail')
    expect(line).toHaveTextContent(/Reports are arriving \(last: .*10:14 UTC\)/)
    expect(screen.queryByText(/no reports yet/i)).not.toBeInTheDocument()
  })
})
