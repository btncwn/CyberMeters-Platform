import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ManagedDmarcCard } from '../WorkspaceEmailProtectionPage'
import { api } from '../../../api'

vi.mock('../../../api', () => ({
  api: {
    getHostedDmarc: vi.fn(),
    setHostedDmarcPolicy: vi.fn(),
    rollbackHostedDmarc: vi.fn(),
    setHostedDmarcAutopilot: vi.fn(),
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
