import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import BrandMonitoringPage from '../BrandMonitoringPage'
import { api } from '../../../api'
import { useWorkspace } from '../../../hooks/useWorkspace'

vi.mock('../../../api', () => ({
  api: {
    getBrandProfile: vi.fn(),
    getBrandSummary: vi.fn(),
    getBrandCandidates: vi.fn(),
    getBrandCases: vi.fn(),
    getWorkspaceBrandMonitoring: vi.fn(),
    runBrandDiscovery: vi.fn(),
  },
}))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: vi.fn() }))

const WS_ID = 'ws_brand_discovery_1'
const CONFIGURED = { brand_name: 'Acme', primary_domain: 'acme.test', keywords: [], protected_domains: [], inferred: false }

function mount() {
  return render(<MemoryRouter><BrandMonitoringPage /></MemoryRouter>)
}

beforeEach(() => {
  vi.clearAllMocks()
  useWorkspace.mockReturnValue({ wsId: WS_ID, wsName: 'Acme workspace' })
  api.getBrandSummary.mockResolvedValue({})
  api.getBrandCandidates.mockResolvedValue({ candidates: [] })
  api.getBrandCases.mockResolvedValue({ cases: [] })
  api.getWorkspaceBrandMonitoring.mockResolvedValue({ candidates: [] })
})

describe('BrandMonitoringPage — on-demand passive discovery', () => {
  it('is disabled until a brand profile is configured', async () => {
    api.getBrandProfile.mockResolvedValue({ profile: { ...CONFIGURED, inferred: true } })
    mount()
    const button = await screen.findByRole('button', { name: /check now/i })
    expect(button).toBeDisabled()
    expect(screen.getByText(/Save a brand profile above/)).toBeInTheDocument()
    expect(api.runBrandDiscovery).not.toHaveBeenCalled()
  })

  it('runs the check, reports the outcome and reloads candidates', async () => {
    api.getBrandProfile.mockResolvedValue({ profile: CONFIGURED })
    api.runBrandDiscovery.mockResolvedValue({ status: 200, ok: true, body: { inserted: 1, updated: 0 } })
    mount()
    const button = await screen.findByRole('button', { name: /check now/i })
    expect(button).toBeEnabled()
    const loadsBefore = api.getBrandCandidates.mock.calls.length
    fireEvent.click(button)
    await waitFor(() => expect(api.runBrandDiscovery).toHaveBeenCalledWith(WS_ID))
    expect(await screen.findByText('1 new lookalike candidate found.')).toBeInTheDocument()
    await waitFor(() => expect(api.getBrandCandidates.mock.calls.length).toBeGreaterThan(loadsBefore))
    expect(screen.getByText(/not proof of abuse/)).toBeInTheDocument()
  })

  it('explains a rate-limited run without an upgrade prompt', async () => {
    api.getBrandProfile.mockResolvedValue({ profile: CONFIGURED })
    api.runBrandDiscovery.mockResolvedValue({ status: 429, ok: false, body: { code: 'rate_limit_exceeded', upgrade_message: 'Upgrade your plan' } })
    mount()
    fireEvent.click(await screen.findByRole('button', { name: /check now/i }))
    expect(await screen.findByText('This check was run recently.')).toBeInTheDocument()
    expect(screen.queryByText(/upgrade/i)).not.toBeInTheDocument()
  })

  it('a network failure is reported, not swallowed', async () => {
    api.getBrandProfile.mockResolvedValue({ profile: CONFIGURED })
    api.runBrandDiscovery.mockRejectedValue(new Error('offline'))
    mount()
    fireEvent.click(await screen.findByRole('button', { name: /check now/i }))
    expect(await screen.findByText('The check could not be completed.')).toBeInTheDocument()
  })
})
