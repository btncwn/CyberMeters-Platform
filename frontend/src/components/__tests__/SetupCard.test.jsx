import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import SetupCard, { setupSteps, setupComplete } from '../SetupCard'
import { api } from '../../api'

// The "Get set up" steps that lived on /services now sit on Overview while
// setup is incomplete, from the same flags; the card disappears once every
// step is Done. Statuses are never invented from unknown flags.

vi.mock('../../api', () => ({ api: { getWorkspaceSummary: vi.fn(), getWorkspaceDomains: vi.fn(), getHostedDmarc: vi.fn() } }))

beforeEach(() => vi.clearAllMocks())

describe('setupSteps', () => {
  it('derives the three steps from the flags and treats unknown as not done', () => {
    expect(setupSteps({ hasDomain: null, hasScan: null, dmarcConnected: null }).map((s) => s.status)).toEqual(['next', 'waiting', 'waiting'])
    expect(setupSteps({ hasDomain: true, hasScan: false, dmarcConnected: false }).map((s) => s.status)).toEqual(['done', 'next', 'waiting'])
    expect(setupSteps({ hasDomain: true, hasScan: true, dmarcConnected: false }).map((s) => s.status)).toEqual(['done', 'done', 'next'])
    expect(setupComplete({ hasDomain: true, hasScan: true, dmarcConnected: true })).toBe(true)
    expect(setupComplete({ hasDomain: true, hasScan: true, dmarcConnected: null })).toBe(false)
    expect(setupSteps({})[0].to).toBe('/ws/domains')
  })
})

describe('<SetupCard>', () => {
  it('shows the steps with Done / Next / Waiting while setup is incomplete', async () => {
    api.getWorkspaceSummary.mockResolvedValue({ domains: 1, latest_score: null, reports_count: 0 })
    api.getWorkspaceDomains.mockResolvedValue({ domains: [{ domain: 'a.example', verification_status: 'verified' }] })
    api.getHostedDmarc.mockResolvedValue({ record: { status: 'pending' } })
    render(<MemoryRouter><SetupCard workspaceId="ws1" /></MemoryRouter>)
    const card = await screen.findByTestId('setup-card')
    expect(card).toHaveTextContent('Get set up')
    expect(card).toHaveTextContent('1 of 3 done')
    expect(screen.getByTestId('setup-step-domain')).toHaveAttribute('data-status', 'done')
    expect(screen.getByTestId('setup-step-scan')).toHaveAttribute('data-status', 'next')
    expect(screen.getByTestId('setup-step-dmarc')).toHaveAttribute('data-status', 'waiting')
    expect(screen.getByRole('link', { name: 'Start Cyber MOT' })).toHaveAttribute('href', '/scans/new')
    expect(screen.queryByRole('link', { name: 'Add domain' })).toBeNull()
  })

  it('renders nothing once every step is Done', async () => {
    api.getWorkspaceSummary.mockResolvedValue({ domains: 1, latest_score: 82, reports_count: 2 })
    api.getWorkspaceDomains.mockResolvedValue({ domains: [{ domain: 'a.example', verification_status: 'verified' }] })
    api.getHostedDmarc.mockResolvedValue({ record: { status: 'active' } })
    const { container } = render(<MemoryRouter><SetupCard workspaceId="ws1" /></MemoryRouter>)
    await waitFor(() => expect(api.getHostedDmarc).toHaveBeenCalledWith('ws1', 'a.example'))
    await waitFor(() => expect(container).toBeEmptyDOMElement())
  })

  it('a DMARC read failure fails closed to not connected; no workspace renders nothing', async () => {
    api.getWorkspaceSummary.mockResolvedValue({ domains: 1, latest_score: 82 })
    api.getWorkspaceDomains.mockResolvedValue({ domains: [{ domain: 'a.example' }] })
    api.getHostedDmarc.mockRejectedValue(new Error('boom'))
    render(<MemoryRouter><SetupCard workspaceId="ws1" /></MemoryRouter>)
    expect((await screen.findByTestId('setup-step-dmarc'))).toHaveAttribute('data-status', 'next')
    const { container } = render(<MemoryRouter><SetupCard workspaceId={null} /></MemoryRouter>)
    expect(container).toBeEmptyDOMElement()
  })
})
