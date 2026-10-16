import { render, screen, within, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import BrandMonitoringPage from '../BrandMonitoringPage'
import { api } from '../../../api'
import { useWorkspace } from '../../../hooks/useWorkspace'

vi.mock('../../../api', () => ({ api: {
  getBrandProfile: vi.fn(), getBrandSummary: vi.fn(), getBrandCandidates: vi.fn(),
  getBrandCases: vi.fn(), getWorkspaceBrandMonitoring: vi.fn(),
  classifyBrandCandidate: vi.fn(), refreshBrandMonitoring: vi.fn(),
} }))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: vi.fn() }))
vi.mock('../../../components/module/ModuleContract', () => ({
  default: ({ children }) => <div>{children}</div>,
  useAreaAnchor: () => vi.fn(),
}))

const candidate = (overrides = {}) => ({
  id: 'candidate-1', candidate_domain: 'lookalike.example', classification: 'unreviewed',
  risk_level: 'high', action_required: true, ...overrides,
})
const mount = () => render(<MemoryRouter><BrandMonitoringPage /></MemoryRouter>)

beforeEach(() => {
  vi.clearAllMocks()
  useWorkspace.mockReturnValue({ wsId: 'ws-1', wsName: 'Workspace', workspaces: [{ id: 'ws-1', role: 'admin' }] })
  api.getBrandProfile.mockResolvedValue({ profile: null })
  api.getBrandSummary.mockResolvedValue({ summary: {} })
  api.getBrandCandidates.mockResolvedValue({ candidates: [candidate()] })
  api.getBrandCases.mockResolvedValue({ cases: [] })
  api.classifyBrandCandidate.mockResolvedValue({ candidate: candidate({ classification: 'monitoring' }) })
  api.refreshBrandMonitoring.mockResolvedValue({ updated: 1 })
})

describe('Brand Protection actions', () => {
  it('submits the accepted monitoring classification and labels the returned candidate', async () => {
    const user = userEvent.setup()
    api.getBrandCandidates.mockResolvedValueOnce({ candidates: [candidate()] })
      .mockResolvedValue({ candidates: [candidate({ classification: 'monitoring', action_required: false })] })
    mount()
    const row = (await screen.findByText('lookalike.example')).closest('.border-b')
    await user.click(within(row).getByRole('button', { name: /classify/i }))
    await user.click(within(row).getByRole('button', { name: 'Monitor' }))
    await waitFor(() => expect(api.classifyBrandCandidate).toHaveBeenCalledWith('ws-1', 'candidate-1', 'monitoring'))
    expect(await screen.findByText('Monitoring')).toBeInTheDocument()
    expect(screen.queryByText('Needs review')).not.toBeInTheDocument()
  })

  it.each([
    [true, 'Review this risk and decide whether to escalate.'],
    [false, 'Continue monitoring this domain.'],
  ])('renders text for action_required=%s rather than a boolean', async (required, expected) => {
    const user = userEvent.setup()
    api.getBrandCandidates.mockResolvedValue({ candidates: [candidate({ classification: 'monitoring', action_required: required })] })
    mount()
    await user.click(await screen.findByRole('button', { name: /lookalike.example/i }))
    expect(screen.getByText(expected)).toBeInTheDocument()
    expect(screen.queryByText('true')).not.toBeInTheDocument()
  })

  it('shows the existing evidence bundle fields and case deadline', async () => {
    api.getBrandCases.mockResolvedValue({ cases: [{
      id: 'case-1', domain: 'lookalike.example', status: 'evidence_ready', due_at: '2026-10-30T12:00:00Z',
      recommended_actions: [{ title: 'Prepare takedown submission' }],
      evidence: { latest_evidence_bundle: { captured_at: '2026-10-16T12:00:00Z' }, bundle: {
        dns_snapshot: { A: ['192.0.2.1'], MX: ['mail.example'] },
        rdap_snapshot: { registrar: 'Example Registrar' },
        recipients: [{ role: 'abuse', contact: 'abuse@example.test' }],
      } },
    }] })
    mount()
    expect(await screen.findByText('Example Registrar')).toBeInTheDocument()
    expect(screen.getByText('192.0.2.1')).toBeInTheDocument()
    expect(screen.getByText('mail.example')).toBeInTheDocument()
    expect(screen.getByText('abuse: abuse@example.test')).toBeInTheDocument()
    expect(screen.getByText('Prepare takedown submission')).toBeInTheDocument()
    expect(screen.getByText('Due:')).toBeInTheDocument()
    expect(screen.getByText('Captured')).toBeInTheDocument()
  })

  it('checks DNS, reloads the queue, and exposes rate limiting', async () => {
    const user = userEvent.setup()
    mount()
    await user.click(await screen.findByRole('button', { name: 'Check DNS now' }))
    await waitFor(() => expect(api.refreshBrandMonitoring).toHaveBeenCalledWith('ws-1'))
    await waitFor(() => expect(api.getBrandCandidates).toHaveBeenCalledTimes(2))
    api.refreshBrandMonitoring.mockRejectedValueOnce({ status: 429 })
    await user.click(screen.getByRole('button', { name: 'Check DNS now' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/rate limited/i)
  })

  it('only offers DNS refresh to roles allowed to add domains', async () => {
    useWorkspace.mockReturnValue({ wsId: 'ws-1', wsName: 'Workspace', workspaces: [{ id: 'ws-1', role: 'analyst' }] })
    mount()
    await screen.findByText('lookalike.example')
    expect(screen.queryByRole('button', { name: 'Check DNS now' })).not.toBeInTheDocument()
  })
})
