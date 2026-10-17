import { render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, expect, it, vi } from 'vitest'
import ServiceLauncher from '../ServiceLauncher'
import { api } from '../../api'

vi.mock('../../api', () => ({ api: {
  getWorkspaceSummary: vi.fn(), getWorkspaceDomains: vi.fn(),
  getDmarcIngestEndpoint: vi.fn(), verifyDmarcDns: vi.fn(),
} }))
vi.mock('../../hooks/useWorkspace', () => ({ useWorkspace: () => ({ wsId: 'ws1', wsName: 'Workspace' }) }))

beforeEach(() => {
  vi.clearAllMocks()
  api.getWorkspaceSummary.mockResolvedValue({ domains: 1, reports_count: 1 })
  api.getWorkspaceDomains.mockResolvedValue({ domains: [{ domain: 'example.test', is_primary: true }] })
})

const step = () => within(screen.getByText('Connect DMARC reporting').closest('li'))

it('shows DMARC connection done only when the real endpoint received reports and DNS is verified', async () => {
  api.getDmarcIngestEndpoint.mockResolvedValue({ endpoint: { last_inbound_at: '2026-10-17T12:00:00Z' } })
  api.verifyDmarcDns.mockResolvedValue({ status: 'verified' })
  render(<MemoryRouter><ServiceLauncher /></MemoryRouter>)
  await waitFor(() => expect(step().getByText('Done')).toBeInTheDocument())
  expect(api.getDmarcIngestEndpoint).toHaveBeenCalledWith('ws1', 'example.test')
  expect(api.verifyDmarcDns).toHaveBeenCalledWith('ws1', 'example.test')
  expect(step().getByRole('link', { name: /Review/ })).toHaveAttribute('href', '/ws/email-protection')
})

it('does not mark reporting done when the connection read fails', async () => {
  api.getDmarcIngestEndpoint.mockRejectedValue(new Error('offline'))
  api.verifyDmarcDns.mockResolvedValue({ status: 'verified' })
  render(<MemoryRouter><ServiceLauncher /></MemoryRouter>)
  await waitFor(() => expect(api.getDmarcIngestEndpoint).toHaveBeenCalled())
  expect(step().queryByText('Done')).not.toBeInTheDocument()
})
