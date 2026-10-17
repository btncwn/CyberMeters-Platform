import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, expect, it, vi } from 'vitest'
import SetupCard from '../SetupCard'
import { api } from '../../api'

// Ported from the retired launcher's reporting test (#673) onto the setup card
// that replaced it: the DMARC step is Done only when the real ingest endpoint
// has received reports AND the DNS record verifies, for the primary domain; a
// failed connection read never marks it Done.

vi.mock('../../api', () => ({ api: {
  getWorkspaceSummary: vi.fn(), getWorkspaceDomains: vi.fn(),
  getDmarcIngestEndpoint: vi.fn(), verifyDmarcDns: vi.fn(),
} }))

beforeEach(() => {
  vi.clearAllMocks()
  // A domain exists but no scan has run yet, so the card stays visible and the DMARC step can be read.
  api.getWorkspaceSummary.mockResolvedValue({ domains: 1, reports_count: 0, latest_score: null })
  api.getWorkspaceDomains.mockResolvedValue({ domains: [{ domain: 'other.test' }, { domain: 'example.test', is_primary: true }] })
})

it('shows DMARC connection done only when the real endpoint received reports and DNS is verified', async () => {
  api.getDmarcIngestEndpoint.mockResolvedValue({ endpoint: { last_inbound_at: '2026-10-17T12:00:00Z' } })
  api.verifyDmarcDns.mockResolvedValue({ status: 'verified' })
  render(<MemoryRouter><SetupCard workspaceId="ws1" /></MemoryRouter>)
  await waitFor(() => expect(screen.getByTestId('setup-step-dmarc')).toHaveAttribute('data-status', 'done'))
  expect(api.getDmarcIngestEndpoint).toHaveBeenCalledWith('ws1', 'example.test')
  expect(api.verifyDmarcDns).toHaveBeenCalledWith('ws1', 'example.test')
})

it('does not mark reporting done when the connection read fails', async () => {
  api.getDmarcIngestEndpoint.mockRejectedValue(new Error('offline'))
  api.verifyDmarcDns.mockResolvedValue({ status: 'verified' })
  render(<MemoryRouter><SetupCard workspaceId="ws1" /></MemoryRouter>)
  await waitFor(() => expect(api.getDmarcIngestEndpoint).toHaveBeenCalled())
  expect(await screen.findByTestId('setup-step-dmarc')).not.toHaveAttribute('data-status', 'done')
})
