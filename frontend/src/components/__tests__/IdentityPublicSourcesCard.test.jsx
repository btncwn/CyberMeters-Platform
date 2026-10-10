import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api'
import IdentityPublicSourcesCard from '../IdentityPublicSourcesCard'
vi.mock('../../api', () => ({ api: { getIdentityPublicSources: vi.fn(), checkIdentityPublicSources: vi.fn() } }))
const meta = { can_manage: true, domains: [{ id: 'd', domain: 'example.test' }], checks: [], scope_note: 'Bounded public source check.' }
beforeEach(() => { vi.clearAllMocks(); api.getIdentityPublicSources.mockResolvedValue(meta) })
describe('Identity public source checks', () => {
  it('submits the selected verified domain and displays an unverified masked candidate', async () => {
    api.checkIdentityPublicSources.mockResolvedValue({ check: { id: 'check1', created_at: '2026-10-10T00:00:00Z', result: {
      source_url: 'https://example.test/', coverage: 'partial', state: 'candidates_observed', checked_sources: [{ source_url: 'https://example.test/app.js', status: 'checked', http_status: 200 }],
      findings: [{ fingerprint: 'hash', label: 'Stripe live secret key', source_url: 'https://example.test/app.js', masked_evidence: 'sk_l…MASK', line: 5, recommendation: 'Review and rotate if real.' }],
    } } })
    render(<IdentityPublicSourcesCard workspaceId="wa" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Check public files' }))
    await waitFor(() => expect(api.checkIdentityPublicSources).toHaveBeenCalledWith('wa', { domain_id: 'd', source_url: 'https://example.test/' }))
    expect(await screen.findByText('Stripe live secret key — candidate')).toBeInTheDocument()
    expect(screen.getByText('sk_l…MASK')).toBeInTheDocument()
    expect(screen.getByText(/Key validity and account compromise have not been tested/)).toBeInTheDocument()
    expect(screen.queryByText(/Account compromised|Critical risk/)).not.toBeInTheDocument()
  })
  it('does not offer checks without a verified domain', async () => {
    api.getIdentityPublicSources.mockResolvedValue({ ...meta, domains: [] })
    render(<IdentityPublicSourcesCard workspaceId="wa" />)
    expect(await screen.findByText('Verify a domain to check its public files.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Check public files' })).not.toBeInTheDocument()
  })
  it('shows unavailable rather than a clean result on load failure', async () => {
    api.getIdentityPublicSources.mockRejectedValue(new Error('failed'))
    render(<IdentityPublicSourcesCard workspaceId="wa" />)
    expect(await screen.findByRole('alert')).toHaveTextContent('Public source checks are unavailable.')
    expect(screen.queryByText(/No supported key pattern/)).not.toBeInTheDocument()
  })
})
