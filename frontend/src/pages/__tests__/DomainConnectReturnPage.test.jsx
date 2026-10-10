import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import DomainConnectReturnPage, { readDomainConnectTarget } from '../DomainConnectReturnPage'
import { api } from '../../api'

// The query string the provider lands on: our signed redirect_uri, plus whatever
// the provider appends (Cloudflare drops `state`, so the page must not need it).
const returnQuery = (extra = '') => `domain=d1&workspace=ws_a${extra}`
const renderAt = (query) => render(
  <MemoryRouter initialEntries={[`/domains/verify-return?${query}`]}>
    <DomainConnectReturnPage intervalMs={0} />
  </MemoryRouter>,
)
const verifiedRow = { domain_id: 'd1', verification_status: 'verified', verified_at: '2026-10-10T18:00:00Z' }
const pendingRow = { domain_id: 'd1', verification_status: 'pending', verified_at: null }

beforeEach(() => { vi.restoreAllMocks() })

describe('readDomainConnectTarget', () => {
  it('accepts plain ids only', () => {
    expect(readDomainConnectTarget(new URLSearchParams('domain=d1&workspace=ws_a'))).toEqual({ domainId: 'd1', workspaceId: 'ws_a' })
    expect(readDomainConnectTarget(new URLSearchParams('domain=../x&workspace=ws_a'))).toBeNull()
    expect(readDomainConnectTarget(new URLSearchParams('domain=d1'))).toBeNull()
    expect(readDomainConnectTarget(new URLSearchParams(''))).toBeNull()
  })
})

describe('DomainConnectReturnPage', () => {
  it('verified only from the authoritative re-read of the exact record', async () => {
    vi.spyOn(api, 'verifyDomain').mockResolvedValue({ success: true })
    vi.spyOn(api, 'getWorkspaceDomains').mockResolvedValue({ domains: [verifiedRow] })
    renderAt(returnQuery())
    await waitFor(() => expect(screen.getByText('Domain ownership verified')).toBeInTheDocument())
    expect(api.verifyDomain).toHaveBeenCalledWith('d1', 'ws_a')
  })

  it('works when the provider appends its own parameters', async () => {
    vi.spyOn(api, 'verifyDomain').mockResolvedValue({ success: true })
    vi.spyOn(api, 'getWorkspaceDomains').mockResolvedValue({ domains: [verifiedRow] })
    renderAt(returnQuery('&state=ignored-by-cloudflare'))
    await waitFor(() => expect(screen.getByText('Domain ownership verified')).toBeInTheDocument())
  })

  it('a success claim without a persisted record never shows verified', async () => {
    vi.spyOn(api, 'verifyDomain').mockResolvedValue({ success: true, verification_status: 'verified' })
    vi.spyOn(api, 'getWorkspaceDomains').mockResolvedValue({ domains: [pendingRow] })
    renderAt(returnQuery())
    await waitFor(() => expect(screen.getByText('Your record is still being published')).toBeInTheDocument())
    expect(screen.queryByText('Domain ownership verified')).toBeNull()
    expect(api.verifyDomain).toHaveBeenCalledTimes(8)
  })

  it('a cancelled consent changes nothing and offers the way back', async () => {
    const verify = vi.spyOn(api, 'verifyDomain').mockResolvedValue({})
    renderAt(returnQuery('&error=access_denied&error_description=user_cancel'))
    expect(screen.getByText('No changes were made')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Back to verification' })).toHaveAttribute('href', '/domains/d1/verify')
    expect(verify).not.toHaveBeenCalled()
  })

  it('a link without a recognisable domain never calls the API', () => {
    const verify = vi.spyOn(api, 'verifyDomain').mockResolvedValue({})
    renderAt('state=garbage')
    expect(screen.getByText(/couldn.t match this link/)).toBeInTheDocument()
    expect(verify).not.toHaveBeenCalled()
  })
})
