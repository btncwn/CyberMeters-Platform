import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import DomainConnectReturnPage, { decodeDomainConnectState } from '../DomainConnectReturnPage'
import { api } from '../../api'

const state = (d, w) => btoa(JSON.stringify({ d, w })).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
const renderAt = (query) => render(
  <MemoryRouter initialEntries={[`/domains/verify-return?${query}`]}>
    <DomainConnectReturnPage intervalMs={0} />
  </MemoryRouter>,
)
const verifiedRow = { domain_id: 'd1', verification_status: 'verified', verified_at: '2026-10-10T18:00:00Z' }
const pendingRow = { domain_id: 'd1', verification_status: 'pending', verified_at: null }

beforeEach(() => { vi.restoreAllMocks() })

describe('decodeDomainConnectState', () => {
  it('accepts the server-issued shape only', () => {
    expect(decodeDomainConnectState(state('d1', 'ws_a'))).toEqual({ domainId: 'd1', workspaceId: 'ws_a' })
    expect(decodeDomainConnectState('not-base64!')).toBeNull()
    expect(decodeDomainConnectState(state('../x', 'ws_a'))).toBeNull()
    expect(decodeDomainConnectState(null)).toBeNull()
  })
})

describe('DomainConnectReturnPage', () => {
  it('verified only from the authoritative re-read of the exact record', async () => {
    vi.spyOn(api, 'verifyDomain').mockResolvedValue({ success: true })
    vi.spyOn(api, 'getWorkspaceDomains').mockResolvedValue({ domains: [verifiedRow] })
    renderAt(`state=${state('d1', 'ws_a')}`)
    await waitFor(() => expect(screen.getByText('Domain ownership verified')).toBeInTheDocument())
    expect(api.verifyDomain).toHaveBeenCalledWith('d1', 'ws_a')
  })

  it('a success claim without a persisted record never shows verified', async () => {
    vi.spyOn(api, 'verifyDomain').mockResolvedValue({ success: true, verification_status: 'verified' })
    vi.spyOn(api, 'getWorkspaceDomains').mockResolvedValue({ domains: [pendingRow] })
    renderAt(`state=${state('d1', 'ws_a')}`)
    await waitFor(() => expect(screen.getByText('Your record is still being published')).toBeInTheDocument())
    expect(screen.queryByText('Domain ownership verified')).toBeNull()
    expect(api.verifyDomain).toHaveBeenCalledTimes(8)
  })

  it('a cancelled consent changes nothing and offers the way back', async () => {
    const verify = vi.spyOn(api, 'verifyDomain').mockResolvedValue({})
    renderAt(`error=access_denied&error_description=user_cancel&state=${state('d1', 'ws_a')}`)
    expect(screen.getByText('No changes were made')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Back to verification' })).toHaveAttribute('href', '/domains/d1/verify')
    expect(verify).not.toHaveBeenCalled()
  })

  it('an unrecognised state never calls the API', () => {
    const verify = vi.spyOn(api, 'verifyDomain').mockResolvedValue({})
    renderAt('state=garbage')
    expect(screen.getByText(/couldn.t match this link/)).toBeInTheDocument()
    expect(verify).not.toHaveBeenCalled()
  })
})
