import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, cleanup } from '@testing-library/react'
import IdentityWorkforceCard from '../IdentityWorkforceCard'
import { api } from '../../api'
vi.mock('../../api', () => ({ api: { getIdentityWorkforce: vi.fn(), addIdentityAccount: vi.fn(), updateIdentityAccount: vi.fn(), observeIdentityAccount: vi.fn(), previewIdentityResponse: vi.fn(), applyIdentityResponse: vi.fn(), verifyIdentityResponse: vi.fn() } }))
const upn = 'person@example.test'
const person = { id: 'person', upn, display_name: '', vip: false, source: 'entra', provider_user_id: 'user-id', tenant_id: 'tenant', client_id: 'client', updated_at: '2026-10-10T00:00:00Z', observation: { checkedAt: '2026-10-10T00:00:00Z', roles: { state: 'unavailable', items: [] }, authentication: { state: 'unavailable', mfaRegistered: null } } }
const action = { id: 'action', account_id: 'person', concern: 'Customer concern', requested_by: 'owner', status: 'previewed', created_at: '2026-10-10T00:00:00Z', expires_at: '2099-01-01T00:00:00Z', preview: { upn, id: 'user-id' } }
const meta = { accounts: [person], actions: [], scope_note: 'No employee breach feed.' }
beforeEach(() => { cleanup(); vi.clearAllMocks(); api.getIdentityWorkforce.mockResolvedValue(meta) })
async function select() { fireEvent.click(await screen.findByRole('button', { name: upn })); fireEvent.change(screen.getByLabelText('Entra client secret'), { target: { value: 'test-secret' } }) }
describe('workforce evidence and explicit response', () => {
  it('does not translate missing security data into a clean account', async () => {
    render(<IdentityWorkforceCard workspaceId="wa" />)
    expect(await screen.findByText(/Direct roles: Not available/)).toBeTruthy()
    expect(screen.getByText(/MFA registration: Not available/)).toBeTruthy()
    expect(api.applyIdentityResponse).not.toHaveBeenCalled()
  })
  it('previews the selected exact account without applying and clears its secret', async () => {
    api.previewIdentityResponse.mockResolvedValue({ action })
    render(<IdentityWorkforceCard workspaceId="wa" />); await select()
    fireEvent.change(screen.getByLabelText('Response reason'), { target: { value: 'Customer concern' } })
    fireEvent.click(screen.getByRole('button', { name: 'Preview session response' }))
    await waitFor(() => expect(api.previewIdentityResponse).toHaveBeenCalledWith('wa', { account_id: 'person', concern: 'Customer concern', credentials: { tenantId: 'tenant', clientId: 'client', clientSecret: 'test-secret' } }))
    await waitFor(() => expect(screen.getByLabelText('Entra client secret').value).toBe(''))
    expect(api.applyIdentityResponse).not.toHaveBeenCalled()
  })
  it('requires exact target confirmation and never retries a failed apply', async () => {
    api.getIdentityWorkforce.mockResolvedValue({ ...meta, actions: [action] })
    api.applyIdentityResponse.mockRejectedValue(new Error('Outcome uncertain'))
    render(<IdentityWorkforceCard workspaceId="wa" />); await select()
    const button = screen.getByRole('button', { name: 'Request session revocation' })
    expect(button.disabled).toBe(true)
    fireEvent.change(screen.getByLabelText('Confirm action'), { target: { value: upn } }); expect(button.disabled).toBe(false)
    fireEvent.click(button)
    await waitFor(() => expect(api.applyIdentityResponse).toHaveBeenCalledTimes(1))
    await waitFor(() => expect(screen.getByLabelText('Entra client secret').value).toBe(''))
    expect(screen.getByRole('alert').textContent).toContain('Outcome uncertain')
    expect(api.applyIdentityResponse).toHaveBeenCalledWith('wa', 'action', { confirmed_upn: upn, credentials: { tenantId: 'tenant', clientId: 'client', clientSecret: 'test-secret' } })
  })
  it('shows provider acceptance and timestamp without claiming logout completion', async () => {
    api.getIdentityWorkforce.mockResolvedValue({ ...meta, actions: [{ ...action, status: 'provider_accepted', verification: { state: 'provider_timestamp_advanced', checkedAt: action.created_at, note: 'Not proof of completed logout.' } }] })
    render(<IdentityWorkforceCard workspaceId="wa" />); await select()
    expect(screen.getByText('Microsoft accepted the request')).toBeTruthy()
    expect(screen.getByText(/Logout from every application has not been independently verified/)).toBeTruthy()
    expect(screen.getByText(/Not proof of completed logout/)).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Request session revocation' })).toBeNull()
  })
  it('marks VIP without sending Entra credentials or calling the provider', async () => {
    render(<IdentityWorkforceCard workspaceId="wa" />)
    fireEvent.click(await screen.findByLabelText('VIP '+upn))
    await waitFor(() => expect(api.updateIdentityAccount).toHaveBeenCalledWith('wa','person',{ vip:true }))
    expect(api.observeIdentityAccount).not.toHaveBeenCalled()
  })
})
