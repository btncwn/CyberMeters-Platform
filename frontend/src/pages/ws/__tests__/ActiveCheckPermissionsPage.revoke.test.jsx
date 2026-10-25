import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, expect, it, vi } from 'vitest'
import { api } from '../../../api'
import ActiveCheckPermissionsPage from '../ActiveCheckPermissionsPage'

// P1 (founder 25 Oct 2026, /ws/active-checks/permission): "Revoke permission" did
// nothing — the page never rendered its confirmation dialog, so the prompt never
// resolved and no request was sent. This test uses the REAL AppDialog (no mock):
// click → the dialog appears → confirm → the API is called → the card reads Revoked.
vi.mock('../../../api', () => ({
  api: { getActiveCheckConsents: vi.fn(), grantActiveCheckConsent: vi.fn(), revokeActiveCheckConsent: vi.fn(), getWorkspaceDomains: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: () => ({ wsId: 'ws1', wsName: 'Example Ltd', loading: false }) }))
vi.mock('../../../context/AuthContext', () => ({ useAuth: () => ({ user: { email: 'owner@example.co.uk' } }) }))

const AUTHORITY = { version: 'active-checks-2026-10-22', text: 'I confirm that I am authorised.' }
const consent = (over = {}) => ({ id: 'acc_1', domain: 'probe.example.com', hosts: [], checks: ['tls_intrusive_robot'], status: 'active',
  granted_at: '2026-10-24T09:44:00.000Z', signer: { name: 'Taylor Owner', title: 'Director', workspace_role: 'owner' }, authority_version: AUTHORITY.version, ...over })
const payload = (c) => ({ consents: [c], catalogue: [{ id: 'tls_intrusive_robot', label: 'TLS ROBOT test', available: true }], authority: AUTHORITY, capabilities: { can_manage: true } })

beforeEach(() => {
  vi.clearAllMocks()
  api.getWorkspaceDomains.mockResolvedValue({ domains: [] })
})

it('Revoke permission opens the confirmation, revokes on confirm and the card reads Revoked', async () => {
  api.getActiveCheckConsents
    .mockResolvedValueOnce(payload(consent()))
    .mockResolvedValue(payload(consent({ status: 'revoked', revoked_at: '2026-10-25T15:40:00.000Z' })))
  api.revokeActiveCheckConsent.mockResolvedValue({ ok: true })
  render(<MemoryRouter><ActiveCheckPermissionsPage /></MemoryRouter>)
  fireEvent.click(await screen.findByRole('button', { name: 'Revoke permission' }))
  const dialog = await screen.findByTestId('app-dialog')
  expect(dialog).toHaveTextContent('Revoke permission for probe.example.com?')
  fireEvent.change(within(dialog).getByRole('textbox', { name: 'Reason (optional)' }), { target: { value: 'No longer needed' } })
  fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke permission' }))
  await waitFor(() => expect(api.revokeActiveCheckConsent).toHaveBeenCalledWith('ws1', 'acc_1', 'No longer needed'))
  expect(await screen.findByText('Revoked')).toBeInTheDocument()
  expect(screen.getByText('Permission revoked.')).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Revoke permission' })).toBeNull()
})

it('an empty optional reason still revokes', async () => {
  api.getActiveCheckConsents.mockResolvedValueOnce(payload(consent())).mockResolvedValue(payload(consent({ status: 'revoked', revoked_at: '2026-10-25T15:40:00.000Z' })))
  api.revokeActiveCheckConsent.mockResolvedValue({ ok: true })
  render(<MemoryRouter><ActiveCheckPermissionsPage /></MemoryRouter>)
  fireEvent.click(await screen.findByRole('button', { name: 'Revoke permission' }))
  const dialog = await screen.findByTestId('app-dialog')
  fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke permission' }))
  await waitFor(() => expect(api.revokeActiveCheckConsent).toHaveBeenCalledWith('ws1', 'acc_1', ''))
})

it('Cancel sends nothing and the permission stays Active', async () => {
  api.getActiveCheckConsents.mockResolvedValue(payload(consent()))
  render(<MemoryRouter><ActiveCheckPermissionsPage /></MemoryRouter>)
  fireEvent.click(await screen.findByRole('button', { name: 'Revoke permission' }))
  fireEvent.click(within(await screen.findByTestId('app-dialog')).getByRole('button', { name: 'Cancel' }))
  await waitFor(() => expect(screen.queryByTestId('app-dialog')).toBeNull())
  expect(api.revokeActiveCheckConsent).not.toHaveBeenCalled()
  expect(screen.getByText('Active')).toBeInTheDocument()
})
