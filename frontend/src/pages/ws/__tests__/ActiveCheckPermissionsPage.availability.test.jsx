import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../../api'
import ActiveCheckPermissionsPage from '../ActiveCheckPermissionsPage'

// #929: catalogue[].available says whether a released engine runs the check
// today. An unavailable check is shown, cannot be ticked, says "Not available
// yet", and is never sent; the rest of the form is unchanged.

vi.mock('../../../api', () => ({
  api: { getActiveCheckConsents: vi.fn(), grantActiveCheckConsent: vi.fn(), revokeActiveCheckConsent: vi.fn(), getWorkspaceDomains: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: () => ({ wsId: 'ws1', wsName: 'Black Bull Barbers', loading: false }) }))
vi.mock('../../../context/AuthContext', () => ({ useAuth: () => ({ user: { email: 'owner@example.co.uk' } }) }))
vi.mock('../../../components/AppDialog', () => ({ useAppDialog: () => ({ prompt: vi.fn() }) }))

const AUTHORITY = { version: 'active-checks-2026-10-22', text: 'I confirm that I am authorised by the organisation that owns this domain to permit CyberMeters to run the active checks listed here.' }
const NA = 'Not available yet — CyberMeters does not run this check today, so it cannot be authorised.'
const CATALOGUE = [
  { id: 'tls_intrusive_heartbleed', label: 'TLS Heartbleed test', available: false },
  { id: 'mail_open_relay', label: 'Open mail relay (no message is delivered)', available: true },
  { id: 'dns_open_resolver', label: 'Open DNS resolver' }, // older catalogue: no field → offered
]

beforeEach(() => {
  vi.clearAllMocks()
  api.getWorkspaceDomains.mockResolvedValue({ domains: [{ domain: 'blackbullbarbers.co.uk', domain_id: 'dom_1', verification_status: 'verified', verified_at: '2026-10-01T00:00:00Z' }] })
  api.getActiveCheckConsents.mockResolvedValue({ consents: [], catalogue: CATALOGUE, authority: AUTHORITY, capabilities: { can_manage: true } })
  api.grantActiveCheckConsent.mockResolvedValue({ consent: { id: 'acc_1', domain: 'blackbullbarbers.co.uk', hosts: ['mail.blackbullbarbers.co.uk'], checks: ['mail_open_relay'], granted_at: '2026-10-22T08:00:00.000Z', signer: { name: 'Taylor Owner', title: 'Director', workspace_role: 'owner', user_id: 'usr_1' }, authority_version: AUTHORITY.version, status: 'active' } })
})

const render_ = () => render(<MemoryRouter><ActiveCheckPermissionsPage /></MemoryRouter>)

describe('Active Checks availability (#929)', () => {
  it('an unavailable check is disabled and says "Not available yet"; available ones are unchanged', async () => {
    render_()
    await screen.findByRole('form', { name: 'Authorise active checks' })
    const heartbleed = screen.getByRole('checkbox', { name: /TLS Heartbleed test/ })
    expect(heartbleed).toBeDisabled()
    expect(heartbleed).toHaveAccessibleDescription(NA)
    expect(screen.getByTestId('active-check-tls_intrusive_heartbleed')).toHaveTextContent(NA)
    expect(screen.getByRole('checkbox', { name: 'Open mail relay (no message is delivered)' })).toBeEnabled()
    expect(screen.getByRole('checkbox', { name: 'Open DNS resolver' })).toBeEnabled()
    expect(screen.getAllByText(NA)).toHaveLength(1)
  })
  it('clicking an unavailable check does nothing; only available checks are sent', async () => {
    render_()
    fireEvent.change(await screen.findByRole('combobox', { name: 'Verified domain' }), { target: { value: 'dom_1' } })
    fireEvent.change(screen.getByRole('textbox', { name: /Hosts/ }), { target: { value: 'mail.blackbullbarbers.co.uk' } })
    fireEvent.click(screen.getByRole('checkbox', { name: /TLS Heartbleed test/ }))
    expect(screen.getByRole('checkbox', { name: /TLS Heartbleed test/ })).not.toBeChecked()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Open mail relay (no message is delivered)' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'Your name' }), { target: { value: 'Taylor Owner' } })
    fireEvent.change(screen.getByRole('textbox', { name: 'Your title' }), { target: { value: 'Director' } })
    fireEvent.click(screen.getByRole('checkbox', { name: AUTHORITY.text }))
    fireEvent.click(screen.getByRole('button', { name: 'Authorise' }))
    await waitFor(() => expect(api.grantActiveCheckConsent).toHaveBeenCalled())
    expect(api.grantActiveCheckConsent.mock.calls[0][1].checks).toEqual(['mail_open_relay'])
  })
  it('the server refusal active_check_not_available reads in plain words', async () => {
    api.grantActiveCheckConsent.mockRejectedValue(Object.assign(new Error('active_check_not_available'), { status: 422 }))
    render_()
    fireEvent.change(await screen.findByRole('combobox', { name: 'Verified domain' }), { target: { value: 'dom_1' } })
    fireEvent.change(screen.getByRole('textbox', { name: /Hosts/ }), { target: { value: 'mail.blackbullbarbers.co.uk' } })
    fireEvent.click(screen.getByRole('checkbox', { name: 'Open DNS resolver' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'Your name' }), { target: { value: 'Taylor Owner' } })
    fireEvent.change(screen.getByRole('textbox', { name: 'Your title' }), { target: { value: 'Director' } })
    fireEvent.click(screen.getByRole('checkbox', { name: AUTHORITY.text }))
    fireEvent.click(screen.getByRole('button', { name: 'Authorise' }))
    expect(await screen.findByText('A chosen check is not available yet, so it cannot be authorised. Untick it and try again.')).toBeInTheDocument()
  })
})
