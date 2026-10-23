import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../../api'
import ActiveCheckPermissionsPage from '../ActiveCheckPermissionsPage'

// Founder, 23 Oct 2026: Authorise looked enabled while disabled, so clicking it
// "did nothing" (only the UTC clock changed). It is disabled AND says why, in one
// sentence tied to the button; a refused or failed submit always shows a message.

vi.mock('../../../api', () => ({
  api: { getActiveCheckConsents: vi.fn(), grantActiveCheckConsent: vi.fn(), revokeActiveCheckConsent: vi.fn(), getWorkspaceDomains: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: () => ({ wsId: 'ws1', wsName: 'Black Bull Barbers', loading: false }) }))
vi.mock('../../../context/AuthContext', () => ({ useAuth: () => ({ user: { email: 'owner@example.co.uk' } }) }))
vi.mock('../../../components/AppDialog', () => ({ useAppDialog: () => ({ prompt: vi.fn() }) }))

const AUTHORITY = { version: 'active-checks-2026-10-22', text: 'I confirm that I am authorised by the organisation that owns this domain to permit CyberMeters to run the active checks listed here.' }
const payload = (catalogue) => ({ consents: [], catalogue, authority: AUTHORITY, capabilities: { can_manage: true } })
const NONE = 'None of these checks can be authorised yet. They become available here when CyberMeters starts running them.'
const TICK = 'Tick at least one check to authorise.'

beforeEach(() => {
  vi.clearAllMocks()
  api.getWorkspaceDomains.mockResolvedValue({ domains: [{ domain: 'blackbullbarbers.co.uk', domain_id: 'dom_1', verification_status: 'verified', verified_at: '2026-10-01T00:00:00Z' }] })
})
const mount = () => render(<MemoryRouter><ActiveCheckPermissionsPage /></MemoryRouter>)

describe('Authorise says why it is unavailable', () => {
  it('no check available: disabled, with the founder\'s sentence as its description', async () => {
    api.getActiveCheckConsents.mockResolvedValue(payload([{ id: 'tls_intrusive_heartbleed', label: 'TLS Heartbleed test', available: false }]))
    mount()
    const button = await screen.findByRole('button', { name: 'Authorise' })
    expect(button).toBeDisabled()
    expect(button).toHaveAccessibleDescription(NONE)
    expect(screen.getByTestId('authorise-reason')).toHaveTextContent(NONE)
  })
  it('some available, none ticked: "Tick at least one check"; ticking moves to the next missing field', async () => {
    api.getActiveCheckConsents.mockResolvedValue(payload([{ id: 'mail_open_relay', label: 'Open mail relay (no message is delivered)', available: true }]))
    mount()
    const button = await screen.findByRole('button', { name: 'Authorise' })
    expect(button).toHaveAccessibleDescription(TICK)
    fireEvent.click(screen.getByRole('checkbox', { name: 'Open mail relay (no message is delivered)' }))
    expect(screen.getByTestId('authorise-reason')).toHaveTextContent('Choose a verified domain to authorise.')
  })
  it('a ready form has no reason; a refused submit shows an inline message', async () => {
    api.getActiveCheckConsents.mockResolvedValue(payload([{ id: 'mail_open_relay', label: 'Open mail relay (no message is delivered)', available: true }]))
    api.grantActiveCheckConsent.mockRejectedValue(Object.assign(new Error('active_check_not_available'), { status: 422 }))
    mount()
    fireEvent.change(await screen.findByRole('combobox', { name: 'Verified domain' }), { target: { value: 'dom_1' } })
    fireEvent.change(screen.getByRole('textbox', { name: /Hosts/ }), { target: { value: 'mail.blackbullbarbers.co.uk' } })
    fireEvent.click(screen.getByRole('checkbox', { name: 'Open mail relay (no message is delivered)' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'Your name' }), { target: { value: 'Taylor Owner' } })
    fireEvent.change(screen.getByRole('textbox', { name: 'Your title' }), { target: { value: 'Director' } })
    fireEvent.click(screen.getByRole('checkbox', { name: AUTHORITY.text }))
    expect(screen.queryByTestId('authorise-reason')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Authorise' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('not available yet')
  })
  it('a failed submit (network) shows the generic inline message, never silence', async () => {
    api.getActiveCheckConsents.mockResolvedValue(payload([{ id: 'mail_open_relay', label: 'Open mail relay (no message is delivered)', available: true }]))
    api.grantActiveCheckConsent.mockRejectedValue(new Error('network'))
    mount()
    fireEvent.change(await screen.findByRole('combobox', { name: 'Verified domain' }), { target: { value: 'dom_1' } })
    fireEvent.change(screen.getByRole('textbox', { name: /Hosts/ }), { target: { value: 'mail.blackbullbarbers.co.uk' } })
    fireEvent.click(screen.getByRole('checkbox', { name: 'Open mail relay (no message is delivered)' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'Your name' }), { target: { value: 'Taylor Owner' } })
    fireEvent.change(screen.getByRole('textbox', { name: 'Your title' }), { target: { value: 'Director' } })
    fireEvent.click(screen.getByRole('checkbox', { name: AUTHORITY.text }))
    fireEvent.click(screen.getByRole('button', { name: 'Authorise' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('The permission could not be recorded. Nothing was saved. Try again.')
  })
})
