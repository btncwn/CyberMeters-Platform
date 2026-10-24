import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../../api'
import ActiveCheckPermissionsPage from '../ActiveCheckPermissionsPage'

// S1-A (founder decision 22 Oct 2026): the Active Checks consent form on the
// S2-A API. Every field is the API's; the page invents none.

const prompt = vi.fn()
vi.mock('../../../api', () => ({
  api: { getActiveCheckConsents: vi.fn(), grantActiveCheckConsent: vi.fn(), revokeActiveCheckConsent: vi.fn(), getWorkspaceDomains: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: () => ({ wsId: 'ws1', wsName: 'Black Bull Barbers', loading: false }) }))
vi.mock('../../../context/AuthContext', () => ({ useAuth: () => ({ user: { email: 'owner@example.co.uk' } }) }))
vi.mock('../../../components/AppDialog', () => ({ useAppDialog: () => ({ prompt }) }))

const AUTHORITY = { version: 'active-checks-2026-10-22', text: 'I confirm that I am authorised by the organisation that owns this domain to permit CyberMeters to run the active checks listed here.' }
const CATALOGUE = [
  // #929: only `available: true` is offered (an absent field is not an offer).
  { id: 'tls_intrusive_heartbleed', label: 'TLS Heartbleed test', available: true },
  { id: 'mail_open_relay', label: 'Open mail relay (no message is delivered)', available: true },
]
const grant = (over = {}) => ({
  id: 'acc_1', domain: 'blackbullbarbers.co.uk', hosts: ['mail.blackbullbarbers.co.uk'], checks: ['mail_open_relay'],
  granted_at: '2026-10-22T08:00:00.000Z', signer: { name: 'Taylor Owner', title: 'Director', workspace_role: 'owner', user_id: 'usr_1' },
  authority_version: AUTHORITY.version, status: 'active', revoked_at: null, revoked_by: null, ...over,
})
const payload = (over = {}) => ({ consents: [], catalogue: CATALOGUE, authority: AUTHORITY, capabilities: { can_manage: true }, ...over })

function renderPage() {
  return render(<MemoryRouter><ActiveCheckPermissionsPage /></MemoryRouter>)
}

beforeEach(() => {
  vi.clearAllMocks()
  api.getWorkspaceDomains.mockResolvedValue({ domains: [{ domain: 'blackbullbarbers.co.uk', domain_id: 'dom_1', verification_status: 'verified', verified_at: '2026-10-01T00:00:00Z' }] })
  api.getActiveCheckConsents.mockResolvedValue(payload())
  api.grantActiveCheckConsent.mockResolvedValue({ consent: grant() })
  api.revokeActiveCheckConsent.mockResolvedValue({ consent: grant({ status: 'revoked' }) })
})

async function fillForm() {
  fireEvent.change(await screen.findByRole('combobox', { name: 'Verified domain' }), { target: { value: 'dom_1' } })
  fireEvent.change(screen.getByRole('textbox', { name: /Hosts/ }), { target: { value: 'Mail.BlackBullBarbers.co.uk.\nmail.blackbullbarbers.co.uk' } })
  fireEvent.click(screen.getByRole('checkbox', { name: 'Open mail relay (no message is delivered)' }))
  fireEvent.change(screen.getByRole('textbox', { name: 'Your name' }), { target: { value: '  Taylor Owner ' } })
  fireEvent.change(screen.getByRole('textbox', { name: 'Your title' }), { target: { value: 'Director' } })
  fireEvent.click(screen.getByRole('checkbox', { name: AUTHORITY.text }))
}

describe('Active Checks permission (S1-A)', () => {
  it('one primary action; nothing is preselected; the authority text is the API’s, verbatim', async () => {
    renderPage()
    const form = await screen.findByRole('form', { name: 'Authorise active checks' })
    expect(within(form).getAllByRole('button')).toHaveLength(1)
    expect(screen.getByRole('button', { name: 'Authorise' })).toBeDisabled()
    for (const c of CATALOGUE) expect(screen.getByRole('checkbox', { name: c.label })).not.toBeChecked()
    expect(screen.getByRole('checkbox', { name: AUTHORITY.text })).not.toBeChecked()
    expect(screen.getByText('owner@example.co.uk')).toBeInTheDocument()
    expect(screen.getByText(/UTC$/)).toBeInTheDocument()
    expect(screen.getByText(/does not independently verify it/)).toBeInTheDocument()
  })

  it('records exactly the API fields: domain id, normalised distinct hosts, chosen checks, signer, confirmation and version', async () => {
    renderPage()
    await fillForm()
    const button = screen.getByRole('button', { name: 'Authorise' })
    expect(button).toBeEnabled()
    fireEvent.click(button)
    await waitFor(() => expect(api.grantActiveCheckConsent).toHaveBeenCalledWith('ws1', {
      domain_id: 'dom_1',
      hosts: ['mail.blackbullbarbers.co.uk'],
      checks: ['mail_open_relay'],
      signer_name: 'Taylor Owner',
      signer_title: 'Director',
      authority_confirmed: true,
      authority_version: AUTHORITY.version,
    }))
    expect(await screen.findByText('Permission recorded. No check was started.')).toBeInTheDocument()
    expect(api.getActiveCheckConsents).toHaveBeenCalledTimes(2)
  })

  it('cannot authorise without the authority statement confirmed', async () => {
    renderPage()
    await fillForm()
    fireEvent.click(screen.getByRole('checkbox', { name: AUTHORITY.text }))
    expect(screen.getByRole('button', { name: 'Authorise' })).toBeDisabled()
  })

  it('a refused grant says why in words and records nothing', async () => {
    api.grantActiveCheckConsent.mockRejectedValue(Object.assign(new Error('Something went wrong. Please try again.'), { status: 400, error: 'invalid_active_check_hosts', code: 'invalid_active_check_hosts' }))
    renderPage()
    await fillForm()
    fireEvent.click(screen.getByRole('button', { name: 'Authorise' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Each host must be the domain itself or a name under it')
    expect(document.body.textContent).not.toMatch(/invalid_active_check_hosts/)
  })

  it('a receipt shows the stored record; revoking asks first, then appends a revocation', async () => {
    api.getActiveCheckConsents.mockResolvedValue(payload({ consents: [grant()] }))
    prompt.mockResolvedValue('')
    renderPage()
    const receipt = within(await screen.findByTestId('consent-receipt'))
    expect(receipt.getByText('mail.blackbullbarbers.co.uk')).toBeInTheDocument()
    expect(receipt.getByText('Open mail relay (no message is delivered)')).toBeInTheDocument()
    expect(receipt.getByText(/Taylor Owner, Director \(workspace owner\)/)).toBeInTheDocument()
    expect(receipt.getByText(/22 Oct 2026, 08:00 UTC/)).toBeInTheDocument()
    expect(receipt.getByText(new RegExp(AUTHORITY.text.slice(0, 40)))).toBeInTheDocument()
    fireEvent.click(receipt.getByRole('button', { name: 'Revoke permission' }))
    await waitFor(() => expect(api.revokeActiveCheckConsent).toHaveBeenCalledWith('ws1', 'acc_1', ''))
    expect(prompt).toHaveBeenCalledWith(expect.objectContaining({ confirmLabel: 'Revoke permission', tone: 'danger', label: 'Reason (optional)' }))
  })

  it('declining the confirmation revokes nothing', async () => {
    api.getActiveCheckConsents.mockResolvedValue(payload({ consents: [grant()] }))
    prompt.mockResolvedValue(null)
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Revoke permission' }))
    await waitFor(() => expect(prompt).toHaveBeenCalled())
    expect(api.revokeActiveCheckConsent).not.toHaveBeenCalled()
  })

  it('a revoked receipt cannot be revoked again; an empty host list reads as the domain only', async () => {
    api.getActiveCheckConsents.mockResolvedValue(payload({ consents: [grant({ hosts: [], status: 'revoked', revoked_at: '2026-10-22T09:00:00.000Z' })] }))
    renderPage()
    const receipt = within(await screen.findByTestId('consent-receipt'))
    expect(receipt.getByText('blackbullbarbers.co.uk only')).toBeInTheDocument()
    expect(receipt.getAllByText(/Revoked/).length).toBeGreaterThan(0)
    expect(receipt.queryByRole('button', { name: 'Revoke permission' })).toBeNull()
  })

  it('a member who cannot manage sees every record but no form and no revoke', async () => {
    api.getActiveCheckConsents.mockResolvedValue(payload({ consents: [grant()], capabilities: { can_manage: false } }))
    renderPage()
    expect(await screen.findByText(/A workspace admin can authorise or revoke/)).toBeInTheDocument()
    expect(screen.queryByRole('form', { name: 'Authorise active checks' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Revoke permission' })).toBeNull()
    expect(screen.getByTestId('consent-receipt')).toBeInTheDocument()
  })

  it('before the permission service is live it says so and authorises nothing', async () => {
    api.getActiveCheckConsents.mockRejectedValue(Object.assign(new Error('Not found'), { status: 404 }))
    renderPage()
    expect(await screen.findByText(/not available yet\. Nothing has been authorised/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Authorise' })).toBeNull()
  })

  it('a check no longer in the catalogue never shows its id', async () => {
    api.getActiveCheckConsents.mockResolvedValue(payload({ consents: [grant({ checks: ['retired_check_id'] })] }))
    renderPage()
    const receipt = within(await screen.findByTestId('consent-receipt'))
    expect(receipt.getByText('A check no longer offered')).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/retired_check_id|tls_intrusive|mail_open_relay/)
  })

  it('a reason typed in the revoke dialog is sent with the revocation', async () => {
    api.getActiveCheckConsents.mockResolvedValue(payload({ consents: [grant()] }))
    prompt.mockResolvedValue('The mail server moved to a new provider.')
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Revoke permission' }))
    await waitFor(() => expect(api.revokeActiveCheckConsent).toHaveBeenCalledWith('ws1', 'acc_1', 'The mail server moved to a new provider.'))
  })

  it('a receipt shows its own stored statement, the admin-only IP, and why it was revoked', async () => {
    const older = 'An earlier statement, exactly as it was agreed.'
    api.getActiveCheckConsents.mockResolvedValue(payload({ consents: [
      grant({ id: 'acc_old', authority_version: 'active-checks-2026-01-01', authority_text: older, signer: { ...grant().signer, ip_address: '203.0.113.7' },
        status: 'revoked', revoked_at: '2026-10-22T09:00:00.000Z', revocation_reason: 'Moved provider.' }),
      grant({ id: 'acc_new', status: 'revoked', revoked_at: '2026-10-22T09:30:00.000Z', revocation_reason: null }),
    ] }))
    renderPage()
    const [oldReceipt, newReceipt] = (await screen.findAllByTestId('consent-receipt')).map((el) => within(el))
    expect(oldReceipt.getByText(`“${older}”`)).toBeInTheDocument()
    expect(oldReceipt.getByText('203.0.113.7')).toBeInTheDocument()
    expect(oldReceipt.getByText('Moved provider.')).toBeInTheDocument()
    expect(newReceipt.getByText('No reason given')).toBeInTheDocument()
    expect(newReceipt.queryByText('IP address')).toBeNull()
  })
})
