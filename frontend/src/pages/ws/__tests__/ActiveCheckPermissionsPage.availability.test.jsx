import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../../api'
import ActiveCheckPermissionsPage from '../ActiveCheckPermissionsPage'

// catalogue[].available says whether a released engine runs the check today
// (#929). Founder, 27 Oct 2026: only those checks are offered. An unavailable or
// unknown entry is not shown as a choice at all and can never enter a grant;
// older receipts that name one still read in words and can still be revoked.

vi.mock('../../../api', () => ({
  api: { getActiveCheckConsents: vi.fn(), grantActiveCheckConsent: vi.fn(), revokeActiveCheckConsent: vi.fn(), getWorkspaceDomains: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: () => ({ wsId: 'ws1', wsName: 'Example Ltd', loading: false }) }))
vi.mock('../../../context/AuthContext', () => ({ useAuth: () => ({ user: { email: 'owner@example.co.uk' } }) }))
vi.mock('../../../components/AppDialog', () => ({ useAppDialog: () => ({ prompt: vi.fn() }) }))

const AUTHORITY = { version: 'active-checks-2026-10-22', text: 'I confirm that I am authorised by the organisation that owns this domain to permit CyberMeters to run the active checks listed here.' }
// The production catalogue's shape: three released TLS checks, five without an engine.
const RELEASED = [
  { id: 'tls_intrusive_heartbleed', label: 'TLS Heartbleed test', available: true },
  { id: 'tls_intrusive_robot', label: 'TLS ROBOT test', available: true },
  { id: 'tls_intrusive_ccs', label: 'TLS CCS injection test', available: true },
]
const UNRELEASED = [
  { id: 'takeover_active_confirm', label: 'Subdomain takeover confirmation (no claim is made)', available: false },
  { id: 'dns_open_resolver', label: 'Open DNS resolver', available: false },
  { id: 'mail_open_relay', label: 'Open mail relay (no message is delivered)', available: false },
  { id: 'mail_starttls_strip', label: 'Mail accepted without STARTTLS', available: false },
  { id: 'mail_spoof_resistance', label: 'Spoofed message to your designated seed mailbox', available: false },
]
const CATALOGUE = [...RELEASED, ...UNRELEASED]
const payload = (catalogue, consents = []) => ({ consents, catalogue, authority: AUTHORITY, capabilities: { can_manage: true } })

beforeEach(() => {
  vi.clearAllMocks()
  api.getWorkspaceDomains.mockResolvedValue({ domains: [{ domain: 'example.co.uk', domain_id: 'dom_1', verification_status: 'verified', verified_at: '2026-10-01T00:00:00Z' }] })
  api.getActiveCheckConsents.mockResolvedValue(payload(CATALOGUE))
  api.grantActiveCheckConsent.mockResolvedValue({ consent: { id: 'acc_1' } })
})

const render_ = () => render(<MemoryRouter><ActiveCheckPermissionsPage /></MemoryRouter>)
const checksGroup = async () => within(await screen.findByRole('group', { name: 'Checks' }))
const fillAndSubmit = () => {
  fireEvent.change(screen.getByRole('combobox', { name: 'Verified domain' }), { target: { value: 'dom_1' } })
  fireEvent.change(screen.getByRole('textbox', { name: 'Your name' }), { target: { value: 'Taylor Owner' } })
  fireEvent.change(screen.getByRole('textbox', { name: 'Your title' }), { target: { value: 'Director' } })
  fireEvent.click(screen.getByRole('checkbox', { name: AUTHORITY.text }))
  fireEvent.click(screen.getByRole('button', { name: 'Authorise' }))
}

describe('Active Checks: only released checks are offered', () => {
  it('3 available + 5 unavailable: exactly the 3 are offered, none preselected, no teaser for the 5', async () => {
    render_()
    const group = await checksGroup()
    const boxes = group.getAllByRole('checkbox')
    expect(boxes.map((b) => b.closest('label').textContent)).toEqual(RELEASED.map((c) => c.label))
    for (const box of boxes) { expect(box).toBeEnabled(); expect(box).not.toBeChecked() }
    for (const c of UNRELEASED) {
      expect(screen.queryByText(c.label)).toBeNull()
      expect(screen.queryByTestId(`active-check-${c.id}`)).toBeNull()
    }
    expect(screen.queryByText(/Not available yet/)).toBeNull()
    expect(screen.getByTestId('tls-scope-note')).toBeInTheDocument()
  })
  it('an entry with no or a non-true `available` is never offered (an offer never comes from an absent field)', async () => {
    api.getActiveCheckConsents.mockResolvedValue(payload([
      RELEASED[0],
      { id: 'dns_open_resolver', label: 'Open DNS resolver' },
      { id: 'mail_open_relay', label: 'Open mail relay (no message is delivered)', available: 'true' },
      { id: 'mail_starttls_strip', label: 'Mail accepted without STARTTLS', available: null },
    ]))
    render_()
    const group = await checksGroup()
    expect(group.getAllByRole('checkbox').map((b) => b.closest('label').textContent)).toEqual(['TLS Heartbleed test'])
  })
  it('a grant sends only ticked released checks', async () => {
    render_()
    const group = await checksGroup()
    fireEvent.click(group.getByRole('checkbox', { name: 'TLS ROBOT test' }))
    fillAndSubmit()
    await waitFor(() => expect(api.grantActiveCheckConsent).toHaveBeenCalledTimes(1))
    const body = api.grantActiveCheckConsent.mock.calls[0][1]
    expect(body.checks).toEqual(['tls_intrusive_robot'])
    expect(Object.keys(body).sort()).toEqual(['authority_confirmed', 'authority_version', 'checks', 'domain_id', 'hosts', 'signer_name', 'signer_title'])
  })
  it('nothing available: an honest empty state, no choices, Authorise disabled with its reason', async () => {
    api.getActiveCheckConsents.mockResolvedValue(payload(UNRELEASED))
    render_()
    const group = await checksGroup()
    expect(group.queryAllByRole('checkbox')).toHaveLength(0)
    expect(screen.getByTestId('no-active-checks-offered')).toHaveTextContent('No active check can be authorised here yet.')
    expect(screen.queryByTestId('tls-scope-note')).toBeNull()
    expect(screen.getByRole('button', { name: 'Authorise' })).toBeDisabled()
    expect(screen.getByTestId('authorise-reason')).toHaveTextContent('None of these checks can be authorised yet.')
  })
  it('an older receipt naming now-hidden checks keeps their names and can still be revoked', async () => {
    api.getActiveCheckConsents.mockResolvedValue(payload(CATALOGUE, [{
      id: 'acc_old', domain: 'example.co.uk', hosts: ['mail.example.co.uk'], status: 'active', granted_at: '2026-10-22T08:00:00.000Z',
      checks: ['tls_intrusive_heartbleed', 'mail_open_relay', 'dns_open_resolver'],
      signer: { name: 'Taylor Owner', title: 'Director', workspace_role: 'owner' }, authority_version: AUTHORITY.version,
    }]))
    render_()
    const receipt = within(await screen.findByTestId('consent-receipt'))
    expect(receipt.getByText('Open mail relay (no message is delivered)')).toBeInTheDocument()
    expect(receipt.getByText('Open DNS resolver')).toBeInTheDocument()
    expect(receipt.getAllByTestId('receipt-check-unavailable')).toHaveLength(2)
    expect(receipt.getByText('mail.example.co.uk')).toBeInTheDocument()
    expect(receipt.getByRole('button', { name: 'Revoke permission' })).toBeEnabled()
    // Hidden from the form, still named on the record.
    expect((await checksGroup()).queryByText('Open DNS resolver')).toBeNull()
  })
  it('the server refusal active_check_not_available still reads in plain words', async () => {
    api.grantActiveCheckConsent.mockRejectedValue(Object.assign(new Error('Something went wrong. Please try again.'), { status: 422, error: 'active_check_not_available', code: 'active_check_not_available' }))
    render_()
    fireEvent.click((await checksGroup()).getByRole('checkbox', { name: 'TLS Heartbleed test' }))
    fillAndSubmit()
    expect(await screen.findByText('A chosen check is not available yet, so it cannot be authorised. Untick it and try again.')).toBeInTheDocument()
  })
})
