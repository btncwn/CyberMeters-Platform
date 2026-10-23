import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../../api'
import ActiveCheckPermissionsPage from '../ActiveCheckPermissionsPage'

// TLS specials go-live (Executive 23:00, Codex C-50 G02/G04): after a grant, the
// newest active receipt shows ONE next step — start a scan — and the hosts help
// says when extra hosts are tested.

vi.mock('../../../api', () => ({
  api: { getActiveCheckConsents: vi.fn(), grantActiveCheckConsent: vi.fn(), revokeActiveCheckConsent: vi.fn(), getWorkspaceDomains: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: () => ({ wsId: 'ws1', wsName: 'Black Bull Barbers', loading: false }) }))
vi.mock('../../../context/AuthContext', () => ({ useAuth: () => ({ user: { email: 'owner@example.co.uk' } }) }))
vi.mock('../../../components/AppDialog', () => ({ useAppDialog: () => ({ prompt: vi.fn() }) }))

const AUTHORITY = { version: 'active-checks-2026-10-22', text: 'I confirm that I am authorised.' }
const grant = (over) => ({ id: 'acc_1', domain: 'blackbullbarbers.co.uk', hosts: [], checks: ['tls_intrusive_heartbleed'], granted_at: '2026-10-23T08:00:00.000Z',
  signer: { name: 'Taylor Owner', title: 'Director', workspace_role: 'owner' }, authority_version: AUTHORITY.version, status: 'active', ...over })

beforeEach(() => {
  vi.clearAllMocks()
  api.getWorkspaceDomains.mockResolvedValue({ domains: [{ domain: 'blackbullbarbers.co.uk', domain_id: 'dom_1', verification_status: 'verified', verified_at: '2026-10-01T00:00:00Z' }] })
})
const mount = () => render(<MemoryRouter><ActiveCheckPermissionsPage /></MemoryRouter>)

describe('after a grant', () => {
  it('the newest active receipt offers "Start a scan now" for its domain, with the started-scans sentence', async () => {
    api.getActiveCheckConsents.mockResolvedValue({ consents: [grant(), grant({ id: 'acc_0', domain: 'old.example', status: 'revoked', revoked_at: '2026-10-22T08:00:00Z' })],
      catalogue: [{ id: 'tls_intrusive_heartbleed', label: 'TLS Heartbleed test', available: true }], authority: AUTHORITY, capabilities: { can_manage: true } })
    mount()
    const steps = await screen.findAllByTestId('consent-next-step')
    expect(steps).toHaveLength(1)
    expect(steps[0]).toHaveTextContent('Authorised checks run only on scans you start yourself, never on scheduled scans.')
    expect(within(steps[0]).getByRole('link', { name: 'Start a scan now' })).toHaveAttribute('href', '/scans/new?domain=blackbullbarbers.co.uk')
  })
  it('no active grant, no next step; the hosts help names the TLS services condition', async () => {
    api.getActiveCheckConsents.mockResolvedValue({ consents: [], catalogue: [{ id: 'tls_intrusive_heartbleed', label: 'TLS Heartbleed test', available: true }], authority: AUTHORITY, capabilities: { can_manage: true } })
    mount()
    await screen.findByRole('form', { name: 'Authorise active checks' })
    expect(screen.queryByTestId('consent-next-step')).toBeNull()
    expect(screen.getByRole('textbox', { name: /Hosts/ })).toHaveAccessibleDescription(/Extra hosts are tested only if they are also added as TLS services under Certificates & Trust → Settings\./)
  })
})
