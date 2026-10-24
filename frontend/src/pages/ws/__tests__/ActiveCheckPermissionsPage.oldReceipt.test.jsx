import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, expect, it, vi } from 'vitest'
import { api } from '../../../api'
import ActiveCheckPermissionsPage from '../ActiveCheckPermissionsPage'

// Founder live run (24 Oct 2026): a 22 Oct permission lists checks that are not
// available (open relay, DNS resolver…). Each one says "Not available — never run".
vi.mock('../../../api', () => ({
  api: { getActiveCheckConsents: vi.fn(), grantActiveCheckConsent: vi.fn(), revokeActiveCheckConsent: vi.fn(), getWorkspaceDomains: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: () => ({ wsId: 'ws1', wsName: 'Example Ltd', loading: false }) }))
vi.mock('../../../context/AuthContext', () => ({ useAuth: () => ({ user: { email: 'owner@example.co.uk' } }) }))
vi.mock('../../../components/AppDialog', () => ({ useAppDialog: () => ({ prompt: vi.fn() }) }))

beforeEach(() => {
  vi.clearAllMocks()
  api.getWorkspaceDomains.mockResolvedValue({ domains: [{ domain: 'example.co.uk', domain_id: 'dom_1', verification_status: 'verified' }] })
})

it('an older permission marks each unavailable check "Not available — never run"; available ones read plainly', async () => {
  api.getActiveCheckConsents.mockResolvedValue({
    consents: [{ id: 'acc_old', domain: 'example.co.uk', hosts: [], status: 'active', granted_at: '2026-10-22T08:00:00.000Z',
      checks: ['tls_intrusive_heartbleed', 'smtp_open_relay', 'dns_open_resolver'],
      signer: { name: 'Taylor Owner', title: 'Director', workspace_role: 'owner' }, authority_version: 'active-checks-2026-10-22' }],
    catalogue: [
      { id: 'tls_intrusive_heartbleed', label: 'TLS Heartbleed test', available: true },
      { id: 'smtp_open_relay', label: 'Mail open-relay test', available: false },
      { id: 'dns_open_resolver', label: 'Open DNS resolver test', available: false },
    ],
    authority: { version: 'active-checks-2026-10-22', text: 'I confirm that I am authorised.' }, capabilities: { can_manage: true },
  })
  render(<MemoryRouter><ActiveCheckPermissionsPage /></MemoryRouter>)
  const marks = await screen.findAllByTestId('receipt-check-unavailable')
  const items = marks.map((m) => m.closest('li').textContent)
  expect(items).toEqual(['Mail open-relay test — Not available — never run', 'Open DNS resolver test — Not available — never run'])
  const receiptList = marks[0].closest('ul')
  expect(within(receiptList).getByText('TLS Heartbleed test').closest('li')).not.toHaveTextContent('Not available')
  expect(screen.getAllByTestId('receipt-check-unavailable')).toHaveLength(2)
})
