import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import PendingInvitationBanner from '../PendingInvitationBanner'
import { api } from '../../api'

// The safety net after login: a live invitation for this account is offered
// with Join / Not now, never accepted automatically; anything not live is
// dropped silently; errors read in plain English.

vi.mock('../../api', () => ({ api: { getInvitationPreview: vi.fn(), acceptWorkspaceInvitation: vi.fn() } }))

const TOKEN = `cmi_${'c'.repeat(64)}`
const preview = (over = {}) => ({ workspace_name: 'Black Bull Barbers', invited_by_name: 'Taylor Owner', role: 'viewer', status: 'pending', expires_at: '2099-01-01T00:00:00Z', signed_in_matches: true, ...over })
const renderBanner = (props = {}) => render(
  <MemoryRouter initialEntries={['/onboarding']}>
    <Routes>
      <Route path="/onboarding" element={<PendingInvitationBanner {...props} />} />
      <Route path="/dashboard" element={<p data-testid="dashboard">dashboard</p>} />
    </Routes>
  </MemoryRouter>,
)

beforeEach(() => { vi.clearAllMocks(); localStorage.clear(); sessionStorage.clear() })

it('offers a live invitation with Join and Not now, and does not accept on its own', async () => {
  localStorage.setItem('cybermeters_pending_invite', TOKEN)
  api.getInvitationPreview.mockResolvedValue(preview())
  const onState = vi.fn()
  renderBanner({ onState })
  expect(await screen.findByRole('heading', { name: "You've been invited to Black Bull Barbers" })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Join Black Bull Barbers' })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Not now' })).toBeInTheDocument()
  expect(api.acceptWorkspaceInvitation).not.toHaveBeenCalled()
  await waitFor(() => expect(onState).toHaveBeenLastCalledWith('offer'))
})

it('Join accepts, selects the workspace and opens the dashboard', async () => {
  localStorage.setItem('cybermeters_pending_invite', TOKEN)
  api.getInvitationPreview.mockResolvedValue(preview())
  api.acceptWorkspaceInvitation.mockResolvedValue({ workspace_id: 'ws_bbb' })
  renderBanner()
  fireEvent.click(await screen.findByRole('button', { name: 'Join Black Bull Barbers' }))
  expect(await screen.findByTestId('dashboard')).toBeInTheDocument()
  expect(api.acceptWorkspaceInvitation).toHaveBeenCalledWith(TOKEN)
  expect(localStorage.getItem('cybermeters_workspace_id')).toBe('ws_bbb')
  expect(localStorage.getItem('cybermeters_pending_invite')).toBeNull()
})

it('Not now hides it for this session and reports dismissed', async () => {
  localStorage.setItem('cybermeters_pending_invite', TOKEN)
  api.getInvitationPreview.mockResolvedValue(preview())
  const onState = vi.fn()
  renderBanner({ onState })
  fireEvent.click(await screen.findByRole('button', { name: 'Not now' }))
  expect(screen.queryByTestId('pending-invitation')).toBeNull()
  expect(onState).toHaveBeenLastCalledWith('dismissed')
  expect(sessionStorage.getItem('cybermeters_invite_dismissed')).toBe(TOKEN)
})

it.each([
  ['accepted already', { status: 'accepted' }],
  ['expired', { expires_at: '2000-01-01T00:00:00Z' }],
  ['for another account', { signed_in_matches: false }],
])('drops an invitation that is %s', async (_label, over) => {
  localStorage.setItem('cybermeters_pending_invite', TOKEN)
  api.getInvitationPreview.mockResolvedValue(preview(over))
  const onState = vi.fn()
  renderBanner({ onState })
  await waitFor(() => expect(onState).toHaveBeenLastCalledWith('none'))
  expect(screen.queryByTestId('pending-invitation')).toBeNull()
})

it('a failed Join reads in plain English', async () => {
  localStorage.setItem('cybermeters_pending_invite', TOKEN)
  api.getInvitationPreview.mockResolvedValue(preview())
  api.acceptWorkspaceInvitation.mockRejectedValue(Object.assign(new Error('Unauthorized'), { status: 401 }))
  renderBanner()
  fireEvent.click(await screen.findByRole('button', { name: 'Join Black Bull Barbers' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Sign in with the invited email address')
  expect(document.body.textContent).not.toMatch(/Unauthorized/)
})

it('renders nothing without a remembered invitation', () => {
  const onState = vi.fn()
  const { container } = renderBanner({ onState })
  expect(container).toBeEmptyDOMElement()
  expect(api.getInvitationPreview).not.toHaveBeenCalled()
  expect(onState).toHaveBeenLastCalledWith('none')
})
