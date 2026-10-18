import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import InvitationLandingPage from '../InvitationLandingPage'
import { api, logoutWithToken } from '../../api'
import { useAuth } from '../../context/AuthContext'
import { INVITATION_ERRORS } from '../../lib/invitationFlow'

// Invitation page (18 Oct 2026): a signed-in visitor whose email does not match
// never sees "Join Workspace"; the one action signs out and returns to this
// same invitation; the invited address is shown masked; no raw API error ever
// renders. Signing up carries the token onward.

vi.mock('../../api', () => ({ api: { getInvitationPreview: vi.fn(), acceptWorkspaceInvitation: vi.fn() }, logoutWithToken: vi.fn() }))
vi.mock('../../context/AuthContext', () => ({ useAuth: vi.fn() }))

const TOKEN = `cmi_${'b'.repeat(64)}`
const preview = (over = {}) => ({ workspace_name: 'Black Bull Barbers', invited_by_name: 'Taylor Owner', role: 'analyst', expires_at: '2099-01-01T00:00:00Z', status: 'pending', invited_email_masked: 'c•••••r@gmail.com', ...over })

function Where() { const l = useLocation(); return <p data-testid="where">{l.pathname}|{JSON.stringify(l.state || null)}</p> }
function renderAt(auth) {
  useAuth.mockReturnValue({ isLoading: false, logout: vi.fn(), ...auth })
  return render(
    <MemoryRouter initialEntries={[`/invitations/${TOKEN}`]}>
      <Routes>
        <Route path="/invitations/:token" element={<><InvitationLandingPage /><Where /></>} />
        <Route path="*" element={<Where />} />
      </Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => { vi.clearAllMocks(); localStorage.clear() })

describe('email mismatch', () => {
  it('hides Join, shows the masked invited address and one "Sign out and continue" button', async () => {
    api.getInvitationPreview.mockResolvedValue(preview({ signed_in_matches: false }))
    renderAt({ isAuthenticated: true, user: { email: 'someone.else@example.com' } })
    await screen.findByTestId('invitation-mismatch')
    expect(screen.queryByRole('button', { name: /Join Workspace/ })).toBeNull()
    expect(screen.getByTestId('invitation-mismatch')).toHaveTextContent('c•••••r@gmail.com')
    expect(screen.getByTestId('invitation-mismatch')).toHaveTextContent('someone.else@example.com')
    expect(screen.getAllByRole('button', { name: 'Sign out and continue as the invited address' })).toHaveLength(1)
  })

  it('signing out returns to this same invitation URL', async () => {
    const logout = vi.fn()
    localStorage.setItem('cybermeters_auth_token', 'tok_x')
    api.getInvitationPreview.mockResolvedValue(preview({ signed_in_matches: false }))
    renderAt({ isAuthenticated: true, user: { email: 'someone.else@example.com' }, logout })
    fireEvent.click(await screen.findByRole('button', { name: 'Sign out and continue as the invited address' }))
    expect(logout).toHaveBeenCalled()
    expect(logoutWithToken).toHaveBeenCalledWith('tok_x')
    expect(screen.getByTestId('where')).toHaveTextContent(`/invitations/${TOKEN}`)
  })

  it('an older API without the flag: a 403 on Join switches to the mismatch screen, never the raw text', async () => {
    api.getInvitationPreview.mockResolvedValue(preview())
    api.acceptWorkspaceInvitation.mockRejectedValue(Object.assign(new Error('Invitation email does not match authenticated user'), { status: 403 }))
    renderAt({ isAuthenticated: true, user: { email: 'someone.else@example.com' } })
    fireEvent.click(await screen.findByRole('button', { name: 'Join Workspace' }))
    await screen.findByTestId('invitation-mismatch')
    expect(screen.queryByRole('button', { name: 'Join Workspace' })).toBeNull()
    expect(document.body.textContent).not.toMatch(/does not match authenticated user/)
  })
})

describe('no raw API errors', () => {
  it.each([
    [Object.assign(new Error('Unauthorized'), { status: 401 }), 'sign_in_required'],
    [Object.assign(new Error('Invitation expired'), { status: 410 }), 'expired'],
    [Object.assign(new Error('Invitation is accepted'), { status: 409 }), 'already_accepted'],
    [Object.assign(new Error('Invitation is cancelled'), { status: 409 }), 'revoked'],
    [Object.assign(new Error('Internal Server Error'), { status: 500 }), 'unavailable'],
  ])('a Join failure %s shows the mapped sentence', async (error, kind) => {
    api.getInvitationPreview.mockResolvedValue(preview({ signed_in_matches: true }))
    api.acceptWorkspaceInvitation.mockRejectedValue(error)
    renderAt({ isAuthenticated: true, user: { email: 'c.owner@gmail.com' } })
    fireEvent.click(await screen.findByRole('button', { name: 'Join Workspace' }))
    expect(await screen.findByText(INVITATION_ERRORS[kind])).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/Unauthorized|Internal Server Error|Invitation is (accepted|cancelled)|\b(401|409|410|500)\b/)
  })

  it('a failed preview shows the mapped sentence, not the server string', async () => {
    api.getInvitationPreview.mockRejectedValue(Object.assign(new Error('Invitation not found'), { status: 404 }))
    renderAt({ isAuthenticated: false, user: null })
    expect(await screen.findByTestId('invitation-load-error')).toHaveTextContent(INVITATION_ERRORS.not_found)
    expect(document.body.textContent).not.toMatch(/Invitation not found/)
  })
})

describe('signed out', () => {
  it('signing up carries the token and remembers it', async () => {
    api.getInvitationPreview.mockResolvedValue(preview({ signed_in_matches: null }))
    renderAt({ isAuthenticated: false, user: null })
    expect(await screen.findByTestId('invited-address')).toHaveTextContent('Sent to c•••••r@gmail.com')
    fireEvent.click(screen.getByRole('button', { name: /Sign Up & Join Workspace/ }))
    expect(screen.getByTestId('where')).toHaveTextContent(`/signup|{"invitationToken":"${TOKEN}"}`)
    expect(localStorage.getItem('cybermeters_pending_invite')).toBe(TOKEN)
  })

  it('a matching signed-in account sees Join and joins', async () => {
    api.getInvitationPreview.mockResolvedValue(preview({ signed_in_matches: true }))
    api.acceptWorkspaceInvitation.mockResolvedValue({ workspace_id: 'ws_bbb' })
    localStorage.setItem('cybermeters_pending_invite', TOKEN)
    renderAt({ isAuthenticated: true, user: { email: 'c.owner@gmail.com' } })
    fireEvent.click(await screen.findByRole('button', { name: 'Join Workspace' }))
    expect(await screen.findByText('Successfully joined workspace')).toBeInTheDocument()
    expect(localStorage.getItem('cybermeters_workspace_id')).toBe('ws_bbb')
    expect(localStorage.getItem('cybermeters_pending_invite')).toBeNull()
  })
})
