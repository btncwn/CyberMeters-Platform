/**
 * Security Hardening v2 — F-2: Microsoft SSO must enforce MFA.
 *
 * The backend, for an MFA-enabled account, returns { mfa_required, challenge_token }
 * from the OAuth exchange instead of a session. These tests pin the frontend half of
 * that contract:
 *   1. MicrosoftCallbackPage hands the challenge to /login (and never logs the user in).
 *   2. LoginPage renders its existing second-factor step from that handoff and
 *      completes via the same api.mfaChallenge endpoint as password login.
 * If the SSO path ever falls back to logging in without the second factor, these fail.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

const navigateSpy = vi.fn()
const loginSpy = vi.fn()

vi.mock('react-router-dom', async (orig) => {
  const actual = await orig()
  return { ...actual, useNavigate: () => navigateSpy }
})
vi.mock('../../context/AuthContext', () => ({ useAuth: () => ({ login: loginSpy }) }))
vi.mock('../../api', () => ({
  BASE: 'http://test',
  api: {
    exchangeOAuthCode: vi.fn(),
    mfaChallenge: vi.fn(),
    getWorkspaces: vi.fn(),
  },
}))

import { api } from '../../api'
import MicrosoftCallbackPage from '../MicrosoftCallbackPage'
import LoginPage from '../LoginPage'

beforeEach(() => {
  navigateSpy.mockReset()
  loginSpy.mockReset()
  api.exchangeOAuthCode.mockReset()
  api.mfaChallenge.mockReset()
  api.getWorkspaces.mockReset()
})

describe('F-2 SSO MFA — MicrosoftCallbackPage', () => {
  it('hands the challenge to /login and does NOT create a session when MFA is required', async () => {
    api.exchangeOAuthCode.mockResolvedValue({ mfa_required: true, challenge_token: 'cmfa_abc' })

    render(
      <MemoryRouter initialEntries={['/auth/microsoft/callback?otc=otc123']}>
        <MicrosoftCallbackPage />
      </MemoryRouter>
    )

    await waitFor(() => expect(navigateSpy).toHaveBeenCalled())
    expect(navigateSpy).toHaveBeenCalledWith('/login', {
      replace: true,
      state: { mfaChallengeToken: 'cmfa_abc' },
    })
    // The second factor is not yet satisfied — no session may be established.
    expect(loginSpy).not.toHaveBeenCalled()
  })

  it('still logs in normally when no MFA is required (non-regression)', async () => {
    api.exchangeOAuthCode.mockResolvedValue({ token: 't', id: 'u1', email: 'a@b.com', name: 'A', plan: 'free' })
    api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'w1' }] })

    render(
      <MemoryRouter initialEntries={['/auth/microsoft/callback?otc=otc123']}>
        <MicrosoftCallbackPage />
      </MemoryRouter>
    )

    await waitFor(() => expect(loginSpy).toHaveBeenCalled())
    expect(loginSpy).toHaveBeenCalledWith('t', expect.objectContaining({ id: 'u1', email: 'a@b.com' }))
  })
})

describe('F-2 SSO MFA — LoginPage', () => {
  it('renders the second-factor step from the SSO handoff and completes via mfaChallenge', async () => {
    api.mfaChallenge.mockResolvedValue({ token: 't', user: { id: 'u1', email: 'a@b.com', plan: 'free' } })
    api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'w1' }] })

    render(
      <MemoryRouter initialEntries={[{ pathname: '/login', state: { mfaChallengeToken: 'cmfa_abc' } }]}>
        <LoginPage />
      </MemoryRouter>
    )

    // MFA UI shown; the password form is not.
    expect(screen.getByText(/Two-factor authentication/i)).toBeInTheDocument()
    expect(screen.queryByLabelText(/Password/i)).not.toBeInTheDocument()

    fireEvent.change(screen.getByPlaceholderText('000000'), { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: /Verify/i }))

    await waitFor(() => expect(api.mfaChallenge).toHaveBeenCalled())
    expect(api.mfaChallenge).toHaveBeenCalledWith('cmfa_abc', '123456')
  })

  it('shows the password form (not MFA) for a normal visit with no handoff state', () => {
    render(
      <MemoryRouter initialEntries={['/login']}>
        <LoginPage />
      </MemoryRouter>
    )
    expect(screen.queryByText(/Two-factor authentication/i)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Sign in/i })).toBeInTheDocument()
  })
})
