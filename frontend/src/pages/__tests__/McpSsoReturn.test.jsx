import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

const navigateSpy = vi.fn()
const loginSpy = vi.fn()
const startSpy = vi.fn()

vi.mock('react-router-dom', async (original) => {
  const actual = await original()
  return { ...actual, useNavigate: () => navigateSpy }
})
vi.mock('../../context/AuthContext', () => ({ useAuth: () => ({ login: loginSpy }) }))
vi.mock('../../api', () => ({
  api: {
    authLogin: vi.fn(), mfaChallenge: vi.fn(), mfaRecoveryCode: vi.fn(),
    startMicrosoftSignIn: vi.fn(), exchangeOAuthCode: vi.fn(),
    getWorkspaces: vi.fn(),
  },
}))
vi.mock('../../lib/microsoftLoginBinding', async (original) => {
  const actual = await original()
  return { ...actual, startMicrosoftSignIn: (...args) => startSpy(...args) }
})

import { api } from '../../api'
import { saveMicrosoftMcpContinuation } from '../../lib/mcpLoginContinuation'
import LoginPage from '../LoginPage'
import MicrosoftCallbackPage from '../MicrosoftCallbackPage'

const INTENT = 'i'.repeat(43)
const BINDING = 'b'.repeat(43)
const DESTINATION = `/mcp/connect?intent=${INTENT}`
const FROM = { pathname: '/mcp/connect', search: `?intent=${INTENT}` }
const VERIFIER = 'v'.repeat(43)

function browserBinding() {
  localStorage.setItem('cm_ms_login_bindings', JSON.stringify([
    { verifier: VERIFIER, at: Date.now() },
  ]))
}

beforeEach(() => {
  navigateSpy.mockReset()
  loginSpy.mockReset()
  startSpy.mockReset()
  for (const method of Object.values(api)) method.mockReset()
  localStorage.clear()
  sessionStorage.clear()
})

describe('MCP connection return after sign-in', () => {
  it('returns a password login to the original valid MCP intent', async () => {
    api.authLogin.mockResolvedValue({ token: 'session', user: { id: 'u1' } })
    api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws1' }] })
    render(<MemoryRouter initialEntries={[{ pathname: '/login', state: { from: FROM } }]}>
      <LoginPage />
    </MemoryRouter>)
    fireEvent.change(screen.getByLabelText(/Email/i), { target: { value: 'u@example.com' } })
    fireEvent.change(screen.getByLabelText(/^Password$/i), { target: { value: 'password' } })
    fireEvent.click(screen.getByRole('button', { name: /^Sign in$/i }))
    await waitFor(() => expect(navigateSpy).toHaveBeenCalledWith(DESTINATION, { replace: true }))
    expect(loginSpy).toHaveBeenCalledWith('session', { id: 'u1' })
  })

  it('stores the MCP destination only after Microsoft sign-in starts, bound to its challenge', async () => {
    api.startMicrosoftSignIn.mockResolvedValue({ authorize_url: 'https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize' })
    startSpy.mockImplementation(async ({ start }) => { await start(BINDING) })
    render(<MemoryRouter initialEntries={[{ pathname: '/login', state: { from: FROM } }]}>
      <LoginPage />
    </MemoryRouter>)
    fireEvent.click(screen.getByRole('button', { name: /Continue with Microsoft/i }))
    await waitFor(() => expect(api.startMicrosoftSignIn).toHaveBeenCalledWith(BINDING))
    const saved = JSON.parse(sessionStorage.getItem('cm_ms_mcp_continuation'))
    expect(saved).toMatchObject({ binding: BINDING, destination: DESTINATION })
    expect(saved).not.toHaveProperty('token')
  })

  it('takes a matching Microsoft callback to consent without putting the session token in a URL', async () => {
    browserBinding()
    saveMicrosoftMcpContinuation(BINDING, DESTINATION)
    api.exchangeOAuthCode.mockResolvedValue({ token: 'session', id: 'u1', email: 'u@example.com', binding: BINDING })
    api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws1' }] })
    render(<MemoryRouter initialEntries={[`/auth/microsoft/callback?otc=${'a'.repeat(64)}`]}>
      <MicrosoftCallbackPage />
    </MemoryRouter>)
    await waitFor(() => expect(navigateSpy).toHaveBeenCalledWith(DESTINATION, { replace: true }))
    expect(loginSpy).toHaveBeenCalledWith('session', expect.objectContaining({ id: 'u1' }))
    expect(JSON.stringify(navigateSpy.mock.calls)).not.toContain('session')
    expect(sessionStorage.getItem('cm_ms_mcp_continuation')).toBeNull()
  })

  it('carries the destination through Microsoft MFA and only navigates after second factor', async () => {
    browserBinding()
    saveMicrosoftMcpContinuation(BINDING, DESTINATION)
    api.exchangeOAuthCode.mockResolvedValue({ mfa_required: true, challenge_token: 'cmfa_abc', binding: BINDING })
    const callback = render(<MemoryRouter initialEntries={['/auth/microsoft/callback?otc=otc123']}>
      <MicrosoftCallbackPage />
    </MemoryRouter>)
    await waitFor(() => expect(navigateSpy).toHaveBeenCalledWith('/login', {
      replace: true, state: { mfaChallengeToken: 'cmfa_abc', from: FROM },
    }))
    expect(loginSpy).not.toHaveBeenCalled()
    callback.unmount()
    navigateSpy.mockReset()
    api.mfaChallenge.mockResolvedValue({ token: 'session', user: { id: 'u1' } })
    api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws1' }] })
    render(<MemoryRouter initialEntries={[{ pathname: '/login', state: {
      mfaChallengeToken: 'cmfa_abc', from: FROM,
    } }]}><LoginPage /></MemoryRouter>)
    fireEvent.change(screen.getByPlaceholderText('000000'), { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: /^Verify$/i }))
    await waitFor(() => expect(navigateSpy).toHaveBeenCalledWith(DESTINATION, { replace: true }))
  })

  it('ignores a callback URL intent and a mismatched browser binding', async () => {
    browserBinding()
    saveMicrosoftMcpContinuation(BINDING, DESTINATION)
    api.exchangeOAuthCode.mockResolvedValue({ token: 'session', id: 'u1', email: 'u@example.com',
      binding: 'x'.repeat(43) })
    api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws1' }] })
    render(<MemoryRouter initialEntries={[`/auth/microsoft/callback?otc=otc123&intent=${INTENT}`]}>
      <MicrosoftCallbackPage />
    </MemoryRouter>)
    await waitFor(() => expect(navigateSpy).toHaveBeenCalledWith('/dashboard', { replace: true }))
    expect(JSON.stringify(navigateSpy.mock.calls)).not.toContain(INTENT)
  })
})
