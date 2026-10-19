import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { BrowserRouter, Route, Routes } from 'react-router-dom'

// Secrets out of URLs (19 Oct 2026): every route that receives a token works
// with the new link (token in the fragment) and with a link sent before the
// change (token in the path or query), and after load the token is nowhere in
// the address bar. These tests drive the real browser address and history.

vi.mock('../api', () => ({
  BASE: 'https://api.example',
  api: {
    resetPassword: vi.fn(), verifyEmail: vi.fn(), resendVerification: vi.fn(),
    getInvitationPreview: vi.fn(), acceptWorkspaceInvitation: vi.fn(),
    exchangeOAuthCode: vi.fn(), getWorkspaces: vi.fn(),
  },
  logoutWithToken: vi.fn(),
}))
vi.mock('../context/AuthContext', () => ({
  useAuth: () => ({ isLoading: false, isAuthenticated: false, token: 'session', user: null, login: vi.fn(), logout: vi.fn() }),
}))

import { api } from '../api'
import { captureUrlSecrets } from '../lib/urlSecrets'
import ResetPasswordPage from '../pages/ResetPasswordPage'
import EmailVerificationPage from '../pages/EmailVerificationPage'
import InvitationLandingPage from '../pages/InvitationLandingPage'
import MicrosoftCallbackPage from '../pages/MicrosoftCallbackPage'
import McpConnectPage from '../pages/McpConnectPage'

const INVITE = `cmi_${'c'.repeat(64)}`
const HEX = 'e'.repeat(64)
const INTENT = 'n'.repeat(43)

// Open a link the way a browser does: set the address, run the start-up
// capture (the first import of main.jsx), then mount the app's router.
function openLink(href, element, path) {
  window.history.replaceState(null, '', href)
  captureUrlSecrets(window)
  return render(
    <BrowserRouter>
      <Routes>
        <Route path={path} element={element} />
        {path === '/invitations' && <Route path="/invitations/:token" element={element} />}
        <Route path="*" element={<p>elsewhere</p>} />
      </Routes>
    </BrowserRouter>,
  )
}

function expectAddressClean(...secrets) {
  const address = window.location.href
  for (const secret of secrets) {
    expect(address).not.toContain(secret)
    expect(address).not.toContain(encodeURIComponent(secret))
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  sessionStorage.clear()
  window.history.replaceState(null, '', '/')
})

describe.each([
  ['new link (fragment)', `/reset-password#t=${HEX}`],
  ['older link (query)', `/reset-password?token=${HEX}`],
])('password reset — %s', (_, href) => {
  it('sets the new password with the token, and the token is not in the address', async () => {
    api.resetPassword.mockResolvedValue({ success: true })
    openLink(href, <ResetPasswordPage />, '/reset-password')
    expectAddressClean(HEX)
    expect(window.location.pathname).toBe('/reset-password')
    fireEvent.change(screen.getByPlaceholderText('At least 12 characters'), { target: { value: 'a-long-new-passphrase' } })
    fireEvent.change(screen.getByPlaceholderText('Re-enter your password'), { target: { value: 'a-long-new-passphrase' } })
    fireEvent.click(screen.getByRole('button', { name: /reset|set|update|save/i }))
    await waitFor(() => expect(api.resetPassword).toHaveBeenCalledWith(HEX, 'a-long-new-passphrase'))
    expectAddressClean(HEX)
  })
})

describe('email verification', () => {
  it('new link: verifies the token from the fragment and keeps the invitation, address clean', async () => {
    api.verifyEmail.mockResolvedValue({ success: true, outcome: 'verified' })
    openLink(`/verify-email#t=${HEX}&next=%2Finvitations%2F${INVITE}`, <EmailVerificationPage />, '/verify-email')
    expectAddressClean(HEX, INVITE)
    expect(await screen.findByRole('heading', { name: 'Email verified' })).toBeInTheDocument()
    expect(api.verifyEmail).toHaveBeenCalledTimes(1)
    expect(api.verifyEmail).toHaveBeenCalledWith(HEX)
    expect(localStorage.getItem('cybermeters_pending_invite')).toBe(INVITE)
    expectAddressClean(HEX, INVITE)
  })

  it('new link: an expired token reads as expired, in plain words', async () => {
    api.verifyEmail.mockRejectedValue(Object.assign(new Error('x'), { code: 'expired', status: 400 }))
    const expiredToken = 'd'.repeat(64)
    openLink(`/verify-email#t=${expiredToken}`, <EmailVerificationPage />, '/verify-email')
    expect(await screen.findByText(/This verification link has expired/)).toBeInTheDocument()
    expectAddressClean(expiredToken)
  })

  it.each([
    ['older redirect (next in the query)', `/verify-email?success=1&next=%2Finvitations%2F${INVITE}`],
    ['new redirect (next in the fragment)', `/verify-email?success=1#next=%2Finvitations%2F${INVITE}`],
  ])('%s: shows the outcome and keeps the invitation, address clean', async (_, href) => {
    openLink(href, <EmailVerificationPage />, '/verify-email')
    expectAddressClean(INVITE)
    expect(window.location.search).toBe('?success=1')
    expect(await screen.findByRole('heading', { name: 'Email verified' })).toBeInTheDocument()
    expect(api.verifyEmail).not.toHaveBeenCalled()
    expect(localStorage.getItem('cybermeters_pending_invite')).toBe(INVITE)
  })
})

describe.each([
  ['new link (fragment)', `/invitations#t=${INVITE}`],
  ['older link (path)', `/invitations/${INVITE}`],
])('invitation — %s', (_, href) => {
  it('loads the invitation with the token, and the token is not in the address', async () => {
    api.getInvitationPreview.mockResolvedValue({ workspace_name: 'Black Bull Barbers', role: 'analyst', status: 'pending', expires_at: '2099-01-01T00:00:00Z' })
    openLink(href, <InvitationLandingPage />, '/invitations')
    expectAddressClean(INVITE)
    expect(window.location.pathname).toBe('/invitations')
    await screen.findByText('Black Bull Barbers', { exact: false })
    expect(api.getInvitationPreview).toHaveBeenCalledWith(INVITE)
    expectAddressClean(INVITE)
  })
})

describe.each([
  ['new redirect (fragment)', `/auth/microsoft/callback#otc=${HEX}`],
  ['older redirect (query)', `/auth/microsoft/callback?otc=${HEX}`],
])('Microsoft sign-in return — %s', (_, href) => {
  it('exchanges the one-time code, and the code is not in the address', async () => {
    localStorage.setItem('cm_ms_login_bindings', JSON.stringify([{ verifier: 'v'.repeat(43), at: Date.now() }]))
    api.exchangeOAuthCode.mockReturnValue(new Promise(() => {}))
    openLink(href, <MicrosoftCallbackPage />, '/auth/microsoft/callback')
    expectAddressClean(HEX)
    await waitFor(() => expect(api.exchangeOAuthCode).toHaveBeenCalledWith(HEX, expect.any(Array)))
  })
})

describe.each([
  ['new link (fragment)', `/mcp/connect#intent=${INTENT}`],
  ['older link (query)', `/mcp/connect?intent=${INTENT}`],
])('MCP connection — %s', (_, href) => {
  it('offers the permission review for the intent, and the intent is not in the address', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockReturnValue(new Promise(() => {}))
    openLink(href, <McpConnectPage />, '/mcp/connect')
    expectAddressClean(INTENT)
    fireEvent.click(screen.getByRole('button', { name: 'Continue to permission review' }))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalled())
    const [url, init] = fetchSpy.mock.calls[0]
    expect(url).not.toContain(INTENT)
    expect(JSON.parse(init.body)).toEqual({ intent: INTENT })
    fetchSpy.mockRestore()
  })
})
