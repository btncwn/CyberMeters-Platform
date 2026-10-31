import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'

// A session the server refused and a session nobody could check are different
// things. Only the first signs the customer out. These tests stub the network
// alone and drive the real validateSession, AuthProvider and ProtectedRoute.

import { SessionUnavailableError, validateSession } from '../api'
import { AuthProvider, useAuth } from '../context/AuthContext'
import ProtectedRoute from '../components/ProtectedRoute'
import { TOKEN_KEY, USER_KEY } from '../context/authKeys'
import { WS_ID_KEY, WS_NAME_KEY } from '../lib/activeWorkspace'

const USER = { id: 'usr_a', email: 'a@example.co.uk', name: 'Account A', plan: 'free' }

const ok = (body = USER) => new Response(JSON.stringify(body), { status: 200 })
const status = (code) => new Response(JSON.stringify({ error: 'x' }), { status: code })
const networkDown = () => Promise.reject(new TypeError('Failed to fetch'))

function deferred() {
  let resolve
  const promise = new Promise((r) => { resolve = r })
  return { promise, resolve }
}

function Probe() {
  const { isAuthenticated, user, token, login, logout } = useAuth()
  return (
    <div>
      <p data-testid="authenticated">{String(isAuthenticated)}</p>
      <p data-testid="user">{user?.email || 'none'}</p>
      <p data-testid="token">{token || 'none'}</p>
      <button type="button" onClick={() => login('token_b', { ...USER, id: 'usr_b', email: 'b@example.co.uk' })}>test: sign in as B</button>
      <button type="button" onClick={() => logout()}>test: sign out</button>
    </div>
  )
}

function Where() {
  return <p data-testid="path">{useLocation().pathname}</p>
}

function renderApp() {
  return render(
    <MemoryRouter initialEntries={['/scans/scan_1']}>
      <AuthProvider>
        <Probe />
        <Where />
        <Routes>
          <Route path="/login" element={<p>login page</p>} />
          <Route path="/scans/:id" element={<ProtectedRoute><p>secret report</p></ProtectedRoute>} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const retryButton = () => screen.findByRole('button', { name: 'Try again' })

function expectStoredSessionKept() {
  expect(localStorage.getItem(TOKEN_KEY)).toBe('token_a')
  expect(JSON.parse(localStorage.getItem(USER_KEY)).id).toBe('usr_a')
  expect(localStorage.getItem(WS_ID_KEY)).toBe('ws_a')
  expect(localStorage.getItem(WS_NAME_KEY)).toBe('Alpha')
}

function expectStoredSessionCleared() {
  expect(localStorage.getItem(TOKEN_KEY)).toBeNull()
  expect(localStorage.getItem(USER_KEY)).toBeNull()
  expect(localStorage.getItem(WS_ID_KEY)).toBeNull()
  expect(localStorage.getItem(WS_NAME_KEY)).toBeNull()
}

let fetchMock

beforeEach(() => {
  localStorage.clear()
  localStorage.setItem(TOKEN_KEY, 'token_a')
  localStorage.setItem(USER_KEY, JSON.stringify(USER))
  localStorage.setItem(WS_ID_KEY, 'ws_a')
  localStorage.setItem(WS_NAME_KEY, 'Alpha')
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
  localStorage.clear()
})

describe('validateSession', () => {
  it('returns the user when the server confirms the session', async () => {
    fetchMock.mockResolvedValue(ok())
    await expect(validateSession()).resolves.toEqual(USER)
  })

  it('returns null only for a refused session or no token at all', async () => {
    fetchMock.mockResolvedValue(status(401))
    await expect(validateSession()).resolves.toBeNull()

    fetchMock.mockClear()
    localStorage.removeItem(TOKEN_KEY)
    await expect(validateSession()).resolves.toBeNull()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it.each([
    ['a network failure', networkDown],
    ['a 500', () => status(500)],
    ['a maintenance 503', () => status(503)],
    ['a rate limit', () => status(429)],
    ['a 403 from something in front of the API', () => status(403)],
    ['a 200 that is not JSON', () => new Response('<html></html>', { status: 200 })],
    ['a 200 that is not a user', () => ok({ ok: true })],
  ])('reports %s as unavailable, not as a refused session', async (_name, respond) => {
    fetchMock.mockImplementation(respond)
    await expect(validateSession()).rejects.toBeInstanceOf(SessionUnavailableError)
  })
})

describe('session check on load', () => {
  it('opens protected content for a confirmed session', async () => {
    fetchMock.mockResolvedValue(ok({ ...USER, name: 'Fresh Name' }))
    renderApp()
    expect(await screen.findByText('secret report')).toBeInTheDocument()
    expect(screen.getByTestId('authenticated')).toHaveTextContent('true')
    expect(JSON.parse(localStorage.getItem(USER_KEY)).name).toBe('Fresh Name')
  })

  it('still signs out on a real 401', async () => {
    fetchMock.mockResolvedValue(status(401))
    renderApp()
    expect(await screen.findByText('login page')).toBeInTheDocument()
    expect(screen.queryByText('secret report')).not.toBeInTheDocument()
    expectStoredSessionCleared()
  })

  it.each([
    ['a network failure', networkDown],
    ['a 500', () => status(500)],
    ['a maintenance 503', () => status(503)],
  ])('%s keeps the stored session but opens nothing', async (_name, respond) => {
    fetchMock.mockImplementation(respond)
    renderApp()

    expect(await screen.findByRole('alert')).toHaveTextContent('You have not been signed out')
    expect(await retryButton()).toBeInTheDocument()
    expect(screen.queryByText('secret report')).not.toBeInTheDocument()
    expect(screen.queryByText('login page')).not.toBeInTheDocument()
    expect(screen.getByTestId('path')).toHaveTextContent('/scans/scan_1')
    expectStoredSessionKept()

    // Nothing downstream treats the unconfirmed session as signed in.
    expect(screen.getByTestId('authenticated')).toHaveTextContent('false')
    expect(screen.getByTestId('user')).toHaveTextContent('none')
    expect(screen.getByTestId('token')).toHaveTextContent('none')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})

describe('trying again', () => {
  it('recovers to the same page once the server confirms the session', async () => {
    fetchMock.mockImplementationOnce(networkDown).mockResolvedValueOnce(ok())
    renderApp()
    fireEvent.click(await retryButton())

    expect(await screen.findByText('secret report')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.getByTestId('path')).toHaveTextContent('/scans/scan_1')
    expect(screen.getByTestId('authenticated')).toHaveTextContent('true')
    expect(screen.getByTestId('user')).toHaveTextContent(USER.email)
    expectStoredSessionKept()
  })

  it('stays on the message, still closed, when the retry also fails', async () => {
    fetchMock.mockImplementationOnce(networkDown).mockImplementationOnce(() => status(502))
    renderApp()
    fireEvent.click(await retryButton())

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))
    expect(await retryButton()).toBeEnabled()
    expect(screen.queryByText('secret report')).not.toBeInTheDocument()
    expectStoredSessionKept()
  })

  it('does not send a second check while one is running', async () => {
    const pending = deferred()
    fetchMock.mockImplementationOnce(networkDown).mockImplementationOnce(() => pending.promise)
    renderApp()
    const button = await retryButton()
    fireEvent.click(button)

    expect(await screen.findByRole('button', { name: 'Trying again…' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: 'Trying again…' }))
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(screen.queryByText('secret report')).not.toBeInTheDocument()

    await act(async () => { pending.resolve(ok()) })
    expect(await screen.findByText('secret report')).toBeInTheDocument()
  })

  it('signs out when the retry gets a real 401', async () => {
    fetchMock.mockImplementationOnce(networkDown).mockResolvedValueOnce(status(401))
    renderApp()
    fireEvent.click(await retryButton())

    expect(await screen.findByText('login page')).toBeInTheDocument()
    expectStoredSessionCleared()
  })
})

describe('sign-out and account boundaries', () => {
  it('signs out from the message: local state clears and the server is told', async () => {
    fetchMock.mockImplementationOnce(networkDown).mockResolvedValue(status(200))
    renderApp()
    fireEvent.click(await screen.findByRole('button', { name: 'Sign out' }))

    expect(await screen.findByText('login page')).toBeInTheDocument()
    expectStoredSessionCleared()
    const [url, init] = fetchMock.mock.calls[1]
    expect(url).toMatch(/\/auth\/logout$/)
    expect(init.method).toBe('POST')
    expect(init.headers.Authorization).toBe('Bearer token_a')
  })

  it('a check that returns after sign-out cannot restore the session', async () => {
    const pending = deferred()
    fetchMock.mockImplementationOnce(() => pending.promise)
    renderApp()
    fireEvent.click(screen.getByRole('button', { name: 'test: sign out' }))
    await act(async () => { pending.resolve(ok()) })

    expect(await screen.findByText('login page')).toBeInTheDocument()
    expectStoredSessionCleared()
    expect(screen.getByTestId('user')).toHaveTextContent('none')
  })

  it('a 401 for the old token cannot sign out the account that signed in since', async () => {
    const pending = deferred()
    fetchMock.mockImplementationOnce(networkDown).mockImplementationOnce(() => pending.promise)
    renderApp()
    fireEvent.click(await retryButton())
    await screen.findByRole('button', { name: 'Trying again…' })

    fireEvent.click(screen.getByRole('button', { name: 'test: sign in as B' }))
    await act(async () => { pending.resolve(status(401)) })

    expect(await screen.findByText('secret report')).toBeInTheDocument()
    expect(localStorage.getItem(TOKEN_KEY)).toBe('token_b')
    expect(screen.getByTestId('user')).toHaveTextContent('b@example.co.uk')
  })

  it('signing in as another account from the message state drops the old workspace', async () => {
    fetchMock.mockImplementationOnce(networkDown)
    renderApp()
    await retryButton()
    fireEvent.click(screen.getByRole('button', { name: 'test: sign in as B' }))

    expect(await screen.findByText('secret report')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(localStorage.getItem(WS_ID_KEY)).toBeNull()
    expect(localStorage.getItem(WS_NAME_KEY)).toBeNull()
  })
})
