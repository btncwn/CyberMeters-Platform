import { beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'

// SIRA 1b (19 Oct 2026): signing in as one account showed another account's
// workspace name ("SheShire") in the dashboard heading. The API refused the
// data, but the browser kept the previous account's active workspace across
// sign-out. These tests drive the real AuthProvider, Layout and Dashboard.

const ACCOUNTS = {
  token_a: { workspaces: [{ id: 'ws_sheshire', name: 'SheShire', role: 'owner' }], default_workspace_id: 'ws_sheshire' },
  token_b: { workspaces: [{ id: 'ws_bravo', name: 'Bravo Bakery', role: 'owner' }], default_workspace_id: 'ws_bravo' },
}
const USERS = {
  a: { id: 'usr_a', email: 'a@example.co.uk', name: 'Account A', plan: 'free' },
  b: { id: 'usr_b', email: 'b@example.co.uk', name: 'Account B', plan: 'free' },
}

// Every API call resolves empty, except the workspace list, which answers for
// whichever account holds the session.
vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal()
  const calls = {}
  const getWorkspaces = vi.fn(async () => ACCOUNTS[localStorage.getItem('cybermeters_auth_token')] || { workspaces: [] })
  const api = new Proxy({ getWorkspaces }, {
    get(target, key) {
      if (!(key in target)) target[key] = vi.fn(async () => ({}))
      calls[key] = true
      return target[key]
    },
  })
  return {
    ...actual,
    api,
    validateSession: vi.fn(async () => JSON.parse(localStorage.getItem('cybermeters_auth_user') || 'null')),
    logoutWithToken: vi.fn(),
    registerUnauthorizedHandler: vi.fn(),
  }
})

import { api } from '../api'
import { AuthProvider, useAuth } from '../context/AuthContext'
import Layout from '../components/Layout'
import Dashboard from '../pages/Dashboard'
import { readActiveWorkspace } from '../lib/activeWorkspace'

function Controls() {
  const { login, logout, isAuthenticated } = useAuth()
  return (
    <div>
      <button type="button" onClick={() => logout()}>test: sign out</button>
      <button type="button" onClick={() => { localStorage.setItem('cybermeters_auth_token', 'token_b'); login('token_b', USERS.b) }}>test: sign in as B</button>
      <p data-testid="signed-in">{String(isAuthenticated)}</p>
    </div>
  )
}

function App() {
  const { isAuthenticated } = useAuth()
  return isAuthenticated
    ? <Routes><Route path="/" element={<Layout />}><Route index element={<Dashboard />} /></Route></Routes>
    : <p>signed out</p>
}

function renderApp() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <Controls />
        <App />
      </AuthProvider>
    </MemoryRouter>,
  )
}

const heading = () => screen.findByRole('heading', { name: /exposed today\?/ })

beforeEach(() => {
  localStorage.clear()
  vi.clearAllMocks()
})

describe('active workspace across accounts', () => {
  it("sign out as A, sign in as B: B's workspace, never A's name", async () => {
    localStorage.setItem('cybermeters_auth_token', 'token_a')
    localStorage.setItem('cybermeters_auth_user', JSON.stringify(USERS.a))
    localStorage.setItem('cybermeters_workspace_id', 'ws_sheshire')
    localStorage.setItem('cybermeters_workspace_name', 'SheShire')
    renderApp()
    expect(await heading()).toHaveTextContent('Where is SheShire exposed today?')

    fireEvent.click(screen.getByRole('button', { name: 'test: sign out' }))
    expect(await screen.findByText('signed out')).toBeInTheDocument()
    expect(readActiveWorkspace()).toEqual({ id: null, name: '' })
    // From here on, only B's session: forget the calls A's session made.
    for (const fn of Object.values(api)) fn?.mockClear?.()

    fireEvent.click(screen.getByRole('button', { name: 'test: sign in as B' }))
    await waitFor(async () => expect(await heading()).toHaveTextContent('Where is Bravo Bakery exposed today?'))
    expect(document.body.textContent).not.toContain('SheShire')
    expect(readActiveWorkspace()).toEqual({ id: 'ws_bravo', name: 'Bravo Bakery' })
    // The dashboard never asked the API for A's workspace on B's session.
    for (const fn of Object.values(api)) {
      if (typeof fn?.mock?.calls === 'object' && fn !== api.getWorkspaces) {
        for (const args of fn.mock.calls) expect(args).not.toContain('ws_sheshire')
      }
    }
  })

  it("B signing in on a browser still holding A's workspace (no sign-out) gets B's", async () => {
    // e.g. a session that ended without the sign-out button, from an older build.
    localStorage.setItem('cybermeters_workspace_id', 'ws_sheshire')
    localStorage.setItem('cybermeters_workspace_name', 'SheShire')
    localStorage.setItem('cybermeters_auth_token', 'token_b')
    localStorage.setItem('cybermeters_auth_user', JSON.stringify(USERS.b))
    renderApp()
    await waitFor(async () => expect(await heading()).toHaveTextContent('Where is Bravo Bakery exposed today?'))
    expect(document.body.textContent).not.toContain('SheShire')
  })

  it('a different account signing in clears the previous one before anything renders', async () => {
    localStorage.setItem('cybermeters_auth_user', JSON.stringify(USERS.a))
    localStorage.setItem('cybermeters_workspace_id', 'ws_sheshire')
    localStorage.setItem('cybermeters_workspace_name', 'SheShire')
    renderApp()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'test: sign in as B' })) })
    await waitFor(async () => expect(await heading()).toHaveTextContent('Bravo Bakery'))
    expect(document.body.textContent).not.toContain('SheShire')
  })
})
