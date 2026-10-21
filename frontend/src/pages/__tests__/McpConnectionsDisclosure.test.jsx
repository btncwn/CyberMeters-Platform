import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

const auth = vi.hoisted(() => ({ token: null }))
vi.mock('../../context/AuthContext', () => ({ useAuth: () => auth }))

import McpConnectionsPage from '../McpConnectionsPage'

describe('MCP connection disclosure', () => {
  it('explains read-only beta, provider retention, revocation, and fixed portfolio selection', () => {
    render(<MemoryRouter><McpConnectionsPage /></MemoryRouter>)
    const notice = screen.getByText(/Connected AI clients can receive approved CyberMeters workspace data/)
    expect(notice).toHaveTextContent(/AI assistant can read your CyberMeters data \(beta, read-only\)/)
    expect(notice).toHaveTextContent(/It does not verify or fix issues/)
    expect(notice).toHaveTextContent(/provider may retain data it receives under its own terms and settings/)
    expect(notice).toHaveTextContent(/Removing a connection stops future CyberMeters reads, but cannot delete data already sent/)
    expect(notice).toHaveTextContent(/read only the workspaces you selected during consent/)
    expect(notice).toHaveTextContent(/newly added workspaces are never included automatically/)
  })

  it('shows the exact workspaces selected for a portfolio connection', async () => {
    auth.token = 'test-session'
    vi.stubEnv('VITE_MCP_BETA_ENABLED', 'false') // the page ignores the old build flag
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({
      eligible: true, next_offset: null, connections: [{
        id: 'conn_1', client_id: 'client_1', portfolio_read: true,
        scopes: ['mcp:read', 'portfolio:read'], status: 'active', last_used_at: null,
        selected_workspaces: [
          { workspace_id: 'ws_a', workspace_name: 'Alpha customer' },
          { workspace_id: 'ws_b', workspace_name: 'Beta customer' },
        ],
      }],
    }) })))
    try {
      render(<MemoryRouter><McpConnectionsPage /></MemoryRouter>)
      expect(await screen.findByText('Selected workspaces (2)')).toBeInTheDocument()
      expect(screen.getByText('Alpha customer')).toBeInTheDocument()
      expect(screen.getByText('Beta customer')).toBeInTheDocument()
    } finally {
      auth.token = null
      vi.unstubAllEnvs()
      vi.unstubAllGlobals()
    }
  })

  it('explains workspace eligibility when this account has no eligible workspace', async () => {
    auth.token = 'test-session'
    vi.stubEnv('VITE_MCP_BETA_ENABLED', 'false') // the page ignores the old build flag
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({
      eligible: false, next_offset: null, connections: [],
    }) })))
    try {
      render(<MemoryRouter><McpConnectionsPage /></MemoryRouter>)
      expect(await screen.findByText(/MCP beta requires an eligible trial or paid workspace and current membership/))
        .toBeInTheDocument()
      expect(screen.queryByText(/Connect an eligible AI client/)).not.toBeInTheDocument()
    } finally {
      auth.token = null
      vi.unstubAllEnvs()
      vi.unstubAllGlobals()
    }
  })
})

// Security P1 (21 Oct 2026): production was built with the flag false, so a
// customer with active connections saw "not available" and could revoke none.
describe('MCP connections are always manageable', () => {
  const active = (over = {}) => ({
    id: 'conn_9', client_id: 'https://claude.example/oauth', portfolio_read: false, workspace_name: 'Example Ltd',
    scopes: ['mcp:read'], status: 'active', last_used_at: '2026-10-21T10:00:00Z', ...over,
  })
  function serve({ eligible, connections }) {
    const calls = []
    vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
      calls.push({ url: String(url), method: init.method || 'GET' })
      if (init.method === 'DELETE') return { ok: true, json: async () => ({ revoked: true }) }
      const after = calls.some((c) => c.method === 'DELETE')
      return { ok: true, json: async () => ({ eligible, next_offset: null, connections: after ? [] : connections }) }
    }))
    return calls
  }
  afterEach(() => { auth.token = null; vi.unstubAllEnvs(); vi.unstubAllGlobals() })

  it('lists connections and removes one after confirming, with the build flag false', async () => {
    auth.token = 'test-session'
    vi.stubEnv('VITE_MCP_BETA_ENABLED', 'false')
    const calls = serve({ eligible: true, connections: [active()] })
    render(<MemoryRouter><McpConnectionsPage /></MemoryRouter>)
    expect(screen.queryByText(/not available for this account/)).not.toBeInTheDocument()
    fireEvent.click(await screen.findByRole('button', { name: 'Remove access' }))
    const dialog = await screen.findByTestId('app-dialog')
    expect(dialog).toHaveTextContent('Remove access for claude.example?')
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false)
    fireEvent.click(within(dialog).getByRole('button', { name: 'Remove access' }))
    await waitFor(() => expect(calls).toContainEqual({ url: expect.stringMatching(/\/mcp\/oauth\/connections\/conn_9$/), method: 'DELETE' }))
    expect(await screen.findByText('No MCP connections yet.')).toBeInTheDocument()
  })

  it('cancelling the confirmation removes nothing', async () => {
    auth.token = 'test-session'
    const calls = serve({ eligible: true, connections: [active()] })
    render(<MemoryRouter><McpConnectionsPage /></MemoryRouter>)
    fireEvent.click(await screen.findByRole('button', { name: 'Remove access' }))
    fireEvent.click(within(await screen.findByTestId('app-dialog')).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByTestId('app-dialog')).not.toBeInTheDocument())
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false)
  })

  it('a no-longer-eligible account can still see and remove what it connected', async () => {
    auth.token = 'test-session'
    serve({ eligible: false, connections: [active()] })
    render(<MemoryRouter><McpConnectionsPage /></MemoryRouter>)
    expect(await screen.findByRole('button', { name: 'Remove access' })).toBeInTheDocument()
    expect(screen.queryByText(/Connect an eligible AI client/)).not.toBeInTheDocument()
  })
})
