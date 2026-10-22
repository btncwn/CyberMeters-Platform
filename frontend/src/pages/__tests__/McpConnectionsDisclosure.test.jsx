import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

const auth = vi.hoisted(() => ({ token: null }))
vi.mock('../../context/AuthContext', () => ({ useAuth: () => auth }))

import McpConnectionsPage from '../McpConnectionsPage'

describe('MCP connection disclosure', () => {
  it('explains read-only access, provider retention, revocation, and fixed portfolio selection', () => {
    render(<MemoryRouter><McpConnectionsPage /></MemoryRouter>)
    const notice = screen.getByText(/Connected AI clients can receive approved CyberMeters workspace data/)
    expect(notice).toHaveTextContent(/AI assistant can read your CyberMeters data \(read-only\)/)
    expect(notice.textContent).not.toMatch(/beta/i)
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
      expect(await screen.findByText(/MCP access requires an eligible trial or paid workspace and current membership/))
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
    expect(await screen.findByText('No active MCP connections.')).toBeInTheDocument()
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
    // The URL stays visible (21 Oct 2026), with the eligibility limit said plainly.
    expect(screen.getByTestId('mcp-connect')).toHaveTextContent(/this account has none right now/)
  })
})

describe('MCP connections page layout (21 Oct 2026)', () => {
  const conn = (id, status, over = {}) => ({
    id, client_id: 'GqD2ShqmaD1f_fga', portfolio_read: false, workspace_name: 'Example Ltd', scopes: ['mcp:read'],
    status, created_at: '2026-10-21T09:00:00Z', last_used_at: null, revoked_at: status === 'revoked' ? '2026-10-21T12:00:00Z' : null, ...over,
  })
  afterEach(() => { auth.token = null; vi.unstubAllGlobals() })
  function serve(body) {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ next_offset: null, ...body }) })))
  }

  it('active connections first; revoked ones collapsed under Previous connections; each id once', async () => {
    auth.token = 'test-session'
    serve({ eligible: true, connections: [conn('mcpconn_a', 'active'), conn('mcpconn_a', 'active'), conn('mcpconn_b', 'revoked'), conn('mcpconn_c', 'active', { created_at: '2026-10-20T08:00:00Z' })] })
    render(<MemoryRouter><McpConnectionsPage /></MemoryRouter>)
    const active = await screen.findByRole('region', { name: 'Active connections (2)' })
    expect(within(active).getAllByTestId('mcp-connection')).toHaveLength(2)
    expect(within(active).getAllByRole('button', { name: 'Remove access' })).toHaveLength(2)
    const previous = screen.getByTestId('mcp-previous')
    expect(previous).not.toHaveAttribute('open')
    expect(within(previous).getByText('Previous connections (1)')).toBeInTheDocument()
    // Two connections from the same client are told apart by when they were made.
    expect(within(active).getAllByText(/^Connected: /)).toHaveLength(2)
  })

  it('the server URL and setup link stay visible when connections exist, even if no longer eligible', async () => {
    auth.token = 'test-session'
    serve({ eligible: false, connections: [conn('mcpconn_a', 'active')] })
    render(<MemoryRouter><McpConnectionsPage /></MemoryRouter>)
    const panel = await screen.findByTestId('mcp-connect')
    expect(panel).toHaveTextContent('https://mcp.cybermeters.com/mcp')
    expect(within(panel).getByRole('link', { name: 'Client setup and compatibility' })).toHaveAttribute('href', 'https://cybermeters.com/support#mcp')
  })
})

describe('MCP connection names (founder, 21 Oct 2026)', () => {
  afterEach(() => { auth.token = null; vi.unstubAllGlobals() })
  const serve = (connections) => vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => ({
    ok: true, json: async () => (init.method === 'DELETE' ? { revoked: true } : { eligible: true, next_offset: null, connections }),
  })))
  const base = { portfolio_read: false, workspace_name: 'Example Ltd', scopes: ['mcp:read'], status: 'active', created_at: '2026-10-21T19:08:00Z', last_used_at: null }

  it('a raw client id is never a card title; the client\'s own name is, labelled as such', async () => {
    auth.token = 'test-session'
    serve([
      { ...base, id: 'mcpconn_1', client_id: 'bhSWf6RgdRikkev-', client_name: 'ChatGPT' },
      { ...base, id: 'mcpconn_2', client_id: 'NDZYnyivspx-mnsY' },
    ])
    render(<MemoryRouter><McpConnectionsPage /></MemoryRouter>)
    expect(await screen.findByText('ChatGPT')).toBeInTheDocument()
    expect(screen.getByText('The name this app gave when it connected')).toBeInTheDocument()
    expect(screen.getByText(/^Unnamed client \(connected /)).toBeInTheDocument()
    for (const raw of ['bhSWf6RgdRikkev-', 'NDZYnyivspx-mnsY']) expect(screen.queryByText(raw)).toBeNull()
    expect(screen.getAllByRole('button', { name: 'Copy connection ID' }).length).toBe(2)
  })

  it('the remove dialog names the client the same way', async () => {
    auth.token = 'test-session'
    serve([{ ...base, id: 'mcpconn_1', client_id: 'bhSWf6RgdRikkev-', client_name: 'ChatGPT' }])
    render(<MemoryRouter><McpConnectionsPage /></MemoryRouter>)
    fireEvent.click(await screen.findByRole('button', { name: 'Remove access' }))
    expect(await screen.findByTestId('app-dialog')).toHaveTextContent('Remove access for ChatGPT?')
  })
})
