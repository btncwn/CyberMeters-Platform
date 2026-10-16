import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
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
    vi.stubEnv('VITE_MCP_BETA_ENABLED', 'true')
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
})
