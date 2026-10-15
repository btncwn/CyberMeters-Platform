import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { BASE } from '../api'
import { useAuth } from '../context/AuthContext'

const MCP_ENDPOINT = (() => {
  try {
    if (new URL(BASE).origin === 'https://api-staging.cybermeters.com') {
      return 'https://mcp-staging.cybermeters.com/mcp'
    }
  } catch { /* The page remains hidden until the API base is configured. */ }
  return 'https://mcp.cybermeters.com/mcp'
})()

function displayClient(value) {
  if (typeof value !== 'string') return 'Unknown client'
  try {
    const url = new URL(value)
    if (url.protocol === 'https:') return url.hostname
  } catch { /* A dynamically registered client may have an opaque ID. */ }
  return value.length <= 80 ? value : `${value.slice(0, 77)}…`
}

export default function McpConnectionsPage() {
  const { token } = useAuth()
  const [connections, setConnections] = useState([])
  const [eligible, setEligible] = useState(false)
  const [loading, setLoading] = useState(true)
  const [busyId, setBusyId] = useState(null)
  const [nextOffset, setNextOffset] = useState(null)
  const [moreLoading, setMoreLoading] = useState(false)
  const [error, setError] = useState('')

  const enabled = import.meta.env.VITE_MCP_BETA_ENABLED === 'true'
  const load = useCallback(async () => {
    if (!enabled || !token || !BASE) { setLoading(false); return }
    setLoading(true)
    setError('')
    try {
      const response = await fetch(`${BASE}/mcp/oauth/connections`, {
        credentials: 'include', cache: 'no-store',
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!response.ok) throw new Error('unavailable')
      const data = await response.json()
      if (!Array.isArray(data.connections) || typeof data.eligible !== 'boolean') {
        throw new Error('invalid_response')
      }
      if (data.next_offset !== null &&
          (!Number.isInteger(data.next_offset) || data.next_offset < 1 || data.next_offset > 100_000)) {
        throw new Error('invalid_response')
      }
      setConnections(data.connections)
      setEligible(data.eligible)
      setNextOffset(data.next_offset)
    } catch {
      setEligible(false)
      setNextOffset(null)
      setError('MCP connections are unavailable right now. Please try again later.')
    } finally { setLoading(false) }
  }, [enabled, token])

  useEffect(() => { load() }, [load])

  async function loadMore() {
    if (moreLoading || nextOffset === null || !token || !BASE) return
    setMoreLoading(true)
    setError('')
    try {
      const response = await fetch(`${BASE}/mcp/oauth/connections?offset=${nextOffset}`, {
        credentials: 'include', cache: 'no-store',
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!response.ok) throw new Error('unavailable')
      const data = await response.json()
      if (!Array.isArray(data.connections) ||
          (data.next_offset !== null &&
            (!Number.isInteger(data.next_offset) || data.next_offset <= nextOffset || data.next_offset > 100_000))) {
        throw new Error('invalid_response')
      }
      setConnections((current) => [...current, ...data.connections])
      setNextOffset(data.next_offset)
    } catch {
      setError('More MCP connections are unavailable right now. Please try again later.')
    } finally { setMoreLoading(false) }
  }

  async function revoke(id) {
    if (busyId || !token || !BASE) return
    setBusyId(id)
    setError('')
    try {
      const response = await fetch(`${BASE}/mcp/oauth/connections/${encodeURIComponent(id)}`, {
        method: 'DELETE', credentials: 'include', cache: 'no-store',
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!response.ok) throw new Error('unavailable')
      await load()
    } catch {
      setError('The connection could not be revoked. Please try again.')
    } finally { setBusyId(null) }
  }

  return (
    <div className="max-w-3xl mx-auto p-6 space-y-6">
      <div>
        <Link to="/account" className="text-sm text-brand-700 hover:underline">← Account</Link>
        <h1 className="text-2xl font-bold text-gray-900 mt-2">MCP connections</h1>
        <p className="text-sm text-gray-600 mt-2">
          Your AI assistant can read your CyberMeters data (beta, read-only). It does not verify or fix issues.
          Connected AI clients can receive approved CyberMeters workspace data. The client or its provider
          may retain data it receives under its own terms and settings. Removing a connection stops future
          CyberMeters reads, but cannot delete data already sent to the client. Portfolio connections can
          read only the workspaces you selected during consent while your membership remains active;
          newly added workspaces are never included automatically.
          Access is by workspace invitation. If your plan no longer includes portfolio access,
          that connection is removed and you can reconnect to one eligible workspace.
        </p>
      </div>
      {!enabled ? <p className="text-sm text-gray-600">MCP connections are not available for this account yet.</p> : <>
      {eligible ? <div className="rounded-xl border border-gray-200 bg-white p-5 space-y-2 text-sm">
        <p className="font-semibold text-gray-900">Connect an eligible AI client</p>
        <p className="text-gray-600">In a compatible AI client, add a remote MCP server with this URL:</p>
        <code className="block break-all rounded bg-gray-50 p-3">{MCP_ENDPOINT}</code>
        <p className="text-xs text-gray-500">Claude, OpenAI, and Gemini products have different account, administrator, and regional eligibility. Your client must support remote MCP and OAuth. CyberMeters will ask you to review its read permission before access begins.</p>
      </div> : !loading && !error &&
        <p className="text-sm text-gray-600">New MCP connections are not available for this account yet.</p>}
      {error && <p role="alert" className="text-sm text-red-700">{error}</p>}
      {loading ? <p className="text-sm text-gray-500">Loading connections…</p> :
        connections.length === 0 ? <p className="text-sm text-gray-500">No MCP connections yet.</p> :
          <ul className="space-y-3">
            {connections.map((connection) => (
              <li key={connection.id} className="rounded-xl border border-gray-200 bg-white p-5 space-y-2">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="font-semibold text-gray-900">{displayClient(connection.client_id)}</p>
                    <p className="text-sm text-gray-600">
                      {connection.portfolio_read ? 'Selected portfolio access' : `Workspace: ${connection.workspace_name || connection.workspace_id}`}
                      {' · '}{Array.isArray(connection.scopes) ? connection.scopes.join(', ') : 'Scope unavailable'}
                    </p>
                    {connection.portfolio_read && Array.isArray(connection.selected_workspaces) &&
                      <details className="text-sm text-gray-600">
                        <summary className="cursor-pointer">Selected workspaces ({connection.selected_workspaces.length})</summary>
                        <ul className="mt-1 ml-5 list-disc">
                          {connection.selected_workspaces.map((workspace) =>
                            <li key={workspace.workspace_id}>{workspace.workspace_name || workspace.workspace_id}</li>)}
                        </ul>
                      </details>}
                    <p className="text-xs text-gray-500">
                      {connection.last_used_at ? `Last used: ${connection.last_used_at}` : 'Not used yet'}
                      {' · '}Status: {connection.status}
                    </p>
                  </div>
                  {connection.status === 'active' &&
                    <button type="button" onClick={() => revoke(connection.id)}
                      disabled={busyId === connection.id}
                      className="text-sm text-red-700 hover:underline disabled:opacity-50">
                      {busyId === connection.id ? 'Removing…' : 'Remove access'}
                    </button>}
                </div>
              </li>
            ))}
          </ul>}
      {nextOffset !== null && !loading &&
        <button type="button" onClick={loadMore} disabled={moreLoading}
          className="text-sm text-brand-700 hover:underline disabled:opacity-50">
          {moreLoading ? 'Loading more…' : 'Load more connections'}
        </button>}
      </>}
    </div>
  )
}
