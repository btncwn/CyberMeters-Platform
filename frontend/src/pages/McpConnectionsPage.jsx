import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { BASE } from '../api'
import { useAuth } from '../context/AuthContext'
import { formatDate } from '../utils/dates'
import InternalIdCopyButton from '../components/InternalIdCopyButton'
import { useAppDialog } from '../components/AppDialog'

const MCP_ENDPOINT = (() => {
  try {
    if (new URL(BASE).origin === 'https://api-staging.cybermeters.com') {
      return 'https://mcp-staging.cybermeters.com/mcp'
    }
  } catch { /* An unparseable API base falls back to the production endpoint. */ }
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

// One card per connection id. The API pages with an offset over a status-ordered
// list, so a revoke between pages could repeat a row; the id is the identity.
function uniqueById(list) {
  const seen = new Set()
  return list.filter((c) => c && typeof c.id === 'string' && !seen.has(c.id) && seen.add(c.id))
}

function ConnectionCard({ connection, busyId, onRevoke }) {
  return (
    <li className="rounded-xl border border-gray-200 bg-white p-5 space-y-2" data-testid="mcp-connection">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="font-semibold text-gray-900">{displayClient(connection.client_id)}</p>
          <InternalIdCopyButton id={connection.id} label="connection" />
          <p className="text-sm text-gray-600">
            {connection.portfolio_read ? 'Selected portfolio access' : `Workspace: ${connection.workspace_name || 'Name unavailable'}`}
            {' · '}{Array.isArray(connection.scopes) ? connection.scopes.join(', ') : 'Scope unavailable'}
          </p>
          {connection.portfolio_read && Array.isArray(connection.selected_workspaces) &&
            <details className="text-sm text-gray-600">
              <summary className="cursor-pointer">Selected workspaces ({connection.selected_workspaces.length})</summary>
              <ul className="mt-1 ml-5 list-disc">
                {connection.selected_workspaces.map((workspace) =>
                  <li key={workspace.workspace_id}>{workspace.workspace_name || 'Name unavailable'} <InternalIdCopyButton id={workspace.workspace_id} label="workspace" /></li>)}
              </ul>
            </details>}
          <p className="text-xs text-gray-500">
            {connection.created_at ? `Connected: ${formatDate(connection.created_at)}` : 'Connection date unavailable'}
            {' · '}{connection.last_used_at ? `Last used: ${formatDate(connection.last_used_at)}` : 'Not used yet'}
            {connection.status === 'revoked' && connection.revoked_at ? ` · Removed: ${formatDate(connection.revoked_at)}` : ''}
            {connection.status !== 'active' && connection.status !== 'revoked' ? ` · Status: ${connection.status}` : ''}
          </p>
        </div>
        {connection.status === 'active' &&
          <button type="button" onClick={() => onRevoke(connection)}
            disabled={busyId === connection.id}
            className="text-sm text-red-700 hover:underline disabled:opacity-50">
            {busyId === connection.id ? 'Removing…' : 'Remove access'}
          </button>}
      </div>
    </li>
  )
}

export default function McpConnectionsPage() {
  const { token } = useAuth()
  const dialog = useAppDialog()
  const [connections, setConnections] = useState([])
  const [eligible, setEligible] = useState(false)
  const [loading, setLoading] = useState(true)
  const [busyId, setBusyId] = useState(null)
  const [nextOffset, setNextOffset] = useState(null)
  const [moreLoading, setMoreLoading] = useState(false)
  const [error, setError] = useState('')

  // No build-time gate (21 Oct 2026): anyone who can connect a client must be
  // able to see and remove it. The API decides eligibility and returns only the
  // caller's own connections.
  const load = useCallback(async () => {
    if (!token || !BASE) { setLoading(false); return }
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
      setConnections(uniqueById(data.connections))
      setEligible(data.eligible)
      setNextOffset(data.next_offset)
    } catch {
      setEligible(false)
      setNextOffset(null)
      setError('MCP connections are unavailable right now. Please try again later.')
    } finally { setLoading(false) }
  }, [token])

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
      setConnections((current) => uniqueById([...current, ...data.connections]))
      setNextOffset(data.next_offset)
    } catch {
      setError('More MCP connections are unavailable right now. Please try again later.')
    } finally { setMoreLoading(false) }
  }

  async function revoke(connection) {
    const id = connection.id
    if (busyId || !token || !BASE) return
    const client = displayClient(connection.client_id)
    const confirmed = await dialog.confirm({
      title: `Remove access for ${client}?`,
      message: `${client} will no longer be able to read your CyberMeters data. Data it has already received stays with the client under its own terms.`,
      confirmLabel: 'Remove access',
      tone: 'danger',
    })
    if (!confirmed) return
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
          Your AI assistant can read your CyberMeters data (read-only). It does not verify or fix issues.
          Connected AI clients can receive approved CyberMeters workspace data. The client or its provider
          may retain data it receives under its own terms and settings. Removing a connection stops future
          CyberMeters reads, but cannot delete data already sent to the client. Portfolio connections can
          read only the workspaces you selected during consent while your membership remains active;
          newly added workspaces are never included automatically.
          Access requires an eligible trial or paid workspace and current membership. Each time you connect a client, a separate connection is created, so the same client can appear more than once. If your plan no longer includes portfolio access,
          that connection is removed and you can reconnect to one eligible workspace.
        </p>
      </div>
      {/* The server URL and setup link stay visible whenever connecting is
          possible or connections exist (founder, 21 Oct 2026). */}
      {(eligible || connections.length > 0) && <div className="rounded-xl border border-gray-200 bg-white p-5 space-y-2 text-sm" data-testid="mcp-connect">
        <p className="font-semibold text-gray-900">Connect an eligible AI client</p>
        <p className="text-gray-600">In a compatible AI client, add a remote MCP server with this URL:</p>
        <code className="block break-all rounded bg-gray-50 p-3">{MCP_ENDPOINT}</code>
        <a className="text-brand-700 underline" href="https://cybermeters.com/support#mcp">Client setup and compatibility</a>
        <p className="text-xs text-gray-500">Client availability depends on your account and region. Your client must support remote MCP and OAuth. CyberMeters will ask you to review its read permission before access begins.</p>
        {!eligible && <p className="text-xs text-gray-600">New connections need an eligible trial or paid workspace and current membership; this account has none right now. Existing connections can still be removed below.</p>}
      </div>}
      {!eligible && !loading && !error && connections.length === 0 &&
        <p className="text-sm text-gray-600">MCP access requires an eligible trial or paid workspace and current membership. No eligible workspace is available for this account yet.</p>}
      {error && <p role="alert" className="text-sm text-red-700">{error}</p>}
      {loading ? <p className="text-sm text-gray-500">Loading connections…</p> : (() => {
        const active = connections.filter((c) => c.status === 'active')
        const previous = connections.filter((c) => c.status !== 'active')
        return <>
          <section aria-labelledby="mcp-active-heading" className="space-y-3">
            <h2 id="mcp-active-heading" className="text-base font-semibold text-gray-900">Active connections ({active.length})</h2>
            {active.length === 0
              ? <p className="text-sm text-gray-500">No active MCP connections.</p>
              : <ul className="space-y-3">{active.map((c) => <ConnectionCard key={c.id} connection={c} busyId={busyId} onRevoke={revoke} />)}</ul>}
          </section>
          {previous.length > 0 &&
            <details className="space-y-3" data-testid="mcp-previous">
              <summary className="cursor-pointer text-base font-semibold text-gray-900">Previous connections ({previous.length})</summary>
              <ul className="space-y-3 mt-3">{previous.map((c) => <ConnectionCard key={c.id} connection={c} busyId={busyId} onRevoke={revoke} />)}</ul>
            </details>}
        </>
      })()}
      {nextOffset !== null && !loading &&
        <button type="button" onClick={loadMore} disabled={moreLoading}
          className="text-sm text-brand-700 hover:underline disabled:opacity-50">
          {moreLoading ? 'Loading more…' : 'Load more connections'}
        </button>}
      {dialog.element}
    </div>
  )
}
