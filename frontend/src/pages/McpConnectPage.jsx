import { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { BASE } from '../api'
import { useAuth } from '../context/AuthContext'
import { validMcpContinuationUrl } from '../lib/mcpContinuationUrl'
import { urlSecret } from '../lib/urlSecrets'

const INTENT = /^[A-Za-z0-9_-]{43}$/

export default function McpConnectPage() {
  const { token } = useAuth()
  const location = useLocation()
  // The intent arrives in the fragment (older links: the query), is cleared from
  // the address bar on load and is read from router state (lib/urlSecrets.js).
  const intent = urlSecret(location, 'mcpIntent') || new URLSearchParams(location.search).get('intent')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function continueToConsent() {
    if (busy || !INTENT.test(intent || '') || !token || !BASE) return
    setBusy(true)
    setError('')
    try {
      const response = await fetch(`${BASE}/mcp/oauth/browser-session`, {
        method: 'POST', credentials: 'include', cache: 'no-store',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ intent }),
      })
      if (!response.ok) throw new Error('unavailable')
      const data = await response.json()
      const destination = validMcpContinuationUrl(BASE, intent, data.continue_url)
      if (!destination) throw new Error('invalid_destination')
      window.location.assign(destination)
    } catch {
      setError('Connection could not continue. Your link may have expired or your workspace may not be enrolled in the MCP beta.')
      setBusy(false)
    }
  }

  return (
    <main className="min-h-screen bg-gray-50 flex items-center justify-center p-6">
      <section className="bg-white border border-gray-200 rounded-2xl p-8 max-w-lg w-full space-y-5">
        <h1 className="text-2xl font-bold text-gray-900">Connect an AI assistant</h1>
        <p className="text-sm text-gray-600">
          CyberMeters will show the client name, workspace, and read permission before you approve access.
          This connection cannot change DNS, start scans, create cases, or manage users.
        </p>
        {!INTENT.test(intent || '') ? (
          <p role="alert" className="text-sm text-red-700">This connection link is invalid or incomplete.</p>
        ) : (
          <button type="button" onClick={continueToConsent} disabled={busy}
            className="btn btn-primary disabled:opacity-50">
            {busy ? 'Preparing secure review…' : 'Continue to permission review'}
          </button>
        )}
        {error && <p role="alert" className="text-sm text-red-700">{error}</p>}
        <p className="text-xs text-gray-500">
          You can review and revoke connections in <Link to="/account/mcp" className="underline">MCP connections</Link>.
        </p>
      </section>
    </main>
  )
}
