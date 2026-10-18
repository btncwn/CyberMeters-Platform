import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import Spinner from './Spinner'
import { isForbidden } from '../lib/workspaceRole'
import {
  canonicalDomainInput, isAuthoritativeVerified, isPlanOrRateLimit, isVerificationRequired, safeErrorMessage,
} from '../lib/newScanVerification'

const NEEDS_REVERIFY = 'A workspace admin needs to verify this domain again before it can be scanned.'

/**
 * The domains this workspace has already verified, each with a Rescan button —
 * what a member who may start scans but not add domains is offered (decision,
 * 18 Oct 2026). Verified means the authoritative workspace-domain record, the
 * same contract the new-scan form uses; a domain asked for in the link
 * (?domain=) is listed first. A role refusal is handed back to the page.
 */
export default function RescanVerifiedDomains({ wsId, preferred, onRefused }) {
  const [domains, setDomains] = useState(null) // null = loading, [] = none
  const [loadFailed, setLoadFailed] = useState(false)
  const [starting, setStarting] = useState(null)
  const [notes, setNotes] = useState({})
  const navigate = useNavigate()

  useEffect(() => {
    if (!wsId) return undefined
    let alive = true
    Promise.resolve().then(() => api.getWorkspaceDomains(wsId))
      .then((res) => {
        if (!alive) return
        const want = canonicalDomainInput(preferred || '')
        const verified = (res?.domains || [])
          .filter((d) => isAuthoritativeVerified(d, { domain_id: d.domain_id }))
          .sort((a, b) => (b.domain === want) - (a.domain === want) || String(a.domain).localeCompare(String(b.domain)))
        setDomains(verified); setLoadFailed(false)
      })
      .catch(() => { if (alive) { setDomains([]); setLoadFailed(true) } })
    return () => { alive = false }
  }, [wsId, preferred])

  async function rescan(domain) {
    if (starting) return
    setStarting(domain); setNotes((n) => ({ ...n, [domain]: null }))
    try {
      const data = await api.createScan(domain, wsId)
      const id = data?.scan?.id || data?.scan_id || data?.id
      navigate(id ? `/scans/${id}` : '/scans')
    } catch (e) {
      // Plan and rate limits are shown once by the global upgrade prompt.
      if (isVerificationRequired(e)) setNotes((n) => ({ ...n, [domain]: NEEDS_REVERIFY }))
      else if (isPlanOrRateLimit(e)) setNotes((n) => ({ ...n, [domain]: null }))
      else if (isForbidden(e)) onRefused?.()
      else setNotes((n) => ({ ...n, [domain]: safeErrorMessage(e) }))
    } finally {
      setStarting(null)
    }
  }

  if (domains === null) {
    return <div className="py-4 flex items-center gap-2 text-sm text-gray-500"><Spinner size="sm" /> Reading this workspace’s domains…</div>
  }
  if (loadFailed) {
    return <p className="text-sm text-gray-600" data-testid="rescan-load-failed">The domain list could not be read just now. Reload the page to try again.</p>
  }
  if (domains.length === 0) {
    return <p className="text-sm text-gray-600" data-testid="rescan-none">No domain in this workspace has been verified yet. A workspace admin adds and verifies domains.</p>
  }
  return (
    <ul className="divide-y divide-gray-100 border border-gray-100 rounded-xl" data-testid="rescan-domains" aria-label="Verified domains">
      {domains.map((d) => (
        <li key={d.domain_id} className="px-4 py-3">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <span className="mono text-sm font-medium text-gray-900 break-all">{d.domain}</span>
            <button
              type="button"
              onClick={() => rescan(d.domain)}
              disabled={Boolean(starting)}
              className="btn-secondary px-4 py-1.5 text-sm disabled:opacity-40 disabled:cursor-not-allowed"
              aria-label={`Rescan ${d.domain}`}
            >
              {starting === d.domain ? <><Spinner size="sm" /><span>Starting…</span></> : <span>Rescan</span>}
            </button>
          </div>
          {notes[d.domain] && <p className="text-xs text-gray-600 mt-2">{notes[d.domain]}</p>}
        </li>
      ))}
    </ul>
  )
}
