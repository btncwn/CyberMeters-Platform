import { useEffect, useRef, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { ShieldCheck, Clock, XCircle } from 'lucide-react'
import { api } from '../api'
import Spinner from '../components/Spinner'
import { isAuthoritativeVerified } from '../lib/newScanVerification'

// Landing page after the customer approves (or cancels) the DNS change on their
// provider's Domain Connect consent screen. The provider only wrote the TXT
// record; ownership is proven here by the normal verify route reading DNS, and
// success is shown only from a re-read of the exact workspace-domain record.

const ATTEMPTS = 8
const INTERVAL_MS = 5000

export function decodeDomainConnectState(raw) {
  try {
    const b64 = String(raw || '').replace(/-/g, '+').replace(/_/g, '/')
    const parsed = JSON.parse(atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4)))
    const ok = (v) => typeof v === 'string' && /^[A-Za-z0-9_-]{1,80}$/.test(v)
    return ok(parsed?.d) && ok(parsed?.w) ? { domainId: parsed.d, workspaceId: parsed.w } : null
  } catch {
    return null
  }
}

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

export default function DomainConnectReturnPage({ intervalMs = INTERVAL_MS }) {
  const { search } = useLocation()
  const params = new URLSearchParams(search)
  const target = decodeDomainConnectState(params.get('state'))
  const providerError = params.get('error')
  const [status, setStatus] = useState(providerError ? 'cancelled' : target ? 'checking' : 'invalid')
  const [attempt, setAttempt] = useState(0)
  const [run, setRun] = useState(0)
  const alive = useRef(true)

  useEffect(() => () => { alive.current = false }, [])

  useEffect(() => {
    if (!target || providerError) return
    let cancelled = false
    ;(async () => {
      setStatus('checking')
      for (let i = 1; i <= ATTEMPTS; i++) {
        if (cancelled || !alive.current) return
        setAttempt(i)
        try {
          await api.verifyDomain(target.domainId, target.workspaceId)
          const res = await api.getWorkspaceDomains(target.workspaceId)
          const record = (res?.domains || []).find((d) => d.domain_id === target.domainId)
          if (isAuthoritativeVerified(record, { domain_id: target.domainId })) {
            if (!cancelled) setStatus('verified')
            return
          }
        } catch { /* a failed check is a reason to try again, not a verdict */ }
        if (i < ATTEMPTS) await wait(intervalMs)
      }
      if (!cancelled) setStatus('pending')
    })()
    return () => { cancelled = true }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [run])

  const backTo = target ? `/domains/${target.domainId}/verify` : '/scans/new'
  const backState = target ? { workspaceId: target.workspaceId } : undefined

  return (
    <div className="max-w-lg mx-auto px-6 py-16">
      <div className="card p-6 space-y-4 text-center">
        {status === 'checking' && (
          <>
            <Spinner size="lg" className="mx-auto" />
            <h1 className="text-lg font-semibold text-gray-900">Checking your DNS record…</h1>
            <p className="text-sm text-gray-500">
              Your DNS provider added the record. We&rsquo;re confirming it is published (check {attempt} of {ATTEMPTS}).
            </p>
          </>
        )}
        {status === 'verified' && (
          <>
            <ShieldCheck className="w-10 h-10 text-brand-600 mx-auto" />
            <h1 className="text-lg font-semibold text-gray-900">Domain ownership verified</h1>
            <p className="text-sm text-gray-500">You can now run your Cyber MOT.</p>
            <div className="flex flex-wrap justify-center gap-2 pt-2">
              <Link to="/scans/new" className="btn-primary">Run Cyber MOT</Link>
              <Link to="/dashboard" className="btn-secondary">Go to dashboard</Link>
            </div>
          </>
        )}
        {status === 'pending' && (
          <>
            <Clock className="w-10 h-10 text-amber-500 mx-auto" />
            <h1 className="text-lg font-semibold text-gray-900">Your record is still being published</h1>
            <p className="text-sm text-gray-500">
              This usually takes under a minute, occasionally longer. CyberMeters also re-checks pending
              domains automatically, so you can leave this page.
            </p>
            <div className="flex flex-wrap justify-center gap-2 pt-2">
              <button type="button" className="btn-primary" onClick={() => setRun((n) => n + 1)}>Check again</button>
              <Link to={backTo} state={backState} className="btn-secondary">Back to verification</Link>
            </div>
          </>
        )}
        {status === 'cancelled' && (
          <>
            <XCircle className="w-10 h-10 text-gray-400 mx-auto" />
            <h1 className="text-lg font-semibold text-gray-900">No changes were made</h1>
            <p className="text-sm text-gray-500">
              The DNS change was cancelled at your provider. You can try again or add the TXT record yourself.
            </p>
            <Link to={backTo} state={backState} className="btn-primary inline-flex">Back to verification</Link>
          </>
        )}
        {status === 'invalid' && (
          <>
            <XCircle className="w-10 h-10 text-gray-400 mx-auto" />
            <h1 className="text-lg font-semibold text-gray-900">We couldn&rsquo;t match this link to a domain</h1>
            <p className="text-sm text-gray-500">Start verification again from the domain page.</p>
            <Link to="/scans/new" className="btn-primary inline-flex">Go to New Scan</Link>
          </>
        )}
      </div>
    </div>
  )
}
