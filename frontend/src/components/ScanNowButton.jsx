import { useEffect, useId, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import Spinner from './Spinner'
import { useWorkspaceRole } from '../hooks/useWorkspaceRole'
import { isForbidden } from '../lib/workspaceRole'
import {
  canonicalDomainInput, isAuthoritativeVerified, isPlanOrRateLimit, isVerificationRequired, safeErrorMessage,
} from '../lib/newScanVerification'

const ACTIVE = new Set(['queued', 'running', 'processing'])
const POLL_MS = 15000
const POLL_LIMIT = 24 // six minutes, then the progress link is the way to follow it

export const SCAN_STARTED_TEXT = 'Scan started — results in about 2–3 minutes.'

/**
 * "Scan now" — the one labelled way to start a scan from a module page or the
 * Overview (founder, 21 Oct 2026: the only control on these pages was an
 * icon that reloaded the list, and it looked like the scan button).
 *
 * It rescans a domain this workspace has already verified, through the same
 * POST /api/scan the new-scan page uses, so plan, rate and role limits are the
 * server's. When it cannot be used it stays visible, disabled, with the reason
 * in words. `domain` is the domain the page is showing; otherwise one verified
 * domain is used directly and several get a labelled picker.
 */
export default function ScanNowButton({ workspaceId, domain = null, align = 'end', label = 'Scan now', variant = 'primary' }) {
  const [domains, setDomains] = useState(null) // null = loading
  const [loadFailed, setLoadFailed] = useState(false)
  const [choice, setChoice] = useState('')
  const [starting, setStarting] = useState(false)
  const [note, setNote] = useState(null)
  const [started, setStarted] = useState(null) // { id, domain, status }
  const [refused, setRefused] = useState(false)
  const { canRescan, roleKnown, ownerName } = useWorkspaceRole(workspaceId, { refused })
  const reasonId = useId()
  const pickerId = useId()
  const polls = useRef(0)

  useEffect(() => {
    if (!workspaceId) return undefined
    let alive = true
    setDomains(null)
    Promise.resolve().then(() => api.getWorkspaceDomains(workspaceId))
      .then((res) => {
        if (!alive) return
        const verified = (res?.domains || [])
          .filter((d) => isAuthoritativeVerified(d, { domain_id: d.domain_id }))
          .map((d) => d.domain)
          .sort((a, b) => String(a).localeCompare(String(b)))
        setDomains(verified); setLoadFailed(false)
      })
      .catch(() => { if (alive) { setDomains([]); setLoadFailed(true) } })
    return () => { alive = false }
  }, [workspaceId])

  // Follow the started scan for a bounded time, so the page says when it is done.
  useEffect(() => {
    if (!started?.id || !ACTIVE.has(started.status)) return undefined
    if (polls.current >= POLL_LIMIT) return undefined
    const timer = setTimeout(() => {
      polls.current += 1
      Promise.resolve().then(() => api.getScan(started.id))
        .then((res) => {
          const status = res?.scan?.status || res?.status
          if (status) setStarted((s) => (s && s.id === started.id ? { ...s, status } : s))
        })
        .catch(() => { polls.current = POLL_LIMIT })
    }, POLL_MS)
    return () => clearTimeout(timer)
  }, [started])

  const preferred = canonicalDomainInput(domain || '')
  const list = domains || []
  const target = list.includes(preferred) ? preferred
    : list.length === 1 ? list[0]
      : (list.includes(choice) ? choice : '')
  const needsPicker = !list.includes(preferred) && list.length > 1

  let reason = null
  if (domains === null) reason = 'Reading this workspace’s domains…'
  else if (loadFailed) reason = 'The domain list could not be read just now, so a scan cannot be started here. Reload the page to try again.'
  else if (list.length === 0) reason = 'No domain in this workspace is verified yet. A workspace admin verifies a domain before it can be scanned.'
  else if (roleKnown && (!canRescan || refused)) reason = `Your role in this workspace cannot start scans. Ask ${ownerName || 'the workspace owner'} to start one or to change your role.`
  else if (needsPicker && !target) reason = 'Choose the domain to scan.'
  const disabled = Boolean(reason) || starting || !roleKnown

  async function start() {
    if (disabled || !target) return
    setStarting(true); setNote(null); setStarted(null); polls.current = 0
    try {
      const data = await api.createScan(target, workspaceId)
      const id = data?.scan?.id || data?.scan_id || data?.id || null
      setStarted({ id, domain: target, status: data?.scan?.status || 'queued' })
    } catch (e) {
      if (isVerificationRequired(e)) setNote('A workspace admin needs to verify this domain again before it can be scanned.')
      else if (isPlanOrRateLimit(e)) setNote('The scan did not start: your plan’s scan limit has been reached for now.')
      else if (isForbidden(e)) setRefused(true)
      else setNote(safeErrorMessage(e))
    } finally {
      setStarting(false)
    }
  }

  const running = started && ACTIVE.has(started.status)
  const centre = align === 'center'
  const alignStart = align === 'start'
  const textAlign = centre ? 'text-center' : alignStart ? 'text-left' : 'lg:text-right'
  return (
    <div className={`flex flex-col gap-1.5 ${centre ? 'items-center' : alignStart ? 'items-start' : 'items-stretch lg:items-end'}`} data-testid="scan-now">
      <div className={`flex flex-wrap items-center gap-2 ${centre ? 'justify-center' : alignStart ? 'justify-start' : 'lg:justify-end'}`}>
        {needsPicker && (
          <>
            <label htmlFor={pickerId} className="text-xs font-semibold text-gray-600">Domain to scan</label>
            <select id={pickerId} value={target} onChange={(e) => setChoice(e.target.value)} className="input py-1.5 text-sm w-auto">
              <option value="">Choose…</option>
              {list.map((d) => <option key={d} value={d}>{d}</option>)}
            </select>
          </>
        )}
        <button
          type="button"
          onClick={start}
          disabled={disabled}
          aria-describedby={reason ? reasonId : undefined}
          className={variant === 'secondary' ? 'btn-secondary' : 'btn-primary'}
        >
          {starting ? <><Spinner size="sm" /><span>Starting…</span></> : <span>{label}</span>}
        </button>
      </div>
      {!needsPicker && target && !started && !reason && (
        <p className="text-xs text-gray-500">Scans {target}</p>
      )}
      {reason && <p id={reasonId} className={`text-xs text-gray-600 max-w-xs ${textAlign}`}>{reason}</p>}
      {note && <p role="alert" className={`text-xs text-red-700 max-w-xs ${textAlign}`}>{note}</p>}
      {started && (
        <p role="status" className={`text-xs text-gray-700 max-w-xs ${textAlign}`}>
          {started.status === 'completed' ? `The scan of ${started.domain} is complete. Reload the page to see the new results.`
            : started.status === 'failed' ? `The scan of ${started.domain} did not complete.`
              : `${SCAN_STARTED_TEXT} (${started.domain})`}
          {started.id && (
            <> <Link to={`/scans/${encodeURIComponent(started.id)}`} className="font-semibold text-brand-700 hover:text-brand-800">{running ? 'Follow progress' : 'Open the scan'}</Link></>
          )}
        </p>
      )}
    </div>
  )
}
