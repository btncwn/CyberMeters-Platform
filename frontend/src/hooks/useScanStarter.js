import { useEffect, useRef, useState } from 'react'
import { api } from '../api'
import { useWorkspaceRole } from './useWorkspaceRole'
import { isForbidden } from '../lib/workspaceRole'
import {
  isAuthoritativeVerified, isPlanOrRateLimit, isVerificationRequired, safeErrorMessage,
} from '../lib/newScanVerification'

const ACTIVE = new Set(['queued', 'running', 'processing'])
const POLL_MS = 15000
const POLL_LIMIT = 24 // six minutes, then the progress link is the way to follow it

export const SCAN_STARTED_TEXT = 'Scan started — results in about 2–3 minutes.'
export const isActiveScan = (status) => ACTIVE.has(status)

/**
 * Starting a scan of a domain this workspace has already verified, shared by
 * "Scan now" and the Overview scan box: the verified domains, the role check,
 * POST /api/scan (the server owns plan, rate and role limits), and a bounded
 * follow-up of the started scan. `onComplete` runs once when it finishes.
 */
export function useScanStarter(workspaceId, { onComplete = null } = {}) {
  const [domains, setDomains] = useState(null) // null = loading
  const [loadFailed, setLoadFailed] = useState(false)
  const [starting, setStarting] = useState(false)
  const [note, setNote] = useState(null)
  const [started, setStarted] = useState(null) // { id, domain, status }
  const [refused, setRefused] = useState(false)
  const role = useWorkspaceRole(workspaceId, { refused })
  const polls = useRef(0)
  const onCompleteRef = useRef(onComplete)
  onCompleteRef.current = onComplete

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
          if (!status) return
          setStarted((s) => (s && s.id === started.id ? { ...s, status } : s))
          if (status === 'completed') onCompleteRef.current?.()
        })
        .catch(() => { polls.current = POLL_LIMIT })
    }, POLL_MS)
    return () => clearTimeout(timer)
  }, [started])

  async function start(target) {
    if (starting || !target) return
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

  return {
    domains, loadFailed, starting, note, started, refused, start,
    canRescan: role.canRescan, canScanNewDomain: role.canScanNewDomain, roleKnown: role.roleKnown, ownerName: role.ownerName,
  }
}
