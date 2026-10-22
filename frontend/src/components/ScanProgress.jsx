// ScanProgress — the ONE status block for a queued or running scan on the scan
// page (no banner above it, no second card below it). Queued and running are
// distinct states with distinct words. It shows a live count-up ("Queued for
// 40 s" / "Running for 1 min 20 s"), an honest expectation from the workspace's
// own COMPLETE scans only ("Usually takes about 8 min, based on your last 7
// complete scans of this domain"), "A full check usually takes 5–15 minutes."
// without them, what the scan is doing now from the API's progress.stage, a
// plain line past 15 and 30 minutes, and the "gone quiet" line when the API
// says the scan stopped reporting. Never a countdown.
import { useEffect, useRef, useState } from 'react'
import { api } from '../api'
import Spinner from './Spinner'
import { parseServerDate } from '../utils/dates'
import { expectedDuration, rememberSample, rememberedSamples, scanProgressCopy, SAMPLE_WINDOW, DOMAIN_MIN_SAMPLES } from '../lib/scanDuration'

const startMs = (value) => { const d = parseServerDate(value); const t = d ? d.getTime() : NaN; return Number.isFinite(t) ? t : null }

/**
 * Collect duration samples for the estimate: what this browser remembers, plus
 * the technical reports of the newest completed scans the list names (domain
 * first; the workspace when the domain has too few). Bounded to SAMPLE_WINDOW
 * report reads, sequential, abortable.
 */
async function collectSamples({ workspaceId, domain, excludeScanId, signal }) {
  const remembered = rememberedSamples(workspaceId)
  if (!workspaceId) return remembered
  let listed = []
  try {
    const res = await Promise.resolve().then(() => api.getWorkspaceScans(workspaceId))
    // Only complete scans estimate a full check; partial runs end early.
    listed = (res?.scans || []).filter((s) => s?.status === 'completed' && s?.scan_quality === 'complete' && s.id !== excludeScanId)
  } catch { return remembered }
  if (signal?.aborted) return remembered
  listed.sort((a, b) => (startMs(b.created_at) ?? 0) - (startMs(a.created_at) ?? 0))
  const own = listed.filter((s) => String(s.domain || '').toLowerCase() === String(domain || '').toLowerCase())
  const candidates = (own.length >= DOMAIN_MIN_SAMPLES ? own : listed).slice(0, SAMPLE_WINDOW)
  const known = new Set(remembered.map((r) => r.scanId))
  const samples = [...remembered]
  for (const row of candidates) {
    if (signal?.aborted) break
    if (known.has(row.id)) continue
    try {
      const report = await api.getScanReport(row.id)
      const sample = rememberSample({ workspaceId, scanId: row.id, domain: row.domain, startedAt: report?.started_at, completedAt: report?.completed_at, quality: row.scan_quality })
      if (sample) samples.push(sample)
    } catch { /* a report that cannot be read contributes no sample */ }
  }
  return samples
}

export default function ScanProgress({ scan, workspaceId, pollSeconds, progress = null }) {
  const status = String(scan?.status || '').toLowerCase()
  const [now, setNow] = useState(() => Date.now())
  const [estimate, setEstimate] = useState({ loading: true, value: null })
  const runningSinceRef = useRef(null)
  const sawQueuedRef = useRef(false)

  // Count-up, one tick a second.
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(t) }, [])

  // When the page itself watched the scan move from queued to running, the
  // running clock starts there; otherwise it starts at the request time.
  useEffect(() => {
    if (status === 'queued') { sawQueuedRef.current = true; runningSinceRef.current = null }
    else if (sawQueuedRef.current && runningSinceRef.current === null) runningSinceRef.current = Date.now()
  }, [status])

  useEffect(() => {
    const controller = new AbortController()
    setEstimate({ loading: true, value: null })
    collectSamples({ workspaceId, domain: scan?.domain, excludeScanId: scan?.id, signal: controller.signal })
      .then((samples) => { if (!controller.signal.aborted) setEstimate({ loading: false, value: expectedDuration({ domain: scan?.domain, samples }) }) })
      .catch(() => { if (!controller.signal.aborted) setEstimate({ loading: false, value: null }) })
    return () => controller.abort()
  }, [workspaceId, scan?.domain, scan?.id])

  const base = (status !== 'queued' && runningSinceRef.current) || startMs(scan?.created_at) || now
  const elapsedMs = Math.max(0, now - base)
  const copy = scanProgressCopy({ status, elapsedMs, estimate: estimate.value, domain: scan?.domain, progress })

  return (
    <section className="card px-6 py-6" role="status" aria-live="polite" data-testid="scan-progress" data-status={status}>
      <div className="flex items-start gap-4">
        <div className="pt-0.5 shrink-0"><Spinner /></div>
        <div className="min-w-0">
          <p className="text-sm font-bold text-gray-900">{copy.heading}</p>
          <p className="text-sm text-gray-700 mt-1 leading-relaxed">{copy.detail}</p>
          {copy.stage && <p className="text-sm font-medium text-gray-900 mt-2" data-testid="scan-progress-stage">{copy.stage}</p>}
          <p className="text-sm font-semibold text-gray-900 mt-3 tabular-nums" data-testid="scan-progress-timer">{copy.timer}</p>
          <p className="text-sm text-gray-600 mt-1 leading-relaxed" data-testid="scan-progress-expectation">
            {estimate.loading ? 'Working out how long this usually takes…' : copy.expectation}
          </p>
          {copy.longRunning && <p className="text-sm font-medium text-brand-700 mt-1" data-testid="scan-progress-long">{copy.longRunningText}</p>}
          {copy.stale && <p className="text-sm font-medium text-gray-900 mt-1" data-testid="scan-progress-stale">{copy.stale}</p>}
          {pollSeconds ? <p className="text-xs text-gray-500 mt-3">This page refreshes every {pollSeconds} s.</p> : null}
        </div>
      </div>
    </section>
  )
}
