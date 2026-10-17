// Scan duration expectation — PRESENTATION ONLY, from data the app already has.
//
// The expected duration of a queued or running scan is the median of
// (completed_at − started_at) over up to the last 10 completed scans of the
// same domain in this workspace; when the domain has fewer than 3 such samples
// the workspace's last 10 are used instead. With no history at all nothing is
// invented: the page says it is the first scan of this domain. Elapsed time is
// shown as a count-up, never a countdown, so it can never go negative; once it
// passes twice the median the page says the scan is taking longer than usual.
//
// Samples come from the technical report of each completed scan (the only
// surface that records started_at and completed_at). Reports this browser has
// already read are remembered locally so the estimate does not re-read them.
import { parseServerDate } from '../utils/dates'

export const SAMPLE_WINDOW = 10
export const DOMAIN_MIN_SAMPLES = 3
export const LONG_RUNNING_FACTOR = 2
const STORE_KEY = 'cybermeters_scan_duration_samples'
const STORE_CAP = 60

const ms = (value) => {
  const d = parseServerDate(value)
  const t = d ? d.getTime() : NaN
  return Number.isFinite(t) ? t : null
}

/** Duration of one completed scan in ms, or null when either timestamp is unusable. */
export function scanDurationMs(startedAt, completedAt) {
  const a = ms(startedAt); const b = ms(completedAt)
  if (a === null || b === null || b < a) return null
  return b - a
}

/** Median of a list of numbers; null for an empty list. */
export function median(values) {
  const nums = (Array.isArray(values) ? values : []).filter((v) => Number.isFinite(v) && v >= 0).sort((a, b) => a - b)
  if (!nums.length) return null
  const mid = Math.floor(nums.length / 2)
  return nums.length % 2 ? nums[mid] : (nums[mid - 1] + nums[mid]) / 2
}

/**
 * expectedDuration({ domain, samples }) → { medianMs, basis: 'domain'|'workspace', count } | null
 * `samples` are { domain, durationMs, completedAt } for completed scans in the
 * workspace, any order; the newest SAMPLE_WINDOW of the chosen scope are used.
 */
export function expectedDuration({ domain, samples } = {}) {
  const all = (Array.isArray(samples) ? samples : [])
    .filter((s) => s && Number.isFinite(s.durationMs) && s.durationMs >= 0)
    .sort((a, b) => (ms(b.completedAt) ?? 0) - (ms(a.completedAt) ?? 0))
  const own = all.filter((s) => domain && String(s.domain || '').toLowerCase() === String(domain).toLowerCase()).slice(0, SAMPLE_WINDOW)
  if (own.length >= DOMAIN_MIN_SAMPLES) return { medianMs: median(own.map((s) => s.durationMs)), basis: 'domain', count: own.length }
  const ws = all.slice(0, SAMPLE_WINDOW)
  if (!ws.length) return null
  return { medianMs: median(ws.map((s) => s.durationMs)), basis: 'workspace', count: ws.length }
}

/** "about 2 min", "about 1 min", "under a minute" — never a fraction, never negative. */
export function aboutDuration(msValue) {
  if (!Number.isFinite(msValue) || msValue < 0) return null
  const seconds = Math.round(msValue / 1000)
  if (seconds < 45) return 'under a minute'
  const minutes = Math.max(1, Math.round(seconds / 60))
  return `about ${minutes} min`
}

/** "40 s", "1 min 20 s", "12 min 05 s" — a count-up; clamps at zero. */
export function elapsedLabel(msValue) {
  const total = Math.max(0, Math.floor((Number.isFinite(msValue) ? msValue : 0) / 1000))
  const m = Math.floor(total / 60); const s = total % 60
  return m ? `${m} min ${String(s).padStart(2, '0')} s` : `${s} s`
}

/**
 * The single status block's words for an active scan.
 *   status      'queued' | 'running' | 'processing'
 *   elapsedMs   since the scan was requested (or since it was seen running)
 *   estimate    expectedDuration() result or null
 *   domain      for the first-scan sentence
 */
export function scanProgressCopy({ status, elapsedMs, estimate, domain } = {}) {
  const queued = status === 'queued'
  const elapsed = elapsedLabel(elapsedMs)
  const timer = queued ? `Queued for ${elapsed}` : `Running for ${elapsed}`
  const heading = queued ? 'Scan queued' : 'Scan in progress'
  const detail = queued
    ? 'Waiting for a scanner to pick it up. Results appear here automatically.'
    : 'Checks are running against the domain. Results appear here automatically.'
  if (!estimate || !Number.isFinite(estimate.medianMs)) {
    return { heading, timer, detail, expectation: domain ? `First scan of ${domain}; usually a few minutes.` : 'First scan of this domain; usually a few minutes.', longRunning: false }
  }
  const longRunning = !queued && Number.isFinite(elapsedMs) && elapsedMs > estimate.medianMs * LONG_RUNNING_FACTOR
  const scope = estimate.basis === 'domain' ? `your last ${estimate.count} scans of this domain` : `your last ${estimate.count} scans`
  return {
    heading, timer, detail,
    expectation: `Usually takes ${aboutDuration(estimate.medianMs)}, based on ${scope}.`,
    longRunning,
    longRunningText: longRunning ? 'Taking longer than usual; it is still running.' : null,
  }
}

// ── Local sample memory (per workspace, bounded, best effort) ────────────────

function readStore() {
  try { const raw = localStorage.getItem(STORE_KEY); const parsed = raw ? JSON.parse(raw) : null; return Array.isArray(parsed) ? parsed : [] } catch { return [] }
}
function writeStore(rows) { try { localStorage.setItem(STORE_KEY, JSON.stringify(rows.slice(0, STORE_CAP))) } catch { /* storage unavailable: estimate still works from fetched samples */ } }

/** Samples remembered for a workspace: [{ scanId, domain, durationMs, completedAt }]. */
export function rememberedSamples(workspaceId) {
  if (!workspaceId) return []
  return readStore().filter((r) => r && r.workspaceId === workspaceId)
}

/** Remember one completed scan's duration (idempotent by scan id). */
export function rememberSample({ workspaceId, scanId, domain, startedAt, completedAt }) {
  const durationMs = scanDurationMs(startedAt, completedAt)
  if (!workspaceId || !scanId || durationMs === null) return null
  const row = { workspaceId, scanId, domain: String(domain || '').toLowerCase(), durationMs, completedAt: ms(completedAt) }
  const rest = readStore().filter((r) => !(r && r.scanId === scanId))
  writeStore([row, ...rest])
  return row
}
