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
// Fixed, honest thresholds (founder, 22 Oct 2026): past 15 minutes the page says
// the check is taking longer than most; past 30 it says so again, plainly.
export const LONGER_THAN_MOST_MS = 15 * 60 * 1000
export const VERY_LONG_MS = 30 * 60 * 1000
export const NO_HISTORY_EXPECTATION = 'A full check usually takes 5–15 minutes.'
// What the scan is doing now, from the API's progress.stage (#862). One table;
// an unknown or absent stage says nothing rather than guess.
export const STAGE_TEXT = Object.freeze({
  discovery_complete: 'Now checking: the hosts and services found for this domain.',
  phase5_intelligence: 'Now checking: technology and known-vulnerability information.',
  finalizing: 'Now checking: putting the results together.',
})
// Where an interrupted scan stopped (#880: a failed scan's progress keeps its
// last stage). One table; an unknown stage says nothing.
export const STAGE_STOPPED_TEXT = Object.freeze({
  discovery_complete: 'It stopped after finding the hosts and services for this domain.',
  phase5_intelligence: 'It stopped while checking technology and known-vulnerability information.',
  finalizing: 'It stopped while putting the results together.',
})

/**
 * The failed-scan block's words (#880 progress on a failed scan):
 * { heading, stage, modules (customer labels) | null, namesRecorded } or null
 * when no check is known to have completed.
 */
// Module keys as a failed scan records them (#880), in customer words. Kept
// here, not in the shared code table: that table rewrites any matching word in
// any sentence, and short keys like "headers" or "dns" are ordinary words.
export const SCAN_MODULE_NAMES = Object.freeze({
  dns: 'DNS checks', headers: 'Security header checks', ssl: 'HTTPS and certificate checks',
  email_security: 'Email authentication checks', email_security_intelligence: 'Email security detail',
  dmarc_core: 'DMARC checks', dmarc_external_rua: 'DMARC report-address checks',
  subdomains: 'Subdomain discovery', dns_bruteforce: 'Subdomain name checks', discovery_depth: 'Subdomain discovery depth',
  customer_hostnames: 'Your listed host names', referenced_hostnames: 'Host names your website references',
  page_discovery: 'Website page discovery', page_references: 'Website page references',
  asset_exposure: 'Asset exposure checks', cloud_storage_discovery: 'Cloud storage checks',
  identity_discovery: 'Identity discovery checks', subdomain_takeover: 'Subdomain takeover checks',
  technology_detection: 'Technology detection', whois_intelligence: 'Domain registration checks',
  signed_in_scan: 'Signed-in page checks', scan_finalisation: 'Putting the results together',
})
const moduleName = (key) => SCAN_MODULE_NAMES[key] || 'Another check'

export function interruptedScanCopy(progress, moduleLabel = moduleName) {
  const n = progress?.terminal === true && Number.isInteger(progress?.completed_modules) ? progress.completed_modules : 0
  if (n <= 0) return null
  const names = progress.module_names_recorded === true && Array.isArray(progress.completed_module_names)
    ? progress.completed_module_names.map(moduleLabel) : null
  return {
    heading: `Interrupted — ${n} check${n === 1 ? '' : 's'} completed`,
    stage: STAGE_STOPPED_TEXT[progress.stage] || null,
    modules: names,
    namesNote: names ? null : 'Which checks finished was not recorded for this scan.',
  }
}

export const STALE_TEXT = 'This check has gone quiet. If it does not resume, we will mark what could not be completed rather than guess.'
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
export function scanProgressCopy({ status, elapsedMs, estimate, progress = null } = {}) {
  // F1 (D, Executive 24 Oct 2026): a scan stays 'queued' while its exposure job
  // (services and TLS checks) runs first. The backend says so
  // (progress.exposure_checks: 'pending' | 'running'); then it is working, not
  // waiting, and says "Preparing checks". Real queueing keeps "Scan queued".
  const preparing = status === 'queued' && ['pending', 'running'].includes(progress?.exposure_checks)
  const queued = status === 'queued' && !preparing
  const elapsed = elapsedLabel(elapsedMs)
  const timer = queued ? `Queued for ${elapsed}` : `Running for ${elapsed}`
  const heading = preparing ? 'Preparing checks' : queued ? 'Scan queued' : 'Scan in progress'
  const detail = preparing
    ? 'CyberMeters is checking the domain\u2019s exposed services and certificates first. Results appear here automatically.'
    : queued
      ? 'Waiting for a scanner to pick it up. Results appear here automatically.'
      : 'Checks are running against the domain. Results appear here automatically.'
  const stage = !queued ? STAGE_TEXT[progress?.stage] || null : null
  // The backend marks a queued scan stale when its exposure job is past its
  // deadline or lost its lease (F1 D) — said, never "Queued" forever.
  const stale = progress?.stale === true ? STALE_TEXT : null
  const running = !queued && Number.isFinite(elapsedMs)
  const longRunningText = !running ? null
    : elapsedMs >= VERY_LONG_MS ? 'This check has been running for over 30 minutes. It is still running; if it cannot finish, we will mark what could not be completed rather than guess.'
      : elapsedMs >= LONGER_THAN_MOST_MS ? 'This is taking longer than most checks. It is still running; you can leave this page and come back.'
        : null
  const base = { heading, timer, detail, stage, stale, longRunning: Boolean(longRunningText), longRunningText }
  if (!estimate || !Number.isFinite(estimate.medianMs)) return { ...base, expectation: NO_HISTORY_EXPECTATION }
  const scans = estimate.count === 1 ? 'your last complete scan' : `your last ${estimate.count} complete scans`
  const scope = estimate.basis === 'domain' ? `${scans} of this domain` : scans
  return { ...base, expectation: `Usually takes ${aboutDuration(estimate.medianMs)}, based on ${scope}.` }
}

// ── Local sample memory (per workspace, bounded, best effort) ────────────────

function readStore() {
  try { const raw = localStorage.getItem(STORE_KEY); const parsed = raw ? JSON.parse(raw) : null; return Array.isArray(parsed) ? parsed : [] } catch { return [] }
}
function writeStore(rows) { try { localStorage.setItem(STORE_KEY, JSON.stringify(rows.slice(0, STORE_CAP))) } catch { /* storage unavailable: estimate still works from fetched samples */ } }

/**
 * Samples remembered for a workspace: [{ scanId, domain, durationMs, completedAt }].
 * Only COMPLETE scans count (founder, 22 Oct 2026: four quick PARTIAL runs made
 * "Usually takes under a minute"); rows remembered before quality was recorded
 * are ignored.
 */
export function rememberedSamples(workspaceId) {
  if (!workspaceId) return []
  return readStore().filter((r) => r && r.workspaceId === workspaceId && r.quality === 'complete')
}

/** Remember one completed scan's duration (idempotent by scan id). */
export function rememberSample({ workspaceId, scanId, domain, startedAt, completedAt, quality = null }) {
  const durationMs = scanDurationMs(startedAt, completedAt)
  if (!workspaceId || !scanId || durationMs === null || quality !== 'complete') return null
  const row = { workspaceId, scanId, domain: String(domain || '').toLowerCase(), durationMs, completedAt: ms(completedAt), quality }
  const rest = readStore().filter((r) => !(r && r.scanId === scanId))
  writeStore([row, ...rest])
  return row
}
