// The latest scan ATTEMPT per domain in a workspace, and the report of the one
// selected. The same bounded read WebsiteScanOverview makes: the scans endpoint
// returns the 20 most recent records, the latest attempt per domain is kept
// (including failures — an older success is never substituted), and the report
// is read only for a completed or partial scan. Nothing here derives a state;
// the page reflects what the report records.
import { useEffect, useState } from 'react'
import { api } from '../api'
import { parseServerDate } from '../utils/dates'

export const REPORTABLE_STATUSES = Object.freeze(['completed', 'partial'])

export function latestScanPerDomain(scans) {
  const latest = new Map()
  for (const scan of [...scans].sort((a, b) => parseServerDate(b.created_at) - parseServerDate(a.created_at))) {
    if (scan?.id && scan?.domain && !latest.has(scan.domain)) latest.set(scan.domain, scan)
  }
  return latest
}

export function useLatestScanReport(workspaceId, { refresh = 0, domain = '' } = {}) {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)
  const [result, setResult] = useState(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true); setError(false); setScans([]); setResult(null)
    if (!workspaceId) { setLoading(false); return undefined }
    api.getWorkspaceScans(workspaceId)
      .then((data) => { if (!cancelled) setScans(Array.isArray(data?.scans) ? data.scans : []) })
      .catch(() => { if (!cancelled) setError(true) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [workspaceId, refresh])

  const latest = latestScanPerDomain(scans)
  const scan = latest.get(domain) || latest.values().next().value || null

  useEffect(() => {
    let cancelled = false
    setResult(null)
    if (scan && REPORTABLE_STATUSES.includes(scan.status)) {
      api.getScanReport(scan.id)
        .then((report) => {
          if (report?.scan_id && report.scan_id !== scan.id) throw new Error('Unexpected scan report')
          if (!cancelled) setResult({ scanId: scan.id, report })
        })
        .catch(() => { if (!cancelled) setResult({ scanId: scan.id, error: true }) })
    }
    return () => { cancelled = true }
  }, [scan?.id, scan?.status, workspaceId, refresh])

  const current = result?.scanId === scan?.id ? result : null
  return {
    loading,
    error,
    scan,
    domains: [...latest.keys()],
    report: current?.report || null,
    reportError: current?.error === true,
    // A completed or partial scan whose report has not arrived yet.
    reportPending: Boolean(scan && REPORTABLE_STATUSES.includes(scan.status) && !current),
    boundedHistory: scans.length >= 20,
  }
}
