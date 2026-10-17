// Report archive presentation — PRESENTATION ONLY.
//
// The Period column names the report in the customer's words. A scan
// snapshot's stored `report_period` is an internal key (scan id, snapshot id
// and checksum joined); it exists for deduplication and must never reach the
// screen. Every other report type carries a customer-meaningful period label
// (the week, month or quarter, or the label the customer typed for a manual
// snapshot) and is shown as it is.
import { parseServerDate } from '../utils/dates'

const INTERNAL_PERIOD = /^scan-v2-|^scan_[0-9a-f]{6,}|^snap_|^rep_|[0-9a-f]{32,}/i

export function isInternalPeriod(value) {
  return typeof value === 'string' && INTERNAL_PERIOD.test(value.trim())
}

function fmtDay(str) {
  if (!str) return null
  const s = str.includes('T') ? str : str.replace(' ', 'T') + 'Z'
  const d = parseServerDate(s)
  if (!d || Number.isNaN(d.getTime())) return null
  return d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })
}

/**
 * reportPeriodLabel(report) → the customer label for the Period cell.
 *   scan_snapshot (or any internal-looking period) → "Single scan · 16 Oct 2026"
 *   (the domain first when the row carries one) · otherwise the stored period.
 */
export function reportPeriodLabel(report) {
  if (!report || typeof report !== 'object') return '—'
  const period = typeof report.report_period === 'string' ? report.report_period.trim() : ''
  const single = report.report_type === 'scan_snapshot' || isInternalPeriod(period)
  if (!single) return period || '—'
  const day = fmtDay(report.generated_at || report.created_at)
  const domain = typeof report.domain === 'string' && report.domain ? report.domain : null
  const head = domain ? `${domain} · Single scan` : 'Single scan'
  return day ? `${head} · ${day}` : head
}

/** Download filename: never an internal id; the period label, made file-safe. */
export function reportFileName(report) {
  const type = String(report?.report_type || 'report').replace(/[^a-z0-9]+/gi, '-').toLowerCase()
  const label = reportPeriodLabel(report).replace(/[^a-z0-9]+/gi, '-').replace(/^-+|-+$/g, '').toLowerCase()
  return `cybermeters-${type}${label && label !== '-' ? `-${label}` : ''}.pdf`
}
