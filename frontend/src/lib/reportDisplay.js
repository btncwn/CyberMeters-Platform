// Report archive presentation — PRESENTATION ONLY.
//
// The Period column names the report in the customer's words. A scan
// snapshot's stored `report_period` is an internal key (scan id, snapshot id
// and checksum joined); it exists for deduplication and must never reach the
// screen. Week, month, quarter and manual reports use customer-readable labels
// derived from their type and recorded date or period.
import { formatDay } from '../utils/dates'

const INTERNAL_PERIOD = /^scan-v2-|^scan_[0-9a-f]{6,}|^snap_|^rep_|^rpt_|^workspace_|^mcpconn_|[0-9a-f]{32,}/i

export function isInternalPeriod(value) {
  return typeof value === 'string' && INTERNAL_PERIOD.test(value.trim())
}

function fmtDay(str) {
  return formatDay(str, null)
}

/**
 * reportPeriodLabel(report) → the customer label for the Period cell.
 *   scan_snapshot (or any internal-looking period) → "Single scan · 16 Oct 2026"
 *   (the domain first when the row carries one); other types get their own label.
 */
export function reportPeriodLabel(report) {
  if (!report || typeof report !== 'object') return '—'
  const period = typeof report.report_period === 'string' ? report.report_period.trim() : ''
  const single = report.report_type === 'scan_snapshot'
  const day = fmtDay(report.generated_at || report.created_at)
  const weekly = /^(\d{4})-W(\d{2})$/.exec(period)
  if (report.report_type === 'weekly_executive' && weekly) return `Weekly executive · week ${Number(weekly[2])}, ${weekly[1]}`
  const monthly = /^(\d{4})-(\d{2})$/.exec(period)
  if (report.report_type === 'monthly_executive' && monthly) {
    const month = new Intl.DateTimeFormat('en-GB', { month: 'long', timeZone: 'UTC' }).format(new Date(Date.UTC(Number(monthly[1]), Number(monthly[2]) - 1, 1)))
    return `Monthly executive · ${month} ${monthly[1]}`
  }
  const quarterly = /^(\d{4})-Q([1-4])$/.exec(period)
  if (report.report_type === 'quarterly_executive' && quarterly) return `Quarterly executive · Q${quarterly[2]} ${quarterly[1]}`
  if (report.report_type === 'manual') return day ? `Manual · ${day}` : 'Manual'
  if (isInternalPeriod(period) && !single) {
    const type = String(report.report_type || 'Report').replace(/_/g, ' ').replace(/^./, c => c.toUpperCase())
    return day ? `${type} · ${day}` : type
  }
  if (!single) return period || '—'
  const domain = typeof report.domain === 'string' && report.domain ? report.domain : null
  const head = domain ? `${domain} · Single scan` : 'Single scan'
  return day ? `${head} · ${day}` : head
}

/** Download filename: never an internal id; the period label, made file-safe. */
export function reportFileName(report) {
  const type = String(report?.report_type || 'report').replace(/[^a-z0-9]+/gi, '-').toLowerCase()
  const label = reportPeriodLabel(report).replace(/[^a-z0-9]+/gi, '-').replace(/^-+|-+$/g, '').toLowerCase()
  const suffix = label.startsWith(`${type}-`) ? label.slice(type.length + 1) : label === type ? '' : label
  return `cybermeters-${type}${suffix && suffix !== '-' ? `-${suffix}` : ''}.pdf`
}
