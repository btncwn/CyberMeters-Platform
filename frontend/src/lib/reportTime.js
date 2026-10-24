import { createContext, useContext } from 'react'
import { formatDate, formatDay, formatLocalDateTime, parseServerDate } from '../utils/dates'

// One timezone convention for an assessment report, web and PDF alike: UTC.
// The PDF is rendered by the server for whoever opens it, so the web report
// follows it rather than the viewer's clock. A report surface states the zone
// once (REPORT_TIME_NOTE) and provides ReportTimeLabelled; shared evidence
// components shown on other pages keep a " UTC" suffix on each time, because
// nothing else on those pages names the zone.
// The web report shows the viewer's local time with its zone (Executive 24 Oct
// 2026: one rule app-wide, so the scan list and the scan page never show the same
// scan at two times). The server-rendered PDF still states UTC once. Technical
// evidence stays in UTC and labels each time.
export const REPORT_TIME_NOTE = 'Times are in your local time zone; technical evidence is in UTC.'
export const ReportTimeLabelled = createContext(false)

export function formatReportTime(value, fallback = '—') {
  return formatDate(value, fallback, { timeZone: 'UTC' })
}

export function formatReportDay(value, fallback = '—') {
  return formatDay(value, fallback, { timeZone: 'UTC' })
}

/** Customer-facing time on a report page: local, zone named. */
export function formatViewerTime(value, fallback = '—') {
  return formatLocalDateTime(value, fallback)
}

/** Customer-facing day on a report page: the viewer's calendar day. */
export function formatViewerDay(value, fallback = '—') {
  return formatDay(value, fallback)
}

// Evidence timestamps: ISO/D1 strings, Dates, or epoch seconds.
export function useEvidenceTime() {
  const labelledOnce = useContext(ReportTimeLabelled)
  return (value, fallback = 'Not recorded') => {
    if (!(value instanceof Date) && typeof value !== 'string' && !(Number.isSafeInteger(value) && value >= 0)) return fallback
    const parsed = typeof value === 'number' ? new Date(value * 1000) : parseServerDate(value)
    if (!Number.isFinite(parsed?.getTime())) return fallback
    const text = formatReportTime(parsed, fallback)
    return labelledOnce ? text : `${text} UTC`
  }
}
