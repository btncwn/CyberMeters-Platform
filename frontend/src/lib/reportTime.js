import { createContext, useContext } from 'react'
import { formatDate, formatDay, parseServerDate } from '../utils/dates'

// One timezone convention for an assessment report, web and PDF alike: UTC.
// The PDF is rendered by the server for whoever opens it, so the web report
// follows it rather than the viewer's clock. A report surface states the zone
// once (REPORT_TIME_NOTE) and provides ReportTimeLabelled; shared evidence
// components shown on other pages keep a " UTC" suffix on each time, because
// nothing else on those pages names the zone.
export const REPORT_TIME_NOTE = 'All times are in UTC.'
export const ReportTimeLabelled = createContext(false)

export function formatReportTime(value, fallback = '—') {
  return formatDate(value, fallback, { timeZone: 'UTC' })
}

export function formatReportDay(value, fallback = '—') {
  return formatDay(value, fallback, { timeZone: 'UTC' })
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
