// Presentation for GET /api/workspaces/:id/usage. The numbers are this
// workspace's own activity this calendar month; plan allowances belong to the
// account that owns the workspace and are SHARED by all of its workspaces, so
// they are shown next to the workspace numbers, never as "x of y used".

const UNLIMITED = 999_999

export function allowanceText(value, unit) {
  if (value == null) return null
  const n = Number(value)
  if (!Number.isFinite(n)) return null
  if (n >= UNLIMITED) return `No fixed monthly limit on ${unit}`
  if (n === 0) return `None included on this plan`
  return `${n.toLocaleString()} ${unit} a month`
}

export function monthLabel(periodStart) {
  const d = periodStart ? new Date(periodStart) : null
  return d && !Number.isNaN(d.getTime()) ? d.toLocaleDateString(undefined, { month: 'long', year: 'numeric', timeZone: 'UTC' }) : 'this month'
}

/** Rows for the card: what this workspace did, and the shared plan allowance. */
export function usageRows(data) {
  const c = data?.current_period || {}
  const l = data?.limits || {}
  const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0)
  return [
    {
      key: 'scans',
      label: 'Scans started',
      value: num(c.scans_used),
      sub: `${num(c.scans_completed)} completed`,
      allowance: allowanceText(l.scans_per_month, 'scans'),
    },
    {
      key: 'reports',
      label: 'Reports generated',
      value: num(c.reports_generated),
      sub: `${num(c.scheduled_reports_generated)} from schedules`,
      allowance: allowanceText(l.reports_per_month, 'reports'),
    },
    {
      key: 'assets',
      label: 'Active assets',
      value: num(c.active_assets),
      sub: 'Hosts currently monitored',
      allowance: null,
    },
  ]
}

/** Stored reports: the size is an ESTIMATE (the API says so), never a measurement. */
export function storageText(data) {
  const c = data?.current_period || {}
  const count = Number(c.workspace_report_count) || 0
  const bytes = Number(c.storage_bytes) || 0
  const mb = bytes / 1_000_000
  const size = mb >= 1 ? `${mb.toFixed(1)} MB` : `${Math.round(bytes / 1000)} KB`
  if (!count) return 'No stored reports.'
  return `${count} stored report${count === 1 ? '' : 's'}, about ${size}${c.storage_estimated ? ' (estimated)' : ''}.`
}
