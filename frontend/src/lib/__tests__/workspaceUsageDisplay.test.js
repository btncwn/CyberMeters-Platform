import { describe, it, expect } from 'vitest'
import { allowanceText, storageText, usageRows } from '../workspaceUsageDisplay'

const data = {
  period_start: '2026-10-01T00:00:00.000Z',
  current_period: { scans_used: 12, scans_completed: 10, reports_generated: 3, scheduled_reports_generated: 1, active_assets: 40, workspace_report_count: 6, storage_bytes: 1_500_000, storage_estimated: true },
  limits: { scans_per_month: 100, reports_per_month: 999999 },
}

describe('workspaceUsageDisplay', () => {
  it('shows workspace numbers next to the shared allowance, never as a fraction', () => {
    const rows = usageRows(data)
    expect(rows.map((r) => [r.label, r.value, r.sub, r.allowance])).toEqual([
      ['Scans started', 12, '10 completed', '100 scans a month'],
      ['Reports generated', 3, '1 from schedules', 'No fixed monthly limit on reports'],
      ['Active assets', 40, 'Hosts currently monitored', null],
    ])
    expect(JSON.stringify(rows)).not.toMatch(/ of |remaining|left/)
  })

  it('says when a plan includes none', () => {
    expect(allowanceText(0, 'scans')).toBe('None included on this plan')
    expect(allowanceText(undefined, 'scans')).toBe(null)
  })

  it('labels storage as an estimate', () => {
    expect(storageText(data)).toBe('6 stored reports, about 1.5 MB (estimated).')
    expect(storageText({ current_period: { workspace_report_count: 0 } })).toBe('No stored reports.')
  })

  it('missing fields read as zero, not as a crash', () => {
    expect(usageRows({}).map((r) => r.value)).toEqual([0, 0, 0])
  })
})
