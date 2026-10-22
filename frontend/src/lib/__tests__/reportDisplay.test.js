import { reportPeriodLabel, reportFileName, isInternalPeriod, reportTypeLabel, reportPeriodCell } from '../reportDisplay'

// The Period cell never renders an internal id: a scan snapshot reads as
// "Single scan · <date>" (domain first when known); other periods pass through.

const snapshot = {
  id: 'rep_1', report_type: 'scan_snapshot',
  report_period: 'scan-v2-scan_34030f4c-6d2e-4f0b-b1d8-0c1b2e3f4a5b-snap_9f8e7d6c-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  generated_at: '2026-10-16T09:12:00Z', created_at: '2026-10-16T09:10:00Z',
}

describe('reportPeriodLabel', () => {
  it('labels a scan snapshot by date, never by its internal key', () => {
    const label = reportPeriodLabel(snapshot)
    expect(label).toMatch(/^Single scan · /)
    expect(label).toMatch(/2026/)
    expect(label).not.toMatch(/scan-v2|scan_|snap_|[0-9a-f]{16}/)
  })

  it('puts the domain first when the row carries one', () => {
    expect(reportPeriodLabel({ ...snapshot, domain: 'example.co.uk' })).toMatch(/^example\.co\.uk · Single scan · /)
  })

  it('falls back to a report type when no date is recorded', () => {
    expect(reportPeriodLabel({ report_type: 'scan_snapshot' })).toBe('Single scan')
    expect(reportPeriodLabel({ report_type: 'manual', report_period: '' })).toBe('Manual')
    expect(reportPeriodLabel(null)).toBe('—')
  })

  it('names weekly, monthly, quarterly and manual report periods in customer words', () => {
    expect(reportPeriodLabel({ report_type: 'weekly_executive', report_period: '2026-W42' })).toBe('Weekly executive · week 42, 2026')
    expect(reportPeriodLabel({ report_type: 'monthly_executive', report_period: '2026-09' })).toBe('Monthly executive · September 2026')
    expect(reportPeriodLabel({ report_type: 'quarterly_executive', report_period: '2026-Q4' })).toBe('Quarterly executive · Q4 2026')
    expect(reportPeriodLabel({ report_type: 'manual', report_period: 'recovered-report', generated_at: '2026-10-17T19:21:00Z' })).toMatch(/^Manual · 17 Oct 2026$/)
    expect(reportPeriodLabel({ report_type: 'manual', report_period: 'recovered-report' })).toBe('Manual')
  })

  it('never exposes an internal-looking period, preserving the report type', () => {
    expect(isInternalPeriod('scan-v2-scan_abc123-x')).toBe(true)
    expect(isInternalPeriod('rpt_abc123')).toBe(true)
    expect(isInternalPeriod('workspace_abc123')).toBe(true)
    expect(isInternalPeriod('mcpconn_abc123')).toBe(true)
    expect(isInternalPeriod('2026-W41')).toBe(false)
    expect(reportPeriodLabel({ report_type: 'manual', report_period: 'scan-v2-scan_abc123-x', created_at: '2026-10-01T00:00:00Z' })).toMatch(/^Manual · /)
    expect(reportPeriodLabel({ report_type: 'weekly_executive', report_period: 'rpt_abc123', created_at: '2026-10-01T00:00:00Z' })).toMatch(/^Weekly executive · /)
  })
})

describe('reportFileName', () => {
  it('builds a file-safe name from the type and the label, never the id', () => {
    const name = reportFileName(snapshot)
    expect(name).toMatch(/^cybermeters-scan-snapshot-single-scan-.*\.pdf$/)
    expect(name).not.toMatch(/scan-v2|snap_|rep_/)
    expect(reportFileName({ report_type: 'monthly_executive', report_period: '2026-09' })).toBe('cybermeters-monthly-executive-september-2026.pdf')
  })
})

// Design standard §2/§4 (22 Oct 2026): one name per report type; the Period
// cell carries only the period.
describe('report type names and the Period cell', () => {
  it('names every type from one table and an unknown one "Report", never a key', () => {
    expect(reportTypeLabel('manual')).toBe('Current posture')
    expect(reportTypeLabel('scan_snapshot')).toBe('Single scan')
    expect(reportTypeLabel('monthly_executive')).toBe('Monthly executive summary')
    expect(reportTypeLabel('retired_type')).toBe('Report')
  })
  it('states the period without repeating the type', () => {
    expect(reportPeriodCell({ report_type: 'monthly_executive', report_period: '2026-09' })).toBe('September 2026')
    expect(reportPeriodCell({ report_type: 'weekly_executive', report_period: '2026-W42' })).toBe('Week 42, 2026')
    expect(reportPeriodCell({ report_type: 'quarterly_executive', report_period: '2026-Q3' })).toBe('Q3 2026')
    expect(reportPeriodCell({ report_type: 'manual', generated_at: '2026-10-10T09:00:00Z' })).toBe('10 Oct 2026')
    expect(reportPeriodCell({ report_type: 'scan_snapshot', domain: 'example.co.uk', generated_at: '2026-10-16T10:12:00Z' })).toBe('example.co.uk · 16 Oct 2026')
  })
})
