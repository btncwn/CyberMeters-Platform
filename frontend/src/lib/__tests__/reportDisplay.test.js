import { reportPeriodLabel, reportFileName, isInternalPeriod } from '../reportDisplay'

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

  it('falls back to "Single scan" without any date, and to a dash without any period', () => {
    expect(reportPeriodLabel({ report_type: 'scan_snapshot' })).toBe('Single scan')
    expect(reportPeriodLabel({ report_type: 'manual', report_period: '' })).toBe('—')
    expect(reportPeriodLabel(null)).toBe('—')
  })

  it('shows customer-meaningful periods of other report types as they are', () => {
    expect(reportPeriodLabel({ report_type: 'monthly_executive', report_period: '2026-09' })).toBe('2026-09')
    expect(reportPeriodLabel({ report_type: 'manual', report_period: 'recovered-report' })).toBe('recovered-report')
  })

  it('treats an internal-looking period on any type as a single scan', () => {
    expect(isInternalPeriod('scan-v2-scan_abc123-x')).toBe(true)
    expect(isInternalPeriod('2026-W41')).toBe(false)
    expect(reportPeriodLabel({ report_type: 'manual', report_period: 'scan-v2-scan_abc123-x', created_at: '2026-10-01T00:00:00Z' })).toMatch(/^Single scan · /)
  })
})

describe('reportFileName', () => {
  it('builds a file-safe name from the type and the label, never the id', () => {
    const name = reportFileName(snapshot)
    expect(name).toMatch(/^cybermeters-scan-snapshot-single-scan-.*\.pdf$/)
    expect(name).not.toMatch(/scan-v2|snap_|rep_/)
    expect(reportFileName({ report_type: 'monthly_executive', report_period: '2026-09' })).toBe('cybermeters-monthly-executive-2026-09.pdf')
  })
})
