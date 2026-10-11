import { describe, it, expect } from 'vitest'
import { snapshotRows, snapshotQualityText } from '../reportSnapshotDisplay'

describe('reportSnapshotDisplay', () => {
  it('names the domain, marks the latest per domain, and never hides a missing domain', () => {
    const rows = snapshotRows([
      { id: 's2', scan_id: 'scan2', domain_id: 'd1', assessed_at: 'b', scan_quality: 'complete', superseded_by: null },
      { id: 's1', scan_id: 'scan1', domain_id: 'd1', assessed_at: 'a', scan_quality: 'partial', superseded_by: 's2' },
      { id: 's0', scan_id: 'scan0', domain_id: 'gone', assessed_at: '0', scan_quality: null, superseded_by: null },
    ], [{ domain_id: 'd1', domain: 'acme.test' }])
    expect(rows.map((r) => [r.domain, r.current, r.quality])).toEqual([
      ['acme.test', true, 'Complete scan'],
      ['acme.test', false, 'Partial scan — some evidence was missing'],
      [null, true, 'Scan quality not recorded'],
    ])
  })
  it('unknown quality is not upgraded', () => {
    expect(snapshotQualityText('weird')).toBe('Scan quality not recorded')
  })
})
