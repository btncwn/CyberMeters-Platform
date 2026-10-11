import { describe, it, expect } from 'vitest'
import { maturityHistoryRows, maturityReasonText } from '../maturityDisplay'

describe('maturity history rows', () => {
  it('marks stage changes and keeps unknown codes visible', () => {
    const rows = maturityHistoryRows([
      { maturity_stage: 'managed', reason_code: 'managed_owned', assessed_at: 'b', flags: {} },
      { maturity_stage: 'managed', reason_code: 'some_new_code', assessed_at: 'a', flags: { attested: true } },
      { maturity_stage: 'observed', reason_code: 'observed_clean', assessed_at: '0', flags: {} },
    ])
    expect(rows.map((r) => [r.label, r.changed, r.reason, r.attested])).toEqual([
      ['Under management', false, 'Issues have owners', false],
      ['Under management', true, 'some new code', true],
      ['Observed', true, 'Assessed; nothing to manage', false],
    ])
    expect(maturityReasonText(null)).toBe(null)
    expect(maturityHistoryRows(null)).toEqual([])
  })
})
