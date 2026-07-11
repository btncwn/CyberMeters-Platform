import { describe, expect, it } from 'vitest'
import { parseServerDate } from '../dates'

describe('parseServerDate', () => {
  it('treats D1 bare timestamps as UTC', () => {
    expect(parseServerDate('2026-07-06 14:12:48').toISOString()).toBe('2026-07-06T14:12:48.000Z')
  })

  it('treats zone-less ISO timestamps as UTC', () => {
    expect(parseServerDate('2026-07-06T14:12:48').toISOString()).toBe('2026-07-06T14:12:48.000Z')
  })

  it('returns nullish and Date values without surprising conversion', () => {
    expect(parseServerDate(null)).toBeNull()
    expect(parseServerDate('')).toBeNull()
    const date = new Date('2026-07-06T14:12:48Z')
    expect(parseServerDate(date)).toBe(date)
  })

  it('supports numeric epochs and native date strings', () => {
    expect(parseServerDate(0).toISOString()).toBe('1970-01-01T00:00:00.000Z')
    expect(parseServerDate('2026-07-06T14:12:48+01:00').toISOString()).toBe('2026-07-06T13:12:48.000Z')
  })
})
