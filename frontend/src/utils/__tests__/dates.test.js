import { describe, expect, it } from 'vitest'
import { formatDate, formatDay, parseServerDate } from '../dates'
import { readdirSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'

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

describe('shared customer date format', () => {
  it('uses en-GB day, abbreviated month and 24-hour time', () => {
    expect(formatDate('2026-10-17T19:21:00Z', '—', { timeZone: 'UTC' })).toBe('17 Oct 2026, 19:21')
    expect(formatDay('2026-10-17T19:21:00Z', '—', { timeZone: 'UTC' })).toBe('17 Oct 2026')
    expect(formatDay('2026-10-17')).toBe('17 Oct 2026')
    expect(formatDate('invalid')).toBe('—')
  })

  it('keeps direct toLocaleString calls out of pages', () => {
    const root = resolve(process.cwd(), 'src/pages')
    const pages = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
      if (entry.name === '__tests__') return []
      const path = `${dir}/${entry.name}`
      return entry.isDirectory() ? pages(path) : /\.[jt]sx?$/.test(entry.name) ? [path] : []
    })
    for (const path of pages(root)) {
      expect(readFileSync(path, 'utf8'), path).not.toMatch(/\.toLocaleString\s*\(/)
    }
  })
})
