import { relativeTime } from '../Dashboard'

// The home hero says "Last assessment of <domain> · <age>". The age must never
// read "NaNd ago": a missing or unparsable timestamp yields '' and the hero
// drops the "· … ago" part.

const NOW = Date.parse('2026-10-17T12:00:00.000Z')

describe('relativeTime', () => {
  it('returns an empty string for null, undefined, blanks and unparsable values', () => {
    for (const bad of [null, undefined, '', '   ', 'not-a-date', 'NaNd', 42, {}, []]) {
      expect(relativeTime(bad, NOW)).toBe('')
    }
  })

  it('formats stored SQLite timestamps and ISO strings', () => {
    expect(relativeTime('2026-10-17 11:59:40', NOW)).toBe('just now')
    expect(relativeTime('2026-10-17 11:15:00', NOW)).toBe('45m ago')
    expect(relativeTime('2026-10-17T07:00:00.000Z', NOW)).toBe('5h ago')
    expect(relativeTime('2026-10-14T12:00:00Z', NOW)).toBe('3d ago')
  })

  it('never goes negative for a timestamp slightly in the future (clock skew)', () => {
    expect(relativeTime('2026-10-17T12:00:30.000Z', NOW)).toBe('just now')
  })
})
