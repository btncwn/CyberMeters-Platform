// Shared server-timestamp parser.
//
// D1/SQLite CURRENT_TIMESTAMP produces "YYYY-MM-DD HH:MM:SS" — UTC, but with no
// timezone marker. `new Date()` treats that bare format as LOCAL time, so every
// timestamp renders shifted for any user not on UTC (1h early for UK in summer).
// Parse all server strings through here so "no marker" is interpreted as UTC.
export function parseServerDate(value) {
  if (value == null || value === '') return null
  if (value instanceof Date) return value
  if (typeof value === 'number') return new Date(value)
  const s = String(value).trim()
  // Bare D1 format: "2026-07-06 14:12:48" (optionally with .sss) → explicit UTC
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(s)) {
    return new Date(s.replace(' ', 'T') + 'Z')
  }
  // ISO shape but zone-less: "2026-07-06T14:12:48" → server-generated, also UTC
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(s)) {
    return new Date(s + 'Z')
  }
  // Anything else (ISO with Z/offset, date-only, epoch strings) — native parse
  return new Date(s)
}
