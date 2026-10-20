import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'

// Founder, 20 Oct 2026: em dashes and ellipses were stored corrupted (UTF-8
// read as Latin-1/Windows-1252), so customers saw "â€" on certificate and
// identity screens. Fails if any frontend source carries the corrupted form,
// either as the visible "â€" or as "â" followed by an invisible C1 control
// character, which is how the two affected files actually held it.

const src = resolve(__dirname, '..')
const MOJIBAKE = /â€|[Â-ô][\u0080-\u009f]/

function files(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return files(path)
    return /\.(jsx?|tsx?|css|html|json)$/.test(name) ? [path] : []
  })
}

describe('no mojibake in frontend source', () => {
  it('no file contains corrupted UTF-8 punctuation', () => {
    const hits = files(src)
      .filter((file) => !file.endsWith('noMojibake.test.js'))
      .filter((file) => MOJIBAKE.test(readFileSync(file, 'utf8')))
      .map((file) => relative(src, file))
    expect(hits).toEqual([])
  })

  it('catches both forms', () => {
    expect(MOJIBAKE.test('Recorded by you â€” not yet verified')).toBe(true)
    expect(MOJIBAKE.test('Loadingâ\u0080¦')).toBe(true)
    expect(MOJIBAKE.test('Recorded by you — not yet verified · Loading…')).toBe(false)
  })
})
