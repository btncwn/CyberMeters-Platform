import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'

// RFC 9989 (May 2026) removed the DMARC pct tag: there is no percentage of
// mail a policy applies to. Fails if frontend source (tests excluded) tells a
// customer to publish pct, or describes a policy step as a share of mail.

const src = resolve(__dirname, '..')
const WORDING = [
  /\bpct=\d/,                                     // a record example that publishes pct
  /(quarantine|reject)\s+\d+\s*%/i,               // "Quarantine 25%"-style step labels
  /\d+\s*%\s*of\s+(your\s+)?(mail|messages|email)/i,
]

function files(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === '__tests__' ? [] : files(path)
    return /\.(jsx?|tsx?)$/.test(name) && !/\.test\./.test(name) ? [path] : []
  })
}

describe('no DMARC pct wording in frontend source', () => {
  it('no file recommends pct or a percentage of mail', () => {
    const hits = files(src).flatMap((file) => {
      const text = readFileSync(file, 'utf8')
      return WORDING.filter((re) => re.test(text)).map((re) => `${relative(src, file)} ${re}`)
    })
    expect(hits).toEqual([])
  })
})
