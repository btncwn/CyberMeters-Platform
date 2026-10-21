import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, resolve } from 'node:path'

// Founder (16 Oct 2026): customer-facing text does not count the areas. It
// speaks of the external posture. The structure underneath (one registry,
// eight canonical keys) is unchanged and may say "eight" in code and comments;
// this test reads only the text a customer can see — JSX text and string
// literals — after stripping comments.

const SRC = resolve(__dirname, '..')
const SCAN_DIRS = ['pages', 'components', 'data', 'lib']
const SKIP = /__tests__|\.test\.|fixtures/

function* files(dir) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name)
    if (statSync(full).isDirectory()) yield* files(full)
    else if (/\.(jsx?|tsx?)$/.test(name) && !SKIP.test(full)) yield full
  }
}

function stripComments(source) {
  return source
    .replace(/\{\/\*[\s\S]*?\*\/\}/g, '')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:'"\\])\/\/[^\n]*/g, '$1')
}

// Counting words in customer text: "eight areas", "eight domains", "eight
// services", "eight external security check …", "eight-domain …", "all eight", "the eight".
const COUNTING = /\b(all|the|across|our|your|of)\s+eight\b|\beight[- ](areas?|domains?|services?|security|security check|canonical|area|domain)\b|\bEight[- ]/i

describe('customer wording speaks of the external posture, not a number of areas', () => {
  it('no customer-visible string counts the areas', () => {
    const offenders = []
    for (const dir of SCAN_DIRS) {
      for (const file of files(join(SRC, dir))) {
        const text = stripComments(readFileSync(file, 'utf8'))
        // Only string literals and JSX text can reach a customer.
        const visible = [
          ...[...text.matchAll(/(['"`])((?:\\.|(?!\1)[^\\])*)\1/g)].map(m => m[2]),
          ...[...text.matchAll(/>([^<>{}]+)</g)].map(m => m[1]),
        ]
        for (const s of visible) if (COUNTING.test(s)) offenders.push(`${file.replace(SRC, 'src')}: ${s.trim().slice(0, 80)}`)
      }
    }
    expect(offenders).toEqual([])
  })
})
