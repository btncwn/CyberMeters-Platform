import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { expect, it } from 'vitest'

// Guard (P1, 25 Oct 2026): useAppDialog() returns an `element` the caller must
// render. A page that calls dialog.prompt/confirm without rendering it opens an
// invisible dialog that never resolves — the founder's "Revoke permission does
// nothing". Every source file that calls useAppDialog() renders as many
// `.element` as it has dialogs.
const SRC = join(__dirname, '..', '..')
function* sources(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name)
    if (name === '__tests__' || name === 'node_modules') continue
    if (statSync(path).isDirectory()) yield* sources(path)
    else if (/\.(jsx?|tsx?)$/.test(name)) yield path
  }
}

it('every useAppDialog() caller renders its dialog element', () => {
  const missing = []
  for (const file of sources(SRC)) {
    if (file.endsWith('AppDialog.jsx')) continue
    const text = readFileSync(file, 'utf8')
    const uses = (text.match(/useAppDialog\(\)/g) || []).length
    if (!uses) continue
    const rendered = (text.match(/\{\s*\w+\.element\s*\}/g) || []).length
    if (rendered < uses) missing.push(`${file.slice(SRC.length + 1)} (${uses} dialog, ${rendered} rendered)`)
  }
  expect(missing).toEqual([])
})
