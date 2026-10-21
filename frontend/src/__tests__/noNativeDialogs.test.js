import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'

// Founder, 21 Oct 2026: the app never uses the browser's native alert/confirm/
// prompt ("app.cybermeters.com says …"); every question goes through the
// accessible in-app dialog (components/AppDialog.jsx).
const src = resolve(__dirname, '..')
const NATIVE = /\bwindow\.(alert|confirm|prompt)\s*\(|(^|[^.\w])(alert|confirm|prompt)\(/

function files(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === '__tests__' ? [] : files(path)
    return /\.(jsx?|tsx?)$/.test(name) && !/\.test\./.test(name) ? [path] : []
  })
}

describe('no native browser dialogs', () => {
  it('no source file calls alert, confirm or prompt', () => {
    const hits = files(src).flatMap((file) => readFileSync(file, 'utf8').split('\n')
      .map((line, i) => [line, i + 1])
      .filter(([line]) => NATIVE.test(line.replace(/\b(dialog|d)\.(alert|confirm|prompt)\(/g, '')) && !/^\s*(\/\/|\*|\{\/\*)/.test(line))
      .map(([, n]) => `${relative(src, file)}:${n}`))
    expect(hits).toEqual([])
  })
})
