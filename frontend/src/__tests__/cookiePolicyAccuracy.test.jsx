import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { render } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import CookiePolicyPage from '../pages/CookiePolicyPage'
import TermsPage from '../pages/TermsPage'

// SIRA 4 item 2 (founder, 19 Oct 2026): the Cookie Policy and Terms describe
// what the site really does. Every browser-storage key the app writes, and the
// one cookie the API sets, must be listed; the free-tool retention facts must
// match the constants in code.

const src = resolve(__dirname, '..')
const worker = resolve(__dirname, '../../../workers/scan-api/src')

function files(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === '__tests__' ? [] : files(path)
    return /\.(jsx?|tsx?)$/.test(name) && !/\.test\./.test(name) ? [path] : []
  })
}

function storageKeys() {
  const keys = new Set()
  for (const file of files(src)) {
    const text = readFileSync(file, 'utf8')
    for (const m of text.matchAll(/(?:local|session)Storage\.setItem\(\s*['"`]([A-Za-z0-9_:-]+)['"`]/g)) keys.add(m[1])
    // Keys written through a named constant: const X_KEY = 'name'
    for (const m of text.matchAll(/const\s+([A-Z_]*KEY|RELOAD_FLAG)\s*=\s*['"`]([A-Za-z0-9_:-]+)['"`]/g)) {
      if (new RegExp(`(?:local|session)Storage\\.setItem\\(\\s*${m[1]}\\b`).test(text) || /storage\(\)\??\.setItem\(/.test(text)) keys.add(m[2])
    }
  }
  return [...keys].sort()
}

const policyText = () => {
  const { container } = render(<MemoryRouter><CookiePolicyPage /></MemoryRouter>)
  return container.textContent
}

describe('Cookie Policy matches what the site stores', () => {
  it('lists every browser-storage key the app writes', () => {
    const keys = storageKeys()
    expect(keys.length).toBeGreaterThan(10)
    const text = policyText()
    const missing = keys.filter((key) => !text.includes(key))
    expect(missing).toEqual([])
  })

  it('lists the one cookie the API sets, with its real lifetime', () => {
    const source = readFileSync(join(worker, 'routes/mcp-oauth-browser.js'), 'utf8')
    const name = source.match(/const COOKIE_NAME = "([^"]+)"/)[1]
    const minutes = Number(source.match(/const INTENT_SECONDS = (\d+) \* 60/)[1])
    const text = policyText()
    expect(text).toContain(name)
    expect(text).toContain(`${minutes} minutes`)
  })

  it('states the free-tool retention facts as the code enforces them', () => {
    const gate = readFileSync(join(worker, 'lib/free-tool-gate.js'), 'utf8')
    const share = readFileSync(join(worker, 'lib/free-tool-share.js'), 'utf8')
    const cacheMinutes = Number(gate.match(/cacheSeconds:\s*(\d+)/)[1]) / 60
    const deferHours = Number(gate.match(/deferMaxAgeHours:\s*(\d+)/)[1])
    const shareDays = Number(share.match(/SHARE_TTL_SECONDS = (\d+) \* 24 \* 3600/)[1])
    const text = policyText()
    expect(text).toContain(`for ${cacheMinutes} minutes`)
    expect(text).toContain(`expires after ${shareDays} days`)
    expect(text).toContain(`after ${deferHours} hours at most`)
    expect(text).toMatch(/one-way hash of the IP address or domain/)
    expect(text).toMatch(/No scan report or monitoring history is saved/)
    expect(text).toMatch(/cookieless analytics/)
  })
})

describe('Terms cover the free public checks', () => {
  it('describes them, allows them on any public domain and forbids bulk use or bypassing the limits', () => {
    const { container } = render(<MemoryRouter><TermsPage /></MemoryRouter>)
    const text = container.textContent
    expect(text).toMatch(/Free public checks: the free scan and the free tools/)
    expect(text).toMatch(/may be used on any public domain/)
    expect(text).toMatch(/Run the free checks automatically or in bulk, or get around their limits or the robot check/)
  })

  it('says only the free tools use a robot check: the free scan has none (founder, 21 Oct 2026)', () => {
    const { container } = render(<MemoryRouter><TermsPage /></MemoryRouter>)
    const text = container.textContent
    expect(text).toMatch(/the free tools also use a robot check/)
    expect(text).not.toMatch(/free checks are limited per connection and per domain, use a robot check/)
  })

  it('does not promise portfolio monitoring, which is not customer-accepted (founder, 20 Oct 2026)', () => {
    const { container } = render(<MemoryRouter><TermsPage /></MemoryRouter>)
    expect(container.textContent).not.toMatch(/portfolio monitoring/i)
  })
})
