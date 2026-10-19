import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { preloadOpeningRoute } from '../App'

// Homepage performance (19 Oct 2026): the page a first visit opens on is loaded
// before the first render, and only for the two public pages most visits start on.

describe('opening route preload', () => {
  it('loads the homepage on the marketing host and the free scan on the app host', async () => {
    const landing = preloadOpeningRoute('cybermeters.com', '/')
    expect(landing).toBeInstanceOf(Promise)
    expect(typeof (await landing).default).toBe('function')
    expect(preloadOpeningRoute('www.cybermeters.com', '/')).toBeInstanceOf(Promise)
    const freeScan = preloadOpeningRoute('app.cybermeters.com', '/free-scan/')
    expect(freeScan).toBeInstanceOf(Promise)
    expect(typeof (await freeScan).default).toBe('function')
    expect(preloadOpeningRoute('abc123.cybermeters-platform.pages.dev', '/landing')).toBeInstanceOf(Promise)
  })

  it('waits for nothing anywhere else, so the signed-in app starts exactly as before', () => {
    expect(preloadOpeningRoute('app.cybermeters.com', '/')).toBeNull()
    expect(preloadOpeningRoute('app.cybermeters.com', '/dashboard')).toBeNull()
    expect(preloadOpeningRoute('cybermeters.com', '/pricing')).toBeNull()
    // The marketing host sends /free-scan on to the app host; nothing to wait for.
    expect(preloadOpeningRoute('cybermeters.com', '/free-scan')).toBeNull()
    expect(preloadOpeningRoute('app.cybermeters.com', '/landing')).toBeNull()
  })

  it('never holds the first render back for more than three seconds', () => {
    const main = readFileSync(resolve(__dirname, '../main.jsx'), 'utf8')
    expect(main).toMatch(/opening\.then\(once, once\)/)
    expect(main).toMatch(/window\.setTimeout\(once, 3000\)/)
  })

  it('keeps the signed-in shell out of the first download of the public pages', () => {
    const app = readFileSync(resolve(__dirname, '../App.jsx'), 'utf8')
    expect(app).toMatch(/const Layout\s+= lazy\(\(\) => import\('\.\/components\/Layout'\)\)/)
    expect(app).not.toMatch(/^import Layout from/m)
  })
})
