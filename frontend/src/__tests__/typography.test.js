import { readFileSync, existsSync, statSync } from 'node:fs'
import { resolve } from 'node:path'

// Typography (founder, 16 Oct 2026): page and section titles stay in the serif,
// everything else is the self-hosted product sans. No font comes from a
// third-party host, so the content-security policy is untouched.

const css = readFileSync(resolve(__dirname, '../index.css'), 'utf8')
const fontDir = resolve(__dirname, '../../public/fonts/cm-sans')

describe('product typography', () => {
  it('declares the product sans as a self-hosted variable face with its licence beside it', () => {
    const face = css.match(/@font-face\s*\{[^}]*font-family:\s*'CM Sans'[^}]*\}/)
    expect(face).toBeTruthy()
    expect(face[0]).toMatch(/src:\s*url\('\/fonts\/cm-sans\/CMSans-Variable\.woff2'\)\s*format\('woff2'\)/)
    expect(face[0]).toMatch(/font-weight:\s*300 700/)
    expect(existsSync(resolve(fontDir, 'CMSans-Variable.woff2'))).toBe(true)
    expect(statSync(resolve(fontDir, 'CMSans-Variable.woff2')).size).toBeLessThan(200 * 1024)
    expect(existsSync(resolve(fontDir, 'OFL.txt'))).toBe(true)
  })

  it('loads no font from another host', () => {
    const urls = [...css.matchAll(/url\(\s*['"]?([^'")]+)['"]?\s*\)/g)].map(m => m[1])
    expect(urls.length).toBeGreaterThan(0)
    for (const u of urls) expect(u).toMatch(/^\/fonts\//)
    expect(css).not.toMatch(/@import\s+url/)
  })

  it('body text is the sans and h1/h2 keep the serif', () => {
    const body = css.match(/\n\s*body\s*\{[^}]*\}/)
    expect(body[0]).toMatch(/font-family:\s*'CM Sans'/)
    expect(css).toMatch(/\n\s*h1,\s*h2\s*\{\s*font-family:\s*'Computer Modern Serif'/)
    expect(css).toMatch(/--font-sans:\s*'CM Sans'/)
    expect(css).toMatch(/\.cm-hero-title\s*\{[^}]*font-family:\s*'Computer Modern Serif'/)
  })

  it('the shell canvas is an opaque white-to-sky gradient and the docks take pointer events only on their controls', () => {
    expect(css).toMatch(/\.cm-shell\s*\{[^}]*linear-gradient\(180deg,\s*#ffffff/)
    expect(css).not.toMatch(/\.cm-shell\s*\{[^}]*rgba\(/)
    // The globe is a control now (notifications), so the DOCK is inert and only
    // the canvas inside it is a pointer target; the same holds for the workspace dock.
    expect(css).toMatch(/\.cm-earthdock\s*\{[^}]*pointer-events:\s*none/)
    expect(css).toMatch(/\.cm-earthdock\s*>\s*\*\s*\{[^}]*pointer-events:\s*auto/)
    expect(css).toMatch(/\.cm-dock\s*\{[^}]*pointer-events:\s*none/)
    expect(css).not.toMatch(/\.cm-globe\s*\{/)
    expect(css).not.toMatch(/\.cm-rail\s*\{/)
  })
})
