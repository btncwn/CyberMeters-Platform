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

  it('serves every Computer Modern face as WOFF2 first, the unmodified WOFF only as a fallback', () => {
    const cmDir = resolve(__dirname, '../../public/fonts/computer-modern')
    const faces = [...css.matchAll(/src:\s*url\('\/fonts\/computer-modern\/([a-z]+)\.(woff2?)'\)\s*format\('(woff2?)'\)([^;]*);/g)]
    expect(faces.length).toBe(8)
    for (const [, name, ext, format, rest] of faces) {
      expect(ext).toBe('woff2')
      expect(format).toBe('woff2')
      expect(rest).toContain(`url('/fonts/computer-modern/${name}.woff') format('woff')`)
      // A lossless repackaging is smaller than the WOFF it came from.
      expect(statSync(resolve(cmDir, `${name}.woff2`)).size).toBeLessThan(statSync(resolve(cmDir, `${name}.woff`)).size)
    }
  })

  it('preloads only the face the homepage heading is set in', () => {
    const html = readFileSync(resolve(__dirname, '../../index.html'), 'utf8')
    const preloads = [...html.matchAll(/<link rel="preload"[^>]*>/g)].map(m => m[0])
    expect(preloads).toHaveLength(1)
    expect(preloads[0]).toContain('href="/fonts/computer-modern/cmunrm.woff2"')
    expect(preloads[0]).toContain('type="font/woff2"')
    expect(preloads[0]).toContain('crossorigin')
  })

  it('lets browsers keep the fonts instead of downloading them on every visit', () => {
    const headers = readFileSync(resolve(__dirname, '../../public/_headers'), 'utf8')
    const block = headers.match(/^\/fonts\/\*\n((?:  .*\n)+)/m)
    expect(block).toBeTruthy()
    expect(block[1]).toMatch(/! Cache-Control/)
    expect(block[1]).toMatch(/Cache-Control: public, max-age=31536000, immutable/)
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
    // The globe lives in the top bar (no corner dock, no bell); the workspace dock is inert
    // apart from the card itself.
    expect(css).not.toMatch(/\.cm-earthdock\s*\{/)
    expect(css).not.toMatch(/\.cm-bellbtn\s*\{/)
    expect(css).toMatch(/\.cm-dock\s*\{[^}]*pointer-events:\s*none/)
    // The deck never floats over content (19 Oct 2026): it is a grid column of
    // its own, sticky to the viewport bottom, never a fixed overlay.
    expect(css).not.toMatch(/\.cm-dock[^{]*\{[^}]*position:\s*fixed/)
    expect(css).toMatch(/\.cm-body\s*\{[^}]*display:\s*grid;\s*grid-template-columns:\s*160px minmax\(0, 1fr\)/)
    expect(css).toMatch(/\.cm-dock-card\s*\{[^}]*position:\s*sticky;\s*bottom:\s*22px/)
    // The notification panel hangs under the globe, right-aligned, capped below the bar; the list scrolls inside.
    expect(css).toMatch(/\.cm-notif\s*\{[^}]*position:\s*absolute;\s*right:\s*0;\s*top:\s*calc\(100% \+ 10px\)/)
    expect(css).toMatch(/\.cm-notif\s*\{[^}]*max-height:\s*calc\(100dvh - 100px\)/)
    // The workspace card never turns white on hover and keeps a white letter; its focus ring is aqua.
    expect(css).toMatch(/\.cm-wsbtn:hover[^{]*\{[^}]*color:\s*#fff/)
    // The white offset cards sit on the wrapper, so a hover transform on the button cannot lift them over its ground.
    expect(css).toMatch(/\.cm-wsdock::before,\s*\.cm-wsdock::after\s*\{/)
    expect(css).not.toMatch(/\.cm-wsbtn::before/)
    expect(css).not.toMatch(/\.cm-wsbtn:hover[^{]*\{[^}]*background:\s*#fff/)
    expect(css).toMatch(/\.cm-wsbtn:focus-visible,\s*\.cm-wsmini:focus-visible\s*\{[^}]*outline:\s*3px solid #a9f2e5/)
    expect(css).toMatch(/\.cm-earth-count\s*\{[^}]*background:\s*#a9f2e5;\s*color:\s*#081f1c/)
    expect(css).not.toMatch(/\.cm-globe\s*\{/)
    expect(css).not.toMatch(/\.cm-rail\s*\{/)
  })
})
