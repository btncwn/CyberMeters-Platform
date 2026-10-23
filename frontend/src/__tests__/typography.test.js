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
    // S1-SHELL-V2 (founder-approved 22 Oct 2026): from 1024px the workspace card
    // sits over the foot of the sticky 320px sidebar (its list keeps room), never over
    // an area row; below 1024px it floats at 76px and the page keeps room for it.
    expect(css).toMatch(/\.cm-sidebar\s*\{[^}]*flex:\s*0 0 320px;[^}]*position:\s*sticky;\s*top:\s*0;\s*height:\s*100vh/)
    // C-38 S05: the card floats bottom-left outside the sidebar (24px from 1024px, 16px below),
    // and the sidebar's list keeps room at its foot so the card never covers a row.
    expect(css).not.toMatch(/\.cm-sidebar-dock\s*\{/)
    expect(css).toMatch(/\.cm-sidebar > \.cm-side::after\s*\{[^}]*height:\s*150px/)
    expect(css).toMatch(/\.cm-wsfloat\s*\{[^}]*position:\s*fixed;\s*left:\s*16px;\s*bottom:\s*16px/)
    expect(css).toMatch(/\.cm-wsfloat-wide\s*\{[^}]*left:\s*24px;\s*bottom:\s*24px/)
    expect(css).toMatch(/@media \(max-width: 1023\.98px\)\s*\{\s*\.cm-main\s*\{\s*padding-bottom:\s*108px/)
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

// Tailwind v4 generates an @utility only for a class name it finds verbatim in
// the source. The top-bar pills once rendered unstyled in production because
// Layout built the name in a template literal (`cm-pill${…}`) and the only
// verbatim "cm-pill" lived in a test that was later rewritten (S1-SHELL-V2).
describe('shell utilities are named verbatim where they are used', () => {
  it('Layout spells cm-pill and cm-pill-active as whole literals', () => {
    const layout = readFileSync(resolve(__dirname, '../components/Layout.jsx'), 'utf8')
    expect(layout).toMatch(/'cm-pill cm-pill-active'/)
    expect(layout).toMatch(/: 'cm-pill'/)
  })
})
