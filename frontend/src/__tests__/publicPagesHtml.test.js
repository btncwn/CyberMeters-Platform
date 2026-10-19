import { describe, it, expect } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { pageFileName, renderHomeHtml, renderPageHtml, renderSitemap } from '../../public-pages-html.js'
import { APP_ORIGIN, canonicalUrl, MARKETING_ORIGIN, PUBLIC_PAGE_META, sitemapPages, staticPages } from '../publicPages.js'

// Public-site SEO (19 Oct 2026): each public page's served HTML carries its own
// title, description, share tags and canonical link; only the public site is
// listed; the app host and previews are noindex.

const frontend = resolve(__dirname, '../..')
const indexHtml = readFileSync(resolve(frontend, 'index.html'), 'utf8')
const headers = readFileSync(resolve(frontend, 'public/_headers'), 'utf8')
const robots = readFileSync(resolve(frontend, 'public/robots.txt'), 'utf8')

const attr = (html, selector) => {
  const [kind, key] = selector
  const m = html.match(new RegExp(`<meta\\s+${kind}="${key}"\\s+content="([^"]*)"`))
  return m ? m[1] : null
}
const canonicalOf = (html) => (html.match(/<link rel="canonical" href="([^"]*)"/) || [])[1] ?? null
const unescape = (s) => s.replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>')

describe('static HTML per public page', () => {
  it.each(staticPages().map(p => [p.path, p]))('%s: its own title, description, share tags and canonical link', (_, page) => {
    const html = renderPageHtml(indexHtml, page)
    expect(unescape(html.match(/<title>([^<]*)<\/title>/)[1])).toBe(page.title)
    for (const key of [['name', 'description'], ['property', 'og:description'], ['name', 'twitter:description']]) {
      expect(unescape(attr(html, key))).toBe(page.description)
    }
    expect(unescape(attr(html, ['property', 'og:title']))).toBe(page.title)
    expect(unescape(attr(html, ['name', 'twitter:title']))).toBe(page.title)
    expect(attr(html, ['property', 'og:url'])).toBe(page.canonical)
    expect(canonicalOf(html)).toBe(page.canonical)
    expect(html.match(/<link rel="canonical"/g)).toHaveLength(1)
    // Still the same app: the same entry script, nothing else changed.
    expect(html.match(/<script type="module"[^>]*src="[^"]+"><\/script>/g)).toEqual(indexHtml.match(/<script type="module"[^>]*src="[^"]+"><\/script>/g))
  })

  it('covers every public marketing page and the free scan and pricing pages', () => {
    expect(staticPages().map(p => p.path).sort()).toEqual([
      '/about', '/cookies', '/cyber-essentials-readiness', '/dpa', '/free-scan', '/pricing', '/privacy', '/status', '/support', '/terms', '/trust',
    ])
    expect(pageFileName('/cyber-essentials-readiness')).toBe('cyber-essentials-readiness.html')
  })

  it('points a canonical link at the host each page lives on', () => {
    expect(canonicalUrl('/')).toBe(`${MARKETING_ORIGIN}/`)
    expect(canonicalUrl('/about/')).toBe(`${MARKETING_ORIGIN}/about`)
    expect(canonicalUrl('/pricing')).toBe(`${APP_ORIGIN}/pricing`)
    expect(canonicalUrl('/dashboard')).toBeNull()
  })

  it('gives the homepage its canonical link and og:url without changing its title', () => {
    const home = renderHomeHtml(indexHtml)
    expect(canonicalOf(home)).toBe('https://cybermeters.com/')
    expect(attr(home, ['property', 'og:url'])).toBe('https://cybermeters.com/')
    expect(home.match(/<title>[^<]*<\/title>/)[0]).toBe(indexHtml.match(/<title>[^<]*<\/title>/)[0])
  })

  it('escapes page text into attributes', () => {
    const html = renderPageHtml(indexHtml, { title: 'A & "B" <c>', description: 'd & e', canonical: 'https://cybermeters.com/x' })
    expect(html).toContain('<title>A &amp; &quot;B&quot; &lt;c&gt;</title>')
    expect(html).toContain('content="d &amp; e"')
  })

  it('fails the build rather than ship a page without its tags', () => {
    expect(() => renderPageHtml('<html><head></head></html>', staticPages()[0])).toThrow()
  })

  it('makes no claim the product does not support', () => {
    const all = Object.values(PUBLIC_PAGE_META).map((m) => `${m.title} ${m.description || ''}`).join(' ')
    expect(all).not.toMatch(/DMARC & BEC|certified|guarantee|fully compliant|dark.?web/i)
  })
})

describe('sitemap', () => {
  it('lists the homepage and every indexable public page, and nothing on the app host', () => {
    const xml = renderSitemap()
    const locs = [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map(m => m[1])
    expect(locs[0]).toBe('https://cybermeters.com/')
    expect(locs).toEqual(sitemapPages().map(p => p.loc))
    for (const loc of locs) expect(loc.startsWith(`${MARKETING_ORIGIN}/`)).toBe(true)
    expect(locs).toContain('https://cybermeters.com/cyber-essentials-readiness')
    expect(locs).not.toContain(`${APP_ORIGIN}/pricing`)
    expect(xml.startsWith('<?xml version="1.0" encoding="UTF-8"?>')).toBe(true)
  })

  it('is generated at build time only: no second hand-kept copy', () => {
    expect(existsSync(resolve(frontend, 'public/sitemap.xml'))).toBe(false)
    expect(readFileSync(resolve(frontend, 'vite.config.js'), 'utf8')).toMatch(/publicPagesHtml\(\)/)
  })
})

describe('search engines list only the public site', () => {
  it.each([
    'https://app.cybermeters.com/*',
    'https://app-staging.cybermeters.com/*',
    'https://:project.pages.dev/*',
    'https://:version.:project.pages.dev/*',
  ])('%s carries X-Robots-Tag: noindex', (host) => {
    const block = headers.split(/\n\s*\n/).find(b => b.split('\n').some(line => line.trim() === host))
    expect(block).toBeTruthy()
    expect(block).toMatch(/^\s+X-Robots-Tag: noindex$/m)
  })

  it('never marks the public site noindex', () => {
    const noindexHosts = headers.split(/\n\s*\n/).filter(b => /X-Robots-Tag/.test(b)).map(b => b.split('\n').find(l => /^https?:|^\//.test(l.trim())))
    for (const host of noindexHosts) expect(host).not.toMatch(/^https:\/\/cybermeters\.com|^\//)
  })

  it('robots.txt lets crawlers fetch every page, so they see the noindex, and names the sitemap', () => {
    expect(robots).toMatch(/^User-agent: \*$/m)
    expect(robots).toMatch(/^Allow: \/$/m)
    expect(robots).not.toMatch(/^Disallow:/m)
    expect(robots).toMatch(/^Sitemap: https:\/\/cybermeters\.com\/sitemap\.xml$/m)
  })
})
