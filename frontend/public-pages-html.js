// Static HTML for each public page, and the sitemap (19 Oct 2026).
//
// Every route used to be served the same index.html, so a crawler or a link
// preview that does not run JavaScript saw the homepage's title, description
// and share tags on every page. At build time this writes one copy of the built
// index.html per public page (about.html, trust.html, …) with that page's own
// <title>, description, Open Graph / Twitter tags and canonical link. The app
// itself is unchanged: each copy loads the same bundle. Cloudflare Pages serves
// /about from about.html before the SPA fallback in _redirects.
//
// The pages and their wording come from src/publicPages.js, which the browser
// also reads (components/PublicPageMeta.jsx), so the two never disagree.
import { canonicalUrl, sitemapPages, staticPages } from './src/publicPages.js'

const escapeHtml = (value) => String(value)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

function setMeta(html, attribute, key, value) {
  const pattern = new RegExp(`(<meta\\s+${attribute}="${key.replace(/[.:]/g, '\\$&')}"\\s+content=")[^"]*(")`)
  if (!pattern.test(html)) throw new Error(`index.html has no <meta ${attribute}="${key}"> to set`)
  return html.replace(pattern, (_, start, end) => `${start}${escapeHtml(value)}${end}`)
}

function setCanonical(html, url) {
  const link = `<link rel="canonical" href="${escapeHtml(url)}" />`
  if (/<link rel="canonical"[^>]*>/.test(html)) return html.replace(/<link rel="canonical"[^>]*>/, link)
  if (!/\n[ \t]*<\/head>/.test(html)) throw new Error('index.html has no </head>')
  return html.replace(/\n([ \t]*)<\/head>/, (_, indent) => `\n${indent}  ${link}\n${indent}</head>`)
}

/** The homepage's own HTML: index.html with its canonical link and og:url. */
export function renderHomeHtml(indexHtml) {
  const home = canonicalUrl('/')
  return setCanonical(setMeta(indexHtml, 'property', 'og:url', home), home)
}

/** One public page's HTML: the built index.html with that page's tags. */
export function renderPageHtml(indexHtml, page) {
  if (!/<title>[^<]*<\/title>/.test(indexHtml)) throw new Error('index.html has no <title>')
  let html = indexHtml.replace(/<title>[^<]*<\/title>/, `<title>${escapeHtml(page.title)}</title>`)
  html = setMeta(html, 'name', 'description', page.description)
  html = setMeta(html, 'property', 'og:title', page.title)
  html = setMeta(html, 'property', 'og:description', page.description)
  html = setMeta(html, 'property', 'og:url', page.canonical)
  html = setMeta(html, 'name', 'twitter:title', page.title)
  html = setMeta(html, 'name', 'twitter:description', page.description)
  return setCanonical(html, page.canonical)
}

/** The file a page is served from: /about → about.html. */
export function pageFileName(path) {
  return `${path.replace(/^\//, '')}.html`
}

export function renderSitemap(pages = sitemapPages()) {
  const urls = pages.map(({ loc, priority }) => `  <url><loc>${escapeHtml(loc)}</loc><priority>${priority}</priority></url>`)
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.join('\n')}\n</urlset>\n`
}

export default function publicPagesHtml() {
  return {
    name: 'cybermeters-public-pages-html',
    apply: 'build',
    enforce: 'post',
    generateBundle(_options, bundle) {
      const index = bundle['index.html']
      if (!index || typeof index.source !== 'string') throw new Error('public-pages-html: the build produced no index.html')
      const built = index.source
      index.source = renderHomeHtml(built)
      for (const page of staticPages()) {
        this.emitFile({ type: 'asset', fileName: pageFileName(page.path), source: renderPageHtml(built, page) })
      }
      this.emitFile({ type: 'asset', fileName: 'sitemap.xml', source: renderSitemap() })
    },
  }
}
