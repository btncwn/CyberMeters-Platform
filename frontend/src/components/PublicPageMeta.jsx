import { useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import { APP_ORIGIN, canonicalUrl, normalisePath, PUBLIC_PAGE_META, TITLE_SUFFIX } from '../publicPages'
import { isMarketingHost } from '../utils/siteLinks'

/**
 * Per-page <title>, description, share tags and canonical link after each
 * in-app navigation (19 Oct 2026).
 *
 * The first load already has them: the build writes static HTML per public page
 * (public-pages-html.js), from the same list in src/publicPages.js. This keeps
 * the tags right when the visitor then moves between pages without a reload.
 * index.html stays the one source of the defaults: they are read from the
 * document on first use and restored on every route that is not listed (the
 * homepage and the signed-in app). Off the public site (the app host, previews)
 * a robots noindex tag backs up the X-Robots-Tag header from public/_headers,
 * except on the app-host pages that stay indexable (pricing, the free scan).
 */

export { PUBLIC_PAGE_META, normalisePath }

const APP_HOSTNAME = new URL(APP_ORIGIN).hostname
const DESCRIPTION_TAGS = ['meta[name="description"]', 'meta[property="og:description"]', 'meta[name="twitter:description"]']
const TITLE_TAGS = ['meta[property="og:title"]', 'meta[name="twitter:title"]']

let defaults = null
function readDefaults(doc) {
  if (!defaults) {
    const content = (selector) => doc.querySelector(selector)?.getAttribute('content') ?? null
    defaults = {
      title: doc.title,
      titles: TITLE_TAGS.map(content),
      descriptions: DESCRIPTION_TAGS.map(content),
      url: content('meta[property="og:url"]'),
      canonical: doc.querySelector('link[rel="canonical"]')?.getAttribute('href') ?? null,
    }
  }
  return defaults
}

function setContent(doc, selector, value) {
  const el = doc.querySelector(selector)
  if (el && value != null) el.setAttribute('content', value)
}

function setCanonical(doc, href) {
  let link = doc.querySelector('link[rel="canonical"]')
  if (!href) { link?.remove(); return }
  if (!link) {
    link = doc.createElement('link')
    link.setAttribute('rel', 'canonical')
    doc.head.appendChild(link)
  }
  link.setAttribute('href', href)
}

function setNoindex(doc, noindex) {
  let tag = doc.querySelector('meta[name="robots"]')
  if (!noindex) { tag?.remove(); return }
  if (!tag) {
    tag = doc.createElement('meta')
    tag.setAttribute('name', 'robots')
    doc.head.appendChild(tag)
  }
  tag.setAttribute('content', 'noindex')
}

export function applyPageMeta(pathname, doc = document, hostname = globalThis.location?.hostname || '') {
  const base = readDefaults(doc)
  const path = normalisePath(pathname)
  const meta = PUBLIC_PAGE_META[path]
  const title = meta ? `${meta.title}${TITLE_SUFFIX}` : base.title
  doc.title = title
  TITLE_TAGS.forEach((selector, i) => setContent(doc, selector, meta ? title : base.titles[i]))
  DESCRIPTION_TAGS.forEach((selector, i) => setContent(doc, selector, meta?.description ?? base.descriptions[i]))
  const canonical = canonicalUrl(path)
  setContent(doc, 'meta[property="og:url"]', canonical ?? base.url)
  setCanonical(doc, canonical ?? base.canonical)
  setNoindex(doc, !isMarketingHost(hostname) && !(hostname === APP_HOSTNAME && meta?.host === 'app' && meta.indexable))
}

export function resetPageMetaDefaultsForTests() {
  defaults = null
}

export default function PublicPageMeta() {
  const { pathname } = useLocation()
  useEffect(() => { applyPageMeta(pathname) }, [pathname])
  return null
}
