import { useEffect } from 'react'
import { useLocation } from 'react-router-dom'

/**
 * Per-page <title> and description for the public pages (19 Oct 2026).
 *
 * Every route is served the same index.html, so search results showed the
 * homepage title for /cyber-essentials-readiness. This sets the title and the
 * description tags after each navigation. index.html stays the one source of
 * the defaults: they are read from the document on first use and restored on
 * every route that is not listed here (the homepage and the signed-in app).
 * Wording follows each page's own heading and claims.
 */

const SUFFIX = ' | CyberMeters'

export const PUBLIC_PAGE_META = {
  '/free-scan': {
    title: 'Free Cyber MOT — check your domain',
    description: 'A free, passive check of your domain: public DNS, HTTPS, website headers, email authentication and technology signals. It says what it could not check, and no report is stored.',
  },
  '/cyber-essentials-readiness': {
    title: 'Cyber Essentials Readiness Preview',
    description: 'See how prepared your business looks against the five Cyber Essentials control areas, from external evidence and your own answers. An indicative readiness view, not a certification.',
  },
  '/pricing': {
    title: 'Pricing',
    description: 'Every paid plan is the full Cyber MOT: external posture, alerts, managed cases, reports and remediation. Priced per monitored domain, starting with a 14-day full trial.',
  },
  '/trust': {
    title: 'Trust & Security',
    description: 'How CyberMeters is built and operated, what has been checked, and how the product handles evidence and your data.',
  },
  '/about': {
    title: 'About',
    description: 'CyberMeters helps you understand your external security, choose the next useful action and keep a record of what changed.',
  },
  '/status': { title: 'System status' },
  '/support': {
    title: 'Support',
    description: 'Help with setup, account access, billing or understanding a report, for your business or agency workspace.',
  },
  '/privacy': { title: 'Privacy Policy' },
  '/terms': { title: 'Terms of Service' },
  '/dpa': { title: 'Data Processing Addendum' },
  '/cookies': { title: 'Cookie Policy' },
  '/login': { title: 'Sign in' },
  '/signup': { title: 'Create your account' },
}

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
    }
  }
  return defaults
}

function setContent(doc, selector, value) {
  const el = doc.querySelector(selector)
  if (el && value != null) el.setAttribute('content', value)
}

export function normalisePath(pathname) {
  const p = String(pathname || '/').split(/[?#]/)[0]
  return p.length > 1 ? p.replace(/\/+$/, '') : p
}

export function applyPageMeta(pathname, doc = document) {
  const base = readDefaults(doc)
  const meta = PUBLIC_PAGE_META[normalisePath(pathname)]
  const title = meta ? `${meta.title}${SUFFIX}` : base.title
  doc.title = title
  TITLE_TAGS.forEach((selector, i) => setContent(doc, selector, meta ? title : base.titles[i]))
  DESCRIPTION_TAGS.forEach((selector, i) => setContent(doc, selector, meta?.description ?? base.descriptions[i]))
}

export function resetPageMetaDefaultsForTests() {
  defaults = null
}

export default function PublicPageMeta() {
  const { pathname } = useLocation()
  useEffect(() => { applyPageMeta(pathname) }, [pathname])
  return null
}
