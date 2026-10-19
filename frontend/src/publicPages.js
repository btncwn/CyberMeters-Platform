// The public pages, in one place (19 Oct 2026): each page's title and
// description, which host it lives on, and whether search engines should list
// it. Read at build time by public-pages-html.js (static HTML per page and the
// sitemap) and in the browser by components/PublicPageMeta.jsx (the same tags
// after an in-app navigation). Plain JavaScript: no JSX, no browser APIs.
//
// Wording follows each page's own heading and claims.

export const MARKETING_ORIGIN = 'https://cybermeters.com'
export const APP_ORIGIN = 'https://app.cybermeters.com'
export const TITLE_SUFFIX = ' | CyberMeters'

// host: where the page is served and where its canonical URL points.
// indexable: search engines may list it. Every other app-host page carries
// noindex (public/_headers, whose two exceptions match the app-host pages
// marked indexable here). The sitemap on cybermeters.com lists the indexable
// marketing pages.
// priority: the sitemap priority for an indexable marketing page.
export const PUBLIC_PAGE_META = {
  '/cyber-essentials-readiness': {
    title: 'Cyber Essentials Readiness Preview',
    description: 'See how prepared your business looks against the five Cyber Essentials control areas, from external evidence and your own answers. An indicative readiness view, not a certification.',
    host: 'marketing', indexable: true, priority: '0.8',
  },
  '/about': {
    title: 'About',
    description: 'Who builds CyberMeters and why: external security checks for small businesses and MSPs, with the evidence behind every finding.',
    host: 'marketing', indexable: true, priority: '0.7',
  },
  '/trust': {
    title: 'Trust & Security',
    description: 'How CyberMeters is built and operated, what has been checked, and how the product handles evidence and your data.',
    host: 'marketing', indexable: true, priority: '0.7',
  },
  '/support': {
    title: 'Support',
    description: 'Help with setup, account access, billing or understanding a report, for your business or agency workspace.',
    host: 'marketing', indexable: true, priority: '0.4',
  },
  '/status': {
    title: 'System status',
    description: 'Current availability of the CyberMeters API, database and report storage, checked live.',
    host: 'marketing', indexable: true, priority: '0.4',
  },
  '/terms': {
    title: 'Terms of Service',
    description: 'The terms that govern access to and use of the CyberMeters platform and its services.',
    host: 'marketing', indexable: true, priority: '0.4',
  },
  '/privacy': {
    title: 'Privacy Policy',
    description: 'What personal data CyberMeters collects, how it is used, and your rights in relation to it.',
    host: 'marketing', indexable: true, priority: '0.4',
  },
  '/dpa': {
    title: 'Data Processing Addendum',
    description: 'How CyberMeters processes personal data on behalf of customers when it provides the service.',
    host: 'marketing', indexable: true, priority: '0.4',
  },
  '/cookies': {
    title: 'Cookie Policy',
    description: 'The essential cookies and browser storage CyberMeters uses, and the cookieless visit counting on its sites.',
    host: 'marketing', indexable: true, priority: '0.4',
  },
  '/free-scan': {
    title: 'Free Cyber MOT — check your domain',
    description: 'A free, passive check of your domain: public DNS, HTTPS, website headers, email authentication and technology signals. It says what it could not check, and no report is stored.',
    host: 'app', indexable: true,
  },
  '/pricing': {
    title: 'Pricing',
    description: 'Every paid plan is the full Cyber MOT: external posture, alerts, managed cases, reports and remediation. Priced per monitored domain, starting with a 14-day full trial.',
    host: 'app', indexable: true,
  },
  '/login': { title: 'Sign in', host: 'app', indexable: false },
  '/signup': { title: 'Create your account', host: 'app', indexable: false },
}

// The homepage: its tags live in index.html itself.
export const HOME_PAGE = { path: '/', priority: '1.0' }

export function normalisePath(pathname) {
  const p = String(pathname || '/').split(/[?#]/)[0]
  return p.length > 1 ? p.replace(/\/+$/, '') : p
}

/** The canonical URL of a public page (or the homepage), else null. */
export function canonicalUrl(pathname) {
  const path = normalisePath(pathname)
  if (path === '/') return `${MARKETING_ORIGIN}/`
  const meta = PUBLIC_PAGE_META[path]
  if (!meta) return null
  return `${meta.host === 'app' ? APP_ORIGIN : MARKETING_ORIGIN}${path}`
}

/** Pages that get their own static HTML file: every page with a description. */
export function staticPages() {
  return Object.entries(PUBLIC_PAGE_META)
    .filter(([, meta]) => meta.description)
    .map(([path, meta]) => ({ path, ...meta, title: `${meta.title}${TITLE_SUFFIX}`, canonical: canonicalUrl(path) }))
}

/** The app-host paths search engines may list (no noindex). */
export function indexableAppPaths() {
  return Object.entries(PUBLIC_PAGE_META).filter(([, meta]) => meta.host === 'app' && meta.indexable).map(([path]) => path)
}

/**
 * The URLs the sitemap on cybermeters.com lists: the homepage and every
 * indexable marketing page. A sitemap names URLs on its own host; the
 * indexable app-host pages are reached through links from the public site.
 */
export function sitemapPages() {
  return [
    { loc: `${MARKETING_ORIGIN}/`, priority: HOME_PAGE.priority },
    ...Object.entries(PUBLIC_PAGE_META)
      .filter(([, meta]) => meta.host === 'marketing' && meta.indexable)
      .map(([path, meta]) => ({ loc: canonicalUrl(path), priority: meta.priority })),
  ]
}
