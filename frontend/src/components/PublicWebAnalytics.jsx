import { useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import { isMarketingHost } from '../utils/siteLinks'

/**
 * Cookieless page-view counting for the PUBLIC website only (18 Oct 2026).
 *
 * The beacon is the edge provider's privacy-first web analytics: no cookies, no
 * local storage, no cross-site tracking. It renders on the landing page, pricing,
 * the free scan, the free tools and the legal pages — never inside the signed-in
 * app, and never on preview or local hosts, so test traffic is not counted.
 *
 * On the app host "/" IS the signed-in product, so the landing page only counts on
 * the marketing host. The site token is public (it appears in page source), so
 * it is committed here as the default — the one place it is defined. A build may
 * override it with `VITE_CF_ANALYTICS_TOKEN`.
 */

export const BEACON_SRC = 'https://static.cloudflareinsights.com/beacon.min.js'
export const BEACON_ID = 'cm-public-web-analytics'
export const DEFAULT_SITE_TOKEN = '5e0144918d8746b899039b3e0354f9ba'

const PRODUCTION_APP_HOST = 'app.cybermeters.com'
const LEGAL_PATHS = ['/privacy', '/terms', '/dpa', '/cookies']
const APP_HOST_PUBLIC_PATHS = ['/pricing', '/free-scan', ...LEGAL_PATHS]
const TOKEN_RE = /^[0-9a-f]{32}$/i

function normalisePath(pathname) {
  const p = String(pathname || '/').split(/[?#]/)[0]
  return p.length > 1 ? p.replace(/\/+$/, '') : p
}

const isToolsPath = (p) => p === '/tools' || p.startsWith('/tools/')

/** True only for a public-website route on a production host. */
export function isPublicAnalyticsRoute(hostname, pathname) {
  const host = String(hostname || '').toLowerCase()
  const p = normalisePath(pathname)
  if (isMarketingHost(host)) return p === '/' || LEGAL_PATHS.includes(p) || p === '/pricing' || p === '/free-scan' || isToolsPath(p)
  if (host === PRODUCTION_APP_HOST) return APP_HOST_PUBLIC_PATHS.includes(p) || isToolsPath(p)
  return false
}

/** The site token, only when it has the published shape. No value → the build
 *  override, else the committed default; an explicit empty or malformed value → none. */
export function analyticsToken(value = import.meta.env.VITE_CF_ANALYTICS_TOKEN || DEFAULT_SITE_TOKEN) {
  const t = String(value ?? '').trim()
  return TOKEN_RE.test(t) ? t : null
}

export default function PublicWebAnalytics({ hostname, token } = {}) {
  const { pathname } = useLocation()
  const host = hostname ?? (typeof window === 'undefined' ? '' : window.location.hostname)
  const siteToken = analyticsToken(token)
  const enabled = Boolean(siteToken) && isPublicAnalyticsRoute(host, pathname)

  useEffect(() => {
    // The provider's snippet (deferred module script with the token), loaded once
    // on a public page. `spa: false` added: the beacon counts the page it was loaded
    // on and does not follow client-side navigation into the signed-in app.
    if (!enabled || document.getElementById(BEACON_ID)) return
    const script = document.createElement('script')
    script.id = BEACON_ID
    script.type = 'module'
    script.defer = true
    script.src = BEACON_SRC
    script.setAttribute('data-cf-beacon', JSON.stringify({ token: siteToken, spa: false }))
    document.body.appendChild(script)
  }, [enabled, siteToken])

  return null
}
