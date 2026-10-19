// Where "CyberMeters home" should lead from public pages that live on the app
// host (free check, sign-in, sign-up, pricing). On the app host, "/" is the
// signed-in product, so the brand mark points back to the public site instead.

export const MARKETING_URL = 'https://cybermeters.com'
export const APP_URL = 'https://app.cybermeters.com'

function currentHost() {
  if (typeof window === 'undefined') return ''
  return String(window.location.hostname || '').toLowerCase()
}

export function isMarketingHost(hostname = currentHost()) {
  return hostname === 'cybermeters.com' || hostname === 'www.cybermeters.com'
}

// Pull-request previews and local runs have no separate marketing host.
export function isPreviewHost(hostname = currentHost()) {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname.endsWith('.pages.dev')
}

export function marketingHomeHref(hostname = currentHost()) {
  if (isMarketingHost(hostname)) return '/'
  if (isPreviewHost(hostname)) return '/landing'
  return MARKETING_URL
}

// A full-page navigation (a form submit) to an app-host page from the public
// site. On the marketing host it goes straight to the app host: the relative
// path would load the whole site once on cybermeters.com only to be redirected
// and load it again on app.cybermeters.com. Elsewhere the path stays relative.
export function appHostHref(path, hostname = currentHost()) {
  return isMarketingHost(hostname) ? `${APP_URL}${path}` : path
}
