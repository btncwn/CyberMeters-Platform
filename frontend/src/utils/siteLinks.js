// Where "CyberMeters home" should lead from public pages that live on the app
// host (free check, sign-in, sign-up, pricing). On the app host, "/" is the
// signed-in product, so the brand mark points back to the public site instead.

export const MARKETING_URL = 'https://cybermeters.com'

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
