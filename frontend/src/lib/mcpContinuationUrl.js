const INTENT = /^[A-Za-z0-9_-]{43}$/

/** Accept only the API's exact consent continuation for this one-time intent. */
export function validMcpContinuationUrl(base, intent, value) {
  if (typeof base !== 'string' || typeof value !== 'string' ||
      !INTENT.test(intent || '')) return null
  try {
    const api = new URL(base)
    const target = new URL(value)
    if (api.protocol !== 'https:' || target.origin !== api.origin ||
        target.username || target.password || target.hash ||
        target.pathname !== '/authorize' ||
        target.searchParams.size !== 1 ||
        target.searchParams.get('intent') !== intent) return null
    return target.toString()
  } catch { return null }
}
