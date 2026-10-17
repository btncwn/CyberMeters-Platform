// A Microsoft sign-in leaves the app and loses React navigation state. Preserve
// only a bounded MCP consent destination in this tab, bound to the browser
// binding challenge returned by the one-time-code exchange. No bearer or
// Microsoft URL is stored here.
const STORAGE_KEY = 'cm_ms_mcp_continuation'
const MAX_AGE_MS = 15 * 60 * 1000
const INTENT = /^[A-Za-z0-9_-]{43}$/
const BINDING = /^[A-Za-z0-9_-]{43}$/
const APP_ORIGIN = 'https://app.cybermeters.com'
const SECRET_QUERY_KEYS = new Set([
  'intent', 'bearer', 'authorization', 'access_token', 'refresh_token',
  'id_token', 'token', 'code', 'otc',
])

function mcpDestination(from) {
  if (from?.pathname !== '/mcp/connect' || typeof from.search !== 'string' ||
      from.search.length > 160 || !from.search.startsWith('?')) return null
  const params = new URLSearchParams(from.search)
  const entries = [...params.entries()]
  if (entries.length !== 1 || entries[0][0] !== 'intent' || !INTENT.test(entries[0][1])) return null
  return `/mcp/connect?intent=${entries[0][1]}`
}

/** Only a relative app path can become a post-login destination. */
export function safeLoginDestination(from) {
  const path = from?.pathname
  const search = from?.search ?? ''
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') ||
      path.length > 512 || typeof search !== 'string' || search.length > 1024 ||
      (search && !search.startsWith('?')) ||
      /[\\#\x00-\x1f\x7f\p{Cf}]/u.test(path + search) ||
      path === '/login' || path === '/auth/microsoft/callback') return '/dashboard'
  try {
    const resolved = new URL(`${path}${search}`, APP_ORIGIN)
    if (resolved.origin !== APP_ORIGIN || resolved.pathname !== path) return '/dashboard'
  } catch { return '/dashboard' }
  if (path === '/mcp/connect') return mcpDestination(from) ?? '/dashboard'
  if ([...new URLSearchParams(search).keys()].some(key => SECRET_QUERY_KEYS.has(key.toLowerCase()))) {
    return '/dashboard'
  }
  return `${path}${search}`
}

export function mcpLoginDestination(from) {
  return mcpDestination(from)
}

function store(storage) {
  return storage ?? globalThis.sessionStorage
}

function validStoredDestination(destination) {
  return typeof destination === 'string' && destination.startsWith('/mcp/connect?intent=') &&
    mcpDestination({ pathname: '/mcp/connect',
      search: destination.slice('/mcp/connect'.length) }) === destination
}

/** Call only after the backend accepted the Microsoft sign-in start. */
export function saveMicrosoftMcpContinuation(binding, destination, {
  storage, now = Date.now(),
} = {}) {
  if (!BINDING.test(binding) || !validStoredDestination(destination)) {
    throw new Error('Invalid Microsoft MCP continuation')
  }
  store(storage).setItem(STORAGE_KEY, JSON.stringify({ binding, destination, at: now }))
}

/** Consume once, and only for the browser binding proven by the API exchange. */
export function takeMicrosoftMcpContinuation(binding, {
  storage, now = Date.now(),
} = {}) {
  let value
  try {
    const target = store(storage)
    value = JSON.parse(target.getItem(STORAGE_KEY) || 'null')
    target.removeItem(STORAGE_KEY)
  } catch { return null }
  if (!BINDING.test(binding) || value?.binding !== binding ||
      !Number.isFinite(value?.at) || value.at > now || now - value.at > MAX_AGE_MS) return null
  return validStoredDestination(value.destination) ? value.destination : null
}

export function clearMicrosoftMcpContinuation({ storage } = {}) {
  try { store(storage).removeItem(STORAGE_KEY) } catch { /* nothing to clear */ }
}
