// Secrets never stay in an address-bar URL (19 Oct 2026).
//
// Page analytics and server logs see a page's path and query, so a link that
// carries a token there hands the token to them. Emailed links now carry it in
// the fragment (#t=…), which browsers never send anywhere. Links sent before
// this change carry it in the path or query and must keep working.
//
// On load, before anything else runs, captureUrlSecrets() reads the token from
// either form and replaces the address with a clean URL. The token moves into
// the history entry's state, which the router hands to the page as
// location.state.urlSecrets: never in a URL, kept across a reload of the tab.
// Navigating inside the app passes it the same way (secretRoute).

export const INVITATION_RETURN_RE = /^\/invitations\/cmi_[0-9a-f]{64}$/
const MCP_INTENT_RE = /^[A-Za-z0-9_-]{43}$/
const MAX_SECRET_LENGTH = 512

function clean(value) {
  if (typeof value !== 'string') return null
  const v = value.trim()
  return v && v.length <= MAX_SECRET_LENGTH && !/[\s\x00-\x1f\x7f]/.test(v) ? v : null
}

function decodeSegment(segment) {
  try { return decodeURIComponent(segment) } catch { return null }
}

// One rule per route that receives a secret: where it is read from (the new
// fragment name and the legacy query name), and which name the page reads.
const QUERY_ROUTES = {
  '/reset-password': [{ name: 'resetToken', fragment: 't', query: 'token' }],
  '/verify-email': [
    { name: 'verificationToken', fragment: 't' },
    { name: 'invitationReturn', fragment: 'next', query: 'next' },
  ],
  '/auth/microsoft/callback': [{ name: 'otc', fragment: 'otc', query: 'otc' }],
  '/mcp/connect': [{ name: 'mcpIntent', fragment: 'intent', query: 'intent' }],
}

/**
 * The secrets a URL carries and the clean URL to show instead, or null when it
 * carries none. Pure: reads only the parts it is given.
 */
export function extractUrlSecrets({ pathname = '/', search = '', hash = '' } = {}) {
  const path = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname
  const query = new URLSearchParams(search)
  const fragment = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash)
  const secrets = {}
  let cleanPath = path
  // A secret key present at all, even with a value that cannot be a token, is
  // still removed from the address.
  let touched = false

  const legacyInvitation = path.match(/^\/invitations\/([^/]+)$/)
  if (legacyInvitation) {
    const token = clean(decodeSegment(legacyInvitation[1]))
    if (token) secrets.invitationToken = token
    cleanPath = '/invitations'
  } else if (path === '/invitations' && fragment.has('t')) {
    touched = true
    const token = clean(fragment.get('t'))
    if (token) secrets.invitationToken = token
  }

  for (const rule of QUERY_ROUTES[path] || []) {
    if (fragment.has(rule.fragment) || (rule.query && query.has(rule.query))) touched = true
    const value = clean(fragment.get(rule.fragment)) || (rule.query ? clean(query.get(rule.query)) : null)
    if (value) secrets[rule.name] = value
    if (rule.query) query.delete(rule.query)
  }

  if (!touched && Object.keys(secrets).length === 0 && cleanPath === path) return null
  const rest = query.toString()
  // The fragment on these routes only ever carried the secret, so it goes too.
  return { secrets, url: `${cleanPath}${rest ? `?${rest}` : ''}` }
}

/**
 * Run once at start-up (src/lib/urlSecretsOnLoad.js, the first import of
 * main.jsx). Replaces the address with the clean URL and keeps the secrets in
 * the history entry's state, where the router reads them.
 */
export function captureUrlSecrets(win = globalThis.window) {
  if (!win?.location || typeof win.history?.replaceState !== 'function') return null
  const found = extractUrlSecrets(win.location)
  if (!found) return null
  const previous = win.history.state && typeof win.history.state === 'object' ? win.history.state : {}
  const usr = previous.usr && typeof previous.usr === 'object' ? previous.usr : {}
  const state = { ...previous, usr: { ...usr, urlSecrets: { ...(usr.urlSecrets || {}), ...found.secrets } } }
  try { win.history.replaceState(state, '', found.url) } catch { return null }
  return found
}

/** A secret the router handed this page in location.state, or null. */
export function urlSecret(location, name) {
  const value = location?.state?.urlSecrets?.[name]
  return clean(value)
}

/**
 * Where to navigate for an in-app destination path that names a secret (an
 * invitation return path, an MCP consent continuation): the clean path, with the
 * secret in router state. Any other path is returned unchanged.
 */
export function secretRoute(destination) {
  if (typeof destination === 'string' && INVITATION_RETURN_RE.test(destination)) {
    return { to: '/invitations', state: { urlSecrets: { invitationToken: destination.slice('/invitations/'.length) } } }
  }
  if (typeof destination === 'string' && destination.startsWith('/mcp/connect?intent=')) {
    const intent = destination.slice('/mcp/connect?intent='.length)
    if (MCP_INTENT_RE.test(intent)) return { to: '/mcp/connect', state: { urlSecrets: { mcpIntent: intent } } }
  }
  return { to: destination, state: undefined }
}

/**
 * The return location login uses, from a location whose secret is in router
 * state: the same internal path shapes as before (/invitations/<token>,
 * /mcp/connect?intent=<intent>). These are held in memory and turned back into a
 * clean URL by secretRoute(); they are never shown in the address bar.
 */
export function returnLocation(location) {
  const pathname = location?.pathname || '/'
  const search = location?.search || ''
  const invitationToken = urlSecret(location, 'invitationToken')
  if (pathname === '/invitations' && invitationToken) return { pathname: `/invitations/${invitationToken}`, search: '' }
  const intent = urlSecret(location, 'mcpIntent')
  if (pathname === '/mcp/connect' && intent) return { pathname, search: `?intent=${intent}` }
  return { pathname, search }
}

/**
 * The same page on another host, with any secret back in the fragment (the
 * marketing host forwards app paths to the app host).
 */
export function urlWithSecretsInFragment(origin, location) {
  const pathname = location?.pathname || '/'
  const search = location?.search || ''
  const fragment = new URLSearchParams()
  const add = (key, name) => { const v = urlSecret(location, name); if (v) fragment.set(key, v) }
  if (pathname === '/invitations') add('t', 'invitationToken')
  for (const rule of QUERY_ROUTES[pathname] || []) add(rule.fragment, rule.name)
  const tail = fragment.toString()
  return `${origin}${pathname}${search}${tail ? `#${tail}` : ''}`
}
