// Pages advanced-mode Worker, scoped by _routes.json to /assets/* only (S1-RELOAD,
// P1 outage 23 Oct 2026). A request for a hashed asset that is not in this
// deployment used to get the SPA fallback — index.html, 200, text/html — and the
// /assets/* header rule marked that answer immutable for a year. Browsers AND the
// Cloudflare edge then kept serving HTML under the chunk's URL after the deploy
// finished, so the app could not load until the cache was purged.
// Here: a real asset passes through with its long cache; missing files under
// /assets/ are a plain 404 that nothing may store. Pages also matches the bare
// /assets application route: it must serve the app shell without caching HTML.
const IMMUTABLE = 'public, max-age=31536000, immutable'

export default {
  async fetch(request, env) {
    const path = new URL(request.url).pathname
    const appRoute = path === '/assets' || path === '/assets/'
    const res = await env.ASSETS.fetch(appRoute
      ? new Request(new URL('/', request.url), request)
      : request)
    if (appRoute) {
      const out = new Response(res.body, res)
      out.headers.set('cache-control', 'no-store')
      out.headers.set('x-content-type-options', 'nosniff')
      out.headers.delete('pragma')
      out.headers.delete('expires')
      return out
    }
    const type = res.headers.get('content-type') || ''
    if (res.status === 404 || (res.ok && /text\/html/i.test(type))) {
      return new Response('Not found', {
        status: 404,
        headers: {
          'content-type': 'text/plain; charset=utf-8',
          'cache-control': 'no-store',
          'x-content-type-options': 'nosniff',
        },
      })
    }
    if (!res.ok) return res
    const out = new Response(res.body, res)
    out.headers.set('cache-control', IMMUTABLE)
    out.headers.set('x-content-type-options', 'nosniff')
    out.headers.delete('pragma')
    out.headers.delete('expires')
    return out
  },
}
