// Pages advanced-mode Worker, scoped by _routes.json to /assets/* only (S1-RELOAD,
// P1 outage 23 Oct 2026). A request for a hashed asset that is not in this
// deployment used to get the SPA fallback — index.html, 200, text/html — and the
// /assets/* header rule marked that answer immutable for a year. Browsers AND the
// Cloudflare edge then kept serving HTML under the chunk's URL after the deploy
// finished, so the app could not load until the cache was purged.
// Here: a real asset passes through with its long cache; anything else under
// /assets/ is a plain 404 that nothing may store, so the next request after the
// deploy finishes gets the real file.
const IMMUTABLE = 'public, max-age=31536000, immutable'

export default {
  async fetch(request, env) {
    const res = await env.ASSETS.fetch(request)
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
