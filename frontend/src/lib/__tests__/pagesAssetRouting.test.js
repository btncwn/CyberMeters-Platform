import { describe, expect, it, vi } from 'vitest'
import worker from '../../../public/_worker.js'

const html = '<!doctype html><html><body><div id="root"></div></body></html>'
const response = (body, type, status = 200) => new Response(body, {
  status, headers: { 'content-type': type, 'cache-control': 'public, max-age=31536000, immutable', 'x-frame-options': 'DENY' },
})

describe('Pages assets guard keeps the Attack Surface application route', () => {
  it.each(['/assets', '/assets/', '/assets?tab=settings'])('%s serves the app without caching its HTML', async (path) => {
    const fetch = vi.fn(async () => response(html, 'text/html; charset=utf-8'))
    const out = await worker.fetch(new Request(`https://app.cybermeters.com${path}`), { ASSETS: { fetch } })
    expect(out.status).toBe(200)
    expect(await out.text()).toBe(html)
    expect(out.headers.get('content-type')).toMatch(/text\/html/)
    expect(out.headers.get('cache-control')).toBe('no-store')
    expect(out.headers.get('x-frame-options')).toBe('DENY')
    expect(new URL(fetch.mock.calls[0][0].url).pathname).toBe('/')
  })

  it.each(['/assets/missing.js', '/assets/nested/missing.css'])('%s cannot cache the SPA fallback', async (path) => {
    const out = await worker.fetch(new Request(`https://app.cybermeters.com${path}`), {
      ASSETS: { fetch: async () => response(html, 'text/html') },
    })
    expect(out.status).toBe(404)
    expect(out.headers.get('cache-control')).toBe('no-store')
    expect(out.headers.get('content-type')).not.toMatch(/html/)
  })

  it('a real hashed asset retains its immutable cache and security headers', async () => {
    const out = await worker.fetch(new Request('https://app.cybermeters.com/assets/index-abc123.js'), {
      ASSETS: { fetch: async () => response('export default 1', 'application/javascript') },
    })
    expect(out.status).toBe(200)
    expect(await out.text()).toBe('export default 1')
    expect(out.headers.get('cache-control')).toBe('public, max-age=31536000, immutable')
    expect(out.headers.get('x-frame-options')).toBe('DENY')
  })

  it('HEAD reaches the app shell as HEAD', async () => {
    const fetch = vi.fn(async () => response(null, 'text/html'))
    const out = await worker.fetch(new Request('https://app.cybermeters.com/assets', { method: 'HEAD' }), { ASSETS: { fetch } })
    expect(out.status).toBe(200)
    expect(fetch.mock.calls[0][0].method).toBe('HEAD')
    expect(out.headers.get('cache-control')).toBe('no-store')
  })
})
