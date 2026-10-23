import { describe, expect, it, vi } from 'vitest'
import { evictPoisonedAssets, freshAddress, freshReload, staleAssetCandidates, stripFreshParam } from '../freshReload'

// S1-RELOAD: a missing chunk answered with index.html (200, text/html,
// immutable) poisons the browser cache; a plain reload reads it back forever.
// freshReload replaces poisoned cached assets, then loads a cache-busted address.

const ORIGIN = 'https://app.example.test'
const res = (type, ok = true) => ({ ok, headers: { get: (k) => (k.toLowerCase() === 'content-type' ? type : null) } })

describe('staleAssetCandidates', () => {
  it('collects same-origin /assets/ js/css from the error and resource timing; ignores other origins and paths', () => {
    const perf = { getEntriesByType: () => [
      { name: `${ORIGIN}/assets/index-aaa.js` }, { name: `${ORIGIN}/assets/index-aaa.css` },
      { name: 'https://cdn.other.test/assets/x.js' }, { name: `${ORIGIN}/api/thing` }, { name: `${ORIGIN}/assets/logo.png` },
    ] }
    const got = staleAssetCandidates(new Error(`Failed to fetch dynamically imported module: ${ORIGIN}/assets/Page-bbb.js`), { perf, origin: ORIGIN })
    expect(got.sort()).toEqual([`${ORIGIN}/assets/Page-bbb.js`, `${ORIGIN}/assets/index-aaa.css`, `${ORIGIN}/assets/index-aaa.js`].sort())
  })
  it('a relative path in the error resolves against the origin', () => {
    expect(staleAssetCandidates('Unable to preload CSS for /assets/Area-ccc.css', { perf: null, origin: ORIGIN })).toEqual([`${ORIGIN}/assets/Area-ccc.css`])
  })
})

describe('evictPoisonedAssets', () => {
  it('refetches with cache: reload exactly the URLs whose cached copy is HTML or not OK', async () => {
    const cachedType = { a: 'text/javascript', b: 'text/html; charset=utf-8', c: 'text/css' }
    const fetchImpl = vi.fn(async (url, init) => {
      const k = url.split('/').pop()[0]
      if (init.cache === 'reload') return res('text/javascript')
      return k === 'c' ? res('text/css', false) : res(cachedType[k])
    })
    const replaced = await evictPoisonedAssets(['/assets/a.js', '/assets/b.js', '/assets/c.css'], fetchImpl)
    expect(replaced.sort()).toEqual(['/assets/b.js', '/assets/c.css'])
    expect(fetchImpl).toHaveBeenCalledWith('/assets/b.js', expect.objectContaining({ cache: 'reload' }))
    expect(fetchImpl).not.toHaveBeenCalledWith('/assets/a.js', expect.objectContaining({ cache: 'reload' }))
  })
  it('a network failure never throws', async () => {
    await expect(evictPoisonedAssets(['/assets/a.js'], vi.fn().mockRejectedValue(new Error('offline')))).resolves.toEqual([])
  })
})

describe('freshAddress / stripFreshParam', () => {
  it('keeps path, other params and hash; adds _fresh', () => {
    expect(freshAddress({ href: `${ORIGIN}/ws/email-protection?tab=findings#auth-spf` }, 123)).toBe('/ws/email-protection?tab=findings&_fresh=123#auth-spf')
  })
  it('strip removes only _fresh and leaves other addresses alone', () => {
    const hist = { state: { k: 1 }, replaceState: vi.fn() }
    stripFreshParam({ href: `${ORIGIN}/ws/email-protection?tab=findings&_fresh=123#auth-spf` }, hist)
    expect(hist.replaceState).toHaveBeenCalledWith({ k: 1 }, '', '/ws/email-protection?tab=findings#auth-spf')
    hist.replaceState.mockClear()
    stripFreshParam({ href: `${ORIGIN}/dashboard` }, hist)
    expect(hist.replaceState).not.toHaveBeenCalled()
  })
})

describe('freshReload', () => {
  it('replaces the poisoned chunk named in the error, then navigates to a cache-busted address', async () => {
    const order = []
    const fetchImpl = vi.fn(async (url, init) => { order.push(`${init.cache} ${url}`); return init.cache === 'reload' ? res('text/javascript') : res('text/html') })
    const loc = { origin: ORIGIN, href: `${ORIGIN}/ws/certificates`, replace: vi.fn((to) => order.push(`replace ${to}`)) }
    vi.stubGlobal('location', loc)
    await freshReload(new Error(`Failed to fetch dynamically imported module: ${ORIGIN}/assets/Cert-ddd.js`), { fetchImpl, loc })
    vi.unstubAllGlobals()
    expect(order[0]).toBe(`force-cache ${ORIGIN}/assets/Cert-ddd.js`)
    expect(order).toContain(`reload ${ORIGIN}/assets/Cert-ddd.js`)
    expect(order.at(-1)).toMatch(/^replace \/ws\/certificates\?_fresh=\d+$/)
  })
})
