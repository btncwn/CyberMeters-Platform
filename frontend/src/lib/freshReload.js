// A reload that really loads the latest CyberMeters (S1-RELOAD, 23 Oct 2026).
//
// Why window.location.reload() alone looped: the Pages SPA fallback answers a
// request for a missing /assets/* file with index.html (200, text/html), and
// the /assets/* header rule gives that answer `immutable` for a year. A tab
// that asks for a new chunk while a deploy is still propagating stores that
// HTML under the chunk's URL; every reload then reads it back from the browser
// cache, fails the same way, and shows the same card. Only a hard refresh
// (which bypasses the cache) recovered.
//
// So before navigating we look at every /assets/ file this tab has asked for
// (and any named in the error), read the browser's cached copy, and refetch
// with cache: 'reload' any copy that is HTML or not OK — replacing the poisoned
// entry. Then we navigate to the same address with a cache-busting parameter,
// which stripFreshParam() removes from the address bar on the next boot.

const FRESH_PARAM = '_fresh'
const ASSET_IN_TEXT = /(?:https?:\/\/[^\s"'()]+)?\/assets\/[^\s"'()?#]+\.(?:js|css)/g
const MAX_ASSETS = 80
const BUDGET_MS = 4000

/** Same-origin /assets/*.js|css URLs this tab requested, plus any named in the error. */
export function staleAssetCandidates(error, { perf = globalThis.performance, origin = globalThis.location?.origin } = {}) {
  const found = new Set()
  const add = (raw) => {
    try {
      const u = new URL(raw, origin)
      if (u.origin === origin && u.pathname.startsWith('/assets/')) found.add(u.origin + u.pathname)
    } catch { /* not a URL */ }
  }
  for (const m of String(error?.message || error || '').matchAll(ASSET_IN_TEXT)) add(m[0])
  try {
    for (const e of perf?.getEntriesByType?.('resource') || []) {
      if (/\.(?:js|css)(?:$|\?)/.test(e.name)) add(e.name)
    }
  } catch { /* no resource timing */ }
  return [...found].slice(0, MAX_ASSETS)
}

/** Refetches (bypassing the cache) each URL whose cached copy is HTML or not OK. Returns the URLs replaced. */
export async function evictPoisonedAssets(urls, fetchImpl = globalThis.fetch) {
  if (typeof fetchImpl !== 'function') return []
  const replaced = []
  const queue = [...urls]
  async function worker() {
    while (queue.length) {
      const url = queue.shift()
      try {
        const cached = await fetchImpl(url, { cache: 'force-cache', credentials: 'same-origin' })
        const type = cached.headers?.get?.('content-type') || ''
        if (!cached.ok || /text\/html/i.test(type)) {
          await fetchImpl(url, { cache: 'reload', credentials: 'same-origin' })
          replaced.push(url)
        }
      } catch { /* network trouble: the navigation below still happens */ }
    }
  }
  await Promise.all(Array.from({ length: Math.min(6, queue.length) }, worker))
  return replaced
}

/** The current address with a cache-busting parameter (path, other params and hash kept). */
export function freshAddress(loc = globalThis.location, now = Date.now()) {
  const u = new URL(loc.href)
  u.searchParams.set(FRESH_PARAM, String(now))
  return `${u.pathname}${u.search}${u.hash}`
}

/** Removes the cache-busting parameter from the address bar (called once at boot). */
export function stripFreshParam(loc = globalThis.location, hist = globalThis.history) {
  try {
    const u = new URL(loc.href)
    if (!u.searchParams.has(FRESH_PARAM)) return
    u.searchParams.delete(FRESH_PARAM)
    hist.replaceState(hist.state, '', `${u.pathname}${u.search}${u.hash}`)
  } catch { /* leave the address as it is */ }
}

/** Replace any poisoned cached assets (bounded), then load the same page fresh. */
export async function freshReload(error = null, { fetchImpl = globalThis.fetch, loc = globalThis.location } = {}) {
  const urls = staleAssetCandidates(error)
  await Promise.race([
    evictPoisonedAssets(urls, fetchImpl),
    new Promise((resolve) => setTimeout(resolve, BUDGET_MS)),
  ])
  loc.replace(freshAddress(loc))
}
