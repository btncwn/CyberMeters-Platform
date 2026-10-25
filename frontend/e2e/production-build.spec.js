// P1 outage guard (23 Oct 2026). The dev server the other specs use has no
// hashed chunks and no Pages rules, so it cannot see a broken production
// bundle or the asset-caching outage. This builds the real production bundle,
// serves it the way Pages does (public/_worker.js on /assets/* per
// _routes.json, the SPA fallback elsewhere), and checks:
//   • /, /dashboard and /landing boot to the app (no "new version" card, no uncaught error);
//   • a missing /assets/* file is 404 + no-store — never index.html, never cacheable;
//   • a real asset keeps its long immutable cache.
import { test, expect } from '@playwright/test'
import http from 'node:http'
import { execFileSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { extname, join, normalize } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = fileURLToPath(new URL('..', import.meta.url))
const TYPES = { '.js': 'application/javascript', '.css': 'text/css; charset=utf-8', '.html': 'text/html; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.txt': 'text/plain; charset=utf-8' }

let out, server, base, worker

// Pages' static answer: the file if it exists, else the SPA fallback (index.html,
// 200). /assets/* carries the immutable rule from _headers — exactly the
// combination that poisoned caches before the worker existed.
function staticAnswer(pathname) {
  const file = normalize(join(out, decodeURIComponent(pathname)))
  const found = file.startsWith(out) && existsSync(file) && statSync(file).isFile() && !/\/_(worker\.js|routes\.json|headers|redirects)$/.test(file)
  const body = readFileSync(found ? file : join(out, 'index.html'))
  const type = found ? (TYPES[extname(file)] || 'application/octet-stream') : TYPES['.html']
  const cache = pathname.startsWith('/assets/') ? 'public, max-age=31536000, immutable' : 'no-cache, no-store, must-revalidate'
  return new Response(body, { status: 200, headers: { 'content-type': type, 'cache-control': cache } })
}

test.beforeAll(async () => {
  test.setTimeout(240_000)
  out = mkdtempSync(join(tmpdir(), 'cm-prod-build-'))
  execFileSync('npx', ['vite', 'build', '--outDir', out, '--emptyOutDir', '--logLevel', 'error'], {
    cwd: ROOT, stdio: 'inherit', env: { ...process.env, VITE_API_BASE_URL: 'http://127.0.0.1:8787/api' },
  })
  const routes = JSON.parse(readFileSync(join(out, '_routes.json'), 'utf8'))
  expect(routes.include).toEqual(['/assets/*'])
  // Imported from its text so it is always parsed as the ES module Pages runs.
  const src = readFileSync(join(out, '_worker.js'), 'utf8')
  worker = (await import(`data:text/javascript;base64,${Buffer.from(src).toString('base64')}`)).default
  server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://local')
    // Pages' /assets/* pattern also includes its bare parent application route.
    const answer = url.pathname === '/assets' || url.pathname.startsWith('/assets/')
      ? await worker.fetch(new Request(url), { ASSETS: { fetch: async (r) => staticAnswer(new URL(r.url).pathname) } })
      : staticAnswer(url.pathname)
    res.writeHead(answer.status, Object.fromEntries(answer.headers))
    res.end(Buffer.from(await answer.arrayBuffer()))
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  base = `http://127.0.0.1:${server.address().port}`
})

test.afterAll(async () => {
  if (server) await new Promise((r) => server.close(r))
  if (out) rmSync(out, { recursive: true, force: true })
})

test('a missing /assets/* file is 404 + no-store; a real asset stays immutable', async ({ request }) => {
  for (const p of ['/assets/does-not-exist-abc123.js', '/assets/nested/missing.css']) {
    const r = await request.get(base + p)
    expect(r.status(), p).toBe(404)
    expect(r.headers()['cache-control'], p).toBe('no-store')
    expect(r.headers()['content-type'], p).not.toMatch(/html/)
  }
  const html = await (await request.get(base + '/')).text()
  const entry = html.match(/\/assets\/index-[^"]+\.js/)?.[0]
  expect(entry).toBeTruthy()
  const real = await request.get(base + entry)
  expect(real.status()).toBe(200)
  expect(real.headers()['cache-control']).toBe('public, max-age=31536000, immutable')
  expect(real.headers()['content-type']).toMatch(/javascript/)
})

// On a non-production host / and /dashboard go to sign-in; /landing is the public site.
for (const path of ['/', '/dashboard', '/landing', '/assets', '/assets/', '/assets?tab=settings']) {
  test(`the production build boots on ${path} (no "new version" card, no uncaught error)`, async ({ page }) => {
    const errors = []
    const htmlAssets = []
    page.on('pageerror', (e) => errors.push(String(e.message)))
    page.on('response', (r) => {
      if (/\/assets\/.*\.(js|css)$/.test(r.url()) && (/html/.test(r.headers()['content-type'] || '') || r.status() >= 400)) htmlAssets.push(r.url())
    })
    // Signed out: the API answers 401.
    await page.route('http://127.0.0.1:8787/**', (route) => route.fulfill({ status: 401, contentType: 'application/json', body: '{"error":"unauthorized"}' }))
    await page.goto(base + path)
    if (path === '/landing') await expect(page.getByRole('link', { name: /run a free check/i }).first()).toBeVisible()
    else await expect(page.getByRole('heading', { level: 1, name: 'Sign in' })).toBeVisible()
    await expect(page.getByText(/We've just updated CyberMeters|A new version of CyberMeters|Something went wrong/)).toHaveCount(0)
    expect(errors).toEqual([])
    expect(htmlAssets).toEqual([])
  })
}

// Codex C-42: a fresh reload's ?_fresh= leaves the address bar even when the app
// then fails to boot (public/strip-fresh.js runs before any module).
test('?_fresh= is stripped even when the entry bundle fails to load', async ({ page }) => {
  await page.route(/\/assets\/index-[^/]+\.js$/, (route) => route.abort())
  await page.goto(`${base}/ws/certificates?tab=findings&_fresh=123#cert-caa`)
  await expect.poll(() => page.url()).not.toContain('_fresh')
  const u = new URL(page.url())
  expect(u.pathname).toBe('/ws/certificates')
  expect(u.searchParams.get('tab')).toBe('findings')
  expect(u.hash).toBe('#cert-caa')
})

// Founder, 23 Oct 2026: every public and app page — the free tools included —
// shows the brand favicon. All generated pages copy index.html's head, so each
// must link exactly the brand icons.
test('every generated page links the brand favicon (tools included)', async () => {
  const { readdirSync } = await import('node:fs')
  const pages = ['index.html', ...readdirSync(out).filter((f) => f.endsWith('.html') && f !== 'index.html'), ...readdirSync(join(out, 'tools')).map((f) => `tools/${f}`)]
  expect(pages.some((p) => p.startsWith('tools/'))).toBe(true)
  for (const page of pages) {
    const icons = readFileSync(join(out, page), 'utf8').match(/<link rel="icon"[^>]*>/g) || []
    expect(icons, page).toEqual(['<link rel="icon" href="/favicon.ico?v=20261021" sizes="32x32" />', '<link rel="icon" type="image/svg+xml" href="/favicon.svg?v=20261021" />'])
  }
})
