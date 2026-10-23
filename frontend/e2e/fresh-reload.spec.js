// S1-RELOAD (founder, 23 Oct 2026): after a Pages deploy the "Reload page"
// button did nothing. The Pages fallback answers a missing /assets/* file with
// index.html (200, text/html) and the /assets/* rule makes it `immutable`, so a
// chunk requested mid-deploy is cached as HTML for a year and location.reload()
// reads it back forever. This reproduces that with the REAL browser cache (no
// page.route: routing disables the HTTP cache) and the real lib/freshReload.js.
import { test, expect } from '@playwright/test'
import http from 'node:http'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const FRESH = readFileSync(fileURLToPath(new URL('../src/lib/freshReload.js', import.meta.url)), 'utf8')
const INDEX = `<!doctype html><html><head><meta charset="utf-8"><title>t</title></head><body data-state="loading">
<button id="plain" onclick="location.reload()">plain reload</button>
<button id="fresh">fresh reload</button>
<script type="module">
  import { freshReload } from '/lib/freshReload.js'
  try {
    const m = await import('/assets/Page-abc123.js')
    document.body.dataset.state = m.ok ? 'ok' : 'bad'
  } catch (e) {
    document.body.dataset.state = 'failed'
    document.getElementById('fresh').onclick = () => freshReload(e)
  }
</script></body></html>`

let deployed = false
let server
let base

test.beforeAll(async () => {
  server = http.createServer((req, res) => {
    const path = new URL(req.url, 'http://x').pathname
    if (path === '/lib/freshReload.js') {
      res.writeHead(200, { 'content-type': 'text/javascript', 'cache-control': 'no-cache' }); res.end(FRESH); return
    }
    if (path.startsWith('/assets/')) {
      // Exactly the production answer: the real file once deployed, else the SPA fallback — both immutable.
      if (deployed && path === '/assets/Page-abc123.js') {
        res.writeHead(200, { 'content-type': 'text/javascript', 'cache-control': 'public, max-age=31536000, immutable' }); res.end('export const ok = true'); return
      }
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'public, max-age=31536000, immutable' }); res.end(INDEX); return
    }
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-cache, no-store, must-revalidate' }); res.end(INDEX)
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  base = `http://127.0.0.1:${server.address().port}`
})
test.afterAll(async () => { await new Promise((r) => server.close(r)) })

test('a chunk cached as HTML mid-deploy: plain reload stays broken, one fresh reload recovers', async ({ page }) => {
  deployed = false
  await page.goto(`${base}/ws/certificates?tab=findings#cert-caa`)
  await expect(page.locator('body')).toHaveAttribute('data-state', 'failed')

  // The deploy finishes. A plain reload reads the poisoned chunk from the cache: still broken (the founder's loop).
  deployed = true
  await page.click('#plain')
  await expect(page.locator('body')).toHaveAttribute('data-state', 'failed')

  // One click on the fresh reload: the poisoned entry is replaced and the page opens, same path, params and hash.
  await page.click('#fresh')
  await expect(page.locator('body')).toHaveAttribute('data-state', 'ok')
  const u = new URL(page.url())
  expect(u.pathname).toBe('/ws/certificates')
  expect(u.searchParams.get('tab')).toBe('findings')
  expect(u.hash).toBe('#cert-caa')
})
