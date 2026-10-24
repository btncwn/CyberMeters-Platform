// Founder live finding (24 Oct 2026, PR-3b): Copy ID has its own space and the
// Scans list History action looks like a button, at 1440 and 390.
import { expect, test } from '@playwright/test'
import { API_BASE, installAppMock, scan, seedSession } from './fixtures/app-mock.js'

const ID_SURFACES = [
  { name: 'Scans list row', path: '/scans', text: (p) => p.locator('tbody .cm-rowlink').first() },
  { name: 'Scan page header', path: '/scans/scan_e2e', text: (p) => p.locator('h1').first().locator('xpath=../following-sibling::p[1]') },
]
for (const width of [1440, 390]) {
  for (const s of ID_SURFACES) {
    test(`${s.name} @${width}: Copy ID has its own space`, async ({ page, context }) => {
      await page.setViewportSize({ width, height: 900 })
      await seedSession(context)
      await installAppMock(page)
      // The all-scans list (GET /scans, no workspace filter); registered last, so it wins.
      await page.route(`${API_BASE}/scans`, (route) => route.fulfill({ contentType: 'application/json', body: JSON.stringify({ scans: [scan] }) }))
      await page.goto(s.path, { waitUntil: 'networkidle' })
      const anchor = s.text(page)
      const copy = page.getByTestId('internal-id-copy').first()
      await expect(copy).toBeVisible()
      const style = await copy.evaluate((el) => { const c = getComputedStyle(el); return { border: c.borderTopWidth, ws: c.whiteSpace } })
      expect(style.border).not.toBe('0px')
      expect(style.ws).toBe('nowrap')
      const b = await copy.boundingBox()
      if (s.name === 'Scans list row') {
        const t = await anchor.boundingBox()
        // Either beside it with a visible gap, or wrapped onto its own line.
        const sameLine = Math.abs(t.y - b.y) < t.height
        if (sameLine) expect(b.x - (t.x + t.width)).toBeGreaterThanOrEqual(6)
        else expect(b.y).toBeGreaterThanOrEqual(t.y + t.height - 1)
        const history = page.getByRole('button', { name: 'History' }).first()
        const hs = await history.evaluate((el) => getComputedStyle(el).borderTopWidth)
        expect(hs).not.toBe('0px')
      } else {
        const textEnd = await anchor.evaluate((p) => { const r = document.createRange(); r.selectNodeContents(p.firstChild); return r.getBoundingClientRect() })
        const sameLine = Math.abs(textEnd.y - b.y) < textEnd.height + 4
        if (sameLine) expect(b.x - textEnd.right).toBeGreaterThanOrEqual(6)
      }
      await page.screenshot({ path: `test-results/copy-id-${s.name.replace(/\W+/g, '-')}-${width}.png` })
    })
  }
}

// The row link's › stays on the domain's last word at 390 (never alone on a line).
test('Scans list row @390: the link arrow never wraps alone', async ({ page, context }) => {
  await page.setViewportSize({ width: 390, height: 900 })
  await seedSession(context)
  await installAppMock(page)
  await page.route(`${API_BASE}/scans`, (route) => route.fulfill({ contentType: 'application/json', body: JSON.stringify({ scans: [scan] }) }))
  await page.goto('/scans', { waitUntil: 'networkidle' })
  const link = page.locator('tbody .cm-rowlink').first()
  await expect(link).toBeVisible()
  // The link's own fragments (including the padding that holds the ›): one line.
  const lines = await link.evaluate((el) => new Set([...el.getClientRects()].map((x) => Math.round(x.top))).size)
  expect(lines).toBe(1)
  // The › is out of the line-breaking and underline flow, and still shown.
  const after = await link.evaluate((el) => { const c = getComputedStyle(el, '::after'); return { content: c.content, position: c.position, decoration: c.textDecorationLine } })
  expect(after).toEqual({ content: '"›"', position: 'absolute', decoration: 'none' })
  // Even a long domain keeps the › on its last line: the link fits the cell.
  await link.hover()
  await page.screenshot({ path: 'test-results/rowlink-arrow-390.png' })
})
