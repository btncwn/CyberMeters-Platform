// Founder P1 (23 Oct 2026): "this is not a game of finding the button". A
// navigable title in a list is visibly a link AT REST — link colour and a
// trailing › — distinct from plain heading text (Codex C-45 N01–N24).
import { expect, test } from '@playwright/test'
import { API_BASE, installAppMock, scan, seedSession } from './fixtures/app-mock.js'

async function restingStyle(locator) {
  return locator.evaluate((el) => {
    const s = getComputedStyle(el)
    return { color: s.color, after: getComputedStyle(el, '::after').content, cursor: s.cursor }
  })
}
async function headingColor(page) {
  return page.locator('h1').first().evaluate((el) => getComputedStyle(el).color)
}

const SURFACES = [
  { name: 'Overview area cards', path: '/dashboard', link: (p) => p.locator('.cm-rowlink').first() },
  { name: 'Operations case titles', path: '/ws/cases', link: (p) => p.getByTestId('case-row').first().locator('.cm-rowlink') },
  { name: 'Area Cases tab', path: '/ws/website-security?tab=cases', link: (p) => p.locator('.cm-rowlink').first() },
]

for (const s of SURFACES) {
  test(`${s.name}: the navigable title looks like a link at rest`, async ({ page, context }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await seedSession(context)
    await installAppMock(page)
    await page.goto(s.path, { waitUntil: 'networkidle' })
    const link = s.link(page)
    await expect(link).toBeVisible()
    const style = await restingStyle(link)
    expect(style.color, 'link colour, not heading ink').toBe('rgb(17, 115, 98)')
    expect(style.color).not.toBe(await headingColor(page))
    expect(style.after, 'a resting › cue').toContain('›')
    expect(style.cursor).toBe('pointer')
  })
}

// Founder live finding (24 Oct 2026): "blackbullbarbers.co.ukCopy ID". Copy ID is a
// separate small button that never touches the text beside it, at 1440 and 390;
// History in the Scans list looks like a button.
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
