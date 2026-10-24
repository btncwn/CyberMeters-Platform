// Founder P1 (23 Oct 2026): "this is not a game of finding the button". A
// navigable title in a list is visibly a link AT REST — link colour and a
// trailing › — distinct from plain heading text (Codex C-45 N01–N24).
import { expect, test } from '@playwright/test'
import { installAppMock, seedSession } from './fixtures/app-mock.js'

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
