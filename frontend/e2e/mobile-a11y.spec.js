import { expect, test } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { installAppMock, seedSession } from './fixtures/app-mock.js'
import { APP_ROUTES } from './fixtures/app-routes.js'

// Closing queue 4 (founder, 21 Oct 2026): every signed-in page at a phone's
// width (390px) passes the axe WCAG 2.0/2.1 A + AA rules with no critical or
// serious violation, and never scrolls sideways. A failure names the route,
// the rule and the element, so the fix is exact. Colour contrast has its own
// pass (contrast.spec.js) at both widths.

const BLOCKING = new Set(['critical', 'serious'])

test.use({ viewport: { width: 390, height: 844 }, reducedMotion: 'reduce' })

test('every signed-in page works at 390px: no blocking axe violation, no sideways scroll', async ({ page, context }) => {
  test.setTimeout(600_000)
  await seedSession(context)
  await installAppMock(page)
  const failures = []
  for (const route of APP_ROUTES) {
    await page.goto(route, { waitUntil: 'networkidle' })
    await page.waitForTimeout(250)
    const results = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
      .disableRules(['color-contrast'])
      .analyze()
    for (const v of results.violations.filter((x) => BLOCKING.has(x.impact))) {
      for (const n of v.nodes) failures.push({ route, rule: v.id, impact: v.impact, target: n.target.join(' '), html: n.html.slice(0, 140) })
    }
    const overflow = await page.evaluate(() => {
      const width = document.documentElement.clientWidth
      return document.documentElement.scrollWidth > width + 1 ? document.documentElement.scrollWidth : null
    })
    if (overflow) failures.push({ route, rule: 'horizontal-overflow', impact: 'serious', target: `scrollWidth ${overflow} > 390` })
  }
  expect(failures, JSON.stringify(failures, null, 2)).toEqual([])
})
