import { expect, test } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { installAppMock, seedSession } from './fixtures/app-mock.js'
import { APP_ROUTES } from './fixtures/app-routes.js'

// Readable text everywhere: the axe-core colour-contrast rule (WCAG 2 AA,
// 4.5:1 for text, 3:1 for large text) over every customer route of the
// signed-in app and the auth screens, at 1440 and 390, against the local API
// mock. A violation names the element and the colours, so the fix is exact.

const AUTH_ROUTES = ['/login', '/signup', '/forgot-password', '/invitations/token_e2e']

const VIEWPORTS = [
  { name: '1440', width: 1440, height: 900 },
  { name: '390', width: 390, height: 844 },
]

async function contrastViolations(page) {
  const results = await new AxeBuilder({ page }).withRules(['color-contrast']).analyze()
  return results.violations.flatMap((v) => v.nodes.map((n) => ({
    target: n.target.join(' '),
    summary: n.failureSummary?.split('\n').slice(1).join(' ').trim(),
    html: n.html.slice(0, 160),
  })))
}

for (const vp of VIEWPORTS) {
  test.describe(`colour contrast at ${vp.name}`, () => {
    test.use({ viewport: { width: vp.width, height: vp.height }, reducedMotion: 'reduce' })

    test(`signed-in routes read at ${vp.name}`, async ({ page, context }) => {
      // ~55 routes in one test; it shares workers with the area-page pass (PR-C), so the
      // budget allows for contention. Only the time limit changed — every route and rule stays.
      test.setTimeout(480_000)
      await seedSession(context)
      await installAppMock(page)
      const failures = []
      for (const route of APP_ROUTES) {
        await page.goto(route, { waitUntil: 'networkidle' })
        await page.waitForTimeout(250)
        const violations = await contrastViolations(page)
        for (const v of violations) failures.push({ route, ...v })
      }
      expect(failures, JSON.stringify(failures, null, 2)).toEqual([])
    })

    test(`auth routes read at ${vp.name}`, async ({ page }) => {
      await page.route('**/api/**', (route) => route.fulfill({ status: 404, contentType: 'application/json', body: '{"error":"Not available in this check."}' }))
      const failures = []
      for (const route of AUTH_ROUTES) {
        await page.goto(route, { waitUntil: 'networkidle' })
        await page.waitForTimeout(250)
        const violations = await contrastViolations(page)
        for (const v of violations) failures.push({ route, ...v })
      }
      expect(failures, JSON.stringify(failures, null, 2)).toEqual([])
    })
  })
}
