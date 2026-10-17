import { expect, test } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { installAppMock, seedSession, scan, domain } from './fixtures/app-mock.js'

// Readable text everywhere: the axe-core colour-contrast rule (WCAG 2 AA,
// 4.5:1 for text, 3:1 for large text) over every customer route of the
// signed-in app and the auth screens, at 1440 and 390, against the local API
// mock. A violation names the element and the colours, so the fix is exact.

const APP_ROUTES = [
  '/dashboard', '/services', '/onboarding', '/portfolio', '/portfolio/risk', '/portfolio/domains', '/workspaces',
  `/workspaces/${'ws_e2e'}`, '/intelligence', '/scans', '/scans/new', `/scans/${scan.id}`, `/domain/${domain.domain}/history`,
  '/assets', '/exposure', '/reports', '/schedules', '/accuracy', '/settings', '/account', '/account/mcp', '/account/security',
  '/account/privacy', '/billing', '/ws/dashboard', '/ws/scorecard', '/ws/vendors', '/ws/third-party', '/ws/saas-exposure',
  '/ws/shadow-it', '/ws/cloud-assets', '/ws/admin-surfaces', '/ws/certificates', '/ws/certificates/lifecycle',
  '/ws/website-security', '/ws/identity-exposure', '/ws/brand-monitoring', '/ws/identity-assets', '/ws/email-protection',
  '/ws/reports', '/ws/executive-dashboard', '/ws/business-risk', '/ws/cyber-essentials', '/ws/supply-chain', '/ws/audit-log',
  '/ws/members', '/ws/cases', '/ws/cases/case_1', '/ws/related-changes', '/ws/alerts', '/ws/retention', '/guide', '/academy',
  '/notifications',
]
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
      test.setTimeout(240_000)
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
