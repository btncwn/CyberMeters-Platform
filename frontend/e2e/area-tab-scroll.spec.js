// Founder, 25 Oct 2026: on /assets the tabs changed the URL and highlight but the
// page showed the same top content. Picking a tab brings its section into view.
import { expect, test } from '@playwright/test'
import { installAppMock, seedSession } from './fixtures/app-mock.js'

for (const width of [1440, 390]) {
  test(`Attack Surface @${width}: each tab shows its section`, async ({ page, context }) => {
    await page.setViewportSize({ width, height: 800 })
    await seedSession(context)
    await installAppMock(page)
    await page.goto('/assets', { waitUntil: 'networkidle' })
    for (const label of ['Findings', 'Cases', 'Settings', 'Field Guide', 'Summary']) {
      await page.evaluate(() => window.scrollTo(0, 0))
      await page.getByRole('tab', { name: new RegExp(`^${label}`) }).first().click()
      await expect(page.getByRole('tab', { name: new RegExp(`^${label}`) }).first()).toHaveAttribute('aria-selected', 'true')
      // Wait on the panel's position itself (smooth scroll), not a fixed delay.
      await expect.poll(() => page.locator('#module-tabpanel').evaluate((el) => Math.round(el.getBoundingClientRect().top)),
        { message: `${label} panel top`, timeout: 4000 }).toBeLessThan(800 * 0.6)
      if (label === 'Cases') await page.screenshot({ path: `test-results/assets-tab-cases-${width}.png` })
    }
  })
}
