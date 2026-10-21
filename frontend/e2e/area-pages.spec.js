import { test, expect } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { installAppMock, seedSession } from './fixtures/app-mock.js'
import { findRawKeys } from '../src/lib/rawKeys.js'

// PR-C acceptance (founder, 18 Oct 2026): every area page renders the one
// template — "What we observed" (≤ 4 figures), ONE "Do this next" button, the
// three counts, the five tabs and scope & limits — passes axe (WCAG 2 A/AA)
// at 1440 and 390, and shows no raw internal key anywhere in the page.

const AREA_PAGES = [
  ['/ws/email-protection', 'Email Protection'],
  ['/assets', 'Attack Surface'],
  ['/ws/website-security', 'Website Security'],
  ['/ws/identity-exposure', 'Identity Exposure'],
  ['/ws/shadow-it', 'Shadow IT & Unmanaged Technology'],
  ['/ws/certificates', 'Certificates & Trust'],
  ['/ws/brand-monitoring', 'Brand Protection'],
  ['/ws/cyber-essentials', 'Cyber Essentials Readiness'],
]

for (const [width, height] of [[1440, 900], [390, 844]]) {
  test.describe(`area pages at ${width}`, () => {
    test.use({ viewport: { width, height } })
    test.beforeEach(async ({ page, context }) => {
      await seedSession(context)
      await installAppMock(page)
    })

    for (const [route, title] of AREA_PAGES) {
      test(`${title} renders the template, passes axe and shows no raw key`, async ({ page }) => {
        await page.goto(route)
        await expect(page.getByRole('heading', { level: 1, name: title })).toBeVisible()
        await expect(page.getByTestId('module-observed')).toBeVisible()
        await expect(page.getByTestId('module-next')).toBeVisible()
        await page.waitForLoadState('networkidle')
        // One card, one button.
        const nextButtons = page.getByTestId('module-next').locator('a, button')
        expect(await nextButtons.count()).toBeLessThanOrEqual(1)
        expect(await page.getByTestId('module-figure').count()).toBeLessThanOrEqual(4)
        await expect(page.getByTestId('module-counts').getByRole('button')).toHaveCount(3)
        await expect(page.getByRole('tab')).toHaveText(['Summary', 'Findings', 'Cases', 'Settings', 'Field Guide'])
        await expect(page.getByTestId('module-scope')).toBeVisible()

        const text = await page.locator('main').innerText()
        expect(findRawKeys(text), `raw internal keys on ${route}`).toEqual([])

        const results = await new AxeBuilder({ page }).include('main').withTags(['wcag2a', 'wcag2aa']).analyze()
        expect(results.violations.map((v) => ({ id: v.id, nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 3) })), `axe on ${route}`).toEqual([])
      })
    }

    test('Shadow IT Overview lists the first five unclassified items, each with its own Reject', async ({ page }) => {
      await page.goto('/ws/shadow-it')
      const list = page.getByTestId('shadow-it-unclassified')
      await expect(list.getByTestId('shadow-it-unclassified-item')).toHaveCount(5)
      await expect(list.getByRole('button', { name: 'Classify all 6 items' })).toBeVisible()
      await expect(list.getByRole('button', { name: 'Reject Mailchimp' })).toBeVisible()
      await expect(page.getByTestId('module-next-title')).toHaveText('6 items not yet classified')
    })

    test('Identity Exposure has a real empty state with one button', async ({ page }) => {
      await page.goto('/ws/identity-exposure')
      await expect(page.getByTestId('identity-empty')).toContainText('This page fills after a scan')
      // "Run a scan" starts the scan in place rather than linking away (21 Oct 2026).
      await expect(page.getByTestId('module-next-action-scan').getByRole('button', { name: 'Run a scan' })).toBeVisible()
    })

    test('Cyber Essentials: "Start questionnaire" is the next action until complete', async ({ page }) => {
      await page.goto('/ws/cyber-essentials')
      await expect(page.getByTestId('module-next-action')).toHaveText('Start questionnaire')
      await expect(page.getByTestId('module-next')).toContainText('0 of 2 questions answered')
    })
  })
}
