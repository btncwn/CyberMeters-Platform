import { expect, test } from '@playwright/test'
import { installAppMock, seedSession } from './fixtures/app-mock.js'
import { APP_ROUTES } from './fixtures/app-routes.js'
import { expectNoRawKeys, expectOnePrimaryAction } from './fixtures/design-guards.js'

// S1-SHELL-V2 (founder-approved design, 22 Oct 2026) on every signed-in route:
//   ≥1024px the sidebar with the eight areas; below, a menu button that opens
//   them in a drawer · exactly one tab strip (on an area route; none elsewhere)
//   · no raw keys · nothing overlapping (sidebar vs page vs top-bar rows) · one
//   primary action · no sideways page scroll.

const AREAS = [
  'Email Protection', 'Attack Surface', 'Website Security', 'Identity Exposure',
  'Shadow IT & Unmanaged Technology', 'Certificates & Trust', 'Brand Protection', 'Cyber Essentials Readiness',
]
const AREA_ROUTE = /^\/(ws\/(email-protection|website-security|certificates|identity-exposure|identity-assets|shadow-it|saas-exposure|third-parties|brand-monitoring|cyber-essentials|admin-surfaces|cloud-assets)|assets|exposure|scans|schedules|intelligence)/

const overlap = (a, b) => a && b && Math.min(a.right, b.right) - Math.max(a.left, b.left) > 1 && Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top) > 1

async function areaNames(scope) {
  return scope.locator('.cm-side-name').allInnerTexts()
}

for (const [width, height] of [[1440, 900], [1024, 800], [768, 1000], [390, 844]]) {
  test(`app shell at ${width}: sidebar or drawer, one tab strip, eight areas, no raw keys, no overlap`, async ({ page, context }) => {
    test.setTimeout(900_000)
    await page.setViewportSize({ width, height })
    await seedSession(context)
    await installAppMock(page)
    const wide = width >= 1024
    const failures = []
    for (const route of APP_ROUTES) {
      await page.goto(route, { waitUntil: 'networkidle' })
      await page.waitForTimeout(150)
      const where = `${route} @${width}`
      try {
        if (wide) {
          const side = page.getByRole('navigation', { name: 'Security areas' })
          await expect(side, where).toBeVisible()
          expect(await areaNames(side), where).toEqual(AREAS)
          await expect(page.getByRole('button', { name: 'Open areas menu' }), where).toHaveCount(0)
        } else {
          await expect(page.getByRole('navigation', { name: 'Security areas' }), where).toHaveCount(0)
          await expect(page.getByRole('button', { name: 'Open areas menu' }), where).toBeVisible()
        }
        // Exactly one tab strip on an area route; none elsewhere (pages may own other tab widgets, never area tabs).
        const areaTabs = await page.locator('[role="tablist"][aria-label="Area sections"], [data-testid="area-row"] nav').count()
        if (AREA_ROUTE.test(route)) expect(areaTabs, `${where}: area tab strips`).toBe(1)
        else expect(areaTabs, `${where}: area tab strips`).toBe(0)
        await expect(page.locator('[data-testid="area-row"]'), where).toHaveCount(AREA_ROUTE.test(route) ? 1 : 0)
        await expectNoRawKeys(page)
        await expectNoRawKeys(page, 'header.cm-top')
        await expectOnePrimaryAction(page)
        const boxes = await page.evaluate(() => {
          const box = (sel) => { const el = document.querySelector(sel); if (!el) return null; const r = el.getBoundingClientRect(); return { left: r.left, right: r.right, top: r.top, bottom: r.bottom } }
          return { side: box('.cm-sidebar'), main: box('#main'), row1: box('.cm-top-inner'), row2: box('[data-testid="area-row"]'), scroll: document.documentElement.scrollWidth - document.documentElement.clientWidth }
        })
        expect(overlap(boxes.side, boxes.main), `${where}: sidebar over the page`).toBeFalsy()
        expect(overlap(boxes.row1, boxes.row2), `${where}: top-bar rows overlap`).toBeFalsy()
        expect(boxes.scroll, `${where}: sideways page scroll`).toBeLessThanOrEqual(1)
        if (!wide) {
          await page.getByRole('button', { name: 'Open areas menu' }).click()
          const drawer = page.getByRole('dialog', { name: 'Areas' })
          await expect(drawer, where).toBeVisible()
          expect(await areaNames(drawer), where).toEqual(AREAS)
          await page.keyboard.press('Escape')
          await expect(drawer, where).toHaveCount(0)
        }
      } catch (error) {
        failures.push(`${where}: ${String(error.message).split('\n')[0]}`)
      }
    }
    expect(failures, failures.join('\n')).toEqual([])
  })
}

test('the selected area expands and its sub-topic opens its section; the logo goes to Overview', async ({ page, context }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await seedSession(context)
  await installAppMock(page)
  await page.goto('/dashboard')
  const side = page.getByRole('navigation', { name: 'Security areas' })
  await side.getByRole('button', { name: /Email Protection/ }).click()
  await expect(page).toHaveURL(/\/ws\/email-protection$/)
  await expect(side.getByRole('button', { expanded: true })).toHaveCount(1)
  await side.getByRole('link', { name: 'SPF' }).click()
  await expect(page).toHaveURL(/\/ws\/email-protection#auth-spf$/)
  await expect(page.getByRole('tab', { name: 'Findings', selected: true })).toBeVisible()
  await side.getByRole('link', { name: 'CyberMeters — Overview' }).click()
  await expect(page).toHaveURL(/\/dashboard$/)
})
