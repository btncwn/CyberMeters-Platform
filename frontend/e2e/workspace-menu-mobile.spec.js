import { expect, test } from '@playwright/test'

test.use({ viewport: { width: 390, height: 844 } })

test('390px workspace menu opens above the icon scroller and switches workspace', async ({ page }) => {
  await page.route('**/api/workspaces', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    headers: { 'access-control-allow-origin': '*' },
    body: JSON.stringify({ workspaces: [
      { id: 'ws-a', name: 'Customer A' },
      { id: 'ws-b', name: 'Customer B' },
    ] }),
  }))
  await page.goto('/e2e/fixtures/rail.html')
  const rail = page.getByRole('navigation', { name: 'Modules' })
  const trigger = page.getByRole('button', { name: 'Workspace: Customer A' })
  await trigger.click()
  const menu = page.getByRole('menu', { name: 'Workspace' })
  await expect(menu).toBeVisible()
  await expect(page.getByRole('menuitem', { name: 'Customer B' })).toBeVisible()

  const layout = await page.evaluate(() => {
    const rail = document.querySelector('.cm-rail')
    const list = document.querySelector('.cm-rail-list')
    const menu = document.getElementById('cm-workspace-menu')
    const box = menu.getBoundingClientRect()
    const hit = document.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2)
    return {
      railOverflow: getComputedStyle(rail).overflowX,
      listOverflow: getComputedStyle(list).overflowX,
      menuTop: box.top,
      railTop: rail.getBoundingClientRect().top,
      hitInsideMenu: menu.contains(hit),
      pageWidth: document.documentElement.scrollWidth,
    }
  })
  expect(layout.railOverflow).toBe('visible')
  expect(layout.listOverflow).toBe('auto')
  expect(layout.menuTop).toBeLessThan(layout.railTop)
  expect(layout.hitInsideMenu).toBe(true)
  expect(layout.pageWidth).toBeLessThanOrEqual(390)

  await page.getByRole('menuitem', { name: 'Customer B' }).click()
  await expect(menu).not.toBeVisible()
  expect(await page.evaluate(() => localStorage.getItem('cybermeters_workspace_id'))).toBe('ws-b')
})
