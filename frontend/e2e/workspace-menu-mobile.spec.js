import { expect, test } from '@playwright/test'

test.use({ viewport: { width: 390, height: 844 } })

// The 72px workspace card deck sits in the bottom-left dock on a phone; its
// popover opens above it, is hit-testable, never widens the page, and switching
// writes the workspace the rest of the app reads.
test('390px workspace deck opens its menu above the card and switches workspace', async ({ page }) => {
  await page.route('**/api/workspaces', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    headers: { 'access-control-allow-origin': '*' },
    body: JSON.stringify({ workspaces: [
      { id: 'ws-a', name: 'Customer A' },
      { id: 'ws-b', name: 'Customer B' },
    ] }),
  }))
  await page.goto('/e2e/fixtures/workspace-dock.html')
  const trigger = page.getByRole('button', { name: 'Workspace: Customer A' })
  await expect(trigger).toBeVisible()
  await trigger.click()
  const menu = page.getByRole('menu', { name: 'Workspace' })
  await expect(menu).toBeVisible()
  await expect(page.getByRole('menuitem', { name: 'Customer B' })).toBeVisible()

  const layout = await page.evaluate(() => {
    const card = document.querySelector('.cm-wsbtn')
    const menu = document.getElementById('cm-workspace-menu')
    const box = menu.getBoundingClientRect()
    const cardBox = card.getBoundingClientRect()
    const hit = document.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2)
    return {
      cardWidth: cardBox.width,
      cardHeight: cardBox.height,
      menuBottom: box.bottom,
      cardTop: cardBox.top,
      hitInsideMenu: menu.contains(hit),
      pageWidth: document.documentElement.scrollWidth,
      cardOnScreen: cardBox.bottom <= window.innerHeight && cardBox.left >= 0,
    }
  })
  expect(layout.cardWidth).toBe(72)
  expect(layout.cardHeight).toBe(72)
  expect(layout.cardOnScreen).toBe(true)
  expect(layout.menuBottom).toBeLessThanOrEqual(layout.cardTop)
  expect(layout.hitInsideMenu).toBe(true)
  expect(layout.pageWidth).toBeLessThanOrEqual(390)

  await page.getByRole('menuitem', { name: 'Customer B' }).click()
  await expect(menu).not.toBeVisible()
  expect(await page.evaluate(() => localStorage.getItem('cybermeters_workspace_id'))).toBe('ws-b')
})
