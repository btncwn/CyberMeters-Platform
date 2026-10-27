import { expect, test } from '@playwright/test'
import { API_BASE, installAppMock, seedSession, workspace } from './fixtures/app-mock.js'

// Below 1024px the real shell shows the 36px workspace card in the top bar
// (P2, 27 Oct 2026): a card fixed to the screen corner covered page content
// and controls as they scrolled past. Nothing floats over the page; the menu
// opens below the card, switching works, and Escape / an outside click close
// it. From 1024px the floating deck card is unchanged.
const A = { id: workspace.id, name: 'Example Workspace A', role: 'owner', created_at: workspace.created_at }
const B = { id: 'ws_example_b', name: 'Example Workspace B', role: 'owner', created_at: workspace.created_at }

async function open(page, context, width, height) {
  await page.setViewportSize({ width, height })
  await seedSession(context)
  await context.addInitScript((name) => localStorage.setItem('cybermeters_workspace_name', name), A.name)
  await installAppMock(page)
  await page.route(`${API_BASE}/workspaces`, (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ workspaces: [A, B] }) }))
  await page.route(`${API_BASE}/workspaces/${B.id}/domains`, (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ domains: [] }) }))
  await page.goto('/dashboard', { waitUntil: 'networkidle' })
}

// Every visible fixed-position box that intersects the content column.
const fixedOverContent = (page) => page.evaluate(() => {
  const main = document.getElementById('main').getBoundingClientRect()
  const view = { top: 0, left: 0, bottom: window.innerHeight, right: window.innerWidth }
  return [...document.querySelectorAll('body *')].filter((el) => {
    if (getComputedStyle(el).position !== 'fixed') return false
    const r = el.getBoundingClientRect()
    if (r.width < 2 || r.height < 2) return false
    const onScreen = r.right > view.left && r.left < view.right && r.bottom > view.top && r.top < view.bottom
    const overMain = r.right > main.left && r.left < main.right && r.bottom > Math.max(main.top, 0) && r.top < Math.min(main.bottom, view.bottom)
    return onScreen && overMain
  }).map((el) => el.className || el.tagName)
})

for (const [width, height] of [[390, 844], [768, 1024]]) {
  test(`${width}px: the workspace card is in the top bar, nothing floats over the page, and it switches workspace`, async ({ page, context }) => {
    await open(page, context, width, height)
    await expect(page.getByTestId('workspace-dock')).toHaveCount(0)
    const trigger = page.locator('header.cm-top').getByRole('button', { name: `Workspace: ${A.name}` })
    await expect(trigger).toBeVisible()
    const box = await trigger.boundingBox()
    expect([Math.round(box.width), Math.round(box.height)]).toEqual([36, 36])
    for (const at of ['top', 'middle', 'bottom']) {
      await page.evaluate((at) => window.scrollTo(0, at === 'top' ? 0 : at === 'middle' ? document.documentElement.scrollHeight / 2 : document.documentElement.scrollHeight), at)
      expect(await fixedOverContent(page), `fixed boxes over content @${width} ${at}`).toEqual([])
    }
    await page.evaluate(() => window.scrollTo(0, 0))

    // Escape closes and returns focus to the card.
    await trigger.click()
    const menu = page.getByRole('menu', { name: 'Workspace' })
    await expect(menu).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(menu).toBeHidden()
    await expect(trigger).toBeFocused()
    // An outside click closes it.
    await trigger.click()
    await expect(menu).toBeVisible()
    await page.mouse.click(Math.round(width / 2), Math.round(height - 40))
    await expect(menu).toBeHidden()

    await trigger.click()
    await expect(page.getByRole('menuitem', { name: B.name })).toBeVisible()
    const layout = await page.evaluate(() => {
      const card = document.querySelector('header .cm-wsmini').getBoundingClientRect()
      const menu = document.getElementById('cm-workspace-menu')
      const r = menu.getBoundingClientRect()
      return { menuTop: r.top, cardBottom: card.bottom, menuLeft: r.left, menuRight: r.right,
        hitInsideMenu: menu.contains(document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2)),
        pageWidth: document.documentElement.scrollWidth }
    })
    expect(layout.menuTop).toBeGreaterThanOrEqual(layout.cardBottom)
    expect(layout.menuLeft).toBeGreaterThanOrEqual(0)
    expect(layout.menuRight).toBeLessThanOrEqual(width)
    expect(layout.hitInsideMenu).toBe(true)
    expect(layout.pageWidth).toBeLessThanOrEqual(width)
    await page.getByRole('menuitem', { name: B.name }).click()
    await expect(menu).toBeHidden()
    expect(await page.evaluate(() => localStorage.getItem('cybermeters_workspace_id'))).toBe(B.id)
    // The areas menu and the account menu stay reachable beside it.
    await expect(page.getByTestId('areas-menu-button')).toBeVisible()
    await expect(page.locator('header.cm-top .cm-avatar')).toBeVisible()
    if (process.env.CM_SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.CM_SCREENSHOT_DIR}/workspace-header-${width}.png` })
  })
}

for (const [width, height] of [[1024, 768], [1440, 900]]) {
  test(`${width}px: the floating workspace deck is unchanged and opens the same menu`, async ({ page, context }) => {
    await open(page, context, width, height)
    await expect(page.getByTestId('workspace-header-slot')).toHaveCount(0)
    const dock = page.getByTestId('workspace-dock')
    await expect(dock).toHaveClass(/cm-wsfloat-wide/)
    const card = dock.getByRole('button', { name: `Workspace: ${A.name}` })
    await expect(card).toHaveClass(/cm-wsbtn/)
    await card.click()
    await expect(page.getByRole('menuitem', { name: B.name })).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(card).toBeFocused()
    if (process.env.CM_SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.CM_SCREENSHOT_DIR}/workspace-deck-${width}.png` })
  })
}
