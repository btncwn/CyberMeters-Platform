import { expect, test } from '@playwright/test'
import { API_BASE, installAppMock, seedSession, workspace } from './fixtures/app-mock.js'
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

// C-38 S30: what the first version of this suite missed.
test('44px globe and account initial; the WORKSPACE card label at 1440 and 390; no primary in row 2', async ({ page, context }) => {
  await seedSession(context)
  await installAppMock(page)
  for (const [width, height] of [[1440, 900], [390, 844]]) {
    await page.setViewportSize({ width, height })
    await page.goto('/ws/email-protection', { waitUntil: 'networkidle' })
    const globe = await page.locator('header.cm-top .cm-earthbtn').boundingBox()
    expect(Math.round(globe.width), `globe @${width}`).toBe(44)
    expect(Math.round(globe.height), `globe @${width}`).toBe(44)
    const avatar = await page.locator('header.cm-top .cm-avatar').boundingBox()
    expect(Math.round(avatar.width), `initial @${width}`).toBe(44)
    if (width >= 1024) {
      const dock = page.getByTestId('workspace-dock')
      await expect(dock.getByText('Workspace', { exact: true }), `card label @${width}`).toBeVisible()
      expect(await dock.locator('.cm-wsbtn').evaluate((el) => el.closest('.cm-sidebar')), `card outside the sidebar @${width}`).toBeNull()
    } else {
      // Below 1024px the 36px card is in the top bar and nothing floats (P2, 27 Oct 2026).
      await expect(page.getByTestId('workspace-dock'), `no floating card @${width}`).toHaveCount(0)
      await expect(page.locator('header.cm-top .cm-wsmini'), `top-bar card @${width}`).toBeVisible()
    }
    await expect(page.locator('[data-testid="area-row"] .btn-primary'), `row 2 primary @${width}`).toHaveCount(0)
  }
})

test('every sub-topic opens its named section, fully below the sticky header', async ({ page, context }) => {
  test.setTimeout(600_000)
  await page.setViewportSize({ width: 1440, height: 900 })
  await seedSession(context)
  await installAppMock(page)
  await page.goto('/dashboard', { waitUntil: 'networkidle' })
  const side = page.getByRole('navigation', { name: 'Security areas' })
  const failures = []
  for (const area of AREAS) {
    await side.getByRole('button', { name: new RegExp(area.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) }).click()
    const links = side.getByRole('list', { name: `${area} topics` }).getByRole('link')
    const count = await links.count()
    if (!count) failures.push(`${area}: no sub-topics`)
    for (let i = 0; i < count; i++) {
      const link = side.getByRole('list', { name: `${area} topics` }).getByRole('link').nth(i)
      const [label, href] = [await link.innerText(), await link.getAttribute('href')]
      await link.click()
      await page.waitForLoadState('networkidle')
      const hash = href.includes('#') ? href.slice(href.indexOf('#')) : null
      try {
        await expect(page, `${area} › ${label}`).toHaveURL(new RegExp(href.split('#')[0].replace(/[?]/g, '\\?') + '(#|$)'))
        if (hash) {
          const target = page.locator(hash)
          await expect(target, `${area} › ${label}: ${hash} exists`).toHaveCount(1)
          // Content and row-2 tools may still load and shift the page; the page re-settles its
          // scroll, so poll until the target rests below the sticky header.
          const clearance = async () => {
            const box = await target.boundingBox()
            const header = await page.locator('header.cm-top').boundingBox()
            return box ? Math.round(box.y - (header.y + header.height)) : -9999
          }
          await expect.poll(clearance, { message: `${area} › ${label}: ${hash} below the sticky header`, timeout: 4000 }).toBeGreaterThanOrEqual(-1)
        }
      } catch (error) { failures.push(String(error.message).split('\n')[0]) }
      // Back to the area's own row for the next topic.
      if (!(await side.getByRole('list', { name: `${area} topics` }).count())) await side.getByRole('button', { name: new RegExp(area.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) }).click()
    }
  }
  expect(failures, failures.join('\n')).toEqual([])
})

test('re-clicking the current area from one of its sub-pages opens its front door', async ({ page, context }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await seedSession(context)
  await installAppMock(page)
  await page.goto('/ws/admin-surfaces', { waitUntil: 'networkidle' })
  const side = page.getByRole('navigation', { name: 'Security areas' })
  await side.getByRole('button', { name: /Attack Surface/ }).click()
  await expect(page).toHaveURL(/\/assets$/)
  await expect(side.getByRole('button', { name: /Attack Surface/ })).toHaveAttribute('aria-expanded', 'true')
  // On a phone the drawer closes as it navigates.
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto('/ws/admin-surfaces', { waitUntil: 'networkidle' })
  await page.getByRole('button', { name: 'Open areas menu' }).click()
  await page.getByRole('dialog', { name: 'Areas' }).getByRole('button', { name: /Attack Surface/ }).click()
  await expect(page).toHaveURL(/\/assets$/)
  await expect(page.getByRole('dialog', { name: 'Areas' })).toHaveCount(0)
})

// C-38 S26: in legitimate empty states every sub-topic still lands on its own named section.
test('empty states keep every sub-topic target: no certificates, no Email scans, no Brand cases', async ({ page, context }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await seedSession(context)
  await installAppMock(page)
  const ws = `${API_BASE}/workspaces/${workspace.id}`
  await page.route(`${ws}/certificates`, (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ certificates: [] }) }))
  // The Email page reads scans from /scans?workspace_id=… (not under the workspace path).
  await page.route(new RegExp(`${API_BASE.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/scans\\?workspace_id=`), (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ scans: [] }) }))
  await page.route(`${ws}/brand/cases*`, (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ cases: [] }) }))
  const expectTarget = async (url, id) => {
    await page.goto(url, { waitUntil: 'networkidle' })
    await expect(page.locator(id), `${url} → ${id}`).toHaveCount(1)
  }
  await expectTarget('/ws/certificates', '#cert-expiry')
  await expectTarget('/ws/certificates?tab=findings#cert-trust', '#cert-trust')
  await expectTarget('/ws/certificates?tab=findings#cert-hostname-match', '#cert-hostname-match')
  await expectTarget('/ws/certificates?tab=findings#cert-caa', '#cert-caa')
  await page.goto('/ws/email-protection?tab=findings', { waitUntil: 'networkidle' })
  await expect(page.getByTestId('email-topics-pending'), 'the no-scan state is the one under test').toBeVisible()
  for (const id of ['#auth-dmarc', '#auth-spf', '#auth-dkim', '#report-history', '#mail-transport']) await expectTarget(`/ws/email-protection${id}`, id)
  await expectTarget('/ws/brand-monitoring#managed-brand-cases', '#managed-brand-cases')
})

// Founder rule "no overlapping text" (Executive 04:00): inside every sidebar row the name,
// the chevron and the chip never overlap, and the chip stays on one line, at 1440 and 1024.
test('sidebar rows: name, chevron and chip never overlap; name and chip one line each; equal heights; rows clear the card', async ({ page, context }) => {
  await seedSession(context)
  await installAppMock(page)
  for (const [width, height] of [[1440, 900], [1024, 800]]) {
    await page.setViewportSize({ width, height })
    for (const route of ['/dashboard', '/ws/email-protection']) {
      await page.goto(route, { waitUntil: 'networkidle' })
      await page.waitForTimeout(400)
      const problems = await page.evaluate(() => {
        const hit = (a, b) => Math.min(a.right, b.right) - Math.max(a.left, b.left) > 0.5 && Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top) > 0.5
        return [...document.querySelectorAll('.cm-sidebar .cm-side-item')].flatMap((row) => {
          const name = row.querySelector('.cm-side-name')
          const textBox = (el) => { const r = document.createRange(); r.selectNodeContents(el); return [...r.getClientRects()] }
          const nameRects = textBox(name)
          const chip = row.querySelector('.cm-side-state [data-status]').getBoundingClientRect()
          const chevron = row.querySelector('.cm-side-chevron').getBoundingClientRect()
          const out = []
          if (nameRects.some((r) => hit(r, chip))) out.push(`${name.textContent}: name overlaps chip`)
          if (nameRects.some((r) => hit(r, chevron))) out.push(`${name.textContent}: name overlaps chevron`)
          if (chip.height > 26) out.push(`${name.textContent}: chip wraps (${Math.round(chip.height)}px)`)
          if (nameRects.length > 1) out.push(`${name.textContent}: name wraps (${nameRects.length} lines)`)
          return out
        })
      })
      expect(problems, `${route} @${width}`).toEqual([])
      // Option B (Executive 05:00): every row the same height.
      const heights = await page.locator('.cm-sidebar .cm-side-item').evaluateAll((rows) => rows.map((r) => Math.round(r.getBoundingClientRect().height)))
      expect(new Set(heights).size, `${route} @${width}: row heights ${heights.join(',')}`).toBe(1)
      // Every row can scroll clear of the floating card.
      const clear = await page.evaluate(() => {
        const list = document.querySelector('.cm-sidebar > .cm-side'); list.scrollTop = list.scrollHeight
        const last = [...document.querySelectorAll('.cm-sidebar .cm-side-item')].pop().getBoundingClientRect()
        const card = document.querySelector('[data-testid="workspace-dock"] .cm-wsbtn').getBoundingClientRect()
        return Math.round(card.top - last.bottom)
      })
      expect(clear, `${route} @${width}: last row clears the card when scrolled`).toBeGreaterThanOrEqual(0)
    }
  }
})
