import { expect, test } from '@playwright/test'
import { API_BASE, installAppMock, report, scan, seedSession } from './fixtures/app-mock.js'

// S1-SHELL-V2c — Codex C-38b residuals of S1-SHELL-V2 (app-shell-v2.spec.js):
// S01 · S15 · N01 · N02 · N03, the sidebar card zone (founder 11:31) and the
// ?_fresh= residue (C-42, in production-build.spec.js). Own file: the V2 spec's
// exact contents are mutation-anchored.

const AREAS = [
  'Email Protection', 'Attack Surface', 'Website Security', 'Identity Exposure',
  'Shadow IT & Unmanaged Technology', 'Certificates & Trust', 'Brand Protection', 'Cyber Essentials Readiness',
]
// ── S1-SHELL-V2c (Codex C-38b residuals) ─────────────────────────────────────
const esc = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

// S01: the current area's row returns to its Summary from a tab or a section of
// the area page itself (hash and ?tab= cleared), and closes the phone drawer.
test('V2c S01: clicking the current area from a section returns to its Summary and closes the drawer', async ({ page, context }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await seedSession(context)
  await installAppMock(page)
  await page.goto('/ws/email-protection?tab=findings#auth-spf', { waitUntil: 'networkidle' })
  const side = page.getByRole('navigation', { name: 'Security areas' })
  await side.getByRole('button', { name: /Email Protection/ }).click()
  await expect(page).toHaveURL(/\/ws\/email-protection$/)
  await expect(side.getByRole('button', { name: /Email Protection/ })).toHaveAttribute('aria-expanded', 'true')
  await expect(page.getByRole('tab', { name: 'Summary' })).toHaveAttribute('aria-selected', 'true')
  // A second click on the bare Summary collapses it, as before.
  await side.getByRole('button', { name: /Email Protection/ }).click()
  await expect(side.getByRole('button', { name: /Email Protection/ })).toHaveAttribute('aria-expanded', 'false')
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto('/ws/email-protection?tab=findings#auth-spf', { waitUntil: 'networkidle' })
  await page.getByRole('button', { name: 'Open areas menu' }).click()
  await page.getByRole('dialog', { name: 'Areas' }).getByRole('button', { name: /Email Protection/ }).click()
  await expect(page).toHaveURL(/\/ws\/email-protection$/)
  await expect(page.getByRole('dialog', { name: 'Areas' })).toHaveCount(0)
})

// S15: on a phone the area name and the tabs are ONE scrolling strip — the name
// scrolls away with the tabs instead of eating the tab viewport.
test('V2c S15: at 390 the area name and tabs scroll as one strip', async ({ page, context }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await seedSession(context)
  await installAppMock(page)
  await page.goto('/ws/shadow-it', { waitUntil: 'networkidle' })
  const strip = page.getByTestId('area-row-strip')
  const m = await strip.evaluate((el) => {
    const tabs = el.querySelector('[role="tablist"], .cm-tabs')
    const name = el.querySelector('.cm-arearow-name')
    return {
      stripScrolls: getComputedStyle(el).overflowX === 'auto',
      tabsScrollAlone: tabs ? getComputedStyle(tabs).overflowX !== 'visible' : true,
      hasName: Boolean(name), hasTabs: Boolean(tabs),
      stripWidth: el.clientWidth,
    }
  })
  expect(m).toMatchObject({ stripScrolls: true, tabsScrollAlone: false, hasName: true, hasTabs: true })
  // Scrolled to the end, the last tab is fully inside the strip and the name has scrolled out.
  await strip.evaluate((el) => { el.scrollLeft = el.scrollWidth })
  const after = await strip.evaluate((el) => {
    const box = el.getBoundingClientRect()
    const tabs = [...el.querySelectorAll('[role="tab"], .cm-tab')]
    const last = tabs[tabs.length - 1].getBoundingClientRect()
    const name = el.querySelector('.cm-arearow-name').getBoundingClientRect()
    return { lastInside: last.left >= box.left - 1 && last.right <= box.right + 1, nameOut: name.right <= box.left + 1 }
  })
  expect(after).toEqual({ lastInside: true, nameOut: true })
  expect(m.stripWidth).toBeGreaterThan(300)
})

// N01: ?filter= is the source of truth both ways.
test('V2c N01: leaving the Approved inventory link resets the filter to All; a chip writes the URL', async ({ page, context }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await seedSession(context)
  await installAppMock(page)
  await page.goto('/ws/shadow-it?filter=approved#shadow-it-inventory', { waitUntil: 'networkidle' })
  const chip = (name) => page.locator('#shadow-it-inventory').getByRole('button', { name: new RegExp(`^${esc(name)}`) })
  await expect(chip('Approved')).toHaveAttribute('aria-pressed', 'true')
  const side = page.getByRole('navigation', { name: 'Security areas' })
  await side.getByRole('list', { name: 'Shadow IT & Unmanaged Technology topics' }).getByRole('link', { name: 'Observed technology' }).click()
  await expect(page).not.toHaveURL(/filter=/)
  await expect(chip('All')).toHaveAttribute('aria-pressed', 'true')
  await expect(chip('Approved')).toHaveAttribute('aria-pressed', 'false')
  await chip('Rejected').click()
  await expect(page).toHaveURL(/filter=rejected/)
  await expect(chip('Rejected')).toHaveAttribute('aria-pressed', 'true')
})

// N02: in the not-applicable and no-scan states every advertised Email sub-topic
// still lands on its own named section with an honest sentence.
test('V2c N02: Email not-applicable and no-scan states keep every sub-topic target, Settings MTA-STS included', async ({ page, context }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await seedSession(context)
  await installAppMock(page)
  const topics = ['#auth-dmarc', '#auth-spf', '#auth-dkim', '#report-history', '#mail-transport']
  await page.route(`${API_BASE}/scans/${scan.id}/report`, (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
    ...report, modules: { ...report.modules, email_security: { ...report.modules.email_security, applicability: { applicable: false, reason: 'No mail servers are published for this domain' } } },
  }) }))
  for (const id of topics) {
    await page.goto(`/ws/email-protection?tab=findings${id}`, { waitUntil: 'networkidle' })
    await expect(page.locator(id), `not applicable → ${id}`).toHaveCount(1)
    await expect(page.locator(id)).toContainText('Not applicable')
  }
  await page.goto('/ws/email-protection?tab=settings#mta-sts-setup', { waitUntil: 'networkidle' })
  await expect(page.locator('#mta-sts-setup')).toContainText('Not applicable')
})

test('V2c N02: with no Email scan the Settings MTA-STS target exists and says why', async ({ page, context }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await seedSession(context)
  await installAppMock(page)
  await page.route(new RegExp(`${esc(API_BASE)}/scans\\?workspace_id=`), (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ scans: [] }) }))
  await page.goto('/ws/email-protection?tab=settings#mta-sts-setup', { waitUntil: 'networkidle' })
  await expect(page.locator('#mta-sts-setup')).toContainText('after a completed scan')
})

// N03: a cold deep link whose page keeps growing above the target after the first
// scroll still ends with the target in view. Scroll anchoring is switched off so
// the browser cannot compensate; the page must re-settle by itself.
test('V2c N03: a cold deep link re-settles when content above the target loads late', async ({ page, context }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await seedSession(context)
  await installAppMock(page)
  await page.addInitScript(() => {
    document.addEventListener('DOMContentLoaded', () => { document.documentElement.style.overflowAnchor = 'none'; document.body.style.overflowAnchor = 'none' })
  })
  await page.goto('/ws/email-protection?tab=findings#auth-dmarc')
  await expect(page.locator('#auth-dmarc')).toHaveCount(1)
  await page.waitForTimeout(1200)
  // Late content arrives above the target, after the old one-shot settle had already run.
  await page.evaluate(() => {
    const panel = document.getElementById('module-tabpanel')
    const late = document.createElement('div')
    late.style.height = '2000px'
    late.setAttribute('data-testid', 'late-content')
    panel.prepend(late)
  })
  const inView = async () => {
    const box = await page.locator('#auth-dmarc').boundingBox()
    const header = await page.locator('header.cm-top').boundingBox()
    return Boolean(box && box.y >= header.y + header.height - 1 && box.y < 900)
  }
  await expect.poll(inView, { timeout: 5000, message: '#auth-dmarc back in view after late content' }).toBe(true)
})

// Founder 11:31 (Executive 11:45): the floating workspace card never covers a
// sidebar row. The list ends above the card zone; check every area expanded in
// turn, with the list at its top and scrolled to its end.
for (const [width, height] of [[1440, 900], [1024, 768]]) {
  test(`V2c card zone at ${width}×${height}: no sidebar row under the workspace card, scrolled or not`, async ({ page, context }) => {
    test.setTimeout(300_000)
    await page.setViewportSize({ width, height })
    await seedSession(context)
    await installAppMock(page)
    await page.goto('/dashboard', { waitUntil: 'networkidle' })
    const side = page.getByRole('navigation', { name: 'Security areas' })
    const failures = []
    for (const area of AREAS) {
      const row = side.getByRole('button', { name: new RegExp(esc(area)) })
      if ((await row.getAttribute('aria-expanded')) !== 'true') await row.click()
      await page.waitForLoadState('networkidle')
      for (const where of ['top', 'end']) {
        const hits = await page.evaluate((where) => {
          const list = document.querySelector('.cm-sidebar > .cm-side')
          list.scrollTop = where === 'top' ? 0 : list.scrollHeight
          const view = list.getBoundingClientRect()
          const card = document.querySelector('[data-testid="workspace-dock"]').getBoundingClientRect()
          const out = []
          for (const el of list.querySelectorAll('.cm-side-item, .cm-side-sub')) {
            const r = el.getBoundingClientRect()
            // Only the part of the row the list actually shows.
            const top = Math.max(r.top, view.top), bottom = Math.min(r.bottom, view.bottom)
            if (bottom - top <= 1) continue
            const overlapX = Math.min(r.right, card.right) - Math.max(r.left, card.left)
            const overlapY = Math.min(bottom, card.bottom) - Math.max(top, card.top)
            if (overlapX > 1 && overlapY > 1) out.push(el.textContent.trim().slice(0, 40))
          }
          return out
        }, where)
        if (hits.length) failures.push(`${area} expanded, list at ${where}: under the card → ${hits.join(' | ')}`)
      }
    }
    expect(failures, failures.join('\n')).toEqual([])
  })
}
