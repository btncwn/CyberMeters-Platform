// Founder, 23 Oct 2026: "Free tools" is a public header item (after "How it
// works", before "Pricing") on desktop and in the mobile menu, and /free-tools
// opens the tools index.
import { expect, test } from '@playwright/test'

const ORDER = ['Product', 'Areas', 'How it works', 'Free tools', 'Pricing', 'Trust & Security', 'About']

test('desktop header: "Free tools" sits between How it works and Pricing and opens /tools', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('/landing', { waitUntil: 'networkidle' })
  const nav = page.locator('header').first()
  const labels = (await nav.getByRole('link').allInnerTexts()).map((t) => t.trim()).filter((t) => ORDER.includes(t))
  expect(labels).toEqual(ORDER)
  await nav.getByRole('link', { name: 'Free tools' }).click()
  await expect(page).toHaveURL(/\/tools$/)
})

test('mobile menu lists "Free tools" in the same place', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto('/landing', { waitUntil: 'networkidle' })
  await page.getByRole('button', { name: /Menu/ }).click()
  const labels = (await page.locator('header').first().getByRole('listitem').allInnerTexts()).map((t) => t.trim()).filter((t) => ORDER.includes(t))
  expect(labels).toEqual(ORDER)
  await page.locator('header').first().getByRole('listitem').getByRole('link', { name: 'Free tools' }).click()
  await expect(page).toHaveURL(/\/tools$/)
})

for (const path of ['/free-tools', '/free-tools/dmarc-checker', '/tools/']) {
  test(`${path} opens the tools index`, async ({ page }) => {
    await page.goto(path, { waitUntil: 'networkidle' })
    await expect(page).toHaveURL(/\/tools\/?$/)
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
    await expect(page.getByRole('link', { name: /DMARC/i }).first()).toBeVisible()
  })
}

// Seven items from 1024px: every link one line, nothing overlapping the logo, the
// other links or the "Run a free check" button (light and dark headers).
for (const width of [1024, 1280]) {
  for (const path of ['/landing', '/pricing']) {
    test(`header at ${width} on ${path}: one line per link, no overlap`, async ({ page }) => {
      await page.setViewportSize({ width, height: 800 })
      await page.goto(path, { waitUntil: 'networkidle' })
      const header = page.locator('header').first()
      const boxes = []
      for (const name of ORDER) boxes.push({ name, box: await header.getByRole('navigation', { name: 'Main' }).getByRole('link', { name, exact: true }).boundingBox() })
      boxes.push({ name: 'logo', box: await header.getByRole('link', { name: 'CyberMeters home' }).boundingBox() })
      boxes.push({ name: 'cta', box: await header.getByRole('link', { name: 'Run a free check' }).boundingBox() })
      const lineHeight = Math.min(...boxes.slice(0, ORDER.length).map((b) => b.box.height))
      for (const { name, box } of boxes.slice(0, ORDER.length)) expect(box.height, `${name} on one line`).toBeLessThan(lineHeight * 1.5)
      const overlap = (a, b) => Math.min(a.x + a.width, b.x + b.width) - Math.max(a.x, b.x) > 1 && Math.min(a.y + a.height, b.y + b.height) - Math.max(a.y, b.y) > 1
      const hits = []
      for (let i = 0; i < boxes.length; i++) for (let j = i + 1; j < boxes.length; j++) if (overlap(boxes[i].box, boxes[j].box)) hits.push(`${boxes[i].name}×${boxes[j].name}`)
      expect(hits).toEqual([])
    })
  }
}
