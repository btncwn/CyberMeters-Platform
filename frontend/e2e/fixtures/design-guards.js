import { expect } from '@playwright/test'

// The three Playwright guards every UI PR carries (design standard, founder,
// 21 Oct 2026). Shared so each page group asserts them the same way.

// Visible text that looks like an internal identifier: snake_case keys,
// dotted registry ids with a known prefix, and managed-case ids.
const RAW_KEY = /\b[a-z][a-z0-9]*_[a-z0-9_]+\b|\b(?:asm|web|email|cert|identity|brand|shadow|ce)\.[a-z_]+\.[a-z_.]+\b|\bmc-[a-f0-9]{6,}\b/g

export async function expectOnePrimaryAction(page, scope = 'main') {
  const count = await page.locator(`${scope} .btn-primary:visible`).count()
  expect(count, `visible primary buttons in ${scope}`).toBeLessThanOrEqual(1)
}

export async function expectNoRawKeys(page, scope = 'main') {
  const text = await page.locator(scope).innerText()
  expect(text.match(RAW_KEY) || [], 'internal identifiers in visible text').toEqual([])
}

// No two children of each row overlap (time column vs event text, etc.).
export async function expectNoOverlap(page, rowSelector) {
  const overlaps = await page.locator(rowSelector).evaluateAll((rows) => rows.flatMap((row) => {
    const boxes = [...row.children].map((el) => el.getBoundingClientRect()).filter((b) => b.width > 0 && b.height > 0)
    const hits = []
    for (let i = 0; i < boxes.length; i++) for (let j = i + 1; j < boxes.length; j++) {
      const a = boxes[i], b = boxes[j]
      const x = Math.min(a.right, b.right) - Math.max(a.left, b.left)
      const y = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top)
      if (x > 1 && y > 1) hits.push(row.textContent.slice(0, 80))
    }
    return hits
  }))
  expect(overlaps, `overlapping text in ${rowSelector}`).toEqual([])
}
