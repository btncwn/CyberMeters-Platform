import { expect, test } from '@playwright/test'
import { installAppMock, seedSession } from './fixtures/app-mock.js'
import { APP_ROUTES } from './fixtures/app-routes.js'

// DESIGN-STANDARD §7 (founder, 22 Oct 2026): one strictly descending type scale
// taken from the benchmark dashboards — page title > section > sub-section >
// tabs/controls ≥ body > fine print — and nothing customer-readable under the
// floor. Read from computed styles on every signed-in route, so a page that
// sets its own size cannot slip past the tokens (index.css @theme).

const FLOOR_PX = 12 // the benchmarks' smallest readable fine print
const BODY_PX = 14 // tabs and nav are controls: never below body

const scan = () => {
  const px = (el) => parseFloat(getComputedStyle(el).fontSize)
  const shown = (el) => {
    const r = el.getBoundingClientRect()
    const s = getComputedStyle(el)
    if (r.width < 1 || r.height < 1 || s.visibility === 'hidden' || s.display === 'none' || Number(s.opacity) === 0) return false
    // Screen-reader-only text is not customer-readable on screen.
    if (s.position === 'absolute' && r.width <= 1 && r.height <= 1) return false
    // aria-hidden text that is still painted (a count bubble, a dock label) IS
    // customer-readable, so only SVG and screen-reader-only text are skipped.
    return !el.closest('svg, .sr-only')
  }
  const own = (el) => [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim())
  const all = (sel) => [...document.querySelectorAll(`main ${sel}, header ${sel}, nav ${sel}`)].filter(shown)
  const sizes = (sel) => all(sel).map(px)
  const tooSmall = [...document.querySelectorAll('body *')].filter((el) => own(el) && shown(el) && px(el) < 12)
    .slice(0, 5).map((el) => `${px(el)}px "${el.textContent.trim().slice(0, 40)}"`)
  return {
    h1: sizes('h1'), h2: sizes('h2'), h3: sizes('h3, h4'),
    tabs: sizes('[role="tab"], .cm-tab'),
    tooSmall,
  }
}

for (const [width, height] of [[1440, 900], [390, 844]]) {
  test(`type scale descends and nothing is under the floor at ${width}`, async ({ page, context }) => {
    test.setTimeout(600_000)
    await page.setViewportSize({ width, height })
    await seedSession(context)
    await installAppMock(page)
    const failures = []
    for (const route of APP_ROUTES) {
      await page.goto(route, { waitUntil: 'networkidle' })
      await page.waitForTimeout(200)
      const m = await page.evaluate(scan)
      const lo = (xs) => (xs.length ? Math.min(...xs) : null)
      const hi = (xs) => (xs.length ? Math.max(...xs) : null)
      if (m.tooSmall.length) failures.push(`${route}: under ${FLOOR_PX}px → ${m.tooSmall.join(' | ')}`)
      if (m.h1.length && m.h2.length && lo(m.h1) <= hi(m.h2)) failures.push(`${route}: h1 ${lo(m.h1)}px not above h2 ${hi(m.h2)}px`)
      if (m.h2.length && m.h3.length && lo(m.h2) <= hi(m.h3)) failures.push(`${route}: h2 ${lo(m.h2)}px not above h3 ${hi(m.h3)}px`)
      if (m.tabs.length && lo(m.tabs) < BODY_PX) failures.push(`${route}: tab ${lo(m.tabs)}px below body ${BODY_PX}px`)
    }
    expect(failures, failures.join('\n')).toEqual([])
  })
}
