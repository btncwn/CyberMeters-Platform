import { test, expect } from '@playwright/test'
import { API_BASE, installAppMock, seedSession, workspace, domain } from './fixtures/app-mock.js'

// Closing queue 2 (founder, 21 Oct 2026): on every area page and the MSP
// portfolio, the primary job is ONE labelled action that does the job or opens
// exactly where it is done. Each test clicks it and checks what happened.

const json = (body, status = 200) => ({ status, contentType: 'application/json', body: JSON.stringify(body) })

async function mock(page) {
  const calls = []
  await installAppMock(page)
  await page.route(`${API_BASE}/**`, async (route) => {
    const req = route.request()
    const p = new URL(req.url()).pathname.replace(/^\/api/, '')
    if (req.method() !== 'GET') calls.push({ m: req.method(), p, body: req.postData() ? JSON.parse(req.postData()) : null })
    // Scan now needs the authoritative verified record the real API returns.
    if (p === `/workspaces/${workspace.id}/domains`) return route.fulfill(json({ domains: [{ ...domain, verified_at: '2026-07-08T09:06:00.000Z' }] }))
    if (p === '/scan' && req.method() === 'POST') return route.fulfill(json({ scan_id: 'scan_primary', status: 'queued' }, 202))
    if (p === '/scans/scan_primary') return route.fulfill(json({ scan: { id: 'scan_primary', status: 'running' } }))
    if (p === '/portfolio/overview') return route.fulfill(json({ total_workspaces: 2, total_domains: 2, critical_findings: 3, high_findings: 1, highest_risk_workspace: { id: 'ws_risky', name: 'Riverside Dental', critical_findings: 3 }, generated_at: '2026-10-21T09:00:00Z' }))
    if (p === '/portfolio/workspaces') return route.fulfill(json({ workspaces: [] }))
    if (p === '/portfolio/trends') return route.fulfill(json({ trend: [] }))
    if (p === '/portfolio/alerts') return route.fulfill(json({ alerts: [] }))
    if (p === '/portfolio/executive-summary') return route.fulfill(json({ summary: null }))
    if (p === '/portfolio/maturity') return route.fulfill(json({ workspaces: [] }))
    if (p === '/portfolio/domains') return route.fulfill(json({ domains: [], portfolio_state: 'ok', pagination: { total: 0 } }))
    return route.fallback()
  })
  return calls
}

const next = (page) => page.getByTestId('module-next')

for (const [width, height] of [[1440, 900], [390, 844]]) {
  test.describe(`primary action per page at ${width}`, () => {
    test.use({ viewport: { width, height } })
    test.beforeEach(async ({ context }) => { await seedSession(context) })

    test('Email Protection: a fix awaiting verification opens its case', async ({ page }) => {
      await mock(page)
      await page.goto('/ws/email-protection')
      await expect(next(page).getByRole('link', { name: 'Open the case to verify' })).toHaveAttribute('href', '/ws/cases/case_2')
    })

    for (const [route, area] of [['/assets', 'Attack Surface'], ['/ws/identity-exposure', 'Identity Exposure'], ['/ws/certificates', 'Certificates & Trust'], ['/ws/brand-monitoring', 'Brand Protection']]) {
      test(`${area}: the scan the area needs starts in place`, async ({ page }) => {
        const calls = await mock(page)
        await page.goto(route)
        const button = next(page).getByRole('button', { name: /^Run a scan$/ })
        await expect(button).toBeEnabled()
        await button.click()
        await expect(next(page).getByRole('status')).toContainText('Scan started — results in about 2–3 minutes.')
        expect(calls.filter((c) => c.p === '/scan')).toEqual([{ m: 'POST', p: '/scan', body: { domain: domain.domain, workspace_id: workspace.id } }])
      })
    }

    test('Website Security: Review findings opens the findings', async ({ page }) => {
      await mock(page)
      await page.goto('/ws/website-security')
      await next(page).getByRole('button', { name: 'Review findings' }).click()
      await expect(page.getByRole('tab', { name: 'Findings' })).toHaveAttribute('aria-selected', 'true')
    })

    test('Shadow IT: Classify items opens the unclassified inventory', async ({ page }) => {
      await mock(page)
      await page.goto('/ws/shadow-it')
      await next(page).getByRole('button', { name: 'Classify items' }).click()
      await expect(page.getByRole('button', { name: 'Not yet classified (6)' })).toBeVisible()
    })

    test('Cyber Essentials: Start questionnaire opens the questionnaire', async ({ page }) => {
      await mock(page)
      await page.goto('/ws/cyber-essentials')
      await expect(next(page).getByRole('link', { name: 'Start questionnaire' })).toHaveAttribute('href', '/ws/cyber-essentials?tab=findings#questionnaire')
    })

    test('MSP portfolio: open the customer with the most critical findings', async ({ page }) => {
      await mock(page)
      await page.goto('/portfolio')
      await page.getByRole('button', { name: 'Open Riverside Dental · 3 critical' }).click()
      await expect(page).toHaveURL(/\/dashboard$/)
      expect(await page.evaluate(() => localStorage.getItem('cybermeters_workspace_id'))).toBe('ws_risky')
    })
  })
}
