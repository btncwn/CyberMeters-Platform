import { expect, test } from '@playwright/test'
import { API_BASE, installAppMock, seedSession, workspace } from './fixtures/app-mock.js'

const json = body => ({ contentType: 'application/json', body: JSON.stringify(body) })
const target = { id: 'target_fixture', target: '93.184.216.201', target_type: 'ip', address_count: 1, authorization_status: 'attested', authorized_at: '2026-10-25T12:00:00Z' }
const capabilities = { can_manage: true, can_scan: true, collector_available: true, allowed_ports: [22, 80, 443], limits: { max_addresses: 32, max_ports: 16, max_pairs: 256, max_targets: 32 } }

for (const width of [1440, 1024, 768, 390]) {
  test(`Remove target confirms withdrawal and preserves history at ${width}px`, async ({ page, context }, testInfo) => {
    await page.setViewportSize({ width, height: 1000 })
    await seedSession(context)
    await context.addInitScript(() => localStorage.setItem('cybermeters_workspace_name', 'Example workspace'))
    await installAppMock(page)
    await page.route(`${API_BASE}/**`, route => {
      const path = new URL(route.request().url()).pathname
      if (path.endsWith('/scans')) return route.fulfill(json({ scans: [] }))
      if (path.endsWith('/cases')) return route.fulfill(json({ cases: [] }))
      return route.fallback()
    })
    let removed = false
    let writes = 0
    await page.route(`${API_BASE}/workspaces`, route => route.fulfill(json({ workspaces: [{ ...workspace, name: 'Example workspace' }], default_workspace_id: workspace.id })))
    await page.route(`${API_BASE}/workspaces/${workspace.id}/**`, route => {
      const request = route.request()
      const path = new URL(request.url()).pathname
      if (path.endsWith(`/network-targets/${target.id}`) && request.method() === 'DELETE') {
        writes++
        removed = true
        return route.fulfill(json({ removed: true }))
      }
      if (path.endsWith('/domains')) return route.fulfill(json({ domains: [] }))
      if (/\/assets(?:\/summary|\/timeline)?$/.test(path)) return route.fulfill(json({ assets: [], timeline: [], summary: {} }))
      if (path.endsWith('/network-targets')) return route.fulfill(json({ targets: removed ? [] : [target], capabilities }))
      if (path.endsWith('/network-scans')) return route.fulfill(json({ scans: [{ id: 'scan_fixture', target_id: target.id, target: target.target, status: 'completed', quality: 'complete', created_at: '2026-10-25T12:00:00Z', coverage: { planned: 2, concluded: 2 } }] }))
      if (path.endsWith('/network-assets')) return route.fulfill(json({ assets: [], changes: [], total: 0 }))
      if (path.endsWith('/network-suggestions')) return route.fulfill(json({ suggestions: [] }))
      if (path.includes('/attack-surface/')) return route.fulfill(json({ assets: [], events: [], lists: [], summary: {} }))
      return route.fallback()
    })
    await page.goto('/assets#network-assets')
    const panel = page.getByRole('region', { name: 'Network assets', exact: true })
    await expect(panel.getByRole('button', { name: 'Remove', exact: true })).toBeVisible()
    await panel.scrollIntoViewIfNeeded()
    await panel.getByRole('button', { name: 'Remove', exact: true }).scrollIntoViewIfNeeded()
    const scan = await panel.getByRole('button', { name: 'Run scan', exact: true }).boundingBox()
    const remove = await panel.getByRole('button', { name: 'Remove', exact: true }).boundingBox()
    expect(scan && remove).toBeTruthy()
    expect(scan.x + scan.width <= remove.x || scan.y + scan.height <= remove.y).toBeTruthy()
    await testInfo.attach(`target-row-${width}`, { body: await page.screenshot({ path: testInfo.outputPath(`row-${width}.png`), fullPage: false }), contentType: 'image/png' })
    await panel.getByRole('button', { name: 'Remove', exact: true }).click()
    const dialog = page.getByRole('alertdialog')
    await expect(dialog.getByRole('heading')).toHaveText(`Remove ${target.target} and withdraw your authorisation?`)
    await expect(dialog).toContainText('Future scans will not check it. Past scan results stay in your history.')
    expect(writes).toBe(0)
    const box = await dialog.boundingBox()
    expect(box.x).toBeGreaterThanOrEqual(0)
    expect(box.x + box.width).toBeLessThanOrEqual(width)
    await testInfo.attach(`confirmation-${width}`, { body: await page.screenshot({ path: testInfo.outputPath(`confirmation-${width}.png`), fullPage: false }), contentType: 'image/png' })
    await dialog.getByRole('button', { name: 'Cancel', exact: true }).click()
    expect(writes).toBe(0)
    await panel.getByRole('button', { name: 'Remove', exact: true }).click()
    await page.getByRole('alertdialog').getByRole('button', { name: 'Remove', exact: true }).click()
    await expect(panel.getByText('No network targets recorded yet.')).toBeVisible()
    expect(writes).toBe(1)
    await panel.getByRole('tab', { name: 'Recent scans' }).click()
    await expect(panel.getByText(target.target, { exact: true })).toBeVisible()
    await expect(panel.getByRole('button', { name: 'View evidence' })).toBeVisible()
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy()
  })
}
