// Founder P1 (23 Oct 2026): inside She.Shire the floating card read
// "B · blackbullbarbers.co.uk" — the workspace's first verified domain. The card
// names the ACTIVE workspace (initial + name) on a deep link, after a reload, and
// across switches, and never shows a domain.
import { expect, test } from '@playwright/test'
import { API_BASE, domain, installAppMock, seedSession, workspace } from './fixtures/app-mock.js'

const SHE = { id: workspace.id, name: 'She.Shire', role: 'owner', created_at: workspace.created_at }
const BBB = { id: 'ws_bbb', name: 'Black Bull Barbers', role: 'owner', created_at: workspace.created_at }

async function setup(page, context) {
  await page.setViewportSize({ width: 1440, height: 900 })
  await seedSession(context)
  // After seedSession on every navigation (reload included): the active workspace is She.Shire,
  // whose domain list (the fixture's) is blackbullbarbers.co.uk — the founder's case.
  await context.addInitScript((name) => { if (!sessionStorage.getItem('switched')) localStorage.setItem('cybermeters_workspace_name', name) }, SHE.name)
  await installAppMock(page)
  await page.route(`${API_BASE}/workspaces/ws_bbb/domains`, (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ domains: [{ domain: 'blackbullbarbers.co.uk', verification_status: 'verified' }] }) }))
  await page.route(`${API_BASE}/workspaces`, (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ workspaces: [SHE, BBB] }) }))
}

const card = (page) => page.getByTestId('workspace-dock-button')

test('deep link and reload: the card names the active workspace, never its domain', async ({ page, context }) => {
  await setup(page, context)
  await page.goto('/ws/certificates?tab=findings', { waitUntil: 'networkidle' })
  await expect(page.getByTestId('workspace-initial')).toHaveText('S')
  await expect(card(page)).toHaveAttribute('title', 'Workspace · She.Shire · 1 domain')
  // The identity is the workspace; its domain is only listed (founder, 23 Oct 2026).
  await expect(page.getByTestId('workspace-initial')).not.toHaveText('B')
  await page.reload({ waitUntil: 'networkidle' })
  await expect(page.getByTestId('workspace-initial')).toHaveText('S')
  await expect(card(page)).toHaveAttribute('title', 'Workspace · She.Shire · 1 domain')
})

test('switching A → B → A from the card updates it each time', async ({ page, context }) => {
  await setup(page, context)
  await page.goto('/dashboard', { waitUntil: 'networkidle' })
  await expect(page.getByTestId('workspace-initial')).toHaveText('S')
  await page.evaluate(() => sessionStorage.setItem('switched', '1'))
  await card(page).click()
  await page.getByRole('menu', { name: 'Workspace' }).getByRole('menuitem', { name: /Black Bull Barbers/ }).click()
  await expect(page.getByTestId('workspace-initial')).toHaveText('B')
  await expect(card(page)).toHaveAttribute('title', 'Workspace · Black Bull Barbers · 1 domain')
  await card(page).click()
  await page.getByRole('menu', { name: 'Workspace' }).getByRole('menuitem', { name: /She\.Shire/ }).click()
  await expect(page.getByTestId('workspace-initial')).toHaveText('S')
  await expect(card(page)).toHaveAttribute('title', 'Workspace · She.Shire · 1 domain')
})

// The context bar (founder decision, 23 Oct 2026) on real pages.
test('context bar: Overview names the workspace and its domain; a case deep link names the case\'s domain; portfolio counts workspaces', async ({ page, context }) => {
  await setup(page, context)
  await page.goto('/dashboard', { waitUntil: 'networkidle' })
  const bar = page.getByRole('navigation', { name: 'Workspace context' })
  await expect(bar).toContainText('She.Shire')
  await expect(bar).toContainText(domain.domain)
  await page.goto('/ws/cases/case_2', { waitUntil: 'networkidle' })
  await expect(bar).toHaveText(new RegExp(`She\\.Shire\\s*›\\s*${domain.domain.replace(/\./g, '\\.')}`))
  await page.goto('/portfolio', { waitUntil: 'networkidle' })
  await expect(bar).toContainText('Portfolio')
  await expect(bar).toContainText('2 workspaces')
})
