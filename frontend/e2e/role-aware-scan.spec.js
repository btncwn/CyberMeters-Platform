import { expect, test } from '@playwright/test'

// Live finding (18 Oct 2026): an analyst member saw the Overview scan box and
// /scans/new, typed a domain and got a red "Something went wrong · Forbidden —
// admin role required to add domains" with a Retry and a verify button they
// could not use. The UI now mirrors the backend table: an analyst rescans the
// domains the workspace has already verified (no add, no verify), a viewer has
// no scan action and reads one calm sentence. Owners and admins are unchanged.

const API_BASE = 'http://127.0.0.1:8787/api'
const ws = { id: 'ws_bbb', name: 'Black Bull Barbers', created_at: '2026-07-08T09:00:00Z' }
const json = (body, status = 200) => ({ status, contentType: 'application/json', body: JSON.stringify(body) })
const DOMAINS = [
  { domain_id: 'dom_1', domain: 'blackbullbarbers.co.uk', verification_status: 'verified', verified_at: '2026-10-01T09:00:00Z' },
  { domain_id: 'dom_2', domain: 'bbb-bookings.co.uk', verification_status: 'pending', verified_at: null },
]

async function signInAs(page, role) {
  const names = { owner: 'Taylor Owner', analyst: 'Casey Analyst', viewer: 'Robin Viewer' }
  const user = { id: `usr_${role}`, email: `${role}@example.co.uk`, name: names[role], plan: role === 'owner' ? 'professional' : 'free' }
  await page.addInitScript(({ user, ws }) => {
    localStorage.setItem('cybermeters_auth_token', 'token_e2e')
    localStorage.setItem('cybermeters_auth_user', JSON.stringify(user))
    localStorage.setItem('cybermeters_workspace_id', ws.id)
    localStorage.setItem('cybermeters_workspace_name', ws.name)
  }, { user, ws })
  const calls = { addDomain: 0, scans: [] }
  await page.route(`${API_BASE}/**`, async (route) => {
    const req = route.request()
    const path = new URL(req.url()).pathname.replace(/^\/api/, '')
    const method = req.method()
    if (path === '/auth/me') return route.fulfill(json(user))
    if (path === '/workspaces' && method === 'GET') return route.fulfill(json({ workspaces: [{ ...ws, role }], default_workspace_id: ws.id }))
    if (path === `/workspaces/${ws.id}/members`) return route.fulfill(json({ workspace_id: ws.id, caller_role: role, members: [{ role: 'owner', name: 'Taylor Owner', email: 'owner@example.co.uk' }, { role: 'analyst', name: 'Casey Analyst', email: 'analyst@example.co.uk' }] }))
    if (path === `/workspaces/${ws.id}/domains` && method === 'POST') { calls.addDomain += 1; return route.fulfill(json({ error: 'Forbidden — admin role required to add domains' }, 403)) }
    if (path === `/workspaces/${ws.id}/domains`) return route.fulfill(json({ domains: DOMAINS }))
    if (path === '/scan' && method === 'POST') {
      calls.scans.push(JSON.parse(req.postData() || '{}'))
      return route.fulfill(json({ status: 'running', scan_id: 'scan_rescan_1', domain: 'blackbullbarbers.co.uk', workspace_id: ws.id }, 202))
    }
    if (path === `/workspaces/${ws.id}/scans`) return route.fulfill(json({ scans: [] }))
    if (path === '/account/usage') return route.fulfill(json({ plan: user.plan, features: [], usage: {}, limits: {} }))
    if (path.includes('notifications')) return route.fulfill(json({ notifications: [], unread_count: 0 }))
    if (path.includes('cyber-mot-domains')) return route.fulfill(json({ cyber_mot_domains: [] }))
    if (path.includes('/cases')) return route.fulfill(json({ cases: [] }))
    return route.fulfill(json({}))
  })
  return calls
}

test('analyst: no add-domain box or verify; rescans a domain the workspace already verified', async ({ page }) => {
  const calls = await signInAs(page, 'analyst')
  await page.goto('/dashboard')
  await expect(page.getByRole('heading', { level: 1, name: 'Where is Black Bull Barbers exposed today?' })).toBeVisible()
  await expect(page.getByRole('textbox', { name: 'Domain to scan' })).toHaveCount(0)
  await expect(page.getByRole('form', { name: 'Start a scan' })).toHaveCount(0)

  await page.getByRole('link', { name: 'Rescan a verified domain' }).click()
  await expect(page).toHaveURL(/\/scans\/new$/)
  const panel = page.getByTestId('scan-rescan-only')
  await expect(panel).toContainText('Only workspace admins can add new domains. You can rescan domains this workspace has already verified.')
  // Only the verified domain is offered; the pending one is not.
  await expect(page.getByTestId('rescan-domains').getByRole('listitem')).toHaveCount(1)
  await expect(page.getByText('bbb-bookings.co.uk')).toHaveCount(0)
  await expect(page.getByRole('link', { name: 'See all domains in this workspace' })).toHaveAttribute('href', `/workspaces/${ws.id}`)
  await expect(page.getByRole('textbox')).toHaveCount(0)
  await expect(page.getByRole('button', { name: /Verify domain ownership/ })).toHaveCount(0)
  await expect(page.getByText(/Something went wrong|Forbidden|admin role required/)).toHaveCount(0)
  await expect(page.getByRole('button', { name: /Retry/ })).toHaveCount(0)
  // The right panel names the eight canonical areas.
  await expect(page.getByTestId('scan-areas').getByRole('listitem')).toHaveCount(8)
  await expect(page.getByText('Executive Intelligence')).toHaveCount(0)

  await page.getByRole('button', { name: 'Rescan blackbullbarbers.co.uk' }).click()
  await expect(page).toHaveURL(/\/scans\/scan_rescan_1$/)
  expect(calls.scans).toEqual([{ domain: 'blackbullbarbers.co.uk', workspace_id: ws.id }])
  expect(calls.addDomain).toBe(0)
})

test('viewer: no scan action anywhere, and /scans/new asks the owner', async ({ page }) => {
  const calls = await signInAs(page, 'viewer')
  await page.goto('/dashboard')
  await expect(page.getByRole('heading', { level: 1, name: 'Where is Black Bull Barbers exposed today?' })).toBeVisible()
  await expect(page.getByRole('textbox', { name: 'Domain to scan' })).toHaveCount(0)
  await expect(page.getByRole('link', { name: 'Rescan a verified domain' })).toHaveCount(0)
  await page.goto('/scans/new')
  await expect(page.getByTestId('scan-not-permitted')).toContainText('Only workspace admins can add domains and start scans. Ask Taylor Owner if you need one scanned.')
  await expect(page.getByRole('button', { name: /Rescan|Verify domain ownership|Start Scan/ })).toHaveCount(0)
  await expect(page.getByRole('textbox')).toHaveCount(0)
  expect(calls.scans).toHaveLength(0)
  expect(calls.addDomain).toBe(0)
})

test('owner: the scan box and the domain form are unchanged', async ({ page }) => {
  await signInAs(page, 'owner')
  await page.goto('/dashboard')
  await expect(page.getByRole('textbox', { name: 'Domain to scan' })).toBeVisible()
  await page.goto('/scans/new')
  await expect(page.getByRole('heading', { name: 'Choose a domain' })).toBeVisible()
  await expect(page.getByTestId('scan-not-permitted')).toHaveCount(0)
  await expect(page.getByTestId('scan-rescan-only')).toHaveCount(0)
})
