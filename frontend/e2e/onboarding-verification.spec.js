import { expect, test } from '@playwright/test'

// Live finding (18 Oct 2026, a fresh signup): step 3 "Verify Domain" showed a
// TXT host/value next to a green box reading "No verification token found. Call
// POST /api/domains/:id/verification first." The record now comes only from the
// server-issued token for this workspace's link, is issued automatically when
// step 3 opens, and every verification failure reads as plain copy.

const API_BASE = 'http://127.0.0.1:8787/api'
const ws = { id: 'ws_she', name: 'Sheshire', created_at: '2026-10-18T09:00:00Z' }
const user = { id: 'usr_new', email: 'owner@sheshire.co.uk', name: 'New Owner', plan: 'free' }
const TOKEN = 'c3'.repeat(24)
const json = (body, status = 200) => ({ status, contentType: 'application/json', body: JSON.stringify(body) })

test('fresh signup: free-check domain → record issued and shown → verify fails politely → verifies once the record is published', async ({ page }) => {
  await page.addInitScript(({ user, ws }) => {
    localStorage.setItem('cybermeters_auth_token', 'token_e2e')
    localStorage.setItem('cybermeters_auth_user', JSON.stringify(user))
    localStorage.setItem('cybermeters_workspace_id', ws.id)
    localStorage.setItem('cybermeters_workspace_name', ws.name)
    localStorage.setItem('cm_pending_domain', 'sheshire.co.uk') // handed over by the free check
  }, { user, ws })

  const state = { added: false, link: { verification_status: 'unverified', verification_token: null }, published: false }
  const calls = { issue: [], verify: [] }
  await page.route(`${API_BASE}/**`, async (route) => {
    const req = route.request()
    const path = new URL(req.url()).pathname.replace(/^\/api/, '')
    const method = req.method()
    if (path === '/auth/me') return route.fulfill(json(user))
    if (path === '/workspaces' && method === 'GET') return route.fulfill(json({ workspaces: [{ ...ws, role: 'owner' }], default_workspace_id: ws.id }))
    if (path === `/workspaces/${ws.id}/domains` && method === 'POST') {
      state.added = true
      return route.fulfill(json({ domain: { domain_id: 'dom_she', domain: 'sheshire.co.uk', workspace_id: ws.id } }, 201))
    }
    if (path === `/workspaces/${ws.id}/domains`) {
      return route.fulfill(json({ domains: state.added ? [{ domain_id: 'dom_she', domain: 'sheshire.co.uk', ...state.link }] : [] }))
    }
    if (path === '/domains/dom_she/verification' && method === 'POST') {
      calls.issue.push(JSON.parse(req.postData() || '{}'))
      state.link = { verification_status: 'pending', verification_token: TOKEN }
      return route.fulfill(json({ domain: 'sheshire.co.uk', domain_id: 'dom_she', workspace_id: ws.id, token: TOKEN,
        dns: { record_type: 'TXT', host: '_cybermeters.sheshire.co.uk', value: `cybermeters-verification=${TOKEN}` } }))
    }
    if (path === '/domains/dom_she/verify' && method === 'POST') {
      calls.verify.push(JSON.parse(req.postData() || '{}'))
      if (!state.published) {
        return route.fulfill(json({ success: false, verification_status: 'failed', outcome: 'dns_not_found',
          message: 'Verification not confirmed yet — see POST /api/domains/:id/verify' }))
      }
      state.link = { verification_status: 'verified', verification_token: TOKEN, verified_at: '2026-10-18T10:00:00Z' }
      return route.fulfill(json({ success: true, verification_status: 'verified', outcome: 'verified_dns_txt' }))
    }
    if (path === '/domains/dom_she/verification/domain-connect') return route.fulfill(json({ available: false }))
    if (path === `/workspaces/${ws.id}/scans`) return route.fulfill(json({ scans: [] }))
    if (path.includes('/invitations')) return route.fulfill(json({ invitations: [] }))
    if (path === '/account/usage') return route.fulfill(json({ plan: 'free', features: [], usage: {}, limits: {} }))
    if (path.includes('notifications')) return route.fulfill(json({ notifications: [], unread_count: 0 }))
    if (path.startsWith('/domains/')) throw new Error(`unexpected domain call ${method} ${path}`) // e.g. the legacy GET /domains/:id
    return route.fulfill(json({}))
  })

  await page.goto('/onboarding')
  await expect(page.getByPlaceholder('example.com')).toHaveValue('sheshire.co.uk')
  await page.getByRole('button', { name: 'Add Domain' }).click()

  const step3 = page.locator('section', { has: page.getByRole('heading', { name: 'Verify Domain' }) })
  const record = step3.getByTestId('onboarding-dns-record')
  await expect(record).toContainText(`cybermeters-verification=${TOKEN}`)
  await expect(record).toContainText('_cybermeters.sheshire.co.uk')
  expect(calls.issue).toEqual([{ workspace_id: ws.id }])
  await expect(page.getByRole('button', { name: /Get DNS Record/i })).toHaveCount(0)
  await expect(step3.getByRole('link', { name: 'Advanced verification' })).toBeVisible()

  await step3.getByRole('button', { name: 'Verify ownership' }).click()
  await expect(step3.getByTestId('onboarding-verify-note')).toHaveText('We couldn’t see the record yet. DNS changes can take a few minutes — try again shortly.')
  // The guard: no route path or server instruction anywhere on the page.
  await expect(page.locator('body')).not.toContainText('/api/')
  await expect(page.locator('body')).not.toContainText('Call POST')

  state.published = true
  await step3.getByRole('button', { name: 'Verify ownership' }).click()
  await expect(step3.getByText('Domain ownership is verified.')).toBeVisible()
  expect(calls.verify).toEqual([{ workspace_id: ws.id }, { workspace_id: ws.id }])
  expect(calls.issue).toHaveLength(1)
  await expect(page.locator('body')).not.toContainText('/api/')
})
