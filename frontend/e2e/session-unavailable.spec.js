import { expect, test } from '@playwright/test'

// A failed session check is not a sign-out. An outage keeps the stored session
// and opens nothing; only a real 401 ends it. Driven through a real page load.

const API_BASE = 'http://127.0.0.1:8787/api'
const user = { id: 'usr_owner', email: 'owner@example.co.uk', name: 'Taylor Owner', plan: 'free' }
const json = (body, status = 200) => ({ status, contentType: 'application/json', body: JSON.stringify(body) })

async function open(page, answerSessionCheck) {
  await page.addInitScript(({ user }) => {
    if (sessionStorage.getItem('seeded')) return
    sessionStorage.setItem('seeded', '1')
    localStorage.setItem('cybermeters_auth_token', 'token_e2e')
    localStorage.setItem('cybermeters_auth_user', JSON.stringify(user))
    localStorage.setItem('cybermeters_workspace_id', 'ws_a')
    localStorage.setItem('cybermeters_workspace_name', 'Alpha')
  }, { user })
  const otherCalls = []
  await page.route(`${API_BASE}/**`, async (route) => {
    const path = new URL(route.request().url()).pathname.replace(/^\/api/, '')
    if (path === '/auth/me') return answerSessionCheck(route)
    otherCalls.push(path)
    if (path === '/workspaces') return route.fulfill(json({ workspaces: [{ id: 'ws_a', name: 'Alpha', role: 'owner' }], default_workspace_id: 'ws_a' }))
    return route.fulfill(json({}))
  })
  await page.goto('/account')
  return otherCalls
}

const stored = (page) => page.evaluate(() => ({
  token: localStorage.getItem('cybermeters_auth_token'),
  workspace: localStorage.getItem('cybermeters_workspace_id'),
}))

test('an outage holds the page closed, keeps the session and recovers on retry', async ({ page }) => {
  let healthy = false
  const otherCalls = await open(page, (route) => (healthy ? route.fulfill(json(user)) : route.fulfill(json({ error: 'maintenance' }, 503))))

  await expect(page.getByRole('alert')).toContainText('You have not been signed out')
  await expect(page).toHaveURL(/\/account$/)
  expect(await stored(page)).toEqual({ token: 'token_e2e', workspace: 'ws_a' })
  expect(otherCalls).toEqual([])

  await page.getByRole('button', { name: 'Try again' }).click()
  await expect(page.getByRole('alert')).toContainText('You have not been signed out')
  expect(otherCalls).toEqual([])

  healthy = true
  await page.getByRole('button', { name: 'Try again' }).click()
  await expect(page.getByText('You have not been signed out')).toHaveCount(0)
  await expect(page).toHaveURL(/\/account$/)
  expect(await stored(page)).toEqual({ token: 'token_e2e', workspace: 'ws_a' })
  expect(otherCalls.length).toBeGreaterThan(0)
})

test('a network failure keeps the session and survives a reload', async ({ page }) => {
  await open(page, (route) => route.abort('failed'))
  await expect(page.getByRole('alert')).toContainText('You have not been signed out')
  await page.reload()
  await expect(page.getByRole('alert')).toContainText('You have not been signed out')
  expect(await stored(page)).toEqual({ token: 'token_e2e', workspace: 'ws_a' })
})

test('a real 401 still signs out', async ({ page }) => {
  await open(page, (route) => route.fulfill(json({ error: 'Unauthorized' }, 401)))
  await expect(page).toHaveURL(/\/login$/)
  expect(await stored(page)).toEqual({ token: null, workspace: null })
})
