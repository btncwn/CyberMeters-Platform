import { expect, test } from '@playwright/test'

// P1 (18 Oct 2026): an invited person who signs up must land back on the
// invitation after verifying their email — not on "Get Started" with no
// workspace. The journey: invitation → Sign Up → signup carries an allow-listed
// return path → the verification email's link (/verify-email#t=…&next=…, the
// page verifies by POST) → sign in → back on the invitation → Join → joined.
//
// Secrets out of URLs (19 Oct 2026): every link carries its token in the
// fragment, and the token is never in the address bar once a page has loaded.
// Links sent before the change (token in the path or query) still work.

const API_BASE = 'http://127.0.0.1:8787/api'
const TOKEN = `cmi_${'d'.repeat(64)}`
const invitee = { id: 'usr_invitee', email: 'casey@example.co.uk', name: 'Casey Analyst', plan: 'free' }
const sharedWorkspace = { id: 'ws_shared', name: 'Black Bull Barbers', role: 'analyst', created_at: '2026-07-08T09:00:00.000Z' }
const json = (body, status = 200) => ({ status, contentType: 'application/json', body: JSON.stringify(body) })

async function installMock(page, state) {
  await page.route(`${API_BASE}/**`, async (route) => {
    const request = route.request()
    const url = new URL(request.url())
    const path = url.pathname.replace(/^\/api/, '')
    const method = request.method()
    const body = method === 'GET' ? null : (() => { try { return JSON.parse(request.postData() || '{}') } catch { return {} } })()
    const signedIn = Boolean(request.headers().authorization)

    if (method === 'GET' && path === `/invitations/${TOKEN}`) {
      return route.fulfill(json({
        workspace_name: 'Black Bull Barbers', invited_by_name: 'Taylor Owner', role: 'analyst',
        expires_at: '2099-01-01T00:00:00Z', status: state.accepted ? 'accepted' : 'pending',
        invited_email_masked: 'c•••y@example.co.uk', signed_in_matches: signedIn ? true : null,
      }))
    }
    if (method === 'POST' && path === `/invitations/${TOKEN}/accept`) {
      state.accepted = true
      return route.fulfill(json({ workspace_id: sharedWorkspace.id, role: 'analyst' }))
    }
    if (method === 'POST' && path === '/auth/signup') { state.signup = body; return route.fulfill(json({ success: true })) }
    if (method === 'POST' && path === '/auth/verify-email') {
      state.verified = body
      return route.fulfill(json(body?.token === 'verify_e2e' ? { success: true, outcome: 'verified' } : { success: false, code: 'invalid' }, body?.token === 'verify_e2e' ? 200 : 400))
    }
    if (method === 'POST' && path === '/auth/login') { state.login = body; return route.fulfill(json({ token: 'token_invitee', user: invitee })) }
    if (method === 'GET' && path === '/auth/me') return route.fulfill(json(invitee))
    if (method === 'GET' && path === '/workspaces') {
      const workspaces = state.accepted ? [sharedWorkspace] : []
      return route.fulfill(json({ workspaces, default_workspace_id: workspaces[0]?.id || null }))
    }
    if (method === 'GET' && path === '/account/usage') return route.fulfill(json({ plan: 'free', features: [], usage: {}, limits: {} }))
    if (path.includes('/notifications')) return route.fulfill(json({ notifications: [], unread_count: 0 }))
    return route.fulfill(json({ error: 'Not available in this check.' }, 404))
  })
}

test('signup → verify → sign in returns to the invitation and joins', async ({ page }) => {
  const state = {}
  await installMock(page, state)

  await page.goto(`/invitations#t=${TOKEN}`)
  await expect(page.getByTestId('invited-address')).toContainText('c•••y@example.co.uk')
  expect(page.url()).not.toContain(TOKEN)
  await expect(page).toHaveURL(/\/invitations$/)
  await page.getByRole('button', { name: /Sign Up & Join Workspace/ }).click()
  await expect(page).toHaveURL(/\/signup$/)

  await page.getByPlaceholder('Jane Smith').fill(invitee.name)
  await page.getByPlaceholder('you@example.com').fill(invitee.email)
  await page.getByPlaceholder('At least 12 characters').fill('correct-horse-battery')
  await page.getByPlaceholder('••••••••').fill('correct-horse-battery')
  await page.getByRole('button', { name: /create account/i }).click()
  await expect(page.getByRole('heading', { name: /check your email/i })).toBeVisible()
  // The signup asked the Worker to carry the invitation through verification.
  expect(state.signup).toMatchObject({ email: invitee.email, return_to: `/invitations/${TOKEN}` })

  // The verification email's link opens the app with both tokens in the fragment.
  // A fresh browser context would hold no remembered token: the link alone must be enough.
  await page.evaluate(() => localStorage.clear())
  await page.goto(`/verify-email#t=verify_e2e&next=${encodeURIComponent(`/invitations/${TOKEN}`)}`)
  await expect(page.getByRole('heading', { name: /email verified/i })).toBeVisible()
  expect(state.verified).toEqual({ token: 'verify_e2e' })
  expect(page.url()).not.toContain(TOKEN)
  expect(page.url()).not.toContain('verify_e2e')
  await page.getByRole('link', { name: /sign in/i }).click()

  await page.getByPlaceholder('you@example.com').fill(invitee.email)
  await page.getByPlaceholder('••••••••').fill('correct-horse-battery')
  await page.getByRole('button', { name: /sign in/i }).click()

  // Back on the invitation — never "Get Started" with no workspace — and the
  // token is not in the address.
  await expect(page).toHaveURL(/\/invitations$/)
  expect(page.url()).not.toContain(TOKEN)
  await expect(page.getByText('Get Started')).toHaveCount(0)
  await page.getByRole('button', { name: 'Join Workspace' }).click()
  await expect(page.getByRole('heading', { name: 'Successfully joined workspace' })).toBeVisible()
  expect(state.accepted).toBe(true)
})

test('links sent before the change still work, and their token leaves the address', async ({ page }) => {
  const state = {}
  await installMock(page, state)
  await page.goto(`/invitations/${TOKEN}`)
  await expect(page.getByTestId('invited-address')).toContainText('c•••y@example.co.uk')
  await expect(page).toHaveURL(/\/invitations$/)
  await page.evaluate(() => localStorage.clear())
  // The older verification redirect carried the invitation in the query.
  await page.goto(`/verify-email?success=1&next=${encodeURIComponent(`/invitations/${TOKEN}`)}`)
  await expect(page.getByRole('heading', { name: /email verified/i })).toBeVisible()
  await expect(page).toHaveURL(/\/verify-email\?success=1$/)
  await page.getByRole('link', { name: /sign in/i }).click()
  await page.getByPlaceholder('you@example.com').fill(invitee.email)
  await page.getByPlaceholder('••••••••').fill('correct-horse-battery')
  await page.getByRole('button', { name: /sign in/i }).click()
  await expect(page).toHaveURL(/\/invitations$/)
  await page.getByRole('button', { name: 'Join Workspace' }).click()
  await expect(page.getByRole('heading', { name: 'Successfully joined workspace' })).toBeVisible()
  expect(page.url()).not.toContain(TOKEN)
})

test('a password reset link keeps its token out of the address, old and new form', async ({ page }) => {
  await installMock(page, {})
  for (const href of ['/reset-password#t=reset_e2e_token', '/reset-password?token=reset_e2e_token']) {
    await page.goto(href)
    await expect(page.getByPlaceholder('At least 12 characters')).toBeVisible()
    await expect(page).toHaveURL(/\/reset-password$/)
  }
})

test('a verification link with a non-invitation `next` is ignored — no open redirect', async ({ page }) => {
  const state = {}
  await installMock(page, state)
  await page.goto(`/verify-email?success=1&next=${encodeURIComponent('https://evil.example/phish')}`)
  await expect(page.getByRole('heading', { name: /email verified/i })).toBeVisible()
  await page.getByRole('link', { name: /sign in/i }).click()
  await page.getByPlaceholder('you@example.com').fill(invitee.email)
  await page.getByPlaceholder('••••••••').fill('correct-horse-battery')
  await page.getByRole('button', { name: /sign in/i }).click()
  await expect(page).toHaveURL(/\/onboarding$/)
  expect(page.url()).not.toContain('evil.example')
})

test('after login, a remembered invitation is offered before onboarding (Join / Not now)', async ({ page }) => {
  const state = {}
  await installMock(page, state)
  await page.goto(`/invitations/${TOKEN}`)               // remembers the live invitation
  await page.getByRole('button', { name: /Sign In & Join Workspace/ }).waitFor()
  await page.goto('/login')                                // signs in WITHOUT the invitation return path
  await page.getByPlaceholder('you@example.com').fill(invitee.email)
  await page.getByPlaceholder('••••••••').fill('correct-horse-battery')
  await page.getByRole('button', { name: /sign in/i }).click()
  await expect(page).toHaveURL(/\/onboarding$/)
  await expect(page.getByTestId('pending-invitation')).toContainText("You've been invited to Black Bull Barbers")
  await expect(page.getByText('Get Started')).toHaveCount(0)
  await page.getByRole('button', { name: 'Not now' }).click()
  await expect(page.getByRole('heading', { name: 'Get Started' })).toBeVisible()
  expect(state.accepted).toBeFalsy()
})
