import { expect, test } from '@playwright/test'

const API_BASE = 'http://127.0.0.1:8787/api'

const user = {
  id: 'usr_e2e',
  email: 'owner@example.co.uk',
  name: 'E2E Owner',
  plan: 'professional',
}

const workspace = {
  id: 'ws_e2e',
  name: 'Black Bull Barbers',
  role: 'owner',
  created_at: '2026-07-08T09:00:00.000Z',
}

const domain = {
  id: 'domain_e2e',
  domain_id: 'domain_e2e',
  name: 'blackbullbarbers.co.uk',
  domain: 'blackbullbarbers.co.uk',
  verification_status: 'verified',
  verification_token: 'cm-verify-e2e',
  created_at: '2026-07-08T09:05:00.000Z',
}

const scan = {
  id: 'scan_e2e',
  scan_id: 'scan_e2e',
  domain: domain.domain,
  status: 'completed',
  score: 82,
  rating: 'good',
  created_at: '2026-07-08T09:10:00.000Z',
}

const report = {
  scan_id: scan.id,
  domain: domain.domain,
  score: 82,
  risk_level: 'good',
  started_at: '2026-07-08T09:10:00.000Z',
  completed_at: '2026-07-08T09:12:00.000Z',
  summary: {
    total_findings: 1,
    critical: 0,
    high: 0,
    medium: 1,
    low: 0,
    info: 0,
  },
  findings: [
    {
      id: 'finding_dmarc_policy',
      title: 'DMARC policy is monitoring only',
      severity: 'medium',
      category: 'email',
      finding_type: 'finding',
      score_impact: -6,
      confidence: 90,
      description: 'Email protection can be strengthened.',
      recommendation: 'Move DMARC towards enforcement when ready.',
      evidence: [{ type: 'dns_txt', label: '_dmarc.blackbullbarbers.co.uk', value: 'p=none', source: 'dns' }],
    },
  ],
  modules: {
    email_security: {
      dmarc: { present: true, policy: 'none' },
      dmarc_detail: { raw: 'v=DMARC1; p=none; rua=mailto:dmarc@blackbullbarbers.co.uk', valid: true, policy: 'none' },
      spf: { present: true },
      spf_detail: { raw: 'v=spf1 include:_spf.google.com ~all', valid: true, all_mechanism: '~all' },
      dkim_detail: { status: 'detected' },
      policy_journey: {
        stage: 'monitoring',
        label: 'Monitoring',
        business_risk: 'Your domain is receiving DMARC reports.',
        next_step: 'Review senders before moving to quarantine.',
      },
      remediation_actions: [],
      applicability: { applicable: true },
    },
  },
}

const executiveReport = {
  domain: { name: domain.domain },
  scan: { id: scan.id, status: 'completed', score: 82, rating: 'good' },
  summary: {
    score: 82,
    risk_level: 'good',
    verified_findings_count: 1,
    executive_summary: 'CyberMeters found one email protection improvement to review.',
  },
  engines: [
    {
      id: 'email',
      title: 'Email Protection',
      score: 82,
      risk_level: 'good',
      findings: report.findings,
    },
  ],
  verified_findings: report.findings,
}

function json(body, status = 200) {
  return {
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  }
}

function requestJson(request) {
  try {
    return request.postDataJSON()
  } catch {
    return null
  }
}

function domainForState(state) {
  return {
    ...domain,
    verification_status: state.domainVerified ? 'verified' : 'pending',
  }
}

async function installApiMock(page, state) {
  await page.route(`${API_BASE}/**`, async route => {
    const request = route.request()
    const url = new URL(request.url())
    const path = url.pathname.replace(/^\/api/, '')
    const method = request.method()
    const body = method === 'GET' ? null : requestJson(request)

    if (method === 'POST' && path === '/auth/signup') {
      state.signup = body
      return route.fulfill(json({ success: true }))
    }

    if (method === 'POST' && path === '/auth/login') {
      state.login = body
      return route.fulfill(json({ token: 'token_e2e', user }))
    }

    if (method === 'GET' && path === '/auth/me') {
      return route.fulfill(json(user))
    }

    if (method === 'GET' && path === '/workspaces') {
      const workspaces = state.workspaceCreated ? [workspace] : []
      return route.fulfill(json({ workspaces, default_workspace_id: workspaces[0]?.id || null }))
    }

    if (method === 'POST' && path === '/workspaces') {
      state.workspaceCreated = true
      state.workspacePayload = body
      return route.fulfill(json({ workspace }, 201))
    }

    if (method === 'GET' && path === `/workspaces/${workspace.id}/domains`) {
      return route.fulfill(json({ domains: state.domainAdded ? [domainForState(state)] : [] }))
    }

    if (method === 'POST' && path === `/workspaces/${workspace.id}/domains`) {
      state.domainAdded = true
      state.domainPayload = body
      return route.fulfill(json({ domain: domainForState(state) }, 201))
    }

    if (method === 'GET' && path === `/workspaces/${workspace.id}/reports`) {
      return route.fulfill(json({ reports: [] }))
    }

    if (method === 'GET' && path === '/scans' && url.searchParams.get('workspace_id') === workspace.id) {
      return route.fulfill(json({ scans: state.scanStarted ? [scan] : [] }))
    }

    if (method === 'POST' && path === `/domains/${domain.id}/verification`) {
      return route.fulfill(json({ token: domain.verification_token, dns: { host: `_cybermeters.${domain.domain}`, value: `cybermeters-verification=${domain.verification_token}` } }))
    }

    if (method === 'POST' && path === `/domains/${domain.id}/verify`) {
      state.domainVerified = true
      return route.fulfill(json({ success: true, message: 'Domain verified' }))
    }

    if (method === 'GET' && path === `/domains/${domain.id}`) {
      return route.fulfill(json({ domain: domainForState(state) }))
    }

    if (method === 'POST' && path === '/scan') {
      state.scanStarted = true
      state.scanPayload = body
      return route.fulfill(json({ scan }, 201))
    }

    if (method === 'GET' && path === `/scans/${scan.id}`) {
      return route.fulfill(json({ scan }))
    }

    if (method === 'GET' && path === `/scans/${scan.id}/report`) {
      return route.fulfill(json(report))
    }

    if (method === 'GET' && path === `/scans/${scan.id}/executive-report-v2`) {
      return route.fulfill(json(executiveReport))
    }

    if (method === 'GET' && path === `/workspaces/${workspace.id}/domains/${domain.domain}/dmarc-summary`) {
      return route.fulfill(json({ traffic: { total_messages: 24, pass_rate: 92 }, domain: domain.domain }))
    }

    if (method === 'GET' && path === `/workspaces/${workspace.id}/domains/${domain.domain}/email-senders`) {
      return route.fulfill(json({ senders: [], domain: domain.domain }))
    }

    if (method === 'GET' && path === `/workspaces/${workspace.id}/domains/${domain.domain}/bec-exposure`) {
      return route.fulfill(json({ exposure_level: 'moderate', score: 42 }))
    }

    if (method === 'GET' && path === `/workspaces/${workspace.id}/domains/${domain.domain}/dmarc-ingest-endpoint`) {
      return route.fulfill(json({ endpoint: null }))
    }

    if (method === 'GET' && path === `/workspaces/${workspace.id}/domains/${domain.domain}/dmarc/hosted`) {
      return route.fulfill(json({ hosted: false, status: 'not_configured' }))
    }

    if (method === 'POST' && path === `/workspaces/${workspace.id}/domains/${domain.domain}/dmarc/verify-dns`) {
      return route.fulfill(json({ status: 'ok' }))
    }

    if (method === 'GET' && path === `/workspaces/${workspace.id}/domains/${domain.domain}/remediations`) {
      return route.fulfill(json({ remediations: [] }))
    }

    if (method === 'GET' && path === `/workspaces/${workspace.id}/subscription`) {
      return route.fulfill(json({
        plan: 'starter',
        status: 'active',
        trial_active: false,
        subscription_active: true,
        limits: { domains: 1, users: 3, history_days: 90 },
        features: ['scheduled_scans', 'alerts', 'pdf_reports', 'business_risk_score'],
      }))
    }

    if (method === 'POST' && path === `/workspaces/${workspace.id}/billing/checkout`) {
      state.checkoutPayload = body
      return route.fulfill(json({ url: '/checkout/success?success=true', session_id: 'cs_e2e' }))
    }

    if (method === 'POST' && path === `/workspaces/${workspace.id}/delete-request`) {
      state.deleteRequested = true
      return route.fulfill(json({ request_id: 'delreq_e2e', status: 'pending' }))
    }

    if (path.includes('/notifications')) {
      return route.fulfill(json({ workspace_id: workspace.id, unread_count: 0, count: 0, notifications: [] }))
    }

    return route.fulfill(json({ error: `Unhandled E2E mock: ${method} ${path}` }, 404))
  })
}

test('customer lifecycle: signup, onboarding, scan, email protection, billing, deletion', async ({ page }) => {
  const state = {
    workspaceCreated: false,
    domainAdded: false,
    domainVerified: false,
    scanStarted: false,
    deleteRequested: false,
  }
  await installApiMock(page, state)

  await page.goto('/signup?domain=HTTPS://www.BlackBullBarbers.co.uk/path?q=1')
  await expect(page.getByText(/blackbullbarbers\.co\.uk/i)).toBeVisible()
  await page.getByPlaceholder('Jane Smith').fill(user.name)
  await page.getByPlaceholder('you@example.com').fill(user.email)
  await page.getByPlaceholder('At least 12 characters').fill('correct-horse-battery')
  await page.getByPlaceholder('••••••••').fill('correct-horse-battery')
  await page.getByRole('button', { name: /create account/i }).click()
  await expect(page.getByRole('heading', { name: /check your email/i })).toBeVisible()
  expect(state.signup).toMatchObject({ email: user.email, name: user.name })

  await page.goto('/verify-email?success=1')
  await expect(page.getByRole('heading', { name: /email verified/i })).toBeVisible()

  await page.getByRole('link', { name: /sign in/i }).click()
  await page.getByPlaceholder('you@example.com').fill(user.email)
  await page.getByPlaceholder('••••••••').fill('correct-horse-battery')
  await page.getByRole('button', { name: /sign in/i }).click()
  await expect(page).toHaveURL(/\/onboarding$/)

  await page.getByPlaceholder('Company or customer name').fill(workspace.name)
  await page.getByRole('button', { name: /create workspace/i }).click()
  await expect(page.getByText(new RegExp(`Active workspace:.*${workspace.name}`, 'i'))).toBeVisible()

  await expect(page.locator(`input[value="${domain.domain}"]`)).toBeVisible()
  await page.getByRole('button', { name: /add domain/i }).click()
  await expect(page.getByText(new RegExp(`First domain:.*${domain.domain}`, 'i'))).toBeVisible()

  await page.getByRole('button', { name: /get dns record/i }).click()
  await expect(page.getByText(`cybermeters-verification=${domain.verification_token}`)).toBeVisible()
  await page.getByRole('button', { name: /verify ownership/i }).click()
  await expect(page.getByText(/domain ownership is verified/i)).toBeVisible()

  await page.getByRole('button', { name: /run first cyber mot/i }).click()
  await expect(page.getByRole('link', { name: /open executive report/i })).toBeVisible()
  expect(state.scanPayload).toMatchObject({ domain: domain.domain, workspace_id: workspace.id })

  await page.getByRole('link', { name: /open executive report/i }).click()
  await expect(page).toHaveURL(/\/scans\/scan_e2e$/)
  await expect(page.getByRole('heading', { name: domain.domain })).toBeVisible()
  await expect(page.getByText(/1 verified findings/i)).toBeVisible()
  await page.getByRole('button', { name: /technical details/i }).click()
  await expect(page.getByText(/DMARC policy is monitoring only/i)).toBeVisible()

  await page.goto('/ws/email-protection')
  await expect(page.getByText(/DMARC Policy Journey/i)).toBeVisible()
  await expect(page.getByText('You are here · Monitoring')).toBeVisible()

  await page.goto('/billing')
  await expect(page.getByRole('heading', { name: /subscription/i })).toBeVisible()
  await page.getByRole('button', { name: /upgrade to professional/i }).click()
  await expect(page).toHaveURL(/\/checkout\/success\?success=true$/)
  expect(state.checkoutPayload).toMatchObject({ plan: 'professional', interval: 'monthly' })

  await page.goto('/account/privacy')
  await page.getByRole('button', { name: /request deletion/i }).last().click()
  await page.getByPlaceholder(workspace.name).fill(workspace.name)
  await page.getByRole('button', { name: /^request deletion$/i }).last().click()
  await expect(page.getByText(/deletion requested/i)).toBeVisible()
  expect(state.deleteRequested).toBe(true)
})
