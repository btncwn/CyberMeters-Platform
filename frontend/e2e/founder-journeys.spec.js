import { test, expect } from '@playwright/test'
import { API_BASE, installAppMock, seedSession, motDomains, workspace, domain } from './fixtures/app-mock.js'

// Founder usability pass (21 Oct 2026). Without help, the founder could not
// start a scan, step DMARC, set up MTA-STS or reject a Shadow IT item. Each
// journey starts on the Overview, is driven by accessible names only, and must
// finish in at most three clicks.

const json = (body, status = 200) => ({ status, contentType: 'application/json', body: JSON.stringify(body) })
const enc = encodeURIComponent(domain.domain)
const step = (key, label) => ({ key, label, policy: key.split('_')[0] })

// The Email Protection area with the two registry-mapped findings the
// founder's journeys start from, on top of the shared eight-area fixture.
const domainsWithEmailWork = motDomains.map((d) => d.domain_key !== 'email_protection' ? d : {
  ...d, state: 'issue_detected', highest_severity: 'medium', finding_count: 2,
  finding_details: [
    { finding_id: 'email_intel_mta_sts_missing', status: 'resolved', customer_title: 'Publish MTA-STS', recommended_action: 'Publish an MTA-STS policy file and the supporting TXT record.' },
    { finding_id: 'email_dmarc_policy_none', status: 'resolved', customer_title: 'Strengthen DMARC enforcement', recommended_action: 'Move the requested policy towards quarantine or reject when ready.' },
  ],
})

async function installJourneyMock(page) {
  const calls = []
  await installAppMock(page)
  // Registered after the shared mock, so these answer first.
  await page.route(`${API_BASE}/**`, async (route) => {
    const req = route.request()
    const p = new URL(req.url()).pathname.replace(/^\/api/, '')
    const m = req.method()
    const body = req.postData() ? JSON.parse(req.postData()) : null
    if (m !== 'GET') calls.push({ m, p, body })
    if (p === `/workspaces/${workspace.id}/security-domains`) return route.fulfill(json({ workspace_id: workspace.id, cyber_mot_domains: domainsWithEmailWork }))
    if (p === '/scan' && m === 'POST') return route.fulfill(json({ scan_id: 'scan_journey', status: 'queued' }, 202))
    if (p === '/scans/scan_journey') return route.fulfill(json({ scan: { id: 'scan_journey', status: 'running' } }))
    if (p === `/workspaces/${workspace.id}/domains`) return route.fulfill(json({ domains: [{ ...domain, verified_at: '2026-07-08T09:06:00.000Z' }] }))
    if (p === `/workspaces/${workspace.id}/domains/${enc}/hosted-dmarc` && m === 'GET') return route.fulfill(json({ policy_management_available: true, record: {
      id: 'hd_1', domain: domain.domain, status: 'connected', record_type: 'dmarc', cname_name: `_dmarc.${domain.domain}`,
      policy_step: step('quarantine', 'Quarantine requested'), next_step: step('reject', 'Rejection requested'),
      previous_step: step('none', 'Monitoring only'), ladder: [step('none', 'Monitoring only'), step('quarantine', 'Quarantine requested'), step('reject', 'Rejection requested')],
    } }))
    if (p === `/workspaces/${workspace.id}/domains/${enc}/hosted-dmarc` && m === 'PUT') return route.fulfill(json({ record: { id: 'hd_1', domain: domain.domain, status: 'connected', policy_step: step('none', 'Monitoring only') } }))
    if (p === `/workspaces/${workspace.id}/domains/${enc}/hosted-mta-sts` && m === 'GET') return route.fulfill(json({ record: null }))
    if (p === `/workspaces/${workspace.id}/domains/${enc}/hosted-mta-sts` && m === 'POST') return route.fulfill(json({ record: { id: 'hm_1', status: 'awaiting_cname', cname_name: `_mta-sts.${domain.domain}` } }))
    if (p === `/workspaces/${workspace.id}/domains/${enc}/dmarc-ingest-endpoint`) return route.fulfill(json({ endpoint: { last_inbound_at: '2026-10-20T08:00:00Z' } }))
    if (/\/shadow-it\/items\/[^/]+\/actions$/.test(p) || /\/shadow-it\/inventory\/[^/]+\/action/.test(p)) return route.fulfill(json({ ok: true }))
    return route.fallback()
  })
  return calls
}

async function clicks(page, steps) {
  let n = 0
  for (const s of steps) { await s(); n += 1 }
  return n
}

for (const [width, height] of [[1440, 900], [390, 844]]) {
  test.describe(`founder journeys at ${width}`, () => {
    test.use({ viewport: { width, height } })
    test.beforeEach(async ({ context }) => { await seedSession(context) })

    test('start a scan from the Overview in one click', async ({ page }) => {
      const calls = await installJourneyMock(page)
      await page.goto('/dashboard')
      // The Overview's one scan control: the field prefilled with the verified domain + Scan.
      await expect(page.getByRole('textbox', { name: 'Domain to scan' })).toHaveValue(domain.domain)
      const n = await clicks(page, [() => page.getByRole('button', { name: 'Scan', exact: true }).click()])
      await expect(page.getByRole('status').filter({ hasText: 'Scan started — results in about 2–3 minutes.' })).toBeVisible()
      expect(calls.filter((c) => c.p === '/scan')).toEqual([{ m: 'POST', p: '/scan', body: { domain: domain.domain, workspace_id: workspace.id } }])
      expect(n).toBeLessThanOrEqual(3)
    })

    test('step DMARC back one level from the Overview in three clicks', async ({ page }) => {
      const calls = await installJourneyMock(page)
      await page.goto('/dashboard')
      const n = await clicks(page, [
        () => page.getByRole('link', { name: 'Review DMARC policy steps: Strengthen DMARC enforcement' }).click(),
        () => page.getByRole('button', { name: 'Step back one level' }).click(),
        () => page.getByTestId('app-dialog').getByRole('button', { name: 'Step back to Monitoring only' }).click(),
      ])
      await expect.poll(() => calls.filter((c) => c.m === 'PUT' && c.p.endsWith('/hosted-dmarc')).map((c) => c.body.step)).toEqual(['none'])
      expect(n).toBeLessThanOrEqual(3)
    })

    test('set up MTA-STS from the Overview in two clicks', async ({ page }) => {
      const calls = await installJourneyMock(page)
      await page.goto('/dashboard')
      const n = await clicks(page, [
        () => page.getByRole('link', { name: 'Set up MTA-STS' }).click(),
        () => page.getByRole('button', { name: 'Set up MTA-STS' }).click(),
      ])
      await expect.poll(() => calls.filter((c) => c.m === 'POST' && c.p.endsWith('/hosted-mta-sts')).length).toBe(1)
      expect(n).toBeLessThanOrEqual(3)
    })

    test('reject a Shadow IT item from the Overview in three clicks', async ({ page }) => {
      const calls = await installJourneyMock(page)
      await page.goto('/dashboard')
      await page.getByRole('link', { name: /^Classify: / }).waitFor()
      let n = await clicks(page, [
        () => page.getByRole('link', { name: /^Classify: / }).click(),
        () => page.getByRole('button', { name: 'Reject Mailchimp' }).click(),
      ])
      await page.getByTestId('app-dialog').getByRole('textbox').fill('Not used by us')
      n += await clicks(page, [() => page.getByTestId('app-dialog').getByRole('button', { name: 'Reject' }).click()])
      await expect.poll(() => calls.filter((c) => c.body?.action === 'reject').map((c) => c.body)).toEqual([{ action: 'reject', reason: 'Not used by us' }])
      expect(n).toBeLessThanOrEqual(3)
    })
  })
}
