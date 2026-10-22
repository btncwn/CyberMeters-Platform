import { expect, test } from '@playwright/test'
import { API_BASE, installAppMock, report, scan, seedSession, workspace } from './fixtures/app-mock.js'
import { expectNoOverlap, expectNoRawKeys, expectOnePrimaryAction } from './fixtures/design-guards.js'

// Design standard, page group 1: the case page (founder, 21 Oct 2026).

const json = (body) => ({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })
const caseBody = {
  case: {
    case_id: 'mc-0de966005a15', workspace_id: workspace.id, domain_key: 'attack_surface', case_type: 'asm_exposure',
    status: 'open', canonical_phase: 'detected', verification_support: 'automated', domain: 'blackbullbarbers.co.uk',
    title: 'Admin interface exposed', display_title: 'Admin interface exposed on admin.blackbullbarbers.co.uk',
    summary: 'An administration interface answered publicly on admin.blackbullbarbers.co.uk.',
    severity: 'high', source_finding_type: 'asset_exposure_admin_interface', remediation_id: 'asm.exposure.admin',
    asset_ref: 'admin.blackbullbarbers.co.uk', source_scan_id: 'scan_e2e', reopened_count: 0,
    created_at: '2026-10-21T15:23:00Z', updated_at: '2026-10-21T15:24:00Z',
    guidance: { remediation: { title: 'Restrict the admin interface', explanation: 'The interface is reachable from the internet.', recommended_action: 'Put it behind a VPN or an allow-list.', owner_label: 'Your IT provider', effort: 'low' } },
  },
  events: [
    { id: 'e1', action: 'case_created', actor_type: 'system', created_at: '2026-10-21T15:23:00Z' },
    { id: 'e2', action: 'monitoring_changed', actor_type: 'system', created_at: '2026-10-21T15:24:00Z' },
  ],
  can_manage: true,
  available_transitions: [{ target_status: 'triage', label: 'Begin triage', endpoint: 'attack_surface', requires_owner: false, requires_note: false, requires_expiry: false, requires_attestation: false }],
}

for (const [width, height] of [[1440, 900], [390, 844]]) {
  test(`case page meets the design standard at ${width}`, async ({ page, context }) => {
    await page.setViewportSize({ width, height })
    await seedSession(context)
    await installAppMock(page)
    await page.route(`${API_BASE}/workspaces/${workspace.id}/cases/mc-0de966005a15`, (route) => route.fulfill(json(caseBody)))
    await page.goto('/ws/cases/mc-0de966005a15')
    await page.getByRole('button', { name: 'Begin triage' }).waitFor()
    await expectOnePrimaryAction(page)
    await expectNoRawKeys(page)
    await expectNoOverlap(page, '[data-testid="case-history"] > li')
  })
}

// Design standard, page groups 2–3: the eight area pages.
const AREA_PAGES = ['/ws/email-protection', '/assets', '/ws/website-security', '/ws/identity-exposure', '/ws/shadow-it', '/ws/certificates', '/ws/brand-monitoring', '/ws/cyber-essentials']
const SCAN_CONTROL = /^(Scan now|Run a scan|Run a fresh scan|Run scan to re-check)$/

for (const [width, height] of [[1440, 900], [390, 844]]) {
  test(`area pages meet the design standard at ${width}`, async ({ page, context }) => {
    test.setTimeout(180_000)
    await page.setViewportSize({ width, height })
    await seedSession(context)
    await installAppMock(page)
    for (const route of AREA_PAGES) {
      await page.goto(route, { waitUntil: 'networkidle' })
      await page.getByTestId('module-next-title').waitFor()
      await page.waitForTimeout(300)
      // One control per job: never two buttons that start a scan.
      expect(await page.getByRole('button', { name: SCAN_CONTROL }).count(), `${route}: scan controls`).toBeLessThanOrEqual(1)
      // One word = one place: the area tab is not a second "Overview".
      expect(await page.getByRole('tab', { name: 'Overview' }).count(), `${route}: Overview tab`).toBe(0)
      await expectOnePrimaryAction(page)
      await expectNoRawKeys(page)
    }
  })
}

// Design standard, Overview (founder, 21 Oct 2026): ONE scan-starting control.
const OVERVIEW_SCAN = /^(Scan|Scan now|Run a scan|Run a fresh scan|Start a security check)$/
for (const [width, height] of [[1440, 900], [390, 844]]) {
  test(`Overview has exactly one scan-starting control at ${width}`, async ({ page, context }) => {
    await page.setViewportSize({ width, height })
    await seedSession(context)
    await installAppMock(page)
    await page.route(`${API_BASE}/workspaces/${workspace.id}/domains`, (route) => route.fulfill(json({ domains: [{ domain_id: 'dom_e2e', domain: 'blackbullbarbers.co.uk', verification_status: 'verified', verified_at: '2026-07-08T09:06:00Z' }] })))
    await page.goto('/dashboard', { waitUntil: 'networkidle' })
    await page.getByRole('textbox', { name: 'Domain to scan' }).waitFor()
    const buttons = await page.getByRole('button', { name: OVERVIEW_SCAN }).count()
    const links = await page.getByRole('link', { name: OVERVIEW_SCAN }).count()
    expect(buttons + links, 'scan-starting controls on the Overview').toBe(1)
    await expect(page.getByRole('textbox', { name: 'Domain to scan' })).toHaveValue('blackbullbarbers.co.uk')
    await expect(page.getByRole('button', { name: /Reload results/ })).toHaveCount(0)
    await expectNoRawKeys(page)
  })
}

// Design standard, Operations and Reports groups: header = title + purpose + at
// most one primary action; one status word per row; human dates and labels.
for (const [width, height] of [[1440, 900], [390, 844]]) {
  test(`Operations meets the design standard at ${width}`, async ({ page, context }) => {
    await page.setViewportSize({ width, height })
    await seedSession(context)
    await installAppMock(page)
    await page.goto('/ws/cases', { waitUntil: 'networkidle' })
    await page.getByTestId('case-row').first().waitFor()
    await expectOnePrimaryAction(page)
    await expectNoRawKeys(page)
    await expectNoOverlap(page, '[data-testid="case-row"]')
    const row = await page.getByTestId('case-row').first().innerText()
    expect(row).not.toMatch(/\d{4}-\d{2}-\d{2}/)
    // An "Assigned" step never sits beside "Unassigned".
    expect(/Assigned/.test(row) && /Unassigned/.test(row)).toBe(false)
    await expect(page.getByLabel('Filter cases by area')).toBeVisible()
    // The header block (title + purpose) holds no links; related pages sit below the board.
    await expect(page.locator('main h1').locator('xpath=..').getByRole('link')).toHaveCount(0)
    await expect(page.getByRole('link', { name: 'Open related changes' })).toBeVisible()
  })

  test(`Reports meets the design standard at ${width}`, async ({ page, context }) => {
    await page.setViewportSize({ width, height })
    await seedSession(context)
    await installAppMock(page)
    await page.goto('/reports', { waitUntil: 'networkidle' })
    await expect(page.getByRole('heading', { level: 1, name: 'Reports' })).toBeVisible()
    await expectOnePrimaryAction(page)
    await expectNoRawKeys(page)
    await expect(page.getByText(/^completed$/)).toHaveCount(0)
    await expect(page.getByRole('button', { name: 'Download PDF' }).first()).toBeVisible()
    await expect(page.getByRole('button', { name: /^PDF$|^Refresh$/ })).toHaveCount(0)
  })
}

// Scan report (Executive 21 Oct, sheshire.co.uk first scan): a degraded scan
// reads in sentences, the duration is not shifted by an hour, and an absent
// header behind a protection layer says "Validation uncertain", not "Missing".
const degradedScan = { ...scan, created_at: '2026-10-21 19:30:00', scan_quality: 'degraded' }
const degradedReport = {
  ...report, completed_at: '2026-10-21T19:31:22.000Z',
  scan_quality: {
    status: 'degraded', warnings: ['Module incomplete: tls_assessment'], modules_skipped: [],
    modules_incomplete: [{ module: 'subdomain_takeover', incomplete_reason: 'host_probe_unconfirmed' }, { module: 'technology_detection' }],
  },
  modules: { ...(report.modules || {}), ssl: { https_available: true }, headers: { accessible: true, validation_uncertain: true, present: ['x-content-type-options'], values: { 'x-content-type-options': 'nosniff' } } },
}
for (const [width, height] of [[1440, 900], [390, 844]]) {
  test(`a degraded scan report reads in plain words at ${width}`, async ({ page, context }) => {
    await page.setViewportSize({ width, height })
    await seedSession(context)
    await installAppMock(page)
    await page.route(`${API_BASE}/**`, (route) => {
      const p = new URL(route.request().url()).pathname.replace(/^\/api/, '')
      if (p === `/scans/${scan.id}/report`) return route.fulfill(json(degradedReport))
      if (p === `/scans/${scan.id}`) return route.fulfill(json({ scan: degradedScan, report_availability: { status: 'report_ready' } }))
      return route.fallback()
    })
    await page.goto(`/scans/${scan.id}`, { waitUntil: 'networkidle' })
    await expect(page.getByText('Scan coverage incomplete')).toBeVisible()
    await expectNoRawKeys(page)
    await expect(page.locator('main')).not.toContainText('61m')
    await expect(page.locator('main')).toContainText('1m 22s')
    const headersCard = page.locator('.card').filter({ hasText: 'Security Headers' })
    await expect(headersCard.getByTestId('headers-validation-uncertain')).toBeVisible()
    await expect(headersCard.getByText('Missing', { exact: true })).toHaveCount(0)
  })
}

// S1-A Active Checks permission: one primary action ("Authorise"), no raw
// check ids, the receipt's rows never overlap.
const consentPayload = {
  consents: [{ id: 'acc_1', domain: 'blackbullbarbers.co.uk', hosts: ['mail.blackbullbarbers.co.uk'], checks: ['mail_open_relay', 'tls_intrusive_heartbleed'],
    granted_at: '2026-10-22T08:00:00.000Z', signer: { name: 'Taylor Owner', title: 'Director', workspace_role: 'owner', user_id: 'usr_e2e' },
    authority_version: 'active-checks-2026-10-22', status: 'active', revoked_at: null, revoked_by: null }],
  catalogue: [
    { id: 'tls_intrusive_heartbleed', label: 'TLS Heartbleed test' }, { id: 'tls_intrusive_robot', label: 'TLS ROBOT test' },
    { id: 'tls_intrusive_ccs', label: 'TLS CCS injection test' }, { id: 'takeover_active_confirm', label: 'Subdomain takeover confirmation (no claim is made)' },
    { id: 'dns_open_resolver', label: 'Open DNS resolver' }, { id: 'mail_open_relay', label: 'Open mail relay (no message is delivered)' },
    { id: 'mail_starttls_strip', label: 'Mail accepted without STARTTLS' }, { id: 'mail_spoof_resistance', label: 'Spoofed message to your designated seed mailbox' },
  ],
  authority: { version: 'active-checks-2026-10-22', text: 'I confirm that I am authorised by the organisation that owns this domain to permit CyberMeters to run the active checks listed here against the listed hosts, on demand, until I or another authorised person revokes this permission. I understand that these checks connect to these systems and may be recorded in their logs.' },
  capabilities: { can_manage: true },
}
for (const [width, height] of [[1440, 900], [390, 844]]) {
  test(`Active Checks permission meets the design standard at ${width}`, async ({ page, context }) => {
    await page.setViewportSize({ width, height })
    await seedSession(context)
    await installAppMock(page)
    await page.route(`${API_BASE}/workspaces/${workspace.id}/active-check-consents`, (route) => route.fulfill(json(consentPayload)))
    await page.route(`${API_BASE}/workspaces/${workspace.id}/domains`, (route) => route.fulfill(json({ domains: [{ domain_id: 'dom_e2e', domain: 'blackbullbarbers.co.uk', verification_status: 'verified', verified_at: '2026-07-08T09:06:00Z' }] })))
    await page.goto('/ws/active-checks/permission', { waitUntil: 'networkidle' })
    await page.getByTestId('consent-receipt').waitFor()
    await expectOnePrimaryAction(page)
    await expectNoRawKeys(page)
    await expectNoOverlap(page, '[data-testid="consent-receipt"] dl')
    await expect(page.getByRole('button', { name: 'Authorise' })).toBeDisabled()
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width)
  })
}
