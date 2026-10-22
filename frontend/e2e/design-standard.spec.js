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
      // Header = title, purpose, one action (no page tools in the header).
      const head = page.locator('header.cm-module-head')
      await expect(head.getByRole('searchbox')).toHaveCount(0)
      expect(await head.getByRole('button').count()).toBeLessThanOrEqual(1)
      // Findings is counted once on the first screen.
      await expect(page.getByTestId('module-count-findings')).toHaveCount(0)
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

// Workspace detail (founder, 22 Oct 2026): one control per job — Add Domain in
// the header only; one primary action; no raw keys.
for (const [width, height] of [[1440, 900], [390, 844]]) {
  test(`workspace detail meets the design standard at ${width}`, async ({ page, context }) => {
    await page.setViewportSize({ width, height })
    await seedSession(context)
    await installAppMock(page)
    await page.route(`${API_BASE}/workspaces/${workspace.id}`, (route) => route.fulfill(json({
      workspace: { id: workspace.id, name: workspace.name, created_at: workspace.created_at, role: 'owner' },
      stats: { total_domains: 2, total_scans: 9, cyber_score_average: null, posture_established: true, posture_score: 75, posture_rating: 'good', posture_message: null,
        latest_scan: { id: 'scan_e2e', domain: 'blackbullbarbers.co.uk', status: 'completed', scan_quality: 'partial', score: null, created_at: '2026-10-22T11:16:00Z' } },
    })))
    await page.route(`${API_BASE}/workspaces/${workspace.id}/assets/summary`, (route) => route.fulfill(json(null)))
    await page.goto(`/workspaces/${workspace.id}`, { waitUntil: 'networkidle' })
    await page.getByRole('heading', { level: 1 }).first().waitFor()
    await expectOnePrimaryAction(page)
    await expectNoRawKeys(page)
    await expect(page.getByRole('button', { name: 'Add Domain' })).toHaveCount(1)
    await expect(page.getByText('No score yet')).toBeVisible()
  })
}

// Network assets (founder live, 22 Oct 2026 17:50): probe keys in the evidence
// table read as sentences; the Ports limit is shown and enforced.
test('Network assets: no probe key on screen; the port limit cannot be passed', async ({ page, context }) => {
  await seedSession(context)
  await installAppMock(page)
  const ws = `${API_BASE}/workspaces/${workspace.id}`
  const ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 465, 587, 993, 995, 1433, 3306, 3389, 8080]
  await page.route(`${ws}/network-targets*`, (route) => route.fulfill(json({ targets: [{ id: 't1', target: '93.184.216.34', target_type: 'ip', address_count: 1, authorization_status: 'attested', authorized_at: '2026-10-09T00:00:00Z' }], capabilities: { can_manage: true, can_scan: true, collector_available: true, allowed_ports: ports, limits: { max_addresses: 32, max_ports: 16, max_pairs: 256, max_targets: 32 } } })))
  await page.route(`${ws}/network-assets*`, (route) => route.fulfill(json({ assets: [
    { address: '93.184.216.34', port: 22, transport: 'tcp', state: 'open', service: { name: 'ssh', basis: 'unsolicited_tcp_banner', banner_sample: 'SSH-2.0' }, last_seen_at: '2026-10-22T10:00:00Z', last_checked_at: '2026-10-22T10:00:00Z' },
    { address: '93.184.216.34', port: 8080, transport: 'tcp', state: 'timeout', reason: 'connect_timeout', last_checked_at: '2026-10-22T10:00:00Z' },
  ], changes: [], total: 2 })))
  await page.route(`${ws}/network-scans*`, (route) => route.fulfill(json({ scans: [] })))
  await page.goto('/assets')
  await page.getByRole('tab', { name: 'Findings' }).click()
  const fieldset = page.locator('fieldset', { hasText: 'Ports to check' })
  const boxes = fieldset.getByRole('checkbox')
  // count() does not wait: wait until every offered port is on screen first.
  await expect(page.getByTestId('network-ports-count')).toHaveText(/^2 of 16 selected/)
  await expect(boxes).toHaveCount(ports.length)
  for (let i = 0; i < await boxes.count(); i++) { const box = boxes.nth(i); if (await box.isEnabled() && !(await box.isChecked())) await box.check() }
  await expect(page.getByTestId('network-ports-count')).toHaveText(/^16 of 16 selected/)
  await expect(fieldset.locator('input[type="checkbox"]:checked')).toHaveCount(16)
  await page.getByRole('tab', { name: 'Services' }).click()
  await expect(page.getByText('Service banner received')).toBeVisible()
  await expectNoRawKeys(page, '#network-assets')
})

// S1-A declared-range consent (Executive 22 Oct 2026, backend #906): the three
// states a customer can meet on Network assets → Targets.
test.describe('Network assets: declared-range consent', () => {
  const AUTHORITY = { version: 'network-range-2026-10-22', text: 'I confirm that I am authorised by the organisation that owns or operates these addresses to permit CyberMeters to connect to the listed ports on them.', declaration: 'Authorisation declared by the customer; not independently verified by CyberMeters.' }
  const caps = { can_manage: true, can_scan: true, collector_available: true, allowed_ports: [22, 80, 443, 8443], limits: { max_addresses: 32, max_ports: 16, max_pairs: 256, max_targets: 32 }, range_authority: AUTHORITY }
  async function open(page, context, { targets = [], onAdd }) {
    await seedSession(context)
    await installAppMock(page)
    const ws = `${API_BASE}/workspaces/${workspace.id}`
    await page.route(`${ws}/network-targets*`, (route) => route.request().method() === 'POST' ? onAdd(route) : route.fulfill(json({ targets, capabilities: caps })))
    await page.route(`${ws}/network-assets*`, (route) => route.fulfill(json({ assets: [], changes: [], total: 0 })))
    await page.route(`${ws}/network-scans*`, (route) => route.fulfill(json({ scans: [] })))
    await page.goto('/assets')
    await page.getByRole('tab', { name: 'Findings' }).click()
  }
  async function add(page) {
    await page.getByLabel(/IP address or CIDR/).fill('198.51.100.7')
    await page.getByRole('checkbox', { name: /I own this address range/ }).check()
    await page.getByRole('button', { name: 'Add network target' }).click()
  }
  const refusal = (kind) => (route) => route.fulfill({ status: 422, contentType: 'application/json', body: JSON.stringify({ error: 'network_target_not_observed', range_consent: kind }) })

  test('required: the grant form, verbatim statement, one Grant button that unlocks only when complete', async ({ page, context }) => {
    let body = null
    await open(page, context, { onAdd: (route) => { const sent = route.request().postDataJSON(); if (!sent.range_consent) return refusal('required')(route); body = sent; return route.fulfill(json({ target: { id: 't2', target: sent.target } }, 201)) } })
    await add(page)
    const form = page.getByRole('form', { name: 'Grant authorisation' })
    await expect(form.getByTestId('range-authority-text')).toHaveText(AUTHORITY.text)
    await expect(form.getByText(`Statement version ${AUTHORITY.version}`)).toBeVisible()
    const grant = form.getByRole('button', { name: 'Grant authorisation' })
    await expect(grant).toBeDisabled()
    await form.getByRole('checkbox', { name: '443', exact: true }).check()
    await form.getByLabel('Your name').fill('Taylor Owner')
    await form.getByLabel('Your title').fill('Director')
    await form.getByRole('checkbox', { name: 'I confirm the statement above' }).check()
    await grant.click()
    await expect(page.getByText('Authorisation recorded and target saved. No check was started.')).toBeVisible()
    expect(body.range_consent).toEqual({ ports: [443], signer_name: 'Taylor Owner', signer_title: 'Director', authority_confirmed: true, authority_version: AUTHORITY.version })
    await expectNoRawKeys(page, '#network-assets')
  })

  test('not_grantable_shared: the refusal sentence and no form', async ({ page, context }) => {
    await open(page, context, { onAdd: refusal('not_grantable_shared') })
    await add(page)
    await expect(page.getByTestId('range-consent-refused')).toContainText('shared provider infrastructure')
    await expect(page.getByRole('form', { name: 'Grant authorisation' })).toHaveCount(0)
    await expectNoRawKeys(page, '#network-assets')
  })

  test('a target under a grant: declared, not verified; Revoke is secondary and asks for an optional reason', async ({ page, context }) => {
    const granted = { id: 't1', target: '198.51.100.7', target_type: 'ip', address_count: 1, authorization_status: 'attested', authorized_at: '2026-10-22T20:00:00Z', range_consent: { id: 'nrc_1', status: 'active', ports: [443], granted_at: '2026-10-22T20:00:00Z', signer: { name: 'Taylor Owner', title: 'Director' } } }
    let revoked = null
    await open(page, context, { targets: [granted], onAdd: (route) => route.fulfill(json({})) })
    await page.route(`${API_BASE}/workspaces/${workspace.id}/network-range-consents/nrc_1/revoke`, (route) => { revoked = route.request().postDataJSON(); return route.fulfill(json({})) })
    const cell = page.getByTestId('range-consent-active')
    await expect(cell).toContainText('Authorised by declared range consent — not independently verified by CyberMeters')
    await expect(cell.getByRole('button', { name: 'Revoke' })).toHaveClass(/btn-secondary/)
    await cell.getByRole('button', { name: 'Revoke' }).click()
    const dialog = page.getByRole('alertdialog')
    await dialog.getByRole('textbox').fill('Contract ended')
    await dialog.getByRole('button', { name: 'Revoke' }).click()
    await expect.poll(() => revoked).toEqual({ reason: 'Contract ended' })
  })
})
