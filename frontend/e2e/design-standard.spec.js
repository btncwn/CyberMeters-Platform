import { test } from '@playwright/test'
import { API_BASE, installAppMock, seedSession, workspace } from './fixtures/app-mock.js'
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
