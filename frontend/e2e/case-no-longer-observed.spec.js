import { expect, test } from '@playwright/test'
import { API_BASE, installAppMock, seedSession, workspace } from './fixtures/app-mock.js'
import { expectNoRawKeys, expectOnePrimaryAction } from './fixtures/design-guards.js'

// The HSTS case flow (Executive 22 Oct 2026, 22:05): a Website Security case
// whose condition CyberMeters no longer observes, walked from detected to
// verified against a stateful mock that follows the backend's own machine
// (BASE_CASE_MACHINE) and labels (BASE_TRANSITION_META). No auto-close: the
// customer moves the case to awaiting verification; CyberMeters concludes
// verified itself (automated support is never a customer button).

const json = (body, status = 200) => ({ status, contentType: 'application/json', body: JSON.stringify(body) })
const SENTENCE = 'CyberMeters no longer observes this issue (last check 22 Oct 2026). Mark the case ready to verify and the next scan will confirm it.'

// The customer path for a base case with automated verification support.
const NEXT = {
  detected: { target_status: 'triaged', label: 'Begin triage' },
  triaged: { target_status: 'assigned', label: 'Move to Assigned' },
  assigned: { target_status: 'approved', label: 'Approve to act' },
  approved: { target_status: 'action_in_progress', label: 'Start remediation' },
  action_in_progress: { target_status: 'awaiting_verification', label: 'Submit for verification' },
}
// The backend also advertises the legal rollback while waiting (C-37 row B06N).
const ROLLBACK = { target_status: 'action_in_progress', label: 'Start remediation' }

function caseBody(phase) {
  return {
    case: {
      case_id: 'mc-hsts', workspace_id: workspace.id, domain_key: 'website_security', case_type: 'website_case',
      status: phase, canonical_phase: phase, verification_support: 'automated', domain: 'example.co.uk',
      title: 'Add or strengthen HSTS', display_title: 'Add or strengthen HSTS', summary: 'The website did not send an HSTS header.',
      severity: 'medium', reopened_count: 0, assigned_user_id: 'usr_owner', assigned_user_name: 'Taylor Owner',
      created_at: '2026-10-21T10:00:00Z', updated_at: '2026-10-22T11:16:00Z',
      verified_at: phase === 'verified' ? '2026-10-22T12:00:00Z' : null,
      condition_state: 'no_longer_observed', last_observed_absent_at: '2026-10-22T11:16:00Z',
    },
    events: [],
    can_manage: true,
    available_transitions: NEXT[phase] ? [NEXT[phase]] : phase === 'awaiting_verification' ? [ROLLBACK] : [],
  }
}

test('HSTS case: detected → ready to verify → verified, the sentence only while the customer still has to move it', async ({ page, context }) => {
  let phase = 'detected'
  const moves = []
  await seedSession(context)
  await installAppMock(page)
  const base = `${API_BASE}/workspaces/${workspace.id}/cases/mc-hsts`
  await page.route(base, (route) => route.fulfill(json(caseBody(phase))))
  await page.route(`${base}/transition`, (route) => {
    const sent = route.request().postDataJSON()
    // The mock refuses anything the machine would refuse.
    const allowed = NEXT[phase]?.target_status || (phase === 'awaiting_verification' ? ROLLBACK.target_status : null)
    if (allowed !== sent.target_status) return route.fulfill(json({ error: 'invalid_transition' }, 409))
    moves.push(sent.target_status)
    phase = sent.target_status
    return route.fulfill(json(caseBody(phase).case))
  })

  await page.goto('/ws/cases/mc-hsts')
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Add or strengthen HSTS')

  // Every phase before ready-to-verify: the sentence, and the next move as the one primary action.
  for (const step of ['detected', 'triaged', 'assigned', 'approved', 'action_in_progress']) {
    // Wait for THIS phase's screen (its own next move) before asserting, so a
    // check never passes on the previous phase's still-rendered page.
    await expect(page.getByRole('button', { name: NEXT[step].label })).toBeVisible()
    await expect(page.getByTestId('case-no-longer-observed')).toHaveText(SENTENCE)
    await expectOnePrimaryAction(page)
    // A double-click records one move, never two (S1-CASE-STALE).
    await page.getByRole('button', { name: NEXT[step].label }).dblclick()
    await expect.poll(() => phase).toBe(NEXT[step].target_status)
  }
  expect(moves).toEqual(['triaged', 'assigned', 'approved', 'action_in_progress', 'awaiting_verification'])

  // Ready to verify: the sentence has done its job and goes; no customer "verified" button.
  // Positive marker first: the header chip reads Ready to verify, so the
  // absence checks below run on the new screen, not on a reload gap.
  await expect(page.getByTestId('case-detail').getByText('Ready to verify', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: NEXT.action_in_progress.label })).toHaveCount(0)
  await expect(page.getByTestId('case-no-longer-observed')).toHaveCount(0)
  await expect(page.getByRole('button', { name: /Record customer attestation|Mark verified/ })).toHaveCount(0)
  // S1-CASE-STALE: a waiting state has no primary; the rollback is secondary and says what it does.
  await expect(page.getByTestId('case-waiting-verification')).toContainText('Submitted for verification on 22 Oct 2026 — CyberMeters verifies this on the next complete scan.')
  await expect(page.locator('[data-primary="true"]')).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Not fixed yet — reopen work', exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Start remediation' })).toHaveCount(0)
  expect(moves).toEqual(['triaged', 'assigned', 'approved', 'action_in_progress', 'awaiting_verification'])

  // The next scan confirms it: CyberMeters (the mock verifier) concludes verified.
  phase = 'verified'
  await page.reload()
  await expect(page.getByTestId('case-detail').getByText('Verified', { exact: true })).toBeVisible()
  await expect(page.getByTestId('case-no-longer-observed')).toHaveCount(0)
  await expectNoRawKeys(page)
})

test('the sentence stays hidden when the API does not carry condition_state', async ({ page, context }) => {
  await seedSession(context)
  await installAppMock(page)
  const body = caseBody('detected')
  delete body.case.condition_state
  delete body.case.last_observed_absent_at
  await page.route(`${API_BASE}/workspaces/${workspace.id}/cases/mc-hsts`, (route) => route.fulfill(json(body)))
  await page.goto('/ws/cases/mc-hsts')
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Add or strengthen HSTS')
  await expect(page.getByTestId('case-no-longer-observed')).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Begin triage' })).toBeVisible()
})
