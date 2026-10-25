import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import WorkspaceCaseDetailPage from '../WorkspaceCaseDetailPage'
import { api } from '../../../api'
import { resolutionEventWords } from '../../../lib/caseEventWords'

// Follow-up to 10c (released 25 Oct 2026): Cyber Essentials / Email recovery
// events and certificate replacement events read in plain words, never the
// generic "Recovery observed — moved to detected". Reasons are the keys the
// engines record (cyber-essentials-cases.js, email-protection-cases.js,
// certificate-lifecycle.js).
vi.mock('../../../api', () => ({ api: { getCase: vi.fn(), getWorkspaceMembers: vi.fn() } }))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: () => ({ wsId: 'ws1', wsName: 'Example Ltd', workspaces: [], loading: false }) }))
afterEach(cleanup)
const ev = (action, reason) => ({ action, detail_json: reason ? JSON.stringify({ reason }) : null })

describe('observed-improvement events', () => {
  it.each([
    ['recovery_observed', null, 'CyberMeters observed an improvement. The case stays open until you submit it for verification.'],
    ['recovery_observed_not_verifying', 'external_evidence_incomplete', 'CyberMeters observed an improvement, but some of the external evidence was not collected, so this does not count as a fix.'],
    ['recovery_observed_not_verifying', 'registry_method_is_not_externally_observable', 'CyberMeters observed an improvement, but it cannot verify this fix from outside.'],
    ['replacement_observed', null, 'CyberMeters observed a replacement certificate. The case stays open until you submit it for verification.'],
    ['replacement_observed_not_verifying', 'registry_method_is_not_externally_observable_for_this_finding', 'CyberMeters observed a replacement certificate, but it cannot verify this fix from outside.'],
    ['replacement_observed_not_verifying', 'invalid_transition', 'CyberMeters observed a replacement certificate, but this does not verify the fix.'],
    ['resolution_observed', null, 'CyberMeters no longer observes this condition. The case stays open until you submit it for verification.'],
  ])('%s (%s)', (action, reason, words) => {
    expect(resolutionEventWords(ev(action, reason))).toBe(words)
  })
  it('a closed case keeps no "stays open" promise (a replacement noted on a closed certificate case)', () => {
    for (const status of ['closed_no_action', 'false_positive', 'rejected', 'resolved', 'verified']) {
      expect(resolutionEventWords({ action: 'replacement_observed', from_status: status, to_status: status })).toBe('CyberMeters observed a replacement certificate.')
    }
    expect(resolutionEventWords({ action: 'replacement_observed', from_status: 'detected', to_status: 'detected' }))
      .toBe('CyberMeters observed a replacement certificate. The case stays open until you submit it for verification.')
  })
  it('prototype keys are never table entries and never break History', () => {
    for (const action of ['toString', 'toString_not_verifying', 'constructor', '__proto__', 'hasOwnProperty_not_verifying']) {
      expect(() => resolutionEventWords({ action })).not.toThrow()
      expect(resolutionEventWords({ action })).toBeNull()
    }
    expect(resolutionEventWords({ action: 'recovery_observed_not_verifying', detail_json: JSON.stringify({ reason: 'toString' }) }))
      .toBe('CyberMeters observed an improvement, but this does not verify the fix.')
  })
  it('other events are untouched', () => {
    for (const action of ['case_created', 'assignment_changed', 'observed_something_else']) expect(resolutionEventWords({ action })).toBeNull()
  })
})

it.each([
  ['email_case', 'email_protection', 'recovery_observed', 'CyberMeters observed an improvement.'],
  ['ce_case', 'cyber_essentials', 'recovery_observed_not_verifying', 'CyberMeters observed an improvement, but some of the external evidence was not collected'],
  ['certificate_case', 'certificates_trust', 'replacement_observed', 'CyberMeters observed a replacement certificate.'],
])('the %s History never reads "— moved to" for %s', async (caseType, domainKey, action, words) => {
  api.getWorkspaceMembers.mockResolvedValue({ members: [] })
  api.getCase.mockResolvedValue({ can_manage: true, case: {
    case_id: 'mc1', case_type: caseType, domain_key: domainKey, domain: 'example.org',
    display_title: 'A case', status: 'detected', canonical_phase: 'detected', verification_support: 'automated',
  }, events: [{ id: 'e1', action, actor_type: 'system', from_status: 'detected', to_status: 'detected',
    detail_json: JSON.stringify({ reason: action.endsWith('_not_verifying') ? 'external_evidence_incomplete' : 'case_not_awaiting_verification' }), created_at: '2026-10-24 21:00:00' }],
  available_transitions: [] })
  render(<MemoryRouter initialEntries={['/ws/cases/mc1']}><Routes><Route path="/ws/cases/:caseId" element={<WorkspaceCaseDetailPage />} /></Routes></MemoryRouter>)
  expect(await screen.findByText(new RegExp(words.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))).toBeInTheDocument()
  expect(document.body.textContent).not.toMatch(/observed — moved to/i)
})
