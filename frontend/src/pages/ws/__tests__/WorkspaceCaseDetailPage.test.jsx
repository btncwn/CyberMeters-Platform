import { render, screen } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from '../../../api'
import WorkspaceCaseDetailPage from '../WorkspaceCaseDetailPage'

vi.mock('../../../api', () => ({ api: { getCase: vi.fn(), getWorkspaceMembers: vi.fn(), getWorkspaces: vi.fn(), getWorkspaceDomains: vi.fn(), createScan: vi.fn(), getScan: vi.fn() } }))
vi.mock('../../../hooks/useWorkspace', () => ({
  useWorkspace: () => ({ wsId: 'ws1', wsName: 'WS', workspaces: [{ id: 'ws1', role: 'admin' }], loading: false }),
}))

function renderCase(caseId = 'c1') {
  return render(
    <MemoryRouter initialEntries={[`/ws/cases/${caseId}`]}>
      <Routes><Route path="/ws/cases/:caseId" element={<WorkspaceCaseDetailPage />} /></Routes>
    </MemoryRouter>,
  )
}

const baseCase = {
  case_id: 'c1', workspace_id: 'ws1', domain_key: 'identity_exposure',
  case_type: 'identity_case', status: 'awaiting_verification', canonical_phase: 'awaiting_verification',
  title: 'Exposed admin login', summary: 'An admin login surface was observed.',
  severity: 'high', source_finding_type: 'identity_exposed_login', asset_ref: 'admin.example.com',
  remediation_id: 'identity.exposed_login.remove', reopened_count: 0,
  created_at: '2026-07-01T10:00:00Z', updated_at: '2026-07-02T10:00:00Z',
}

beforeEach(() => {
  api.getCase.mockReset()
  api.getWorkspaceMembers.mockReset()
  api.getWorkspaceMembers.mockResolvedValue({ members: [] })
  api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws1', role: 'admin' }] })
  api.getWorkspaceDomains.mockResolvedValue({ domains: [{ domain: 'example.com', domain_id: 'd1', verification_status: 'verified', verified_at: '2026-07-01T00:00:00Z' }] })
})

describe('WorkspaceCaseDetailPage — verification honesty', () => {
  it('a MANUAL verified case reads as ATTESTED, never "Verified by CyberMeters"', async () => {
    api.getCase.mockResolvedValue({
      case: { ...baseCase, status: 'verified', canonical_phase: 'verified', verification_support: 'manual' },
      events: [],
    })
    renderCase()
    expect(await screen.findAllByText(/Attested by customer — not externally verifiable/i)).not.toHaveLength(0)
    expect(screen.queryByText('Verified by CyberMeters')).toBeNull()
  })

  it('an AUTOMATED verified case reads as "Verified by CyberMeters"', async () => {
    api.getCase.mockResolvedValue({
      case: { ...baseCase, domain_key: 'website_security', status: 'verified', canonical_phase: 'verified', verification_support: 'automated' },
      events: [],
    })
    renderCase()
    expect(await screen.findAllByText('Verified by CyberMeters')).not.toHaveLength(0)
    expect(screen.queryByText(/Attested by customer/i)).toBeNull()
  })

  it('says what was seen in words; internal keys never reach the page body', async () => {
    api.getCase.mockResolvedValue({ case: { ...baseCase, verification_support: 'manual' }, events: [] })
    renderCase()
    expect(await screen.findByText('An admin login surface was observed.')).toBeInTheDocument()
    expect(screen.getByText('admin.example.com')).toBeInTheDocument()
    // Design standard §4: no finding keys, remediation ids or case ids in body text.
    const body = screen.getByTestId('case-detail').textContent
    expect(body).not.toContain('identity_exposed_login')
    expect(body).not.toContain('identity.exposed_login.remove')
    expect(body).not.toMatch(/\bc1\b/)
    expect(screen.getByRole('button', { name: 'Copy case ID' })).toBeInTheDocument()
  })

  it('renders the backend traceability classification verbatim (blocker 3)', async () => {
    api.getCase.mockResolvedValue({
      case: {
        ...baseCase,
        domain_key: 'attack_surface',
        case_type: 'asm_exposure',
        verification_support: 'automated',
        traceability: {
          schema: 'asm-case-traceability-v1',
          relationship: 'retained_historical',
          relationship_label: 'Retained from historical evidence',
          customer_message: 'This case is retained from historical evidence. Its originating observation was not re-observed as a finding in the latest recorded scan. This does not mean the exposure is absent, removed or remediated.',
        },
      },
      events: [],
    })
    renderCase()
    expect(await screen.findByText('Retained from historical evidence')).toBeInTheDocument()
    expect(screen.getByText(/does not mean the exposure is absent, removed or remediated/)).toBeInTheDocument()
  })

  it('omits the traceability block when the backend supplies none', async () => {
    api.getCase.mockResolvedValue({ case: { ...baseCase, verification_support: 'manual' }, events: [] })
    renderCase()
    await screen.findByText('An admin login surface was observed.')
    expect(screen.queryByText(/historical evidence/)).toBeNull()
  })

  it('does not use a green "settled" tone for an automated case that is not yet verified', async () => {
    api.getCase.mockResolvedValue({
      case: { ...baseCase, domain_key: 'website_security', status: 'action_in_progress', canonical_phase: 'action_in_progress', verification_support: 'automated' },
      events: [],
    })
    renderCase()
    const explainer = await screen.findByText(/CyberMeters re-observes this fix itself/i)
    // The informational panel must not read as "settled" (green) before the case is verified.
    expect(explainer.closest('div').className).not.toMatch(/bg-green/)
  })

  it('states completion is an assertion that never reaches a verified state', async () => {
    api.getCase.mockResolvedValue({ case: { ...baseCase, verification_support: 'manual' }, events: [] })
    renderCase()
    expect(await screen.findByText(/completion is an assertion/i)).toBeInTheDocument()
  })

  it('shows recurrence/reopen count and honest history', async () => {
    api.getCase.mockResolvedValue({
      case: { ...baseCase, verification_support: 'manual', reopened_count: 2 },
      events: [
        { id: 'e1', action: 'case_created', actor_type: 'system', to_status: 'detected', created_at: '2026-07-01T10:00:00Z' },
        { id: 'e2', action: 'assignment_changed', actor_type: 'customer', actor_id: 'u1', created_at: '2026-07-01T11:00:00Z' },
      ],
    })
    renderCase()
    expect(await screen.findByText(/reopened/i)).toBeInTheDocument()
    expect(screen.getByText('Case opened')).toBeInTheDocument()
    expect(screen.getByText('Owner assigned')).toBeInTheDocument()
  })

  it('a case with no customer move left says where it is handled, never "no further actions"', async () => {
    api.getCase.mockResolvedValue({ case: { ...baseCase, domain_key: 'brand_protection', case_type: 'brand_abuse', status: 'detected', canonical_phase: 'detected', verification_support: 'automated' }, events: [], can_manage: true, available_transitions: [] })
    renderCase()
    expect(await screen.findByRole('link', { name: 'Open Brand Protection' })).toHaveAttribute('href', '/ws/brand-monitoring')
    expect(screen.queryByText(/No further actions/)).toBeNull()
  })

  it('one exit per job: no domain-workflow card and no separate recheck link', async () => {
    api.getCase.mockResolvedValue({ case: { ...baseCase, verification_support: 'manual' }, events: [], can_manage: true, available_transitions: [{ target_status: 'action_in_progress', label: 'Start remediation' }] })
    renderCase()
    await screen.findByText('An admin login surface was observed.')
    expect(screen.queryByRole('link', { name: /workflow/i })).toBeNull()
    expect(screen.queryByRole('link', { name: 'Recheck domain' })).toBeNull()
  })
})


it.each(['email_protection', 'website_security', 'attack_surface', 'certificates_trust', 'identity_exposure', 'shadow_it_unmanaged_technology', 'brand_protection', 'cyber_essentials_readiness'])('with no customer move left, an automated case re-checks in place: %s', async (domain_key) => {
  api.getCase.mockResolvedValue({ case: { ...baseCase, domain_key, domain: 'example.com', verification_support: 'automated' }, events: [], can_manage: true, available_transitions: [] })
  renderCase()
  expect(await screen.findByRole('button', { name: 'Run scan to re-check' })).toBeInTheDocument()
})
it('the re-check never competes with an available transition', async () => {
  api.getCase.mockResolvedValue({ case: { ...baseCase, domain: 'example.com', verification_support: 'automated' }, events: [], can_manage: true, available_transitions: [{ target_status: 'action_in_progress', label: 'Start remediation' }] })
  renderCase()
  // S1-CASE-STALE: the awaiting-verification rollback is secondary and says what it does.
  await screen.findByRole('button', { name: 'Not fixed yet — reopen work' })
  expect(screen.queryByRole('button', { name: 'Run scan to re-check' })).toBeNull()
})
it.each(['manual', 'external', 'unsupported'])('does not offer an automated recheck for %s verification', async (verification_support) => {
  api.getCase.mockResolvedValue({ case: { ...baseCase, domain: 'example.com', verification_support }, events: [] })
  renderCase()
  await screen.findByText('Exposed admin login')
  expect(screen.queryByRole('button', { name: 'Run scan to re-check' })).toBeNull()
})
