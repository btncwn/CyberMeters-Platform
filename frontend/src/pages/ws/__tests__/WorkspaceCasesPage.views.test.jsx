// Operations view — four lanes from backend phases, wording per
// docs/verification-vocabulary.md. These tests render the page.
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import WorkspaceCasesPage from '../WorkspaceCasesPage'
import { laneForCase, laneCounts, LANE_IDS } from '../../../components/operations/OperationsBoard'
import { api } from '../../../api'

vi.mock('../../../api', () => ({ api: { getCases: vi.fn() } }))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: () => ({ wsId: 'ws1', wsName: 'Customer A', loading: false }) }))

const mk = (id, canonical_phase, over = {}) => ({
  case_id: id, workspace_id: 'ws1', domain_key: 'email_protection', case_type: 'email_case', status: canonical_phase,
  canonical_phase, verification_support: 'automated', title: `Case ${id}`, domain: 'example.co.uk', severity: 'high',
  owner_ref: null, reopened_count: 0, updated_at: '2026-10-15T09:00:00Z', ...over,
})
const ALL = [
  mk('c_detected', 'detected'),
  mk('c_triaged', 'triaged', { owner_ref: 'it-lead' }),
  mk('c_assigned', 'assigned'),
  mk('c_approved', 'approved'),
  mk('c_reopened', 'reopened', { reopened_count: 2 }),
  mk('c_progress', 'action_in_progress'),
  mk('c_await', 'awaiting_verification'),
  mk('c_verified_auto', 'verified', { verification_support: 'automated' }),
  mk('c_verified_manual', 'verified', { verification_support: 'manual' }),
  mk('c_verified_silent', 'verified', { verification_support: undefined }),
  mk('c_monitoring', 'monitoring'),
  mk('c_accepted', 'accepted_risk', { domain_key: 'attack_surface' }),
  mk('c_fp', 'false_positive', { domain_key: 'website_security' }),
  mk('c_unknown', 'something_new'),
]

const renderAt = (url = '/ws/cases') => render(<MemoryRouter initialEntries={[url]}><WorkspaceCasesPage /></MemoryRouter>)
const board = async () => { renderAt(); return within(await screen.findByTestId('operations-board')) }
const rowIds = (b) => b.queryAllByTestId('case-row').map((r) => r.getAttribute('data-case-id'))
const count = (b, id) => b.getByTestId(`ops-count-${id}`).textContent

beforeEach(() => { api.getCases.mockReset(); api.getCases.mockResolvedValue({ cases: ALL }) })

describe('laneForCase (pure)', () => {
  it('folds every backend phase onto one of four lanes, unknown onto Triage', () => {
    expect(laneForCase(mk('x', 'detected'))).toBe('triage')
    expect(laneForCase(mk('x', 'reopened'))).toBe('triage')
    expect(laneForCase(mk('x', 'action_in_progress'))).toBe('in_progress')
    expect(laneForCase(mk('x', 'awaiting_verification'))).toBe('ready_to_verify')
    expect(laneForCase(mk('x', 'verified', { verification_support: 'manual' }))).toBe('closed')
    expect(laneForCase(mk('x', 'monitoring'))).toBe('closed')
    expect(laneForCase(mk('x', 'superseded'))).toBe('closed')
    expect(laneForCase(mk('x', 'brand_new_phase'))).toBe('triage')
    expect(laneForCase({})).toBe('triage')
    expect(LANE_IDS).toEqual(['triage', 'in_progress', 'ready_to_verify', 'closed'])
    expect(laneCounts(ALL)).toEqual({ triage: 6, in_progress: 1, ready_to_verify: 1, closed: 6 })
  })
})

describe('Operations view — lanes', () => {
  it('opens on Triage with counts on every lane and the Triage cases listed', async () => {
    const b = await board()
    await waitFor(() => expect(count(b, 'triage')).toBe('6'))
    expect(count(b, 'in_progress')).toBe('1')
    expect(count(b, 'ready_to_verify')).toBe('1')
    expect(count(b, 'closed')).toBe('6')
    expect(b.getByRole('tab', { name: /^Triage/ })).toHaveAttribute('aria-selected', 'true')
    expect(rowIds(b)).toEqual(['c_detected', 'c_triaged', 'c_assigned', 'c_approved', 'c_reopened', 'c_unknown'])
    expect(b.getByText('Reopened 2×')).toBeInTheDocument()
    expect(b.getByText(/Owner: it-lead/)).toBeInTheDocument()
    expect(api.getCases).toHaveBeenLastCalledWith('ws1', { limit: 200 })
    expect(screen.getByText(/for Customer A/)).toBeInTheDocument()
  })

  it('switches lanes through the URL and shows exactly that lane', async () => {
    const b = await board()
    await waitFor(() => expect(count(b, 'triage')).toBe('6'))
    fireEvent.click(b.getByRole('tab', { name: /In progress/ }))
    await waitFor(() => expect(rowIds(b)).toEqual(['c_progress']))
    expect(b.getByRole('tab', { name: /In progress/ })).toHaveAttribute('aria-selected', 'true')
    fireEvent.click(b.getByRole('tab', { name: /Ready to verify/ }))
    await waitFor(() => expect(rowIds(b)).toEqual(['c_await']))
    expect(b.getByText('Awaiting verification')).toBeInTheDocument()
  })

  it('opens a lane directly from ?view=', async () => {
    renderAt('/ws/cases?view=closed')
    const b = within(await screen.findByTestId('operations-board'))
    await waitFor(() => expect(rowIds(b)).toEqual(['c_verified_auto', 'c_verified_manual', 'c_verified_silent', 'c_monitoring', 'c_accepted', 'c_fp']))
    expect(b.getByRole('tab', { name: /^Closed/ })).toHaveAttribute('aria-selected', 'true')
  })

  it('treats an unknown ?view= as Triage', async () => {
    renderAt('/ws/cases?view=nonsense')
    const b = within(await screen.findByTestId('operations-board'))
    await waitFor(() => expect(b.getByRole('tab', { name: /^Triage/ })).toHaveAttribute('aria-selected', 'true'))
    await waitFor(() => expect(rowIds(b)).toHaveLength(6))
  })

  it('Closed wording: only CyberMeters’ own observation says Verified; the customer’s word and silence are attested', async () => {
    renderAt('/ws/cases?view=closed')
    const b = within(await screen.findByTestId('operations-board'))
    await waitFor(() => expect(rowIds(b)).toHaveLength(6))
    const row = (id) => within(b.queryAllByTestId('case-row').find((r) => r.getAttribute('data-case-id') === id))
    expect(row('c_verified_auto').getByText('Verified by CyberMeters')).toBeInTheDocument()
    expect(row('c_verified_manual').getByText('Attested by customer — not externally verifiable')).toBeInTheDocument()
    expect(row('c_verified_silent').getByText('Attested by customer — not externally verifiable')).toBeInTheDocument()
    expect(row('c_verified_manual').queryByText(/Verified/)).not.toBeInTheDocument()
    expect(row('c_verified_silent').queryByText(/Verified/)).not.toBeInTheDocument()
    expect(row('c_monitoring').getByText('Monitoring')).toBeInTheDocument()
    expect(row('c_accepted').getByText('Accepted risk')).toBeInTheDocument()
    expect(row('c_fp').getByText('False positive')).toBeInTheDocument()
    expect(b.getByText(/"Verified by CyberMeters" is used only when/)).toBeInTheDocument()
    // Rows link to the canonical detail surface, where transitions happen.
    expect(row('c_verified_auto').getByRole('link', { name: 'Case c_verified_auto' })).toHaveAttribute('href', '/ws/cases/c_verified_auto')
  })

  it('empty lanes and an empty workspace say so honestly', async () => {
    api.getCases.mockResolvedValue({ cases: [mk('only', 'detected')] })
    renderAt('/ws/cases?view=ready_to_verify')
    const b = within(await screen.findByTestId('operations-board'))
    expect(await b.findByTestId('ops-lane-empty')).toHaveTextContent('No case is waiting for its fix to be checked.')
    expect(count(b, 'triage')).toBe('1')
  })

  it('an empty workspace says so honestly', async () => {
    api.getCases.mockResolvedValue({ cases: [] })
    const b = await board()
    expect(await b.findByTestId('ops-lane-empty')).toHaveTextContent('No managed cases in this workspace yet.')
    expect(count(b, 'closed')).toBe('0')
  })

  it('a failed read shows Error and never an empty settled lane; counts stay unknown', async () => {
    api.getCases.mockRejectedValue(new Error('Service unavailable'))
    const b = await board()
    expect(await b.findByRole('alert')).toHaveTextContent('could not be read')
    expect(b.queryByTestId('ops-lane-empty')).not.toBeInTheDocument()
    expect(count(b, 'triage')).toBe('…')
  })

  it('a malformed payload is an error, not an empty list', async () => {
    api.getCases.mockResolvedValue({ cases: 'nope' })
    const b = await board()
    expect(await b.findByRole('alert')).toBeInTheDocument()
  })

  it('keeps the service filter in the URL and re-reads with it', async () => {
    const b = await board()
    await waitFor(() => expect(api.getCases).toHaveBeenLastCalledWith('ws1', { limit: 200 }))
    fireEvent.change(b.getByLabelText('Filter cases by service'), { target: { value: 'certificates_trust' } })
    await waitFor(() => expect(api.getCases).toHaveBeenLastCalledWith('ws1', { domain_key: 'certificates_trust', limit: 200 }))
    const options = [...b.getByLabelText('Filter cases by service').querySelectorAll('option')].map((o) => o.textContent)
    expect(options).toEqual(['All services', 'Email Protection', 'Attack Surface', 'Website Security', 'Identity Exposure', 'Shadow IT & Unmanaged Technology', 'Certificates & Trust', 'Brand Protection', 'Cyber Essentials Readiness'])
  })
})
