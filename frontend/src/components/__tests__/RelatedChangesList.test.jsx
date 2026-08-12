import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from '../../api'
import RelatedChangesList from '../RelatedChangesList'
import { HONESTY_NOTE } from '../../lib/relatedChangesDisplay'

vi.mock('../../api', () => ({ api: { getRelatedChanges: vi.fn() } }))

const CLUSTERS = [
  {
    id: 'rc1',
    registrable_domain: 'example.com',
    rule_id: 'new_host_with_cert',
    direction: 'appeared',
    signal_family_count: 2,
    independent_producer_count: 2,
    confidence: 'correlated',
    completeness: 'complete',
    customer_state: 'new',
    first_seen: '2026-07-10T00:00:00Z',
    last_seen: '2026-07-12T00:00:00Z',
    recurrence_count: 1,
    recurrence: { schema_version: 'related_change_recurrence.v2', status: 'comparable', count: 1, reason: null, source: 'canonical_evidence_projection' },
    linked_case_id: null,
  },
  {
    id: 'rc2',
    registrable_domain: 'shop.example.com',
    rule_id: 'identity_with_cert',
    direction: 'changed',
    signal_family_count: 3,
    independent_producer_count: 3,
    confidence: 'correlated',
    completeness: 'partial',
    customer_state: 'expected',
    first_seen: '2026-07-15T00:00:00Z',
    last_seen: '2026-07-18T00:00:00Z',
    recurrence_count: 4,
    recurrence: { schema_version: 'related_change_recurrence.v2', status: 'comparable', count: 4, reason: null, source: 'canonical_evidence_projection' },
    linked_case_id: 'case-9',
  },
]

// The vocabulary lock. The mandated honesty note is the ONE sanctioned use of a
// negating phrase ("Change is not compromise"); it is stripped before the rest
// of the rendered output is checked.
const FORBIDDEN = [
  'attack chain',
  'compromise',
  'malicious',
  'behavioural threat',
  'incident',
  'anomaly',
  'anomalous',
  'statistically unusual',
  'threat detected',
]

beforeEach(() => {
  api.getRelatedChanges.mockReset()
})

function renderList() {
  return render(
    <MemoryRouter initialEntries={['/ws/related-changes']}>
      <Routes>
        <Route path="/ws/related-changes" element={<RelatedChangesList workspaceId="ws1" />} />
        <Route path="/ws/related-changes/:id" element={<div>Detail route</div>} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('RelatedChangesList', () => {
  it('uses authoritative recurrence and never falls back to a polluted raw count', async () => {
    api.getRelatedChanges.mockResolvedValue({
      related_changes: [{
        ...CLUSTERS[1], recurrence_count: 99,
        recurrence: {
          schema_version: 'related_change_recurrence.v2', status: 'not_comparable', count: null,
          reason: 'legacy_identity_multiplicity', source: 'canonical_evidence_projection',
        },
      }],
    })
    renderList()
    expect(await screen.findByText(/Recurrence not comparable/)).toBeInTheDocument()
    expect(screen.queryByText(/Seen 99 times/)).not.toBeInTheDocument()
  })

  it('renders malformed or missing recurrence as unavailable without raw fallback', async () => {
    api.getRelatedChanges.mockResolvedValue({ related_changes: [{ ...CLUSTERS[1], recurrence_count: 88, recurrence: null }] })
    renderList()
    expect(await screen.findByText(/Recurrence unavailable/)).toBeInTheDocument()
    expect(screen.queryByText(/Seen 88 times/)).not.toBeInTheDocument()
  })

  it('renders a loading state before data resolves', () => {
    api.getRelatedChanges.mockReturnValue(new Promise(() => {}))
    renderList()
    expect(screen.getByText('Loading…')).toBeInTheDocument()
  })

  it('renders change clusters with rule label, domain, family count and badges', async () => {
    api.getRelatedChanges.mockResolvedValue({ related_changes: CLUSTERS })
    renderList()

    expect(await screen.findByText('New host with a certificate signal')).toBeInTheDocument()
    expect(screen.getByText('Possible identity-facing hostname with a certificate signal')).toBeInTheDocument()
    // Family count wording (explanation first, number second).
    expect(screen.getByText(/2 independent signal families/)).toBeInTheDocument()
    // Backend-owned customer_state badge, rendered verbatim (no derived verdict).
    // These labels also appear as filter <option>s, so more than one match is expected.
    expect(screen.getAllByText('Needs review').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Expected — planned').length).toBeGreaterThan(0)
    // Deterministic confidence, never a probability.
    expect(screen.getAllByText('Correlated (deterministic)').length).toBeGreaterThan(0)
    // Linked-case hint for the cluster that has one.
    expect(screen.getByText(/Linked to a case/)).toBeInTheDocument()
  })

  it('states the workspace scope and names each affected domain (blocker 3)', async () => {
    api.getRelatedChanges.mockResolvedValue({
      related_changes: [{ ...CLUSTERS[0], affected_domain: 'cybermeters.com', registrable_domain: 'cybermeters.com' }],
      workspace_scope_note: 'This list is workspace-level: backend-supplied scope note.',
    })
    renderList()
    // Backend-owned scope note rendered verbatim.
    expect(await screen.findByText('This list is workspace-level: backend-supplied scope note.')).toBeInTheDocument()
    // The row attributes the change to its canonical affected domain.
    expect(screen.getByText(/Affects cybermeters\.com/)).toBeInTheDocument()
  })

  it('falls back to the canonical scope wording and registrable_domain for legacy responses', async () => {
    // Explicit legacy cluster (no affected_domain): the shared CLUSTERS array is
    // order-mutated by the component's in-place sort in earlier tests.
    api.getRelatedChanges.mockResolvedValue({
      related_changes: [{
        id: 'rc-legacy', registrable_domain: 'legacyexample.com', rule_id: 'new_host_with_cert',
        direction: 'appeared', signal_family_count: 2, independent_producer_count: 2,
        confidence: 'correlated', completeness: 'complete', customer_state: 'new',
        first_seen: '2026-07-10T00:00:00Z', last_seen: '2026-07-12T00:00:00Z',
        recurrence_count: 1, recurrence: null, linked_case_id: null,
      }],
    })
    renderList()
    // Legacy response without affected_domain → registrable_domain fallback.
    expect(await screen.findByText(/Affects legacyexample\.com/)).toBeInTheDocument()
    // No workspace_scope_note in the response → the shared fallback constant.
    expect(screen.getByText(/workspace-level/)).toBeInTheDocument()
  })

  it('sorts by last_seen descending', async () => {
    api.getRelatedChanges.mockResolvedValue({ related_changes: CLUSTERS })
    renderList()
    const titles = await screen.findAllByText(/certificate/i)
    // rc2 (last_seen 2026-07-18) must render before rc1 (2026-07-12).
    expect(titles[0].textContent).toContain('Possible identity-facing hostname')
  })

  it('empty state (c): assessed with no related changes', async () => {
    api.getRelatedChanges.mockResolvedValue({
      related_changes: [],
      assessment: { complete_scans: 3, correlation_possible: true, latest_scan_quality: 'complete' },
    })
    renderList()
    expect(await screen.findByText('No related changes observed in this period.')).toBeInTheDocument()
  })

  it('empty state (a): not yet assessed when there is no complete history', async () => {
    api.getRelatedChanges.mockResolvedValue({
      related_changes: [],
      assessment: { complete_scans: 0, correlation_possible: false, latest_scan_quality: null },
    })
    renderList()
    expect(await screen.findByText('Not yet assessed')).toBeInTheDocument()
    // Must NOT claim "no related changes" (which would imply an assessment happened).
    expect(screen.queryByText('No related changes observed in this period.')).not.toBeInTheDocument()
  })

  it('empty state (b): latest assessment incomplete', async () => {
    api.getRelatedChanges.mockResolvedValue({
      related_changes: [],
      assessment: { complete_scans: 2, correlation_possible: true, latest_scan_quality: 'partial' },
    })
    renderList()
    expect(await screen.findByText('Latest assessment was incomplete')).toBeInTheDocument()
  })

  it('renders a customer-safe error state with retry', async () => {
    api.getRelatedChanges.mockRejectedValue(new Error('boom'))
    renderList()
    expect(await screen.findByText(/could not load related changes/i)).toBeInTheDocument()
    // Never leaks the raw error.
    expect(screen.queryByText('boom')).not.toBeInTheDocument()
  })

  it('refetches with the customer_state filter when changed', async () => {
    api.getRelatedChanges.mockResolvedValue({ related_changes: CLUSTERS })
    renderList()
    await screen.findByText('New host with a certificate signal')

    fireEvent.change(screen.getByLabelText(/filter related changes by review state/i), {
      target: { value: 'unexpected_confirmed' },
    })

    await waitFor(() =>
      expect(api.getRelatedChanges).toHaveBeenCalledWith('ws1', { customer_state: 'unexpected_confirmed' }),
    )
  })

  it('navigates to the detail route on cluster click', async () => {
    api.getRelatedChanges.mockResolvedValue({ related_changes: CLUSTERS })
    renderList()
    const card = await screen.findByText('New host with a certificate signal')
    fireEvent.click(card)
    expect(await screen.findByText('Detail route')).toBeInTheDocument()
  })

  it('shows the honesty note and never renders forbidden vocabulary', async () => {
    api.getRelatedChanges.mockResolvedValue({ related_changes: CLUSTERS })
    const { container } = renderList()
    await screen.findByText('New host with a certificate signal')

    // The mandated honesty note must be present.
    expect(screen.getByText(HONESTY_NOTE)).toBeInTheDocument()

    // Strip the sanctioned honesty note, then assert the rest is threat-free.
    const rendered = container.textContent.replace(HONESTY_NOTE, '').toLowerCase()
    for (const word of FORBIDDEN) {
      expect(rendered).not.toContain(word)
    }
  })
})
