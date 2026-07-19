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
  it('renders a loading state before data resolves', () => {
    api.getRelatedChanges.mockReturnValue(new Promise(() => {}))
    renderList()
    expect(screen.getByText('Loading…')).toBeInTheDocument()
  })

  it('renders change clusters with rule label, domain, family count and badges', async () => {
    api.getRelatedChanges.mockResolvedValue({ related_changes: CLUSTERS })
    renderList()

    expect(await screen.findByText('New host with a new or changed certificate')).toBeInTheDocument()
    expect(screen.getByText('Login or admin surface with a certificate change')).toBeInTheDocument()
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

  it('sorts by last_seen descending', async () => {
    api.getRelatedChanges.mockResolvedValue({ related_changes: CLUSTERS })
    renderList()
    const titles = await screen.findAllByText(/certificate/i)
    // rc2 (last_seen 2026-07-18) must render before rc1 (2026-07-12).
    expect(titles[0].textContent).toContain('Login or admin surface')
  })

  it('renders an honest empty state', async () => {
    api.getRelatedChanges.mockResolvedValue({ related_changes: [] })
    renderList()
    expect(await screen.findByText('No related changes observed in this period.')).toBeInTheDocument()
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
    await screen.findByText('New host with a new or changed certificate')

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
    const card = await screen.findByText('New host with a new or changed certificate')
    fireEvent.click(card)
    expect(await screen.findByText('Detail route')).toBeInTheDocument()
  })

  it('shows the honesty note and never renders forbidden vocabulary', async () => {
    api.getRelatedChanges.mockResolvedValue({ related_changes: CLUSTERS })
    const { container } = renderList()
    await screen.findByText('New host with a new or changed certificate')

    // The mandated honesty note must be present.
    expect(screen.getByText(HONESTY_NOTE)).toBeInTheDocument()

    // Strip the sanctioned honesty note, then assert the rest is threat-free.
    const rendered = container.textContent.replace(HONESTY_NOTE, '').toLowerCase()
    for (const word of FORBIDDEN) {
      expect(rendered).not.toContain(word)
    }
  })
})
