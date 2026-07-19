import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from '../../../api'
import WorkspaceRelatedChangeDetailPage from '../WorkspaceRelatedChangeDetailPage'
import { HONESTY_NOTE } from '../../../lib/relatedChangesDisplay'

vi.mock('../../../api', () => ({
  api: {
    getRelatedChange: vi.fn(),
    relatedChangeFeedback: vi.fn(),
    linkRelatedChangeCase: vi.fn(),
    createRelatedChangeCase: vi.fn(),
  },
}))

vi.mock('../../../hooks/useWorkspace', () => ({
  useWorkspace: () => ({ wsId: 'ws1', wsName: 'Acme', workspaces: [], loading: false }),
}))

const DETAIL = {
  related_change: {
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
  evidence: [
    {
      producer_family: 'host',
      source_table: 'assets',
      source_record_id: 'a-1',
      source_event_type: 'host_appeared',
      entity_key: 'new.example.com',
      observed_at: '2026-07-11T00:00:00Z',
      evidence_ref: 'ref-1',
    },
    {
      producer_family: 'cert',
      source_table: 'certificates',
      source_record_id: 'c-1',
      source_event_type: 'cert_issued',
      entity_key: 'new.example.com',
      observed_at: '2026-07-11T00:00:00Z',
      evidence_ref: 'ref-2',
    },
  ],
}

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
  api.getRelatedChange.mockReset()
  api.relatedChangeFeedback.mockReset()
  api.linkRelatedChangeCase.mockReset()
  api.createRelatedChangeCase.mockReset()
})

function renderDetail(id = 'rc1') {
  return render(
    <MemoryRouter initialEntries={[`/ws/related-changes/${id}`]}>
      <Routes>
        <Route path="/ws/related-changes/:id" element={<WorkspaceRelatedChangeDetailPage />} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('WorkspaceRelatedChangeDetailPage', () => {
  it('renders the cluster summary and related-evidence pointers', async () => {
    api.getRelatedChange.mockResolvedValue(DETAIL)
    renderDetail()

    expect(await screen.findByText('New host with a new or changed certificate')).toBeInTheDocument()
    expect(screen.getByText(/2 independent signal families/)).toBeInTheDocument()
    expect(screen.getByText('Related evidence')).toBeInTheDocument()
    // Evidence is presented as pointers to underlying observations.
    expect(screen.getByText(/links to the underlying observations/i)).toBeInTheDocument()
    expect(screen.getAllByText('Host / attack surface').length).toBeGreaterThan(0)
    expect(screen.getByText('Certificate')).toBeInTheDocument()
  })

  it('submits feedback and reflects the resulting customer_state', async () => {
    api.getRelatedChange.mockResolvedValue(DETAIL)
    api.relatedChangeFeedback.mockResolvedValue({ ok: true, customer_state: 'expected' })
    renderDetail()

    await screen.findByText('New host with a new or changed certificate')
    // Add a note, then mark expected.
    fireEvent.change(screen.getByPlaceholderText(/add context/i), { target: { value: 'Planned migration' } })
    fireEvent.click(screen.getByRole('button', { name: /mark expected/i }))

    await waitFor(() =>
      expect(api.relatedChangeFeedback).toHaveBeenCalledWith('ws1', 'rc1', {
        state: 'expected',
        note: 'Planned migration',
      }),
    )
    // The badge updates to the server-confirmed state.
    expect(await screen.findByText('Expected — planned')).toBeInTheDocument()
    expect(screen.getByText(/your review was recorded/i)).toBeInTheDocument()
  })

  it('omits the note when empty', async () => {
    api.getRelatedChange.mockResolvedValue(DETAIL)
    api.relatedChangeFeedback.mockResolvedValue({ ok: true, customer_state: 'unrelated' })
    renderDetail()

    await screen.findByText('New host with a new or changed certificate')
    fireEvent.click(screen.getByRole('button', { name: /mark unrelated/i }))

    await waitFor(() =>
      expect(api.relatedChangeFeedback).toHaveBeenCalledWith('ws1', 'rc1', { state: 'unrelated' }),
    )
  })

  it('links an existing case', async () => {
    api.getRelatedChange.mockResolvedValue(DETAIL)
    api.linkRelatedChangeCase.mockResolvedValue({ ok: true, linked_case_id: 'case-42' })
    renderDetail()

    await screen.findByText('New host with a new or changed certificate')
    fireEvent.change(screen.getByLabelText(/existing case id/i), { target: { value: 'case-42' } })
    fireEvent.click(screen.getByRole('button', { name: /link to existing case/i }))

    await waitFor(() =>
      expect(api.linkRelatedChangeCase).toHaveBeenCalledWith('ws1', 'rc1', { case_id: 'case-42' }),
    )
    expect(await screen.findByText(/linked to the case/i)).toBeInTheDocument()
  })

  it('creates a case from the related change', async () => {
    api.getRelatedChange.mockResolvedValue(DETAIL)
    api.createRelatedChangeCase.mockResolvedValue({ ok: true, case_id: 'case-new', case_type: 'attack_surface' })
    renderDetail()

    await screen.findByText('New host with a new or changed certificate')
    fireEvent.click(screen.getByRole('button', { name: /create case from this related change/i }))

    await waitFor(() => expect(api.createRelatedChangeCase).toHaveBeenCalledWith('ws1', 'rc1'))
    expect(await screen.findByText(/managed case was created/i)).toBeInTheDocument()
  })

  it('shows a customer-safe error when an action fails', async () => {
    api.getRelatedChange.mockResolvedValue(DETAIL)
    api.relatedChangeFeedback.mockRejectedValue(new Error('kaboom'))
    renderDetail()

    await screen.findByText('New host with a new or changed certificate')
    fireEvent.click(screen.getByRole('button', { name: /confirm unexpected/i }))

    expect(await screen.findByText(/could not record your review/i)).toBeInTheDocument()
    expect(screen.queryByText('kaboom')).not.toBeInTheDocument()
  })

  it('renders the honesty note and no forbidden vocabulary', async () => {
    api.getRelatedChange.mockResolvedValue(DETAIL)
    const { container } = renderDetail()
    await screen.findByText('New host with a new or changed certificate')

    expect(screen.getByText(HONESTY_NOTE)).toBeInTheDocument()

    const rendered = container.textContent.replace(HONESTY_NOTE, '').toLowerCase()
    for (const word of FORBIDDEN) {
      expect(rendered).not.toContain(word)
    }
  })
})
