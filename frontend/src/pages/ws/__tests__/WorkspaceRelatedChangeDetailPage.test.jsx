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
  // Server-declared role: review/case-linkage actions render only for managers.
  can_manage: true,
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
  it('viewer (can_manage false) sees no review or case-linkage controls', async () => {
    api.getRelatedChange.mockResolvedValue({ ...DETAIL, can_manage: false })
    renderDetail()
    expect(await screen.findByText('New host with a certificate signal')).toBeInTheDocument()
    // The manager-only Review section (heading + explanation) is gone.
    expect(screen.queryByText('Confirm whether planned')).not.toBeInTheDocument()
    expect(screen.getByText(/available to workspace managers/i)).toBeInTheDocument()
    // A6 release-gate: assert EACH control is absent, not just the section heading.
    // The three feedback state actions (mark expected / unrelated / unexpected):
    expect(screen.queryByRole('button', { name: /mark expected/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /mark unrelated/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /confirm unexpected/i })).not.toBeInTheDocument()
    // Case linkage (the existing-case input + the two case buttons):
    expect(screen.queryByLabelText(/existing case id/i)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /link to existing case/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /create case from this related change/i })).not.toBeInTheDocument()
    // The read surface (evidence) stays fully visible to the viewer.
    expect(screen.getByText('Related evidence')).toBeInTheDocument()
  })

  it('manager (can_manage true) sees every review + case-linkage control (positive control)', async () => {
    api.getRelatedChange.mockResolvedValue({ ...DETAIL, can_manage: true })
    renderDetail()
    await screen.findByText('New host with a certificate signal')
    expect(screen.getByText('Confirm whether planned')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /mark expected/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /mark unrelated/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /confirm unexpected/i })).toBeInTheDocument()
    expect(screen.getByLabelText(/existing case id/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /link to existing case/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /create case from this related change/i })).toBeInTheDocument()
    expect(screen.queryByText(/available to workspace managers/i)).not.toBeInTheDocument()
  })

  it('internal storage names are never rendered as evidence labels', async () => {
    api.getRelatedChange.mockResolvedValue(DETAIL)
    renderDetail()
    expect(await screen.findByText('Related evidence')).toBeInTheDocument()
    expect(screen.queryByText('asset_events')).not.toBeInTheDocument()
  })

  it('renders the cluster summary and related-evidence pointers', async () => {
    api.getRelatedChange.mockResolvedValue(DETAIL)
    renderDetail()

    expect(await screen.findByText('New host with a certificate signal')).toBeInTheDocument()
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

    await screen.findByText('New host with a certificate signal')
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

    await screen.findByText('New host with a certificate signal')
    fireEvent.click(screen.getByRole('button', { name: /mark unrelated/i }))

    await waitFor(() =>
      expect(api.relatedChangeFeedback).toHaveBeenCalledWith('ws1', 'rc1', { state: 'unrelated' }),
    )
  })

  it('links an existing case', async () => {
    api.getRelatedChange.mockResolvedValue(DETAIL)
    api.linkRelatedChangeCase.mockResolvedValue({ ok: true, linked_case_id: 'case-42' })
    renderDetail()

    await screen.findByText('New host with a certificate signal')
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

    await screen.findByText('New host with a certificate signal')
    fireEvent.click(screen.getByRole('button', { name: /create case from this related change/i }))

    await waitFor(() => expect(api.createRelatedChangeCase).toHaveBeenCalledWith('ws1', 'rc1'))
    expect(await screen.findByText(/managed case was created/i)).toBeInTheDocument()
  })

  it('shows a customer-safe error when an action fails', async () => {
    api.getRelatedChange.mockResolvedValue(DETAIL)
    api.relatedChangeFeedback.mockRejectedValue(new Error('kaboom'))
    renderDetail()

    await screen.findByText('New host with a certificate signal')
    fireEvent.click(screen.getByRole('button', { name: /confirm unexpected/i }))

    expect(await screen.findByText(/could not record your review/i)).toBeInTheDocument()
    expect(screen.queryByText('kaboom')).not.toBeInTheDocument()
  })

  it('collapses identical repeated evidence pointers into one row with an honest repeat count', async () => {
    // Pre-#172 standing-condition cert evidence: the same observation appended
    // once per scan rendered as ~10 separate rows (A6 P3 #1, 20 Jul 2026).
    const repeated = Array.from({ length: 10 }, (_, i) => ({
      producer_family: 'cert',
      source_table: 'asset_events',
      source_record_id: `ae-${i}`,
      source_event_type: 'certificate_sensitive_host_detected',
      entity_key: 'host:api.example.com',
      observed_at: `2026-07-${String(i + 5).padStart(2, '0')}T00:00:00Z`,
      evidence_ref: `ae-${i}`,
    }))
    api.getRelatedChange.mockResolvedValue({
      ...DETAIL,
      evidence: [DETAIL.evidence[0], ...repeated],
    })
    renderDetail()

    await screen.findByText('Related evidence')
    // One collapsed row, not ten — with an honest count and first/last seen.
    expect(screen.getAllByText('Certificate')).toHaveLength(1)
    expect(screen.getByText(/Observed 10 times/)).toBeInTheDocument()
    expect(screen.getByText(/First seen 2026-07-05 · last seen 2026-07-14/)).toBeInTheDocument()
    // The non-repeated host pointer still renders as its own row.
    expect(screen.getAllByText('Host / attack surface').length).toBeGreaterThan(0)
  })

  it('does not collapse observations that differ in a material field', async () => {
    api.getRelatedChange.mockResolvedValue({
      ...DETAIL,
      evidence: [
        { ...DETAIL.evidence[1], source_record_id: 'c-1', evidence_ref: 'c-1', source_event_type: 'certificate_new_detected' },
        { ...DETAIL.evidence[1], source_record_id: 'c-2', evidence_ref: 'c-2', source_event_type: 'certificate_expiring_soon' },
      ],
    })
    renderDetail()

    await screen.findByText('Related evidence')
    expect(screen.getAllByText('Certificate')).toHaveLength(2)
    expect(screen.queryByText(/Observed 2 times/)).not.toBeInTheDocument()
  })

  it('evidence subtypes render as honest labels, never raw internal enums, and the header names the same signals', async () => {
    api.getRelatedChange.mockResolvedValue({
      ...DETAIL,
      evidence: [
        DETAIL.evidence[0],
        { ...DETAIL.evidence[1], source_event_type: 'certificate_sensitive_host_detected' },
      ],
    })
    renderDetail()

    await screen.findByText('New host with a certificate signal')
    // The raw enum never reaches the customer.
    expect(screen.queryByText(/certificate_sensitive_host_detected/)).not.toBeInTheDocument()
    // The evidence row and the header signals line tell the same story as the
    // producer: a sensitive hostname observed in CT — not a new/changed cert.
    expect(
      screen.getAllByText(/Sensitive hostname observed in certificate-transparency logs/).length,
    ).toBeGreaterThanOrEqual(2)
    expect(screen.getByText(/Signals observed:/)).toBeInTheDocument()
  })

  it('renders the honesty note and no forbidden vocabulary', async () => {
    api.getRelatedChange.mockResolvedValue(DETAIL)
    const { container } = renderDetail()
    await screen.findByText('New host with a certificate signal')

    expect(screen.getByText(HONESTY_NOTE)).toBeInTheDocument()

    const rendered = container.textContent.replace(HONESTY_NOTE, '').toLowerCase()
    for (const word of FORBIDDEN) {
      expect(rendered).not.toContain(word)
    }
  })
})
