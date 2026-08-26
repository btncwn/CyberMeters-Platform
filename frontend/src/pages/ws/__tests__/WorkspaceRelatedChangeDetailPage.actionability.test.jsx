import { render, screen, within } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from '../../../api'
import WorkspaceRelatedChangeDetailPage from '../WorkspaceRelatedChangeDetailPage'

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

// Item 12B CL-1/CL-2: the customer sees WHAT co-occurred but never WHY the
// events were grouped, and evidence rows carry no path to the surface that
// owns them. These tests are red-first against that measured state. Every
// sentence the new block renders must be composed from evidence-backed fields
// only, and the causality vocabulary stays locked.

const CAUSAL_FORBIDDEN = [/caused/i, /attack/i, /compromis/i, /incident/i, /malicious/i]

const detailFixture = ({ evidence, related = {} } = {}) => ({
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
    recurrence: { schema_version: 'related_change_recurrence.v2', status: 'comparable', count: 1, reason: null, source: 'canonical_evidence_projection' },
    linked_case_id: null,
    ...related,
  },
  evidence,
})

const assetEvent = (overrides = {}) => ({
  producer_family: 'asset',
  source_table: 'asset_events',
  source_record_id: 'a-1',
  source_event_type: 'host_appeared',
  entity_key: 'host:new.example.com',
  observed_at: '2026-07-11T00:00:00Z',
  evidence_ref: 'ref-1',
  ...overrides,
})

const certEvent = (overrides = {}) => ({
  producer_family: 'cert',
  source_table: 'asset_events',
  source_record_id: 'c-1',
  source_event_type: 'certificate_new_detected',
  entity_key: 'host:new.example.com',
  observed_at: '2026-07-11T06:00:00Z',
  evidence_ref: 'ref-2',
  ...overrides,
})

async function renderDetail(detail) {
  api.getRelatedChange.mockResolvedValue(detail)
  render(
    <MemoryRouter initialEntries={['/ws/related-changes/rc1']}>
      <Routes>
        <Route path="/ws/related-changes/:id" element={<WorkspaceRelatedChangeDetailPage />} />
      </Routes>
    </MemoryRouter>,
  )
  await screen.findByText(/New host with a certificate signal/i)
}

function whyCard() {
  const heading = screen.getByText('Why these are grouped')
  const card = heading.closest('.card') || heading.parentElement
  expect(card).not.toBeNull()
  return card
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('CL-1: why these are grouped (evidence-backed only)', () => {
  it('renders the grouping grounds: families, registrable domain, bounded period', async () => {
    await renderDetail(detailFixture({ evidence: [assetEvent(), certEvent()] }))
    const card = whyCard()
    // Grounds are stated from existing fields only: the contributing families,
    // the shared registrable domain, and the observed period.
    expect(within(card).getAllByText(/example\.com/).length).toBeGreaterThan(0)
    expect(within(card).getAllByText(/2026-07-10/).length).toBeGreaterThan(0)
    expect(within(card).getAllByText(/2026-07-12/).length).toBeGreaterThan(0)
  })

  it('names the exact shared host explicitly when every signal carries it', async () => {
    await renderDetail(detailFixture({ evidence: [assetEvent(), certEvent()] }))
    const card = whyCard()
    expect(within(card).getAllByText(/name the same host/i).length).toBeGreaterThan(0)
    expect(within(card).getAllByText(/new\.example\.com/).length).toBeGreaterThan(0)
  })

  it('states honestly when the signals do NOT name the same host', async () => {
    await renderDetail(detailFixture({
      evidence: [assetEvent(), certEvent({ entity_key: 'host:other.example.com' })],
    }))
    const card = whyCard()
    expect(within(card).getByText(/do not name the same host/i)).toBeInTheDocument()
    expect(within(card).queryByText(/name the same host:/i)).not.toBeInTheDocument()
  })

  it('never uses causal vocabulary in the grouping explanation', async () => {
    await renderDetail(detailFixture({ evidence: [assetEvent(), certEvent()] }))
    const text = whyCard().textContent
    for (const re of CAUSAL_FORBIDDEN) expect(text).not.toMatch(re)
  })
})

describe('CL-1: correlation basis (fe 12A frozen contract: correlation_basis + linkage_host)', () => {
  it('exact_host with linkage_host states the canonical grouping host', async () => {
    await renderDetail(detailFixture({
      evidence: [assetEvent(), certEvent()],
      related: { correlation_basis: 'exact_host', linkage_host: 'new.example.com' },
    }))
    const card = whyCard()
    expect(within(card).getByText(/Grouped on the same host/i)).toBeInTheDocument()
    expect(within(card).getAllByText(/new\.example\.com/).length).toBeGreaterThan(0)
    expect(within(card).queryByText(/not re-validated/i)).not.toBeInTheDocument()
  })

  it('legacy_domain_only renders the honest not-re-validated wording', async () => {
    await renderDetail(detailFixture({
      evidence: [assetEvent(), certEvent()],
      related: { correlation_basis: 'legacy_domain_only' },
    }))
    const card = whyCard()
    expect(within(card).getByText(/not re-validated/i)).toBeInTheDocument()
    expect(within(card).queryByText(/Grouped on the same host/i)).not.toBeInTheDocument()
  })

  it('an ABSENT correlation_basis fails closed to the weaker legacy claim', async () => {
    await renderDetail(detailFixture({ evidence: [assetEvent(), certEvent()] }))
    const card = whyCard()
    expect(within(card).getByText(/not re-validated/i)).toBeInTheDocument()
    expect(within(card).queryByText(/Grouped on the same host/i)).not.toBeInTheDocument()
  })

  it('an UNKNOWN correlation_basis value fails closed to the weaker legacy claim', async () => {
    await renderDetail(detailFixture({
      evidence: [assetEvent(), certEvent()],
      related: { correlation_basis: 'future_mystery_basis' },
    }))
    expect(within(whyCard()).getByText(/not re-validated/i)).toBeInTheDocument()
  })
})

describe('CL-2: evidence deep links only where a canonical route exists', () => {
  it('links asset and cert evidence to their canonical customer surfaces', async () => {
    await renderDetail(detailFixture({ evidence: [assetEvent(), certEvent()] }))
    const links = screen.getAllByRole('link')
    const hrefs = links.map((l) => l.getAttribute('href'))
    expect(hrefs).toEqual(expect.arrayContaining(['/exposure', '/ws/certificates']))
  })

  it('renders an unknown source as a named pointer with NO link', async () => {
    await renderDetail(detailFixture({
      evidence: [assetEvent(), certEvent({ producer_family: 'mystery_family', source_table: 'unknown_table', entity_key: 'thing:zzz' })],
    }))
    const hrefs = screen.getAllByRole('link').map((l) => l.getAttribute('href'))
    expect(hrefs).not.toContain(null)
    expect(hrefs.filter((h) => h === '/ws/certificates')).toHaveLength(0)
  })
})
