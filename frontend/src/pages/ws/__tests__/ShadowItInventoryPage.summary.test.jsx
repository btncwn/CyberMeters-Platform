// S1-SHELL-V2b (Shadow IT), same rules as Identity (R1 15:55): the backend's
// workspace-wide counts hold across filter chips; loading / unavailable never
// read 0; lists read the unfiltered page with a truthful bound; reset on
// workspace change. "Rejected but still seen" is its own section.
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { beforeEach, describe, it, expect, vi } from 'vitest'
import ShadowItInventoryPage, { RejectedStillSeen, shadowItSummaryFigures } from '../ShadowItInventoryPage'
import { api } from '../../../api'
import { useWorkspace } from '../../../hooks/useWorkspace'

vi.mock('../../../api', () => ({
  api: { getShadowItInventory: vi.fn(), getShadowItItem: vi.fn(), shadowItAction: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: vi.fn() }))

const item = (id, over = {}) => ({ inventory_item_id: id, display_name: `${id} app`, classification: 'unreviewed', category: 'saas', last_seen_at: '2026-10-20T10:00:00Z', ...over })
const ITEMS = [
  item('crm'),
  item('chat', { classification: 'rejected', monitoring_reason: 'rejected_still_observed' }),
  item('wiki', { classification: 'rejected' }),
]
const COUNTS = { unreviewed: 1, approved: 0, rejected: 2, exception: 0 }
const fig = (id) => document.getElementById(id)
function mount() {
  return render(<MemoryRouter initialEntries={['/ws/shadow-it?tab=findings']}><Routes><Route path="/ws/shadow-it" element={<ShadowItInventoryPage />} /></Routes></MemoryRouter>)
}

describe('shadowItSummaryFigures', () => {
  it('the backend counts, each with an anchor', () => {
    expect(shadowItSummaryFigures({ status: 'ok', counts: COUNTS }).map((f) => [f.id, f.value])).toEqual([
      ['shadow-it-unreviewed', 1], ['shadow-it-approved', 0], ['shadow-it-rejected', 2], ['shadow-it-exception', 0],
    ])
  })
  it('loading, unavailable and a missing count never read 0', () => {
    expect(shadowItSummaryFigures({ status: 'loading', counts: null }).map((f) => f.value)).toEqual(Array(4).fill('Loading…'))
    expect(shadowItSummaryFigures({ status: 'error', counts: null }).map((f) => f.value)).toEqual(Array(4).fill('Not available'))
    expect(shadowItSummaryFigures({ status: 'ok', counts: { unreviewed: 1 } }).map((f) => f.value)).toEqual([1, 'Not available', 'Not available', 'Not available'])
  })
})

describe('RejectedStillSeen', () => {
  it('lists only what the backend marks rejected_still_observed', () => {
    render(<RejectedStillSeen status="ok" items={ITEMS} />)
    const s = screen.getByTestId('shadow-it-rejected-still-seen')
    expect(s).toHaveAttribute('id', 'shadow-it-rejected-still-seen')
    expect(s).toHaveTextContent('chat app')
    expect(s).not.toHaveTextContent('wiki app')
    expect(s).toHaveTextContent('it does not remove it')
  })
  it('loading, unavailable, none, and none in a full page each say exactly that', () => {
    const { rerender } = render(<RejectedStillSeen status="loading" items={[]} />)
    expect(screen.getByTestId('shadow-it-rejected-still-seen')).toHaveTextContent('Loading…')
    rerender(<RejectedStillSeen status="error" items={ITEMS} />)
    expect(screen.getByTestId('shadow-it-rejected-still-seen')).toHaveTextContent('Not available')
    expect(screen.queryByText('chat app')).toBeNull()
    rerender(<RejectedStillSeen status="ok" items={[ITEMS[0]]} />)
    expect(screen.getByTestId('shadow-it-rejected-still-seen')).toHaveTextContent('Nothing you rejected is still observed.')
    rerender(<RejectedStillSeen status="ok" items={[ITEMS[0]]} atLimit />)
    expect(screen.getByTestId('shadow-it-rejected-still-seen')).toHaveTextContent('None among the first 500 inventory items.')
  })
})

describe('ShadowItInventoryPage summary', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useWorkspace.mockReturnValue({ wsId: 'ws1', wsName: 'WS', loading: false })
    api.getShadowItInventory.mockImplementation(async (_ws, params) => (params?.classification
      ? { items: [], counts: COUNTS, actions: [] }
      : { items: ITEMS, counts: COUNTS, actions: [] }))
  })
  it('a filter chip never changes the figures or the Summary lists — not even while the filtered fetch runs', async () => {
    mount()
    await waitFor(() => expect(fig('shadow-it-rejected')).toHaveTextContent('2'))
    expect(api.getShadowItInventory).toHaveBeenCalledWith('ws1', { limit: 500 })
    let release
    api.getShadowItInventory.mockImplementationOnce(() => new Promise((r) => { release = () => r({ items: [], counts: COUNTS, actions: [] }) }))
    fireEvent.click(screen.getByRole('button', { name: /^Approved/ }))
    expect(fig('shadow-it-rejected')).toHaveTextContent('2')
    expect(fig('shadow-it-unreviewed')).toHaveTextContent('1')
    release()
    await waitFor(() => expect(api.getShadowItInventory).toHaveBeenLastCalledWith('ws1', { classification: 'approved' }))
    expect(fig('shadow-it-rejected')).toHaveTextContent('2')
    expect(screen.getByTestId('shadow-it-rejected-still-seen')).toHaveTextContent('chat app')
  })
  it('an unfiltered load that fails, then a chip: the lists say "Not available", never "nothing"', async () => {
    api.getShadowItInventory.mockImplementation(async (_ws, params) => {
      if (!params?.classification) throw new Error('down')
      return { items: [], counts: COUNTS, actions: [] }
    })
    mount()
    await waitFor(() => expect(screen.getByTestId('shadow-it-rejected-still-seen')).toHaveTextContent('Not available'))
    fireEvent.click(screen.getByRole('button', { name: /^Approved/ }))
    await waitFor(() => expect(api.getShadowItInventory).toHaveBeenLastCalledWith('ws1', { classification: 'approved' }))
    expect(screen.getByTestId('shadow-it-rejected-still-seen')).toHaveTextContent('Not available')
    expect(screen.getByTestId('shadow-it-rejected-still-seen')).not.toHaveTextContent('Nothing you rejected')
  })
  it('a workspace switch shows Loading…, never the previous workspace\'s counts', async () => {
    const view = mount()
    await waitFor(() => expect(fig('shadow-it-rejected')).toHaveTextContent('2'))
    let release
    api.getShadowItInventory.mockImplementation(() => new Promise((r) => { release = () => r({ items: [item('other')], counts: { unreviewed: 1, approved: 0, rejected: 0, exception: 0 }, actions: [] }) }))
    useWorkspace.mockReturnValue({ wsId: 'ws2', wsName: 'Other', loading: false })
    view.rerender(<MemoryRouter initialEntries={['/ws/shadow-it?tab=findings']}><Routes><Route path="/ws/shadow-it" element={<ShadowItInventoryPage />} /></Routes></MemoryRouter>)
    await waitFor(() => expect(api.getShadowItInventory).toHaveBeenLastCalledWith('ws2', { limit: 500 }))
    expect(fig('shadow-it-rejected')).toHaveTextContent('Loading…')
    release()
    await waitFor(() => expect(fig('shadow-it-rejected')).toHaveTextContent('0'))
  })
})

describe('a filtered deep link (the sidebar\'s ?filter=approved)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useWorkspace.mockReturnValue({ wsId: 'ws1', wsName: 'WS', loading: false })
    api.getShadowItInventory.mockImplementation(async (_ws, params) => (params?.classification
      ? { items: [], counts: COUNTS, actions: [] }
      : { items: ITEMS, counts: COUNTS, actions: [] }))
  })
  it('still loads the unfiltered page for the Summary lists, so nothing waits forever', async () => {
    render(<MemoryRouter initialEntries={['/ws/shadow-it?tab=findings&filter=approved']}><Routes><Route path="/ws/shadow-it" element={<ShadowItInventoryPage />} /></Routes></MemoryRouter>)
    await waitFor(() => expect(api.getShadowItInventory).toHaveBeenCalledWith('ws1', { classification: 'approved' }))
    await waitFor(() => expect(api.getShadowItInventory).toHaveBeenCalledWith('ws1', { limit: 500 }))
    await waitFor(() => expect(screen.getByTestId('shadow-it-rejected-still-seen')).toHaveTextContent('chat app'))
    expect(fig('shadow-it-rejected')).toHaveTextContent('2')
  })
})
