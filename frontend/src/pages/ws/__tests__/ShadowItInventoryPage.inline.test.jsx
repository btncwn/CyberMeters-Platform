import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { beforeEach, describe, it, expect, vi } from 'vitest'
import ShadowItInventoryPage from '../ShadowItInventoryPage'
import { nextShadowItActions } from '../../../lib/shadowItDisplay'
import { api } from '../../../api'
import { useWorkspace } from '../../../hooks/useWorkspace'

// Founder, 21 Oct 2026: the overview listed unclassified items with no action
// next to them, Reject lived only in a table behind "See all", "All (1)" counted
// the filtered list, a recurrence sentence sat under Owner, and a row offered
// thirteen buttons at once.

vi.mock('../../../api', () => ({
  api: { getShadowItInventory: vi.fn(), shadowItAction: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: vi.fn() }))

const WS = 'ws_inline'
const ACTIONS = [
  'approve', 'reject', 'mark_exception', 'assign_business_owner', 'assign_technical_owner',
  'set_business_purpose', 'begin_onboarding', 'mark_onboarded', 'begin_removal',
  'mark_removed', 'retire', 'reopen_review',
]
const item = (id, name, over = {}) => ({
  inventory_item_id: id, display_name: name, provider: `${name.toLowerCase()}.example`, category: 'saas',
  classification: 'unreviewed', ownership_status: 'missing', monitoring_status: 'observed',
  last_seen_at: '2026-10-20T00:00:00Z', onboarding_status: null, removal_status: null, removal_verified: null,
  linked_case_id: null, observed_hostnames: [], ...over,
})
const COUNTS = { unreviewed: 7, approved: 0, rejected: 1, exception: 0, retired: 0 }

function mount(path = '/ws/shadow-it') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes><Route path="/ws/shadow-it" element={<ShadowItInventoryPage />} /></Routes>
    </MemoryRouter>,
  )
}

async function answerDialog(value, confirmName) {
  const dialog = await screen.findByTestId('app-dialog')
  const input = dialog.querySelector('input')
  if (input) fireEvent.change(input, { target: { value } })
  await userEvent.click(within(dialog).getByRole('button', { name: confirmName }))
}

beforeEach(() => {
  vi.clearAllMocks()
  useWorkspace.mockReturnValue({ wsId: WS, wsName: 'Example Ltd', loading: false })
  api.shadowItAction.mockResolvedValue({})
  api.getShadowItInventory.mockResolvedValue({
    items: [item('sii_stripe', 'Stripe'), item('sii_miro', 'Miro', { classification: 'rejected', recurrence_summary: 'Miro, which you rejected, is still externally observed.' })],
    counts: COUNTS, actions: ACTIONS, can_manage: true,
  })
})

describe('Shadow IT overview: classify where the item is listed', () => {
  it('each unclassified item has its own Approve, Reject and Exception buttons', async () => {
    mount()
    const row = (await screen.findAllByTestId('shadow-it-unclassified-item'))[0]
    for (const name of ['Approve Stripe', 'Reject Stripe', 'Exception Stripe']) {
      expect(within(row).getByRole('button', { name })).toBeInTheDocument()
    }
  })

  it('Reject from the overview uses the same reason dialog and action call', async () => {
    mount()
    await userEvent.click(await screen.findByRole('button', { name: 'Reject Stripe' }))
    await answerDialog('Not used by us', 'Reject')
    await waitFor(() => expect(api.shadowItAction).toHaveBeenCalledWith(WS, 'sii_stripe', { action: 'reject', reason: 'Not used by us' }))
  })

  it('a viewer gets no inline buttons', async () => {
    api.getShadowItInventory.mockResolvedValue({ items: [item('sii_stripe', 'Stripe')], counts: COUNTS, actions: [], can_manage: false })
    mount()
    await screen.findAllByTestId('shadow-it-unclassified-item')
    expect(screen.queryByRole('button', { name: /Stripe$/ })).toBeNull()
  })

  it('"See all" reads as a clear action naming the count', async () => {
    mount()
    expect(await screen.findByRole('button', { name: 'Classify all 7 items' })).toBeInTheDocument()
    expect(screen.queryByText(/^See all/)).toBeNull()
  })
})

describe('Shadow IT inventory', () => {
  it('"All" counts every item, not the filtered list', async () => {
    api.getShadowItInventory.mockResolvedValue({ items: [item('sii_miro', 'Miro', { classification: 'rejected' })], counts: COUNTS, actions: ACTIONS, can_manage: true })
    mount('/ws/shadow-it?tab=findings')
    expect(await screen.findByRole('button', { name: 'All (8)' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Rejected (1)' })).toBeInTheDocument()
  })

  it('the recurrence sentence sits with Monitoring, not under Owner', async () => {
    mount('/ws/shadow-it?tab=findings')
    const sentence = await screen.findByTestId('shadow-it-recurrence')
    expect(sentence).toHaveTextContent('Miro, which you rejected, is still externally observed.')
    const cells = [...sentence.closest('tr').children]
    expect(cells.indexOf(sentence.closest('td'))).toBe(4) // Technology, Category, Classification, Owner, Monitoring
  })

  it('a row shows its next sensible action first and the rest behind More', async () => {
    mount('/ws/shadow-it?tab=findings')
    await screen.findByText('Miro')
    const miroRow = screen.getByText('Miro').closest('tr')
    expect(within(miroRow).getByRole('button', { name: 'Start removal' })).toBeInTheDocument()
    expect(within(miroRow).queryByRole('button', { name: 'Technical owner' })).toBeNull()
    const more = within(miroRow).getByRole('button', { name: 'More actions for Miro' })
    expect(more).toHaveAttribute('aria-expanded', 'false')
    await userEvent.click(more)
    expect(more).toHaveAttribute('aria-expanded', 'true')
    expect(within(miroRow).getByRole('button', { name: 'Technical owner' })).toBeInTheDocument()
    expect(within(miroRow).queryAllByRole('button', { name: 'Start removal' })).toHaveLength(1)
  })
})

describe('nextShadowItActions', () => {
  it('picks the next step from the item state', () => {
    expect(nextShadowItActions({ classification: 'unreviewed' })).toEqual(['approve', 'reject', 'mark_exception'])
    expect(nextShadowItActions({ classification: 'rejected', removal_status: null })).toEqual(['begin_removal'])
    expect(nextShadowItActions({ classification: 'rejected', removal_status: 'in_progress' })).toEqual(['mark_removed'])
    expect(nextShadowItActions({ classification: 'approved', ownership_status: 'missing' })).toEqual(['assign_business_owner'])
    expect(nextShadowItActions({ classification: 'approved', ownership_status: 'known', onboarding_status: null })).toEqual(['begin_onboarding'])
    expect(nextShadowItActions({ classification: 'approved', ownership_status: 'known', onboarding_status: 'onboarded' })).toEqual([])
    expect(nextShadowItActions({ classification: 'exception' })).toEqual(['reopen_review'])
    expect(nextShadowItActions(null)).toEqual([])
  })
})
