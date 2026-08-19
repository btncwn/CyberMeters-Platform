// ── F-47 — Shadow IT action-set parity between backend and customer UI ────────
//
// THE DEFECT THIS EXISTS TO PREVENT (measured at canonical main 1b02610c):
// `SHADOW_IT_WORKFLOW_ACTIONS` holds 12 actions and `routes/shadow-it.js`
// advertises all 12 to a user with `workspace:manage`, but the only production UI
// caller rendered buttons for 6. Six server-advertised actions —
// assign_technical_owner, begin_onboarding, mark_onboarded, begin_removal,
// mark_removed, reopen_review — had no customer-reachable control at all. The
// route permission was never missing; the gap was UI reachability, and direct API
// access does not satisfy approved-inventory acceptance.
//
// A source-string count is explicitly NOT sufficient (work order §3), so every
// assertion below drives the real component and asserts the ACTUAL client call.
//
// SCOPE BOUNDARY: this harness asserts the customer-reachable action surface and
// its honesty. It takes no position on backend state-machine semantics, and it
// deliberately does not touch the ws=<workspace_UUID> URL-parameter observation
// (I11C-OBS-01), which is a separate, non-gating item.
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { beforeEach, afterEach, describe, it, expect, vi } from 'vitest'
import ShadowItInventoryPage from '../ShadowItInventoryPage'
import { api } from '../../../api'
import { useWorkspace } from '../../../hooks/useWorkspace'

vi.mock('../../../api', () => ({
  api: { getShadowItInventory: vi.fn(), shadowItAction: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: vi.fn() }))

const WS_ID = 'ws_real_shadowit_1'
const ITEM_ID = 'sii_opaque_9f31'

// The canonical backend list, copied verbatim from
// workers/scan-api/src/engines/shadow-it-inventory.js SHADOW_IT_WORKFLOW_ACTIONS.
// If the backend adds an action, this array must be updated and the parity test
// below will fail until a control exists — which is the point.
const BACKEND_ACTIONS = [
  'approve', 'reject', 'mark_exception', 'assign_business_owner', 'assign_technical_owner',
  'set_business_purpose', 'begin_onboarding', 'mark_onboarded', 'begin_removal',
  'mark_removed', 'retire', 'reopen_review',
]

// Accessible names of the control for each action.
const CONTROL_LABEL = {
  approve: 'Approve',
  reject: 'Reject',
  mark_exception: 'Exception',
  retire: 'Retire',
  reopen_review: 'Reopen review',
  assign_business_owner: 'Business owner',
  assign_technical_owner: 'Technical owner',
  set_business_purpose: 'Purpose',
  begin_onboarding: 'Start onboarding',
  mark_onboarded: 'Mark onboarded',
  begin_removal: 'Start removal',
  mark_removed: 'Mark removed',
}

// The six that had no control before F-47.
const PREVIOUSLY_MISSING = [
  'assign_technical_owner', 'begin_onboarding', 'mark_onboarded',
  'begin_removal', 'mark_removed', 'reopen_review',
]
// The six that already worked and must not regress.
const PREVIOUSLY_PRESENT = [
  'approve', 'reject', 'mark_exception', 'assign_business_owner',
  'set_business_purpose', 'retire',
]

function item(overrides = {}) {
  return {
    inventory_item_id: ITEM_ID,
    display_name: 'Acme CRM',
    provider: 'acme.example.com',
    category: 'crm',
    classification: 'unreviewed',
    ownership_status: 'missing',
    monitoring_status: 'observed',
    last_seen_at: '2026-08-16T00:00:00Z',
    business_owner: null,
    technical_owner: null,
    onboarding_status: null,
    removal_status: null,
    removal_verified: null,
    linked_case_id: null,
    observed_hostnames: [],
    ...overrides,
  }
}

function respond({ actions = BACKEND_ACTIONS, items = [item()], can_manage = true } = {}) {
  api.getShadowItInventory.mockResolvedValue({ items, counts: {}, actions, can_manage })
}

function mount() {
  return render(
    <MemoryRouter initialEntries={['/ws/shadow-it']}>
      <Routes><Route path="/ws/shadow-it" element={<ShadowItInventoryPage />} /></Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  useWorkspace.mockReturnValue({ wsId: WS_ID, loading: false })
  api.shadowItAction.mockResolvedValue({ item: item() })
})
afterEach(() => { vi.restoreAllMocks() })

// ── BAR 1 — exact backend/UI action-set parity for a manager ─────────────────
describe('F-47 — action-set parity', () => {
  it('renders a reachable control for ALL 12 server-advertised actions', async () => {
    respond()
    mount()
    await screen.findByText('Acme CRM')
    for (const action of BACKEND_ACTIONS) {
      expect(
        screen.getByRole('button', { name: CONTROL_LABEL[action] }),
        `no control for server-advertised action "${action}"`,
      ).toBeInTheDocument()
    }
  })

  it('covers every backend action with a declared control label (no silent drift)', () => {
    for (const action of BACKEND_ACTIONS) expect(CONTROL_LABEL[action]).toBeTruthy()
    expect(Object.keys(CONTROL_LABEL).sort()).toEqual([...BACKEND_ACTIONS].sort())
    expect([...PREVIOUSLY_MISSING, ...PREVIOUSLY_PRESENT].sort()).toEqual([...BACKEND_ACTIONS].sort())
  })
})

// ── BAR 3 — each control issues the exact client call ────────────────────────
describe('F-47 — the six previously missing actions issue correct calls', () => {
  it('assign_technical_owner sends the existing owner field', async () => {
    respond()
    vi.spyOn(window, 'prompt').mockReturnValue('Dana Ops')
    mount()
    await screen.findByText('Acme CRM')
    await userEvent.click(screen.getByRole('button', { name: 'Technical owner' }))
    await waitFor(() => expect(api.shadowItAction).toHaveBeenCalledWith(
      WS_ID, ITEM_ID, { action: 'assign_technical_owner', owner: 'Dana Ops' },
    ))
  })

  it.each(['begin_onboarding', 'mark_onboarded', 'begin_removal'])(
    '%s sends the bare canonical action with no invented payload', async (action) => {
      respond()
      mount()
      await screen.findByText('Acme CRM')
      await userEvent.click(screen.getByRole('button', { name: CONTROL_LABEL[action] }))
      await waitFor(() => expect(api.shadowItAction).toHaveBeenCalledWith(WS_ID, ITEM_ID, { action }))
    },
  )

  it('reopen_review sends the optional reason', async () => {
    respond()
    vi.spyOn(window, 'prompt').mockReturnValue('vendor contract changed')
    mount()
    await screen.findByText('Acme CRM')
    await userEvent.click(screen.getByRole('button', { name: 'Reopen review' }))
    await waitFor(() => expect(api.shadowItAction).toHaveBeenCalledWith(
      WS_ID, ITEM_ID, { action: 'reopen_review', reason: 'vendor contract changed' },
    ))
  })

  it('reopen_review aborts when the customer cancels the prompt', async () => {
    respond()
    vi.spyOn(window, 'prompt').mockReturnValue(null)
    mount()
    await screen.findByText('Acme CRM')
    await userEvent.click(screen.getByRole('button', { name: 'Reopen review' }))
    expect(api.shadowItAction).not.toHaveBeenCalled()
  })

  it('mark_removed requires confirmation and sends the bare action', async () => {
    respond()
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true)
    mount()
    await screen.findByText('Acme CRM')
    await userEvent.click(screen.getByRole('button', { name: 'Mark removed' }))
    await waitFor(() => expect(api.shadowItAction).toHaveBeenCalledWith(
      WS_ID, ITEM_ID, { action: 'mark_removed' },
    ))
    // Evidence honesty: the confirmation must say this is the CUSTOMER's
    // assertion and must never present it as CyberMeters verification.
    const copy = confirm.mock.calls[0][0]
    expect(copy).toMatch(/YOUR assertion/)
    expect(copy).toMatch(/has not verified/i)
    expect(copy).not.toMatch(/\bverified removal\b|\bconfirmed removed\b/i)
  })

  it('mark_removed does nothing when the customer declines the confirmation', async () => {
    respond()
    vi.spyOn(window, 'confirm').mockReturnValue(false)
    mount()
    await screen.findByText('Acme CRM')
    await userEvent.click(screen.getByRole('button', { name: 'Mark removed' }))
    expect(api.shadowItAction).not.toHaveBeenCalled()
  })
})

// ── BAR 5 — the original six do not regress ─────────────────────────────────
describe('F-47 — previously working actions still work', () => {
  it('approve sends the bare action', async () => {
    respond()
    mount()
    await screen.findByText('Acme CRM')
    await userEvent.click(screen.getByRole('button', { name: 'Approve' }))
    await waitFor(() => expect(api.shadowItAction).toHaveBeenCalledWith(WS_ID, ITEM_ID, { action: 'approve' }))
  })

  it.each(['reject', 'retire'])('%s sends the required reason', async (action) => {
    respond()
    vi.spyOn(window, 'prompt').mockReturnValue('no longer needed')
    mount()
    await screen.findByText('Acme CRM')
    await userEvent.click(screen.getByRole('button', { name: CONTROL_LABEL[action] }))
    await waitFor(() => expect(api.shadowItAction).toHaveBeenCalledWith(
      WS_ID, ITEM_ID, { action, reason: 'no longer needed' },
    ))
  })

  it('mark_exception sends reason and an ISO expiry', async () => {
    respond()
    vi.spyOn(window, 'prompt')
      .mockReturnValueOnce('pending migration')
      .mockReturnValueOnce('2027-01-31')
    mount()
    await screen.findByText('Acme CRM')
    await userEvent.click(screen.getByRole('button', { name: 'Exception' }))
    await waitFor(() => expect(api.shadowItAction).toHaveBeenCalled())
    const [, , payload] = api.shadowItAction.mock.calls[0]
    expect(payload.action).toBe('mark_exception')
    expect(payload.reason).toBe('pending migration')
    expect(payload.exception_until).toBe(new Date('2027-01-31').toISOString())
  })

  it('assign_business_owner still sends the owner field', async () => {
    respond()
    vi.spyOn(window, 'prompt').mockReturnValue('Sam Finance')
    mount()
    await screen.findByText('Acme CRM')
    await userEvent.click(screen.getByRole('button', { name: 'Business owner' }))
    await waitFor(() => expect(api.shadowItAction).toHaveBeenCalledWith(
      WS_ID, ITEM_ID, { action: 'assign_business_owner', owner: 'Sam Finance' },
    ))
  })

  it('set_business_purpose still accepts an empty answer', async () => {
    respond()
    vi.spyOn(window, 'prompt').mockReturnValue('')
    mount()
    await screen.findByText('Acme CRM')
    await userEvent.click(screen.getByRole('button', { name: 'Purpose' }))
    await waitFor(() => expect(api.shadowItAction).toHaveBeenCalledWith(
      WS_ID, ITEM_ID, { action: 'set_business_purpose', business_purpose: '' },
    ))
  })
})

// ── BAR 2 — the frontend invents nothing ────────────────────────────────────
describe('F-47 — server-driven suppression', () => {
  it('renders NO action control for a viewer (actions: [])', async () => {
    respond({ actions: [], can_manage: false })
    mount()
    await screen.findByText('Acme CRM')
    for (const action of BACKEND_ACTIONS) {
      expect(screen.queryByRole('button', { name: CONTROL_LABEL[action] })).toBeNull()
    }
    // No empty group scaffolding is left behind either. Queried by ROLE, not by
    // text: "Classification" is also a table header, so a text query would
    // collide with the column heading rather than the action group.
    expect(screen.queryByRole('group')).toBeNull()
  })

  it('renders ONLY the actions the server advertised, never the rest', async () => {
    const advertised = ['approve', 'mark_removed']
    respond({ actions: advertised })
    mount()
    await screen.findByText('Acme CRM')
    for (const action of BACKEND_ACTIONS) {
      const control = screen.queryByRole('button', { name: CONTROL_LABEL[action] })
      if (advertised.includes(action)) expect(control).toBeInTheDocument()
      else expect(control, `rendered "${action}" the server did not advertise`).toBeNull()
    }
  })

  it('drops a group entirely when none of its actions is advertised', async () => {
    respond({ actions: ['approve'] })
    mount()
    await screen.findByText('Acme CRM')
    expect(screen.getByRole('group', { name: /Classification actions/ })).toBeInTheDocument()
    for (const label of ['Onboarding', 'Removal', 'Ownership']) {
      expect(screen.queryByRole('group', { name: new RegExp(`${label} actions`) })).toBeNull()
    }
    expect(screen.getAllByRole('group')).toHaveLength(1)
  })
})

// ── BAR 3/4 — busy suppression and honest failure ───────────────────────────
describe('F-47 — busy and failure behaviour', () => {
  it('suppresses duplicate submission while an action is in flight', async () => {
    respond()
    let release
    api.shadowItAction.mockReturnValue(new Promise((r) => { release = r }))
    mount()
    await screen.findByText('Acme CRM')
    const approve = screen.getByRole('button', { name: 'Approve' })
    await userEvent.click(approve)
    await waitFor(() => expect(approve).toBeDisabled())
    // Every control in the row is disabled, not just the clicked one.
    expect(screen.getByRole('button', { name: 'Mark removed' })).toBeDisabled()
    await userEvent.click(approve)
    expect(api.shadowItAction).toHaveBeenCalledTimes(1)
    // Settle the in-flight action before unmounting so the resulting state
    // update happens inside the test, not after it.
    release({ item: item() })
    await waitFor(() => expect(approve).not.toBeDisabled())
  })

  it('a failed action does NOT erase the inventory and does not look like success', async () => {
    respond()
    api.shadowItAction.mockRejectedValue(new Error('network'))
    mount()
    await screen.findByText('Acme CRM')
    await userEvent.click(screen.getByRole('button', { name: 'Approve' }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(/did not complete/i)
    // THE REGRESSION THIS PINS: the row must still be on screen. Before F-47 the
    // action error shared the load-error slot and the whole table unmounted.
    expect(screen.getByText('Acme CRM')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Approve' })).toBeInTheDocument()
    // It must not claim the change was rejected by the server.
    expect(alert.textContent).not.toMatch(/no change was saved|was not applied/i)
  })

  it('clears a previous action error when a later action is attempted', async () => {
    respond()
    api.shadowItAction.mockRejectedValueOnce(new Error('network'))
    mount()
    await screen.findByText('Acme CRM')
    await userEvent.click(screen.getByRole('button', { name: 'Approve' }))
    await screen.findByRole('alert')
    api.shadowItAction.mockResolvedValue({ item: item() })
    await userEvent.click(screen.getByRole('button', { name: 'Approve' }))
    await waitFor(() => expect(screen.queryByRole('alert')).toBeNull())
  })
})

// ── BAR 4 — page states remain mutually honest ──────────────────────────────
describe('F-47 — loading, empty and load-error states', () => {
  it('shows loading, then the list', async () => {
    respond()
    mount()
    expect(screen.getByText('Loading…')).toBeInTheDocument()
    await screen.findByText('Acme CRM')
    expect(screen.queryByText('Loading…')).toBeNull()
  })

  it('shows the empty state and no action controls', async () => {
    respond({ items: [] })
    mount()
    expect(await screen.findByText(/No externally observed technology recorded yet/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Approve' })).toBeNull()
  })

  it('a LOAD error hides the table (unlike an action error)', async () => {
    api.getShadowItInventory.mockRejectedValue(new Error('boom'))
    mount()
    expect(await screen.findByText(/Could not load the technology inventory/i)).toBeInTheDocument()
    expect(screen.queryByText('Acme CRM')).toBeNull()
  })
})

// ── Evidence honesty in rendered lifecycle state ────────────────────────────
describe('F-47 — removal is never rendered as verified', () => {
  // Scoped to the Classification cell on purpose: the Actions cell legitimately
  // contains the words "Onboarding"/"Removal" as group labels, so a row-wide
  // query would pass or fail for the wrong reason.
  async function classificationCell() {
    const row = (await screen.findByText('Acme CRM')).closest('tr')
    return row.querySelectorAll('td')[2]
  }

  it('renders a customer-asserted removal as unverified', async () => {
    respond({ items: [item({ removal_status: 'removed', removal_verified: 'unverified' })] })
    mount()
    const cell = await classificationCell()
    expect(within(cell).getByText(/your assertion, not verified by CyberMeters/i)).toBeInTheDocument()
    expect(within(cell).queryByText(/confirmed removed|verified removal/i)).toBeNull()
  })

  it('renders a contradicted removal louder than the assertion', async () => {
    respond({ items: [item({ removal_status: 'removed', removal_verified: 'contradicted' })] })
    mount()
    const cell = await classificationCell()
    expect(within(cell).getByText(/still observed, contradicts the assertion/i)).toBeInTheDocument()
  })

  it('renders onboarding progress without implying external verification', async () => {
    respond({ items: [item({ onboarding_status: 'in_progress' })] })
    mount()
    const cell = await classificationCell()
    expect(within(cell).getByText('Onboarding in progress')).toBeInTheDocument()
  })

  it('renders no lifecycle line when the server sent no lifecycle state', async () => {
    respond()
    mount()
    const cell = await classificationCell()
    expect(within(cell).queryByText(/onboard|removal|removed/i)).toBeNull()
  })
})
