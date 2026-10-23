// S1-SHELL-V2b (Identity), R1 15:55: "What we observed" counts the backend's
// records by claim kind from the UNFILTERED load only; never 0 while loading or
// unavailable; a full page is a lower bound ("N+"); reset on workspace change.
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { beforeEach, describe, it, expect, vi } from 'vitest'
import IdentityExposurePage, { MeasuredEndpoints, identitySummaryFigures, SUMMARY_LIMIT } from '../IdentityExposurePage'
import { api } from '../../../api'
import { useWorkspace } from '../../../hooks/useWorkspace'

vi.mock('../../../api', () => ({
  api: { getIdentitySurfaces: vi.fn(), getIdentitySurface: vi.fn(), identitySurfaceVerify: vi.fn(), identitySurfaceAction: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: vi.fn() }))

const item = (id, kind, over = {}) => ({ identity_exposure_id: id, primary_hostname: `${id}.example.test`, surface_type: 'login_surface',
  identity_claim: { claim_kind: kind, ...(kind === 'measured_identity_surface' ? { reachability: { status: 'reachable' } } : {}) },
  customer_classification: 'unreviewed', allowed_actions: [], ...over })
const ITEMS = [
  item('idp', 'provider_relationship', { provider_name: 'Example IdP', primary_hostname: null }),
  item('sso', 'surface_candidate'),
  item('login', 'measured_identity_surface', { measured_endpoints: ['https://login.example.test/'] }),
]
const ok = (over = {}) => ({ status: 'ok', items: ITEMS, counts: { unreviewed: 3 }, atLimit: false, ...over })
const values = (f) => f.map((x) => x.value)

describe('identitySummaryFigures', () => {
  it('counts each claim kind and the workspace-wide unreviewed count; every figure has an anchor', () => {
    const f = identitySummaryFigures(ok())
    expect(f.map((x) => [x.id, x.value])).toEqual([
      ['identity-providers-observed', 1], ['identity-hostnames-possible', 1], ['identity-measured', 1], ['identity-unreviewed', 3],
    ])
  })
  it('loading → "Loading…" and unavailable → "Not available" for all four, never 0', () => {
    expect(values(identitySummaryFigures({ status: 'loading', items: [], counts: null }))).toEqual(Array(4).fill('Loading…'))
    expect(values(identitySummaryFigures({ status: 'error', items: [], counts: null }))).toEqual(Array(4).fill('Not available'))
  })
  it('a backend response without counts.unreviewed is "Not available", never 0', () => {
    expect(identitySummaryFigures(ok({ counts: {} }))[3].value).toBe('Not available')
    expect(identitySummaryFigures(ok({ counts: null }))[3].value).toBe('Not available')
  })
  it('a full page (the backend maximum) makes the claim-kind counts lower bounds; unreviewed stays exact', () => {
    expect(values(identitySummaryFigures(ok({ atLimit: true })))).toEqual(['1+', '1+', '1+', 3])
    expect(SUMMARY_LIMIT).toBe(500)
  })
  it('the provider explanation does not over-claim DNS', () => {
    expect(identitySummaryFigures(ok())[0].explanation).toBe('Identity providers observed for your domains')
  })
})

describe('MeasuredEndpoints', () => {
  it('lists measured endpoints with the backend claim label', () => {
    render(<MeasuredEndpoints status="ok" items={ITEMS} />)
    const s = screen.getByTestId('identity-measured-endpoints')
    expect(s).toHaveAttribute('id', 'identity-measured-endpoints')
    expect(within(s).getByText('https://login.example.test/')).toBeInTheDocument()
    expect(within(s).getByText('Measured reachable surface')).toBeInTheDocument()
    expect(within(s).queryByText('idp.example.test')).toBeNull()
  })
  it('loading, unavailable, none measured, and none in a full page each say exactly that', () => {
    const { rerender } = render(<MeasuredEndpoints status="loading" items={[]} />)
    expect(screen.getByTestId('identity-measured-endpoints')).toHaveTextContent('Loading…')
    rerender(<MeasuredEndpoints status="error" items={ITEMS} />)
    expect(screen.getByTestId('identity-measured-endpoints')).toHaveTextContent('Not available')
    expect(screen.queryByText('https://login.example.test/')).toBeNull()
    rerender(<MeasuredEndpoints status="ok" items={[]} />)
    expect(screen.getByTestId('identity-measured-endpoints')).toHaveTextContent('No endpoint has been measured yet')
    rerender(<MeasuredEndpoints status="ok" items={[ITEMS[0]]} atLimit />)
    expect(screen.getByTestId('identity-measured-endpoints')).toHaveTextContent('None among the first 500 identity records.')
  })
})

const fig = (id) => document.getElementById(id)
function mount() {
  return render(<MemoryRouter initialEntries={['/ws/identity-exposure?tab=findings']}><Routes><Route path="/ws/identity-exposure" element={<IdentityExposurePage />} /></Routes></MemoryRouter>)
}

describe('IdentityExposurePage summary', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useWorkspace.mockReturnValue({ wsId: 'ws1', wsName: 'WS', loading: false })
    api.getIdentitySurfaces.mockImplementation(async (_ws, params) => (params?.customer_classification
      ? { items: [], counts: { unreviewed: 3 } }
      : { items: ITEMS, counts: { unreviewed: 3 } }))
  })
  it('a filter chip never changes "What we observed" — not even while the filtered fetch runs', async () => {
    mount()
    await waitFor(() => expect(fig('identity-measured')).toHaveTextContent('1'))
    expect(api.getIdentitySurfaces).toHaveBeenCalledWith('ws1', { limit: 500 })
    expect(document.body.textContent).not.toContain('Â')
    expect(screen.getAllByText(/ · Example IdP$/).length).toBeGreaterThan(0)
    let release
    api.getIdentitySurfaces.mockImplementationOnce(() => new Promise((r) => { release = () => r({ items: [], counts: { unreviewed: 3 } }) }))
    fireEvent.click(screen.getByRole('button', { name: /^Expected/ }))
    // In flight: the figures still read the unfiltered load.
    expect(fig('identity-unreviewed')).toHaveTextContent('3')
    expect(fig('identity-measured')).toHaveTextContent('1')
    release()
    await waitFor(() => expect(api.getIdentitySurfaces).toHaveBeenLastCalledWith('ws1', { customer_classification: 'expected' }))
    expect(fig('identity-measured')).toHaveTextContent('1')
    expect(screen.getByTestId('identity-measured-endpoints')).toHaveTextContent('https://login.example.test/')
  })
  it('an unfiltered load that fails, then a chip: every figure and the section say "Not available", never 0 or "none measured"', async () => {
    api.getIdentitySurfaces.mockImplementation(async (_ws, params) => {
      if (!params?.customer_classification) throw new Error('down')
      return { items: [], counts: { unreviewed: 0 } }
    })
    mount()
    await waitFor(() => expect(fig('identity-unreviewed')).toHaveTextContent('Not available'))
    fireEvent.click(screen.getByRole('button', { name: /^Expected/ }))
    await waitFor(() => expect(api.getIdentitySurfaces).toHaveBeenLastCalledWith('ws1', { customer_classification: 'expected' }))
    for (const id of ['identity-providers-observed', 'identity-hostnames-possible', 'identity-measured', 'identity-unreviewed']) {
      expect(fig(id)).toHaveTextContent('Not available')
    }
    expect(screen.getByTestId('identity-measured-endpoints')).toHaveTextContent('Not available')
    expect(screen.getByTestId('identity-measured-endpoints')).not.toHaveTextContent('No endpoint has been measured yet')
  })
  it('a workspace switch with a chip active resets the filter and never shows the previous workspace\'s counts', async () => {
    const view = mount()
    await waitFor(() => expect(fig('identity-measured')).toHaveTextContent('1'))
    fireEvent.click(screen.getByRole('button', { name: /^Expected/ }))
    await waitFor(() => expect(api.getIdentitySurfaces).toHaveBeenLastCalledWith('ws1', { customer_classification: 'expected' }))
    let release
    api.getIdentitySurfaces.mockImplementation(() => new Promise((r) => { release = () => r({ items: [item('other', 'surface_candidate')], counts: { unreviewed: 0 } }) }))
    useWorkspace.mockReturnValue({ wsId: 'ws2', wsName: 'Other', loading: false })
    view.rerender(<MemoryRouter initialEntries={['/ws/identity-exposure?tab=findings']}><Routes><Route path="/ws/identity-exposure" element={<IdentityExposurePage />} /></Routes></MemoryRouter>)
    await waitFor(() => expect(api.getIdentitySurfaces).toHaveBeenLastCalledWith('ws2', { limit: 500 }))
    expect(fig('identity-measured')).toHaveTextContent('Loading…')
    expect(fig('identity-unreviewed')).toHaveTextContent('Loading…')
    release()
    await waitFor(() => expect(fig('identity-unreviewed')).toHaveTextContent('0'))
    expect(fig('identity-measured')).toHaveTextContent('0')
    expect(screen.getByRole('button', { name: /^All/ }).className).toContain('bg-slate-800')
  })
})
