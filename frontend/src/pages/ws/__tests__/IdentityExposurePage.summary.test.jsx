// S1-SHELL-V2b (Identity): "What we observed" counts the backend's records by
// claim kind, unfiltered; "Measured endpoints" is its own section in every state.
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { beforeEach, describe, it, expect, vi } from 'vitest'
import IdentityExposurePage, { MeasuredEndpoints, identitySummaryFigures } from '../IdentityExposurePage'
import { api } from '../../../api'

vi.mock('../../../api', () => ({
  api: { getIdentitySurfaces: vi.fn(), getIdentitySurface: vi.fn(), identitySurfaceVerify: vi.fn(), identitySurfaceAction: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: () => ({ wsId: 'ws1', wsName: 'WS', loading: false }) }))

const item = (id, kind, over = {}) => ({ identity_exposure_id: id, primary_hostname: `${id}.example.test`, surface_type: 'login_surface',
  identity_claim: { claim_kind: kind, ...(kind === 'measured_identity_surface' ? { reachability: { status: 'reachable' } } : {}) },
  customer_classification: 'unreviewed', allowed_actions: [], ...over })
const ITEMS = [
  item('idp', 'provider_relationship', { provider_name: 'Example IdP', primary_hostname: null }),
  item('sso', 'surface_candidate'),
  item('login', 'measured_identity_surface', { measured_endpoints: ['https://login.example.test/'] }),
]

describe('identitySummaryFigures', () => {
  it('counts each claim kind and the unreviewed records; every figure has an anchor', () => {
    const f = identitySummaryFigures({ items: ITEMS, counts: { unreviewed: 3 } })
    expect(f.map((x) => [x.id, x.value])).toEqual([
      ['identity-providers-observed', 1], ['identity-hostnames-possible', 1], ['identity-measured', 1], ['identity-unreviewed', 3],
    ])
  })
  it('loading and error never read as zero', () => {
    expect(identitySummaryFigures({ items: [], counts: {}, loading: true })[0].value).toBe('Loading…')
    expect(identitySummaryFigures({ items: [], counts: {}, error: true })[2].value).toBe('Not available')
  })
})

describe('MeasuredEndpoints', () => {
  it('lists measured endpoints with the backend claim label', () => {
    render(<MemoryRouter><MeasuredEndpoints items={ITEMS} /></MemoryRouter>)
    const s = screen.getByTestId('identity-measured-endpoints')
    expect(s).toHaveAttribute('id', 'identity-measured-endpoints')
    expect(within(s).getByText('https://login.example.test/')).toBeInTheDocument()
    expect(within(s).getByText('Measured reachable surface')).toBeInTheDocument()
    expect(within(s).queryByText('idp.example.test')).toBeNull()
  })
  it('says so honestly before anything is measured, while loading, and on error', () => {
    const { rerender } = render(<MeasuredEndpoints items={[]} />)
    expect(screen.getByTestId('identity-measured-endpoints')).toHaveTextContent('No endpoint has been measured yet')
    rerender(<MeasuredEndpoints items={[]} loading />)
    expect(screen.getByTestId('identity-measured-endpoints')).toHaveTextContent('Loading…')
    rerender(<MeasuredEndpoints items={[]} error />)
    expect(screen.getByTestId('identity-measured-endpoints')).toHaveTextContent('Not available')
  })
})

describe('IdentityExposurePage summary', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.getIdentitySurfaces.mockImplementation(async (_ws, params) => (params?.customer_classification
      ? { items: [], counts: { unreviewed: 3 } }
      : { items: ITEMS, counts: { unreviewed: 3 } }))
  })
  it('a filter chip never changes "What we observed"; the provider separator is a real middle dot', async () => {
    render(<MemoryRouter initialEntries={['/ws/identity-exposure?tab=findings']}><Routes><Route path="/ws/identity-exposure" element={<IdentityExposurePage />} /></Routes></MemoryRouter>)
    await waitFor(() => expect(document.getElementById('identity-measured')).not.toBeNull())
    expect(document.getElementById('identity-measured')).toHaveTextContent('1')
    expect(document.body.textContent).not.toContain('Â')
    expect(screen.getAllByText(/ · Example IdP$/).length).toBeGreaterThan(0)
    fireEvent.click(screen.getByRole('button', { name: /^Expected/ }))
    await waitFor(() => expect(api.getIdentitySurfaces).toHaveBeenLastCalledWith('ws1', { customer_classification: 'expected' }))
    expect(document.getElementById('identity-measured')).toHaveTextContent('1')
    expect(screen.getByTestId('identity-measured-endpoints')).toHaveTextContent('https://login.example.test/')
  })
})
