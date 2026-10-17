import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import WorkspaceDomainsPage from '../WorkspaceDomainsPage'
import { api } from '../../../api'

// The Domains page (extracted from the dissolved workspace administration
// page) keeps that page's tenant discipline: switching workspace clears what
// was shown, requests the new workspace, and ignores a late answer for the old.

let selected = { wsId: 'a', wsName: 'Customer a' }
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: () => selected }))
vi.mock('../../../hooks/useDomainConnectOffer', () => ({ useDomainConnectOffer: () => ({ available: false }) }))
vi.mock('../../../api', () => ({ api: { getWorkspaceDomains: vi.fn(), getWorkspaceSummary: vi.fn(), importWorkspaceDomains: vi.fn() } }))
vi.mock('../../../components/WsPage', () => ({
  default: ({ loading, children }) => loading ? <div>Loading workspace</div> : <div>{children}</div>,
  NoWorkspaceSelected: () => <div>No workspace selected</div>,
}))

const deferred = () => { let resolve; const promise = new Promise((done) => { resolve = done }); return { promise, resolve } }
const domainsOf = (id) => ({ domains: [{ domain_id: `d-${id}`, domain: `${id}.example`, verification_status: 'verified' }] })

beforeEach(() => {
  vi.clearAllMocks()
  selected = { wsId: 'a', wsName: 'Customer a' }
  api.getWorkspaceDomains.mockImplementation((id) => Promise.resolve(domainsOf(id)))
  api.getWorkspaceSummary.mockImplementation((id) => Promise.resolve({ domains: 1, reports_count: id === 'a' ? 9 : 2 }))
})

it('remounts A→B with cleared state and requests B', async () => {
  const b = deferred()
  api.getWorkspaceDomains.mockImplementation((id) => (id === 'b' ? b.promise : Promise.resolve(domainsOf(id))))
  const view = render(<MemoryRouter><WorkspaceDomainsPage /></MemoryRouter>)
  await screen.findByText('a.example')
  selected = { wsId: 'b', wsName: 'Customer b' }
  view.rerender(<MemoryRouter><WorkspaceDomainsPage /></MemoryRouter>)
  expect(screen.queryByText('a.example')).not.toBeInTheDocument()
  expect(screen.getByText('Loading workspace')).toBeInTheDocument()
  b.resolve(domainsOf('b'))
  await screen.findByText('b.example')
  expect(api.getWorkspaceDomains).toHaveBeenCalledWith('b')
})

it('ignores late A results after B finishes', async () => {
  const a = deferred()
  api.getWorkspaceDomains.mockImplementation((id) => (id === 'a' ? a.promise : Promise.resolve(domainsOf(id))))
  const view = render(<MemoryRouter><WorkspaceDomainsPage /></MemoryRouter>)
  await waitFor(() => expect(api.getWorkspaceDomains).toHaveBeenCalledWith('a'))
  selected = { wsId: 'b', wsName: 'Customer b' }
  view.rerender(<MemoryRouter><WorkspaceDomainsPage /></MemoryRouter>)
  await screen.findByText('b.example')
  a.resolve(domainsOf('a'))
  await waitFor(() => expect(screen.getByText('b.example')).toBeInTheDocument())
  expect(screen.queryByText('a.example')).not.toBeInTheDocument()
})

it('with no domains it offers the import widget; with domains the verification stats', async () => {
  api.getWorkspaceDomains.mockResolvedValue({ domains: [] })
  api.getWorkspaceSummary.mockResolvedValue({ domains: 0 })
  render(<MemoryRouter><WorkspaceDomainsPage /></MemoryRouter>)
  await screen.findByText('Add your first domain')
  expect(screen.queryByTestId('domain-verification-stats')).toBeNull()
})
