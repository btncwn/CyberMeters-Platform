import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import Dashboard from '../Dashboard'
import { api } from '../../api'

vi.mock('../../api', () => ({ api: {
  getWorkspaces: vi.fn(), getWorkspaceScans: vi.fn(), getWorkspaceDomains: vi.fn(),
  getWorkspaceScorecard: vi.fn(), getCyberMotDomains: vi.fn(), getScanReport: vi.fn(),
} }))
vi.mock('../../components/overview/SecurityOverview', async importOriginal => ({
  ...(await importOriginal()),
  NextActionCard: ({ signals }) => <div data-testid="action-signals">{JSON.stringify(signals)}</div>,
}))

const deferred = () => {
  let resolve
  const promise = new Promise(done => { resolve = done })
  return { promise, resolve }
}
const domains = state => ({ cyber_mot_domains: [{ domain_key: 'email_protection', display_name: 'Email Protection', state }] })
const scans = domain => ({ scans: [{ id: domain, domain, status: 'failed' }] })

function selectWorkspace(id) {
  localStorage.setItem('cybermeters_workspace_id', id)
  localStorage.setItem('cybermeters_workspace_name', `Customer ${id}`)
  fireEvent(window, new StorageEvent('storage', { key: 'cybermeters_workspace_id', newValue: id }))
  fireEvent(window, new StorageEvent('storage', { key: 'cybermeters_workspace_name', newValue: `Customer ${id}` }))
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  localStorage.setItem('cybermeters_workspace_id', 'a')
  localStorage.setItem('cybermeters_workspace_name', 'Customer a')
  api.getWorkspaceDomains.mockImplementation(id => Promise.resolve({ domains: [{ domain: `${id}.example` }] }))
  api.getWorkspaceScorecard.mockImplementation(id => Promise.resolve({ workspace: id }))
  api.getCyberMotDomains.mockImplementation(id => Promise.resolve(domains(id === 'a' ? 'issue_detected' : 'assessed_healthy')))
  api.getWorkspaceScans.mockImplementation(id => Promise.resolve(scans(`${id}.example`)))
})

it('reloads A→B and clears every A signal while B is pending', async () => {
  const b = deferred()
  api.getWorkspaceScans.mockImplementation(id => id === 'b' ? b.promise : Promise.resolve(scans('a.example')))
  render(<MemoryRouter><Dashboard /></MemoryRouter>)
  expect(await screen.findByText('a.example')).toBeInTheDocument()
  expect(screen.getByTestId('action-signals')).toHaveTextContent('"workspace":"a"')

  selectWorkspace('b')
  expect(screen.queryByText('a.example')).not.toBeInTheDocument()
  expect(screen.queryByTestId('action-signals')).not.toBeInTheDocument()
  b.resolve(scans('b.example'))
  expect(await screen.findByText('b.example')).toBeInTheDocument()
  expect(screen.getByTestId('action-signals')).toHaveTextContent('"workspace":"b"')
  expect(api.getWorkspaceScans).toHaveBeenCalledWith('b')
})

it('ignores A when its response arrives after B', async () => {
  const a = deferred()
  api.getWorkspaceScans.mockImplementation(id => id === 'a' ? a.promise : Promise.resolve(scans('b.example')))
  render(<MemoryRouter><Dashboard /></MemoryRouter>)
  await waitFor(() => expect(api.getWorkspaceScans).toHaveBeenCalledWith('a'))
  selectWorkspace('b')
  expect(await screen.findByText('b.example')).toBeInTheDocument()
  a.resolve(scans('a.example'))
  await waitFor(() => expect(screen.getByRole('heading', { name: 'Where is Customer b exposed today?' })).toBeInTheDocument())
  expect(screen.queryByText('a.example')).not.toBeInTheDocument()
  expect(screen.getByTestId('action-signals')).toHaveTextContent('"workspace":"b"')
})

it('shows failed B optional reads without retaining A values', async () => {
  render(<MemoryRouter><Dashboard /></MemoryRouter>)
  expect(await screen.findByText('a.example')).toBeInTheDocument()
  api.getWorkspaceScans.mockResolvedValue(scans('b.example'))
  api.getWorkspaceDomains.mockRejectedValue(new Error('unavailable'))
  api.getWorkspaceScorecard.mockRejectedValue(new Error('unavailable'))
  api.getCyberMotDomains.mockRejectedValue(new Error('unavailable'))
  selectWorkspace('b')
  expect(await screen.findByText('b.example')).toBeInTheDocument()
  expect(screen.getByTestId('action-signals')).not.toHaveTextContent('"workspace":"a"')
  expect(screen.getByTestId('action-signals')).toHaveTextContent('"scorecard":null')
  expect(screen.getByTestId('action-signals')).toHaveTextContent('"domainCount":null')
  expect(within(screen.getByTestId('posture-card')).getAllByText('Error')).toHaveLength(8)
})
