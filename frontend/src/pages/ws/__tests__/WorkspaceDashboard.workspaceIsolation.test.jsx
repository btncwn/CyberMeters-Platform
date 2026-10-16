import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import WorkspaceDashboard from '../WorkspaceDashboard'
import { api } from '../../../api'

let selected = { wsId: 'a', wsName: 'Customer a' }
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: () => selected }))
vi.mock('../../../context/AuthContext', () => ({ useAuth: () => ({ user: { id: 'owner' } }) }))
vi.mock('../../../api', () => ({ api: {
  getWorkspaceScorecard: vi.fn(), getWorkspacePostureTimeline: vi.fn(),
  getWorkspaceSummary: vi.fn(), getWorkspaceHealth: vi.fn(),
  getWorkspaceDomains: vi.fn(), getCyberMotDomains: vi.fn(),
} }))
vi.mock('../../../components/WsPage', () => ({
  default: ({ loading, children }) => loading ? <div>Loading workspace</div> : <div>{children}</div>,
  NoWorkspaceSelected: () => <div>No workspace selected</div>,
}))
vi.mock('../../../components/overview/SecurityOverview', () => ({
  default: ({ signals }) => <div data-testid="overview-scorecard">{JSON.stringify(signals.scorecard)}</div>,
  requestManagedCases: () => Promise.resolve({ cases: [] }),
}))
vi.mock('../../../components/CyberMotDomains', () => ({ default: ({ domains }) => <div data-testid="mot-domains">{JSON.stringify(domains)}</div> }))
vi.mock('../../../components/WorkspaceMembersPanel', () => ({ default: () => null }))
vi.mock('../../../components/ActivityTimeline', () => ({ default: () => null }))
vi.mock('recharts', () => ({
  ResponsiveContainer: ({ children }) => <>{children}</>,
  AreaChart: ({ children }) => <div>{children}</div>,
  Area: () => null, XAxis: () => null, YAxis: () => null, CartesianGrid: () => null, Tooltip: () => null,
}))

const deferred = () => {
  let resolve
  const promise = new Promise(done => { resolve = done })
  return { promise, resolve }
}
const scorecard = id => ({ workspace: id, current_posture: { state: 'not_established', authoritative: null } })

beforeEach(() => {
  vi.clearAllMocks()
  selected = { wsId: 'a', wsName: 'Customer a' }
  api.getWorkspaceScorecard.mockImplementation(id => Promise.resolve(scorecard(id)))
  api.getWorkspacePostureTimeline.mockResolvedValue({ timeline: [] })
  api.getWorkspaceSummary.mockImplementation(id => Promise.resolve({ domains: 1, reports_count: id === 'a' ? 9 : 2 }))
  api.getWorkspaceHealth.mockResolvedValue({ workspace_status: 'active' })
  api.getWorkspaceDomains.mockImplementation(id => Promise.resolve({ domains: [{ domain: `${id}.example`, verification_status: 'verified' }] }))
  api.getCyberMotDomains.mockImplementation(id => Promise.resolve({ cyber_mot_domains: [{ domain_key: 'email_protection', state: id }] }))
})

it('remounts A→B with cleared state and requests B', async () => {
  const b = deferred()
  api.getWorkspaceScorecard.mockImplementation(id => id === 'b' ? b.promise : Promise.resolve(scorecard(id)))
  const view = render(<MemoryRouter><WorkspaceDashboard /></MemoryRouter>)
  await waitFor(() => expect(screen.getByTestId('overview-scorecard')).toHaveTextContent('"workspace":"a"'))
  selected = { wsId: 'b', wsName: 'Customer b' }
  view.rerender(<MemoryRouter><WorkspaceDashboard /></MemoryRouter>)
  expect(screen.queryByTestId('overview-scorecard')).not.toBeInTheDocument()
  expect(screen.getByText('Loading workspace')).toBeInTheDocument()
  b.resolve(scorecard('b'))
  await waitFor(() => expect(screen.getByTestId('overview-scorecard')).toHaveTextContent('"workspace":"b"'))
  expect(screen.getByTestId('overview-scorecard')).toHaveTextContent('"workspace":"b"')
  expect(api.getWorkspaceScorecard).toHaveBeenCalledWith('b')
})

it('ignores late A results after B finishes', async () => {
  const a = deferred()
  api.getWorkspaceScorecard.mockImplementation(id => id === 'a' ? a.promise : Promise.resolve(scorecard(id)))
  const view = render(<MemoryRouter><WorkspaceDashboard /></MemoryRouter>)
  await waitFor(() => expect(api.getWorkspaceScorecard).toHaveBeenCalledWith('a'))
  selected = { wsId: 'b', wsName: 'Customer b' }
  view.rerender(<MemoryRouter><WorkspaceDashboard /></MemoryRouter>)
  await waitFor(() => expect(screen.getByTestId('overview-scorecard')).toHaveTextContent('"workspace":"b"'))
  a.resolve(scorecard('a'))
  await waitFor(() => expect(screen.getByTestId('overview-scorecard')).toHaveTextContent('"workspace":"b"'))
  expect(screen.getByTestId('mot-domains')).not.toHaveTextContent('"state":"a"')
})

it('does not retain A data when optional B reads fail', async () => {
  const view = render(<MemoryRouter><WorkspaceDashboard /></MemoryRouter>)
  await waitFor(() => expect(screen.getByTestId('overview-scorecard')).toHaveTextContent('"workspace":"a"'))
  api.getWorkspaceScorecard.mockRejectedValue(new Error('unavailable'))
  api.getWorkspaceSummary.mockRejectedValue(new Error('unavailable'))
  api.getWorkspaceDomains.mockRejectedValue(new Error('unavailable'))
  api.getCyberMotDomains.mockRejectedValue(new Error('unavailable'))
  selected = { wsId: 'b', wsName: 'Customer b' }
  view.rerender(<MemoryRouter><WorkspaceDashboard /></MemoryRouter>)
  await waitFor(() => expect(screen.queryByText('Loading workspace')).not.toBeInTheDocument())
  expect(screen.getByTestId('overview-scorecard')).not.toHaveTextContent('"workspace":"a"')
  expect(screen.getByTestId('overview-scorecard')).toHaveTextContent('null')
  expect(screen.getByTestId('mot-domains')).toHaveTextContent('[]')
  expect(screen.queryByText('9')).not.toBeInTheDocument()
})
