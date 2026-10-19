import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import OnboardingPage from '../OnboardingPage'
import { api } from '../../api'

// Found live (18 Oct 2026): members saw the "Get Started" setup checklist for
// someone else's workspace. The checklist belongs to a workspace owner.
vi.mock('../../api', () => ({ api: {
  getWorkspaces: vi.fn(), getWorkspaceDomains: vi.fn(), getWorkspaceScans: vi.fn(), getScan: vi.fn(),
  addDomainToWorkspace: vi.fn(), generateDomainVerification: vi.fn(), verifyDomain: vi.fn(),
} }))
vi.mock('../../hooks/useDomainConnectOffer', () => ({ useDomainConnectOffer: () => null }))
vi.mock('../../components/OneClickDnsButton', () => ({ default: () => null }))

const shared = { id: 'ws-shared', name: 'Black Bull Barbers', role: 'analyst' }
const own = { id: 'ws-own', name: 'My Shop', role: 'owner' }

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  api.getWorkspaceDomains.mockResolvedValue({ domains: [] })
  api.getWorkspaceScans.mockResolvedValue({ scans: [] })
})

it('a member of someone else\'s workspace is not shown the setup checklist', async () => {
  api.getWorkspaces.mockResolvedValue({ workspaces: [shared] })
  localStorage.setItem('cybermeters_workspace_id', shared.id)
  render(<MemoryRouter><OnboardingPage /></MemoryRouter>)
  const panel = await screen.findByTestId('onboarding-member')
  expect(panel).toHaveTextContent('Black Bull Barbers is set up and managed by its owner.')
  expect(screen.getByRole('link', { name: 'Go to overview' })).toHaveAttribute('href', '/dashboard')
  expect(screen.queryByRole('heading', { name: 'Get Started' })).toBeNull()
  expect(screen.queryByText('Create Workspace')).toBeNull()
  expect(api.getWorkspaceDomains).not.toHaveBeenCalled()
  // The active workspace stays the one the member chose.
  expect(localStorage.getItem('cybermeters_workspace_id')).toBe(shared.id)
})

it('someone who owns a workspace gets the checklist for their own workspace, even with a shared one active', async () => {
  api.getWorkspaces.mockResolvedValue({ workspaces: [shared, own] })
  localStorage.setItem('cybermeters_workspace_id', shared.id)
  render(<MemoryRouter><OnboardingPage /></MemoryRouter>)
  expect(await screen.findByRole('heading', { name: 'Get Started' })).toBeInTheDocument()
  expect(screen.getByText('My Shop')).toBeInTheDocument()
  await waitFor(() => expect(api.getWorkspaceDomains).toHaveBeenCalledWith(own.id))
  expect(screen.queryByTestId('onboarding-member')).toBeNull()
})

it('with no workspace at all, the checklist starts at creating one', async () => {
  api.getWorkspaces.mockResolvedValue({ workspaces: [] })
  render(<MemoryRouter><OnboardingPage /></MemoryRouter>)
  expect(await screen.findByRole('heading', { name: 'Get Started' })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Create Workspace' })).toBeInTheDocument()
})
