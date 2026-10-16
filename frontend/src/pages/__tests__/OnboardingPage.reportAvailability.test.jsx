import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import OnboardingPage from '../OnboardingPage'
import { api } from '../../api'

vi.mock('../../api', () => ({ api: {
  getWorkspaces: vi.fn(), getWorkspaceDomains: vi.fn(), getWorkspaceScans: vi.fn(), getScan: vi.fn(),
} }))
vi.mock('../../hooks/useDomainConnectOffer', () => ({ useDomainConnectOffer: () => null }))
vi.mock('../../components/OneClickDnsButton', () => ({ default: () => null }))

const scan = { id: 'scan-1', domain: 'example.com', status: 'completed', scan_quality: 'complete' }

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws-1', name: 'Customer workspace' }] })
  api.getWorkspaceDomains.mockResolvedValue({ domains: [{ id: 'domain-1', domain: 'example.com', verification_status: 'verified' }] })
  api.getWorkspaceScans.mockResolvedValue({ scans: [scan] })
})

it.each([
  ['report_ready', 'Done', 'Your first results are ready.'],
  ['report_preparing', 'Now', 'Your assessment finished. Your report is being prepared.'],
  ['report_unavailable', 'Now', 'Your assessment finished, but the report is unavailable right now.'],
])('reports %s as %s in the onboarding step', async (status, label, message) => {
  api.getScan.mockResolvedValue({ scan, report_availability: { status } })
  render(<MemoryRouter><OnboardingPage /></MemoryRouter>)
  const section = (await screen.findByRole('heading', { name: 'Open Executive Report' })).closest('section')
  expect(await within(section).findByText(message)).toBeInTheDocument()
  expect(within(section).getByText(label)).toBeInTheDocument()
  expect(api.getScan).toHaveBeenCalledWith('scan-1')
  if (status === 'report_ready') {
    expect(within(section).getByRole('link', { name: 'Open Executive Report' })).toBeInTheDocument()
  } else {
    expect(within(section).getByRole('link', { name: 'View scan status' })).toBeInTheDocument()
    expect(within(section).getByRole('button', { name: 'Check report status' })).toBeInTheDocument()
  }
})

it('can recheck a preparing report and marks Done only when it becomes ready', async () => {
  api.getScan.mockResolvedValueOnce({ scan, report_availability: { status: 'report_preparing' } })
    .mockResolvedValueOnce({ scan, report_availability: { status: 'report_ready' } })
  render(<MemoryRouter><OnboardingPage /></MemoryRouter>)
  const section = (await screen.findByRole('heading', { name: 'Open Executive Report' })).closest('section')
  fireEvent.click(await within(section).findByRole('button', { name: 'Check report status' }))
  await waitFor(() => expect(within(section).getByText('Done')).toBeInTheDocument())
  expect(api.getScan).toHaveBeenCalledTimes(2)
})
