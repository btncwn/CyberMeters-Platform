// Codex C-46 reproductions, flipped to the correct behaviour (new-customer journey gaps).
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import OnboardingPage from '../OnboardingPage'
import { api } from '../../api'

vi.mock('../../api', () => ({ api: {
  getWorkspaces: vi.fn(), getWorkspaceDomains: vi.fn(), getWorkspaceScans: vi.fn(),
  getScan: vi.fn(), createScan: vi.fn(), createWorkspace: vi.fn(), addDomainToWorkspace: vi.fn(),
} }))
vi.mock('../../hooks/useDomainConnectOffer', () => ({ useDomainConnectOffer: () => null }))
vi.mock('../../components/OneClickDnsButton', () => ({ default: () => null }))
beforeEach(() => {
  vi.clearAllMocks(); localStorage.clear()
  api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws-1', name: 'Workspace A', role: 'owner' }] })
  api.getWorkspaceDomains.mockResolvedValue({ domains: [{ domain_id: 'dom-1', domain: 'example.org', verification_status: 'verified' }] })
  api.getWorkspaceScans.mockResolvedValue({ scans: [] })
  api.getScan.mockResolvedValue({ scan: { id: 's1', status: 'completed' } })
})
afterEach(() => { cleanup(); vi.useRealTimers() })

const withResults = () => (
  <MemoryRouter initialEntries={['/onboarding']}><Routes>
    <Route path="/onboarding" element={<OnboardingPage/>}/>
    <Route path="/scans/:id" element={<p>Results page</p>}/>
  </Routes></MemoryRouter>
)

it('rank 2: setup follows its first scan and opens the results once the report is ready', async () => {
  let finished = false, started = false, ready = false
  api.getWorkspaceScans.mockImplementation(async () => ({ scans: started ? [{ id: 's1', domain: 'example.org', status: finished ? 'completed' : 'queued' }] : [] }))
  api.createScan.mockImplementation(async () => { started = true; return { id: 's1', domain: 'example.org', status: 'queued' } })
  api.getScan.mockImplementation(async () => ({ scan: { id: 's1', status: 'completed' }, report_availability: { status: ready ? 'report_ready' : 'report_preparing' } }))
  vi.useFakeTimers({ shouldAdvanceTime: true })
  render(withResults())
  fireEvent.click(await screen.findByRole('button', { name: 'Run First Security Check' }))
  await screen.findByText('Your first check has started.')
  await waitFor(() => expect(api.getWorkspaceScans).toHaveBeenCalledTimes(2))
  finished = true
  await act(async () => { await vi.advanceTimersByTimeAsync(9000) })
  expect(api.getWorkspaceScans.mock.calls.length).toBeGreaterThan(2)
  await waitFor(() => expect(api.getScan).toHaveBeenCalled())
  // The report is still preparing: setup keeps checking it, and stays put.
  expect(screen.queryByText('Results page')).toBeNull()
  ready = true
  await act(async () => { await vi.advanceTimersByTimeAsync(9000) })
  expect(await screen.findByText('Results page')).toBeInTheDocument()
  // Polling stops once it has opened the results.
  const scansCalls = api.getWorkspaceScans.mock.calls.length, scanCalls = api.getScan.mock.calls.length
  await act(async () => { await vi.advanceTimersByTimeAsync(30000) })
  expect(api.getWorkspaceScans.mock.calls.length).toBe(scansCalls)
  expect(api.getScan.mock.calls.length).toBe(scanCalls)
})

it('rank 2: a failed report check keeps polling (bounded), without flicker, then opens the results', async () => {
  let started = false, finished = false, attempt = 0
  api.getWorkspaceScans.mockImplementation(async () => ({ scans: started ? [{ id: 's1', domain: 'example.org', status: finished ? 'completed' : 'queued' }] : [] }))
  api.createScan.mockImplementation(async () => { started = true; return { id: 's1', domain: 'example.org', status: 'queued' } })
  api.getScan.mockImplementation(async () => {
    attempt += 1
    if (attempt === 1) throw new Error('network')
    return { scan: { id: 's1', status: 'completed' }, report_availability: { status: attempt >= 3 ? 'report_ready' : 'report_preparing' } }
  })
  vi.useFakeTimers({ shouldAdvanceTime: true })
  render(withResults())
  fireEvent.click(await screen.findByRole('button', { name: 'Run First Security Check' }))
  await screen.findByText('Your first check has started.')
  finished = true
  await act(async () => { await vi.advanceTimersByTimeAsync(9000) })
  await waitFor(() => expect(api.getScan).toHaveBeenCalledTimes(1))
  await act(async () => { await vi.advanceTimersByTimeAsync(9000) })
  await act(async () => { await vi.advanceTimersByTimeAsync(9000) })
  expect(await screen.findByText('Results page')).toBeInTheDocument()
  expect(api.getScan.mock.calls.length).toBeGreaterThanOrEqual(3)
})

it('rank 2: a scan that was already finished on arrival never navigates by itself', async () => {
  api.getWorkspaceScans.mockResolvedValue({ scans: [{ id: 's1', domain: 'example.org', status: 'completed' }] })
  api.getScan.mockResolvedValue({ scan: { id: 's1', status: 'completed' }, report_availability: { status: 'report_ready' } })
  render(withResults())
  expect(await screen.findByRole('link', { name: 'Open Executive Report' })).toBeInTheDocument()
  expect(screen.queryByText('Results page')).toBeNull()
})

it('rank 6: Create Workspace is disabled while the name is empty, and says why', async () => {
  api.getWorkspaces.mockResolvedValue({ workspaces: [] })
  render(<MemoryRouter><OnboardingPage/></MemoryRouter>)
  const button = await screen.findByRole('button', { name: 'Create Workspace' })
  expect(button).toBeDisabled()
  expect(button).toHaveAccessibleDescription('Enter the business name to create its workspace.')
  fireEvent.change(screen.getByRole('textbox', { name: 'Workspace name' }), { target: { value: 'She.Shire' } })
  expect(button).toBeEnabled()
})

it('rank 7: Add Domain is disabled while the domain is empty, and says why', async () => {
  api.getWorkspaceDomains.mockResolvedValue({ domains: [] })
  render(<MemoryRouter><OnboardingPage/></MemoryRouter>)
  const button = await screen.findByRole('button', { name: 'Add Domain' })
  expect(button).toBeDisabled()
  expect(button).toHaveAccessibleDescription('Enter the domain you want to monitor, for example example.com.')
  fireEvent.change(screen.getByRole('textbox', { name: 'Domain to add' }), { target: { value: 'example.org' } })
  expect(button).toBeEnabled()
})
