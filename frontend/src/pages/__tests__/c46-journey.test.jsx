// Codex C-46 reproductions, flipped to the correct behaviour (new-customer journey gaps).
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
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

it('rank 2: setup follows its first scan to completion by itself', async () => {
  let finished = false, started = false
  api.getWorkspaceScans.mockImplementation(async () => ({ scans: started ? [{ id: 's1', domain: 'example.org', status: finished ? 'completed' : 'queued' }] : [] }))
  api.createScan.mockImplementation(async () => { started = true; return { id: 's1', domain: 'example.org', status: 'queued' } })
  vi.useFakeTimers({ shouldAdvanceTime: true })
  render(<MemoryRouter><OnboardingPage/></MemoryRouter>)
  fireEvent.click(await screen.findByRole('button', { name: 'Run First Security Check' }))
  await screen.findByText('Your first check has started.')
  await waitFor(() => expect(api.getWorkspaceScans).toHaveBeenCalledTimes(2))
  finished = true
  await act(async () => { await vi.advanceTimersByTimeAsync(9000) })
  expect(api.getWorkspaceScans.mock.calls.length).toBeGreaterThan(2)
  await waitFor(() => expect(screen.queryByText('Your first passive posture check is running for example.org.')).toBeNull())
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
