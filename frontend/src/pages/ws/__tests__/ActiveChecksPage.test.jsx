import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { api } from '../../../api'
import ActiveChecksPage from '../ActiveChecksPage'

const workspace = vi.hoisted(() => ({ wsId: 'ws-a', wsName: 'Example Ltd', loading: false }))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: () => workspace }))
vi.mock('../../../api', () => ({ api: {
  getActiveCheckConsents: vi.fn(), getWorkspaceScans: vi.fn(), getScan: vi.fn(), getScanReport: vi.fn(),
} }))

const scan = (id = 'scan-a', domain = 'example.test', over = {}) => ({ id, domain, status: 'completed', created_at: '2026-10-27T12:00:00Z', ...over })
const grant = (over = {}) => ({
  id: 'permission-a', domain: 'example.test', hosts: ['example.test'], checks: ['tls_intrusive_heartbleed'],
  status: 'active', granted_at: '2026-10-26T12:00:00Z', signer: { name: 'Taylor', title: 'Director' },
  authority_text: 'The stored authority statement.', ...over,
})
const permissionPayload = (consents = []) => ({
  consents, catalogue: [{ id: 'tls_intrusive_heartbleed', label: 'TLS Heartbleed test', available: true }],
})
const history = (scans, workspace_id = 'ws-a') => ({ workspace_id, scans })
const report = (checks = [], saved = scan()) => ({
  scan_id: saved.id, domain: saved.domain,
  modules: { tls_assessment: { endpoints: [{ hostname: saved.domain, port: 443, checks }] } },
})
const observed = { control: 'heartbleed', state: 'accepted', observed_at: '2026-10-27T12:01:00Z', evidence: { vulnerability: { status: 'not_observed' } } }
const deferred = () => {
  let resolve, reject
  const promise = new Promise((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}
const page = () => <MemoryRouter><ActiveChecksPage /></MemoryRouter>
const read = async (domain = 'example.test') => fireEvent.click(await screen.findByRole('button', { name: new RegExp(`Read saved checks for ${domain}`) }))

beforeEach(() => {
  vi.resetAllMocks()
  Object.assign(workspace, { wsId: 'ws-a', wsName: 'Example Ltd', loading: false })
  api.getActiveCheckConsents.mockResolvedValue(permissionPayload())
  api.getWorkspaceScans.mockResolvedValue(history([]))
  api.getScan.mockResolvedValue({ scan: { ...scan(), workspace_id: 'ws-a' } })
  api.getScanReport.mockResolvedValue(report())
})
afterEach(cleanup)

it('has honest empty states, separate permission and network-asset links, and no eager report requests', async () => {
  render(page())
  expect(await screen.findByText(/No recent scans are recorded/)).toBeInTheDocument()
  expect(screen.getByText(/No permission is recorded/)).toBeInTheDocument()
  expect(screen.getByRole('link', { name: 'Manage permissions' })).toHaveAttribute('href', '/ws/active-checks/permission')
  expect(screen.getByRole('link', { name: 'Network assets' })).toHaveAttribute('href', '/assets')
  expect(api.getActiveCheckConsents).toHaveBeenCalledExactlyOnceWith('ws-a')
  expect(api.getWorkspaceScans).toHaveBeenCalledExactlyOnceWith('ws-a')
  expect(api.getScan).not.toHaveBeenCalled()
  expect(api.getScanReport).not.toHaveBeenCalled()
})

it('a permission and completed scan supply no active result; passive TLS checks remain outside this history', async () => {
  api.getActiveCheckConsents.mockResolvedValue(permissionPayload([grant()]))
  api.getWorkspaceScans.mockResolvedValue(history([scan()]))
  api.getScanReport.mockResolvedValue(report([{ control: 'tls1_2', state: 'accepted' }]))
  render(page())
  expect(await screen.findByTestId('consent-receipt')).toBeInTheDocument()
  expect(api.getScanReport).not.toHaveBeenCalled()
  await read()
  expect(await screen.findByText(/No active-check result was recorded in this scan/)).toBeInTheDocument()
  expect(screen.queryByRole('list', { name: 'Saved active-check outcomes' })).not.toBeInTheDocument()
  expect(screen.getByRole('link', { name: 'Open scan details' })).toHaveAttribute('href', '/scans/scan-a?view=technical')
})

it('shows explicit historical not-authorised evidence even when a current permission exists', async () => {
  api.getActiveCheckConsents.mockResolvedValue(permissionPayload([grant()]))
  api.getWorkspaceScans.mockResolvedValue(history([scan()]))
  api.getScanReport.mockResolvedValue(report([{ control: 'robot', state: 'not_authorized', reason: 'requires_customer_authorisation' }]))
  render(page())
  await read()
  expect(await screen.findByText('Not tested — requires your authorisation')).toBeInTheDocument()
  expect(screen.getByRole('heading', { name: 'ROBOT · example.test:443' })).toBeInTheDocument()
  expect(screen.getByText('Observation time not recorded')).toBeInTheDocument()
})

it('uses the recorded vulnerability result, never a bare accepted state or today’s consent/availability', async () => {
  api.getActiveCheckConsents.mockResolvedValue({ ...permissionPayload([grant({ status: 'revoked', revoked_at: '2026-10-27T14:00:00Z' })]), catalogue: [] })
  api.getWorkspaceScans.mockResolvedValue(history([scan()]))
  api.getScanReport.mockResolvedValue(report([observed, { control: 'ccs', state: 'accepted' }]))
  render(page())
  await read()
  const outcomes = within(await screen.findByRole('list', { name: 'Saved active-check outcomes' }))
  expect(outcomes.getByText('Not observed in this test')).toBeInTheDocument()
  expect(outcomes.getByText('Unknown')).toBeInTheDocument()
  expect(outcomes.getByText('Observed 27 Oct 2026, 12:01 UTC')).toBeInTheDocument()
  expect(outcomes.queryByText(/Accepted|Passed/)).not.toBeInTheDocument()
  expect(screen.getByTestId('consent-receipt')).toHaveTextContent('Revoked')
  expect(api.getScan).toHaveBeenCalledExactlyOnceWith('scan-a')
  expect(api.getScanReport).toHaveBeenCalledExactlyOnceWith('scan-a')
})

it.each(['metadata-domain', 'metadata-workspace', 'report-domain', 'report-id'])('refuses %s mismatches instead of showing another saved result', async mismatch => {
  api.getWorkspaceScans.mockResolvedValue(history([scan()]))
  api.getScan.mockResolvedValue({ scan: { ...scan(), domain: mismatch === 'metadata-domain' ? 'other.test' : 'example.test', workspace_id: mismatch === 'metadata-workspace' ? 'ws-b' : 'ws-a' } })
  api.getScanReport.mockResolvedValue({ ...report([observed]), domain: mismatch === 'report-domain' ? 'other.test' : 'example.test', scan_id: mismatch === 'report-id' ? 'other-scan' : 'scan-a' })
  render(page())
  await read()
  expect(await screen.findByRole('alert')).toHaveTextContent('Saved checks could not be read or matched to this scan')
  expect(screen.queryByText('Not observed in this test')).not.toBeInTheDocument()
  if (mismatch.startsWith('metadata')) expect(api.getScanReport).not.toHaveBeenCalled()
})

it('filters permissions and scans together, clears selected evidence, and ignores a late response from the old domain', async () => {
  const pending = deferred()
  api.getActiveCheckConsents.mockResolvedValue(permissionPayload([grant(), grant({ id: 'permission-b', domain: 'second.test' })]))
  api.getWorkspaceScans.mockResolvedValue(history([scan(), scan('scan-b', 'second.test')]))
  api.getScanReport.mockReturnValue(pending.promise)
  render(page())
  await read()
  await waitFor(() => expect(api.getScanReport).toHaveBeenCalledTimes(1))
  fireEvent.change(screen.getByRole('combobox', { name: 'Domain' }), { target: { value: 'second.test' } })
  expect(screen.queryByRole('heading', { name: 'Saved checks for example.test' })).not.toBeInTheDocument()
  expect(within(screen.getByRole('list', { name: 'Recent scans' })).queryByText('example.test')).not.toBeInTheDocument()
  expect(screen.getAllByTestId('consent-receipt')).toHaveLength(1)
  expect(screen.getByTestId('consent-receipt')).toHaveTextContent('second.test')
  await act(async () => pending.resolve(report([observed])))
  expect(screen.queryByText('Not observed in this test')).not.toBeInTheDocument()
  expect(api.getScan).toHaveBeenCalledTimes(1)
})

it.each(['metadata', 'report'])('clears old workspace details and ignores late %s after switching away and back', async stage => {
  const pending = deferred()
  api.getWorkspaceScans.mockImplementation(async id => history([id === 'ws-a' ? scan() : scan('scan-b', 'second.test')], id))
  if (stage === 'metadata') api.getScan.mockReturnValueOnce(pending.promise)
  else api.getScanReport.mockReturnValueOnce(pending.promise)
  const view = render(page())
  await read()
  await waitFor(() => expect(stage === 'metadata' ? api.getScan : api.getScanReport).toHaveBeenCalledTimes(1))
  Object.assign(workspace, { wsId: 'ws-b', wsName: 'Second Ltd' })
  view.rerender(page())
  expect(screen.queryByRole('heading', { name: 'Saved checks for example.test' })).not.toBeInTheDocument()
  expect(screen.queryByRole('list', { name: 'Recent scans' })).not.toBeInTheDocument()
  await screen.findByRole('button', { name: /Read saved checks for second.test/ })
  Object.assign(workspace, { wsId: 'ws-a', wsName: 'Example Ltd' })
  view.rerender(page())
  await screen.findByRole('button', { name: /Read saved checks for example.test/ })
  await act(async () => pending.resolve(stage === 'metadata' ? { scan: { ...scan(), workspace_id: 'ws-a' } } : report([observed])))
  expect(screen.queryByRole('heading', { name: /Saved checks for/ })).not.toBeInTheDocument()
  expect(screen.queryByText('Not observed in this test')).not.toBeInTheDocument()
  expect(api.getScanReport).toHaveBeenCalledTimes(stage === 'metadata' ? 0 : 1)
})

it('keeps a failed list honest while the other remains usable, and reloads on request', async () => {
  api.getActiveCheckConsents.mockRejectedValueOnce(new Error('Unavailable'))
  api.getWorkspaceScans.mockResolvedValue(history([scan()]))
  render(page())
  expect(await screen.findByRole('alert')).toHaveTextContent('Permissions could not be read')
  await read()
  expect(await screen.findByText(/No active-check result was recorded/)).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Reload records' }))
  await screen.findByText(/No permission is recorded/)
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  expect(screen.queryByRole('heading', { name: /Saved checks for/ })).not.toBeInTheDocument()
  expect(api.getActiveCheckConsents).toHaveBeenCalledTimes(2)
})

it('bounds the recent scan list without fetching details, including queued scans', async () => {
  api.getWorkspaceScans.mockResolvedValue(history(Array.from({ length: 25 }, (_, index) => scan(`scan-${index}`, `host${index}.test`, { status: index === 0 ? 'queued' : 'completed' }))))
  render(page())
  const recent = within(await screen.findByRole('list', { name: 'Recent scans' }))
  expect(recent.getAllByRole('listitem')).toHaveLength(20)
  expect(recent.getAllByRole('button', { name: /Read saved checks for/ })).toHaveLength(19)
  expect(recent.getByText('No finished record yet')).toBeInTheDocument()
  expect(api.getScan).not.toHaveBeenCalled()
  expect(api.getScanReport).not.toHaveBeenCalled()
})
