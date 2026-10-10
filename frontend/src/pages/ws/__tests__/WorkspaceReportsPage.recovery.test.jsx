import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import WorkspaceReportsPage from '../WorkspaceReportsPage'
import { api } from '../../../api'

const workspace = vi.hoisted(() => ({ wsId: 'workspace-a', wsName: 'Workspace A' }))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: () => workspace }))
vi.mock('../../../api', () => ({ api: {
  getWorkspaceReports: vi.fn(),
  getScheduledReports: vi.fn(),
  downloadWorkspaceReport: vi.fn(),
  getWorkspaceScans: vi.fn(),
  generateWorkspaceReport: vi.fn(),
} }))

function deferred() {
  let resolve, reject
  const promise = new Promise((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}
const report = (id, status = 'completed') => ({
  id, status, report_type: 'manual', report_period: id,
  created_at: '2026-10-10T10:00:00Z', generated_at: '2026-10-10T10:00:00Z',
})
const result = (id, status) => ({ reports: [report(id, status)] })
const page = () => <MemoryRouter><WorkspaceReportsPage /></MemoryRouter>

beforeEach(() => {
  vi.resetAllMocks()
  workspace.wsId = 'workspace-a'
  workspace.wsName = 'Workspace A'
  api.getScheduledReports.mockResolvedValue({ scheduled_reports: [] })
  api.downloadWorkspaceReport.mockReturnValue(new Promise(() => {}))
  api.getWorkspaceScans.mockResolvedValue({ scans: [] })
})
afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.restoreAllMocks()
})

it('Retry recovers the archive and its PDF download after an initial request error', async () => {
  api.getWorkspaceReports.mockRejectedValueOnce(new Error('Temporary failure'))
    .mockResolvedValue(result('recovered-report'))
  render(page())
  expect(await screen.findByText('Temporary failure')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
  expect(await screen.findByText('recovered-report')).toBeInTheDocument()
  expect(screen.queryByText('Temporary failure')).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'PDF' }))
  expect(api.downloadWorkspaceReport).toHaveBeenCalledWith('workspace-a', 'recovered-report')
})

it('recovers from a failed background poll and stops polling once the PDF is complete', async () => {
  vi.useFakeTimers()
  api.getWorkspaceReports.mockResolvedValueOnce(result('pending-report', 'pending'))
    .mockRejectedValueOnce(new Error('Polling interrupted'))
    .mockResolvedValue(result('completed-report'))
  render(page())
  await act(async () => {})
  expect(screen.getByText('pending-report')).toBeInTheDocument()
  await act(async () => vi.advanceTimersByTimeAsync(5000))
  expect(screen.getByText('Polling interrupted')).toBeInTheDocument()
  await act(async () => vi.advanceTimersByTimeAsync(5000))
  expect(screen.queryByText('Polling interrupted')).not.toBeInTheDocument()
  expect(screen.getByText('completed-report')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'PDF' })).toBeInTheDocument()
  await act(async () => vi.advanceTimersByTimeAsync(15000))
  expect(api.getWorkspaceReports).toHaveBeenCalledTimes(3)
})

it.each(['success', 'error'])('ignores a previous workspace’s late %s, including after switching back', async (outcome) => {
  const oldA = deferred()
  api.getWorkspaceReports.mockReturnValueOnce(oldA.promise)
    .mockResolvedValueOnce(result('report-b'))
    .mockResolvedValueOnce(result('new-report-a'))
  const view = render(page())
  workspace.wsId = 'workspace-b'
  workspace.wsName = 'Workspace B'
  view.rerender(page())
  expect(await screen.findByText('report-b')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'PDF' }))
  expect(api.downloadWorkspaceReport).toHaveBeenLastCalledWith('workspace-b', 'report-b')
  workspace.wsId = 'workspace-a'
  workspace.wsName = 'Workspace A'
  view.rerender(page())
  expect(await screen.findByText('new-report-a')).toBeInTheDocument()
  await act(async () => {
    if (outcome === 'success') oldA.resolve(result('old-report-a'))
    else oldA.reject(new Error('Old workspace failure'))
  })
  expect(screen.getByText('new-report-a')).toBeInTheDocument()
  expect(screen.queryByText('old-report-a')).not.toBeInTheDocument()
  expect(screen.queryByText('Old workspace failure')).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'PDF' }))
  expect(api.downloadWorkspaceReport).toHaveBeenLastCalledWith('workspace-a', 'new-report-a')
})

it('hides the previous workspace archive until the new workspace finishes loading', async () => {
  const next = deferred()
  api.getWorkspaceReports.mockResolvedValueOnce(result('report-a')).mockReturnValueOnce(next.promise)
  const view = render(page())
  expect(await screen.findByText('report-a')).toBeInTheDocument()
  workspace.wsId = 'workspace-b'
  view.rerender(page())
  expect(screen.queryByText('report-a')).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'PDF' })).not.toBeInTheDocument()
  await act(async () => next.resolve(result('report-b')))
  expect(screen.getByText('report-b')).toBeInTheDocument()
})

it.each(['success', 'error'])('ignores an older refresh’s late %s in the same workspace', async (outcome) => {
  const older = deferred()
  api.getWorkspaceReports.mockResolvedValueOnce(result('initial-report'))
    .mockReturnValueOnce(older.promise).mockResolvedValueOnce(result('newest-report'))
  render(page())
  expect(await screen.findByText('initial-report')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: /Refresh/ }))
  fireEvent.click(screen.getByRole('button', { name: /Refresh/ }))
  expect(await screen.findByText('newest-report')).toBeInTheDocument()
  await act(async () => {
    if (outcome === 'success') older.resolve(result('stale-report'))
    else older.reject(new Error('Stale request failure'))
  })
  expect(screen.getByText('newest-report')).toBeInTheDocument()
  expect(screen.queryByText('stale-report')).not.toBeInTheDocument()
  expect(screen.queryByText('Stale request failure')).not.toBeInTheDocument()
})

it('cancels polling when leaving the page even if an in-flight poll completes later', async () => {
  vi.useFakeTimers()
  const poll = deferred()
  api.getWorkspaceReports.mockResolvedValueOnce(result('pending-report', 'pending'))
    .mockReturnValueOnce(poll.promise)
  const view = render(page())
  await act(async () => {})
  await act(async () => vi.advanceTimersByTimeAsync(5000))
  view.unmount()
  await act(async () => poll.resolve(result('still-pending', 'pending')))
  await act(async () => vi.advanceTimersByTimeAsync(15000))
  expect(api.getWorkspaceReports).toHaveBeenCalledTimes(2)
})

it('lets a slow automatic refresh finish instead of superseding it every five seconds', async () => {
  vi.useFakeTimers()
  const slow = deferred()
  api.getWorkspaceReports.mockResolvedValueOnce(result('pending-report', 'pending'))
    .mockReturnValueOnce(slow.promise)
  render(page())
  await act(async () => {})
  await act(async () => vi.advanceTimersByTimeAsync(15000))
  expect(api.getWorkspaceReports).toHaveBeenCalledTimes(2)
  await act(async () => slow.resolve(result('completed-report')))
  expect(screen.getByText('completed-report')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'PDF' })).toBeInTheDocument()
  await act(async () => vi.advanceTimersByTimeAsync(10000))
  expect(api.getWorkspaceReports).toHaveBeenCalledTimes(2)
})

const completedScan = (id, domain = 'example.com') => ({ id, domain, status: 'completed', created_at: '2026-10-10T10:00:00Z' })
async function chooseReport(label) {
  fireEvent.click(screen.getByRole('button', { name: /Snapshot ▾|Executive ▾/ }))
  fireEvent.click(screen.getByRole('button', { name: label, exact: true }))
  await act(async () => {})
}

it('requires an explicit completed scan and generates its executive snapshot', async () => {
  api.getWorkspaceReports.mockResolvedValue({ reports: [] })
  api.getWorkspaceScans.mockResolvedValue({ scans: [completedScan('older-scan'), { ...completedScan('running-scan'), status: 'running' }, completedScan('latest-scan')] })
  api.generateWorkspaceReport.mockResolvedValue({ report: report('selected-pdf') })
  render(page())
  await act(async () => {})
  await chooseReport('Scan Snapshot')
  expect(api.getWorkspaceScans).toHaveBeenCalledWith('workspace-a')
  expect(screen.getByRole('button', { name: 'Generate Report', exact: true })).toBeDisabled()
  expect(screen.getAllByRole('option').map(option => option.value)).not.toContain('running-scan')
  fireEvent.change(screen.getByLabelText('Recent completed scan'), { target: { value: 'older-scan' } })
  fireEvent.click(screen.getByRole('button', { name: 'Generate Report', exact: true }))
  await act(async () => {})
  expect(api.generateWorkspaceReport).toHaveBeenCalledWith('workspace-a', 'scan_snapshot', 'older-scan')
  fireEvent.click(screen.getByRole('button', { name: 'Download generated PDF' }))
  expect(api.downloadWorkspaceReport).toHaveBeenCalledWith('workspace-a', 'selected-pdf')
})

it.each([
  ['Manual Snapshot', 'manual'], ['Weekly Executive', 'weekly_executive'],
  ['Monthly Executive', 'monthly_executive'], ['Quarterly Executive', 'quarterly_executive'],
])('generates %s without an unrelated scan selection and exposes a deduplicated PDF', async (label, type) => {
  api.getWorkspaceReports.mockResolvedValue({ reports: [] })
  api.generateWorkspaceReport.mockResolvedValue({ report: { ...report('existing-period-pdf'), claimed: false } })
  render(page())
  await act(async () => {})
  await chooseReport(label)
  fireEvent.click(screen.getByRole('button', { name: 'Generate Report', exact: true }))
  await act(async () => {})
  expect(api.generateWorkspaceReport).toHaveBeenCalledWith('workspace-a', type)
  expect(api.getWorkspaceScans).not.toHaveBeenCalled()
  expect(screen.getByRole('status')).toHaveTextContent('already exists')
  fireEvent.click(screen.getByRole('button', { name: 'Download generated PDF' }))
  expect(api.downloadWorkspaceReport).toHaveBeenCalledWith('workspace-a', 'existing-period-pdf')
})

it('lets the customer retry a failed scan list without enabling generation prematurely', async () => {
  api.getWorkspaceReports.mockResolvedValue({ reports: [] })
  api.getWorkspaceScans.mockRejectedValueOnce(new Error('Scan list unavailable')).mockResolvedValue({ scans: [completedScan('ready-scan')] })
  render(page())
  await act(async () => {})
  await chooseReport('Scan Snapshot')
  expect(screen.getByRole('alert')).toHaveTextContent('Scan list unavailable')
  expect(screen.getByRole('button', { name: 'Generate Report', exact: true })).toBeDisabled()
  fireEvent.click(screen.getByRole('button', { name: 'Retry scan list' }))
  await act(async () => {})
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  expect(screen.getAllByRole('option').map(option => option.value)).toContain('ready-scan')
  expect(screen.getByRole('button', { name: 'Generate Report', exact: true })).toBeDisabled()
})

it('cannot reuse scans from a workspace left while the scan list was loading', async () => {
  const oldScans = deferred()
  api.getWorkspaceReports.mockResolvedValue({ reports: [] })
  api.getWorkspaceScans.mockReturnValueOnce(oldScans.promise).mockResolvedValue({ scans: [completedScan('new-scan')] })
  const view = render(page())
  await act(async () => {})
  await chooseReport('Scan Snapshot')
  workspace.wsId = 'workspace-b'; workspace.wsName = 'Workspace B'
  view.rerender(page())
  await act(async () => {})
  await chooseReport('Scan Snapshot')
  await act(async () => oldScans.resolve({ scans: [completedScan('old-scan')] }))
  expect(screen.queryByRole('option', { name: /old-scan/ })).not.toBeInTheDocument()
  expect(screen.getByRole('option', { name: /new-scan/ })).toBeInTheDocument()
  expect(screen.getByLabelText('Recent completed scan')).toHaveValue('')
})
