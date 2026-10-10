import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import WebsiteScanOverview from '../WebsiteScanOverview'
import { api } from '../../api'

vi.mock('../../api', () => ({ api: { getWorkspaceScans: vi.fn(), getScanReport: vi.fn() } }))
const scan = { id: 'scan-1', domain: 'example.com', status: 'completed', scan_quality: 'complete', created_at: '2026-10-10T10:00:00Z' }
const report = {
  scan_id: scan.id, scan_quality: { status: 'complete', modules_skipped: [], modules_incomplete: [] },
  modules: {
    ssl: { https_available: true, https_probe_executed: true, http_redirects_to_https: true, http_redirect_chain: { http_redirect_validated: true } },
    headers: { accessible: true, headers_assessed: true, present: ['strict-transport-security', 'content-security-policy'], missing: ['referrer-policy'] },
    domain_security_enrichment: { cookies: { found: 2, insecure_count: 1, no_httponly: 0, no_samesite: 0 } },
  },
}
const mount = () => render(<MemoryRouter><WebsiteScanOverview workspaceId="ws-1" /></MemoryRouter>)
const tile = (name) => screen.getByRole('heading', { name }).parentElement

beforeEach(() => {
  vi.resetAllMocks()
  api.getWorkspaceScans.mockResolvedValue({ scans: [scan] })
  api.getScanReport.mockResolvedValue(report)
})

describe('Website scan overview — recorded evidence, independent of finding count', () => {
  it('shows actual HTTPS, redirect, header and cookie observations with the recorded scan link', async () => {
    mount()
    await screen.findByText('Response observed')
    expect(api.getWorkspaceScans).toHaveBeenCalledWith('ws-1')
    expect(api.getScanReport).toHaveBeenCalledWith('scan-1')
    expect(screen.getByText('Redirect observed')).toBeInTheDocument()
    expect(screen.getByText('2 present · 1 missing')).toBeInTheDocument()
    expect(screen.getByText('2 cookies observed')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'View latest scan evidence' })).toHaveAttribute('href', '/scans/scan-1?view=technical#website-evidence')
    expect(screen.getByRole('link', { name: 'Recheck this website' })).toHaveAttribute('href', '/scans/new?domain=example.com')
  })

  it('keeps check categories and a first-scan action when no scan exists, without a healthy verdict', async () => {
    api.getWorkspaceScans.mockResolvedValue({ scans: [] })
    mount()
    await screen.findByText('No website scan available yet')
    expect(screen.getAllByText('Not confirmed')).toHaveLength(4)
    expect(screen.getByRole('link', { name: 'Run a website scan' })).toHaveAttribute('href', '/scans/new')
    expect(screen.queryByText(/healthy|all clear|100%/i)).toBeNull()
    expect(api.getScanReport).not.toHaveBeenCalled()
  })

  it('does not turn a scan-list failure into an empty or healthy history', async () => {
    api.getWorkspaceScans.mockRejectedValue(new Error('Unavailable'))
    mount()
    expect(await screen.findByRole('alert')).toHaveTextContent('could not be loaded')
    expect(screen.queryByText('No website scan available yet')).toBeNull()
    expect(api.getScanReport).not.toHaveBeenCalled()
  })

  it('never substitutes an older successful scan for the latest failed attempt', async () => {
    api.getWorkspaceScans.mockResolvedValue({ scans: [scan, { ...scan, id: 'failed-new', status: 'failed', created_at: '2026-10-10T12:00:00Z' }] })
    mount()
    await screen.findByText(/Earlier results have not been substituted/)
    expect(api.getScanReport).not.toHaveBeenCalled()
    expect(screen.getAllByText('Not confirmed')).toHaveLength(4)
    expect(screen.queryByText('Complete evidence')).toBeNull()
    expect(screen.getByRole('link', { name: 'View latest scan evidence' })).toHaveAttribute('href', '/scans/failed-new?view=technical#website-evidence')
  })

  it('withholds observations from skipped and incomplete probes, including derived cookie data', async () => {
    api.getScanReport.mockResolvedValue({ ...report, scan_quality: { status: 'partial', modules_skipped: ['ssl'], modules_incomplete: [{ module: 'headers' }] } })
    mount()
    await screen.findByText('Partial evidence')
    expect(screen.getAllByText('Not confirmed')).toHaveLength(4)
    expect(screen.queryByText('2 present · 1 missing')).toBeNull()
    expect(screen.queryByText('2 cookies observed')).toBeNull()
  })

  it('presents zero observed cookies as inconclusive, never proof of a fix', async () => {
    api.getScanReport.mockResolvedValue({ ...report, modules: { ...report.modules, domain_security_enrichment: { cookies: { found: 0, insecure_count: 0, no_httponly: 0, no_samesite: 0 } } } })
    mount()
    await screen.findByText('No cookies observed')
    expect(within(tile('Cookie attributes')).getByText(/absence does not prove a fix/)).toBeInTheDocument()
    expect(within(tile('Cookie attributes')).queryByText(/healthy|secure cookies|fixed/i)).toBeNull()
  })

  it.each([false, undefined])('does not turn an unvalidated historical redirect flag (%s) into an observed failure', async (validated) => {
    api.getScanReport.mockResolvedValue({ ...report, modules: { ...report.modules, ssl: { ...report.modules.ssl, http_redirects_to_https: false, http_redirect_chain: { http_redirect_validated: validated } } } })
    mount()
    await screen.findByText('Response observed')
    expect(within(tile('HTTP → HTTPS')).getByText('Not confirmed')).toBeInTheDocument()
    expect(screen.queryByText('No redirect observed')).toBeNull()
  })

  it('shows a report failure without inventing observations', async () => {
    api.getScanReport.mockRejectedValue(new Error('No report'))
    mount()
    await screen.findByRole('alert')
    expect(screen.getAllByText('Not confirmed')).toHaveLength(4)
  })

  it('discards late report evidence after selecting another website', async () => {
    let resolveFirst
    api.getWorkspaceScans.mockResolvedValue({ scans: [scan, { ...scan, id: 'scan-2', domain: 'second.example.com', created_at: '2026-10-09T10:00:00Z' }] })
    api.getScanReport.mockImplementation((id) => id === scan.id ? new Promise((resolve) => { resolveFirst = resolve }) : Promise.resolve({ scan_id: 'scan-2', modules: {} }))
    mount()
    await waitFor(() => expect(api.getScanReport).toHaveBeenCalledWith(scan.id))
    fireEvent.change(screen.getByLabelText('Recent scan site'), { target: { value: 'second.example.com' } })
    await waitFor(() => expect(api.getScanReport).toHaveBeenCalledWith('scan-2'))
    await act(async () => resolveFirst(report))
    expect(screen.queryByText('Response observed')).toBeNull()
    expect(screen.getByRole('link', { name: 'View latest scan evidence' })).toHaveAttribute('href', '/scans/scan-2?view=technical#website-evidence')
  })

  it('rejects a report whose scan identity does not match the selected record', async () => {
    api.getScanReport.mockResolvedValue({ ...report, scan_id: 'wrong-scan' })
    mount()
    await screen.findByRole('alert')
    expect(screen.queryByText('Response observed')).toBeNull()
  })
})
