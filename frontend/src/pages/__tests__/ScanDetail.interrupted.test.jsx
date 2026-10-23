import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import ScanDetail from '../ScanDetail'
import { api } from '../../api'
import { interruptedScanCopy } from '../../lib/scanDuration'

// Executive 10:12/14:08 (founder): a failed scan that completed some checks
// reads "Interrupted — N checks completed", from #880's progress on a failed scan.

vi.mock('../../api', () => ({
  api: {
    getScan: vi.fn(), getScanReport: vi.fn(), getExecutiveReportV2: vi.fn(), getScanReportPdf: vi.fn(),
    getFindingWaivers: vi.fn(), waiveFinding: vi.fn(), unwaiveFinding: vi.fn(), getWorkspaceScans: vi.fn(),
  },
}))
vi.mock('../../components/ExecutiveReportV2', () => ({ default: () => <div>Executive report</div> }))

const failed = { id: 'scan_failed_1234567890abcdef', domain: 'sheshire.co.uk', status: 'failed', score: null, rating: null, scan_quality: null, created_at: '2026-10-22T12:37:53Z' }
function renderFailed(progress, scan = failed) {
  api.getScan.mockResolvedValue({ scan, progress, report_availability: { status: 'scan_failed', retryable: false } })
  return render(<MemoryRouter initialEntries={[`/scans/${failed.id}`]}><Routes><Route path="/scans/:id" element={<ScanDetail />} /></Routes></MemoryRouter>)
}
beforeEach(() => { vi.clearAllMocks(); localStorage.clear(); api.getFindingWaivers.mockResolvedValue({ waivers: [] }) })

describe('interruptedScanCopy', () => {
  it('names the count, where it stopped, and the checks when recorded', () => {
    expect(interruptedScanCopy({ terminal: true, stage: 'phase5_intelligence', completed_modules: 12, module_names_recorded: true, completed_module_names: ['dns', 'headers'] }))
      .toEqual({ heading: 'Interrupted — 12 checks completed', stage: 'It stopped while checking technology and known-vulnerability information.', modules: ['DNS checks', 'Security header checks'], namesNote: null })
  })
  it('an unknown module key never shows raw', () => {
    expect(interruptedScanCopy({ terminal: true, completed_modules: 1, module_names_recorded: true, completed_module_names: ['brand_new_module'] }).modules).toEqual(['Another check'])
  })
  it('says the names were not recorded rather than guess', () => {
    const c = interruptedScanCopy({ terminal: true, stage: null, completed_modules: 1, module_names_recorded: false, completed_module_names: null })
    expect(c.heading).toBe('Interrupted — 1 check completed')
    expect(c.stage).toBeNull()
    expect(c.modules).toBeNull()
    expect(c.namesNote).toBe('Which checks finished was not recorded for this scan.')
  })
  it('nothing completed, unknown, or not terminal → no interrupted wording', () => {
    expect(interruptedScanCopy({ terminal: true, completed_modules: 0 })).toBeNull()
    expect(interruptedScanCopy({ terminal: true, completed_modules: null })).toBeNull()
    expect(interruptedScanCopy({ terminal: false, completed_modules: 5 })).toBeNull()
    expect(interruptedScanCopy(null)).toBeNull()
  })
})

describe('the failed-scan page', () => {
  it('a domain that does not exist: could not assess, never a product failure or an interruption', async () => {
    renderFailed({ terminal: true, stage: 'domain_not_found', completed_modules: null, module_names_recorded: false, completed_module_names: null },
      { ...failed, domain: 'lapsed.example', outcome: 'domain_not_found' })
    expect(await screen.findByTestId('scan-domain-not-found')).toHaveTextContent('Could not assess — domain does not exist in public DNS')
    const block = screen.getByTestId('scan-failed')
    expect(block).toHaveTextContent('Previous observations are kept')
    expect(block.textContent).not.toMatch(/didn't finish|interrupted|usually temporary/i)
    expect(screen.getAllByText('Not assessed — domain not found').length).toBeGreaterThan(0)
  })
  it('interrupted with recorded checks: heading, stage, plain-word check names, never a raw key, never an assessment', async () => {
    renderFailed({ terminal: true, stage: 'phase5_intelligence', completed_modules: 2, module_names_recorded: true, completed_module_names: ['subdomain_takeover', 'technology_detection'], last_heartbeat_at: '2026-10-22T12:40:00Z', stale: false })
    expect(await screen.findByTestId('scan-interrupted-heading')).toHaveTextContent('Interrupted — 2 checks completed')
    expect(screen.getByText('It stopped while checking technology and known-vulnerability information.')).toBeInTheDocument()
    expect(screen.getByRole('list', { name: 'Checks that completed' })).toHaveTextContent('Subdomain takeover checks')
    expect(screen.getByTestId('scan-failed').textContent).not.toMatch(/\b[a-z]+_[a-z_]+\b/)
    expect(screen.getByText(/are not an assessment of/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Run a new scan' })).toBeInTheDocument()
  })
  it('no completed checks keeps the existing honest copy', async () => {
    renderFailed({ terminal: true, stage: null, completed_modules: 0, module_names_recorded: false, completed_module_names: null })
    expect(await screen.findByText("This scan didn't finish")).toBeInTheDocument()
    expect(screen.queryByTestId('scan-interrupted-heading')).toBeNull()
  })
})
