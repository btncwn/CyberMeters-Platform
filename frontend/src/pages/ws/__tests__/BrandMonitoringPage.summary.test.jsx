// S1-SHELL-V2b (Brand), R1 rules: "What we observed" reads only the backend
// summary (workspace-wide); the candidate list is a bounded page and never
// stands in for a total; a failed request is "Not available", never 0 or "none".
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import BrandMonitoringPage from '../BrandMonitoringPage'
import { api } from '../../../api'
import { useWorkspace } from '../../../hooks/useWorkspace'

vi.mock('../../../api', () => ({ api: {
  getBrandProfile: vi.fn(), getBrandSummary: vi.fn(), getBrandCandidates: vi.fn(),
  getBrandCases: vi.fn(), getWorkspaceBrandMonitoring: vi.fn(),
  classifyBrandCandidate: vi.fn(), refreshBrandMonitoring: vi.fn(),
} }))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: vi.fn() }))
// Render the figures the page hands the area template, with their anchors.
vi.mock('../../../components/module/ModuleContract', () => ({
  default: ({ children, figures }) => <div>{(figures || []).map((f) => <p key={f.key} id={f.id}>{f.label}: {String(f.value)}</p>)}{children}</div>,
  useAreaAnchor: () => vi.fn(),
}))

const candidate = (id, over = {}) => ({ id, candidate_domain: `${id}.example`, classification: 'unreviewed', risk_level: 'high', ...over })
const fig = (id) => document.getElementById(id)
const mount = () => render(<MemoryRouter><BrandMonitoringPage /></MemoryRouter>)

beforeEach(() => {
  vi.clearAllMocks()
  useWorkspace.mockReturnValue({ wsId: 'ws-1', wsName: 'Workspace', workspaces: [{ id: 'ws-1', role: 'admin' }] })
  api.getBrandProfile.mockResolvedValue({ profile: null })
  api.getBrandSummary.mockResolvedValue({ summary: { total_candidates: 120, high_risk: 9, suspicious: 4, unreviewed: 70 } })
  api.getBrandCandidates.mockResolvedValue({ candidates: [candidate('a'), candidate('b')], total: 120 })
  api.getBrandCases.mockResolvedValue({ cases: [] })
})

describe('Brand "What we observed"', () => {
  it('reads the workspace-wide summary, never the 50-row page; every figure is an anchor', async () => {
    mount()
    await waitFor(() => expect(fig('brand-lookalike')).toHaveTextContent('Lookalike candidates: 120'))
    expect(fig('brand-high-risk')).toHaveTextContent('9')
    expect(fig('brand-suspicious')).toHaveTextContent('4')
    expect(fig('brand-unreviewed')).toHaveTextContent('70')
  })
  it('a failed or field-less summary is "Not available" — never 0, never the page count', async () => {
    api.getBrandSummary.mockRejectedValue(new Error('down'))
    mount()
    await waitFor(() => expect(fig('brand-lookalike')).toHaveTextContent('Not available'))
    for (const id of ['brand-high-risk', 'brand-suspicious', 'brand-unreviewed']) expect(fig(id)).toHaveTextContent('Not available')
    expect(document.body.textContent).not.toMatch(/Lookalike candidates: 2\b/)
  })
  it('a summary without a field reads "Not available" for that figure only', async () => {
    api.getBrandSummary.mockResolvedValue({ summary: { total_candidates: 120, high_risk: 9, suspicious: 4 } })
    mount()
    await waitFor(() => expect(fig('brand-lookalike')).toHaveTextContent('120'))
    expect(fig('brand-unreviewed')).toHaveTextContent('Not available')
  })
})

describe('the queue and takedown tracking', () => {
  it('the queue names its bound when the backend total exceeds the loaded page', async () => {
    mount()
    expect(await screen.findByText('2 of 2 shown · the first 2 of 120 candidates')).toBeInTheDocument()
  })
  it('a failed candidate list says "Not available", never "No lookalike domains found yet"', async () => {
    api.getBrandCandidates.mockRejectedValue(new Error('down'))
    api.getWorkspaceBrandMonitoring.mockRejectedValue(new Error('down'))
    mount()
    expect(await screen.findByText('Not available — the candidate list could not be loaded.')).toBeInTheDocument()
    expect(screen.queryByText('No lookalike domains found yet.')).toBeNull()
  })
  it('failed takedown cases say "Not available", never "No takedown is being tracked yet"', async () => {
    api.getBrandCases.mockRejectedValue(new Error('down'))
    mount()
    expect(await screen.findByText('Not available — the takedown cases could not be loaded.')).toBeInTheDocument()
    expect(document.getElementById('managed-brand-cases')).not.toBeNull()
    expect(screen.queryByText(/No takedown is being tracked yet/)).toBeNull()
  })
  it('no cases at all still says so honestly', async () => {
    mount()
    expect(await screen.findByText(/No takedown is being tracked yet/)).toBeInTheDocument()
  })
})

describe('loading and workspace switch (R1 18:55)', () => {
  const deferred = () => { let resolve; const promise = new Promise((r) => { resolve = r }); return { promise, resolve } }
  it('while the summary loads, no figure reads 0 (the page shows its loading state)', async () => {
    const summary = deferred()
    api.getBrandSummary.mockReturnValue(summary.promise)
    mount()
    await waitFor(() => expect(api.getBrandSummary).toHaveBeenCalled())
    for (const id of ['brand-lookalike', 'brand-high-risk', 'brand-suspicious', 'brand-unreviewed']) {
      const el = fig(id)
      if (el) expect(el.textContent).not.toMatch(/: 0$/)
    }
    expect(document.body.textContent).not.toMatch(/Lookalike candidates: 0/)
    summary.resolve({ summary: { total_candidates: 120, high_risk: 9, suspicious: 4, unreviewed: 70 } })
    await waitFor(() => expect(fig('brand-lookalike')).toHaveTextContent('120'))
  })
  it('a workspace switch never shows the previous workspace\'s counts: loading, then the new counts', async () => {
    const view = mount()
    await waitFor(() => expect(fig('brand-lookalike')).toHaveTextContent('120'))
    const next = deferred()
    api.getBrandSummary.mockReturnValue(next.promise)
    api.getBrandCandidates.mockResolvedValue({ candidates: [candidate('z')], total: 1 })
    useWorkspace.mockReturnValue({ wsId: 'ws-2', wsName: 'Other', workspaces: [{ id: 'ws-2', role: 'admin' }] })
    view.rerender(<MemoryRouter><BrandMonitoringPage /></MemoryRouter>)
    await waitFor(() => expect(api.getBrandSummary).toHaveBeenLastCalledWith('ws-2'))
    // In flight: ws-1's 120 / 9 / 4 / 70 are gone.
    expect(document.body.textContent).not.toMatch(/Lookalike candidates: 120/)
    expect(document.body.textContent).not.toMatch(/Unreviewed: 70/)
    next.resolve({ summary: { total_candidates: 1, high_risk: 0, suspicious: 0, unreviewed: 1 } })
    await waitFor(() => expect(fig('brand-lookalike')).toHaveTextContent('Lookalike candidates: 1'))
    expect(fig('brand-unreviewed')).toHaveTextContent('Unreviewed: 1')
  })
})
