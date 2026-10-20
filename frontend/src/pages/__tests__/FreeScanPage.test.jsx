import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import FreeScanPage, { apexOf } from '../FreeScanPage'
import { deriveFreeScanPresentation, moreInTrialCopy } from '../../lib/freeScanPresentation'
import { api } from '../../api'

const auth = vi.hoisted(() => ({ isAuthenticated: false }))
vi.mock('../../context/AuthContext', () => ({ useAuth: () => auth }))
vi.mock('../../api', async (importOriginal) => ({
  ...(await importOriginal()),
  api: { getWorkspaces: vi.fn(), getWorkspaceDomains: vi.fn() },
}))

function responseFor({ moduleState, coverageState }) {
  const moduleEvidence = [
    { module: 'dns', label: 'DNS', attempted: true, state: 'completed' },
    { module: 'ssl', label: 'TLS', attempted: true, state: moduleState },
    { module: 'headers', label: 'Headers', attempted: true, state: 'completed' },
    { module: 'email_security', label: 'Email', attempted: true, state: 'completed' },
    { module: 'technology_detection', label: 'Technology', attempted: true, state: 'completed' },
  ]
  const cyberMotDomains = [
    ['email_protection', 'Email Protection'],
    ['brand_protection', 'Brand Protection'],
    ['attack_surface', 'Attack Surface'],
    ['certificates_trust', 'Certificates & Trust'],
    ['cyber_essentials_readiness', 'Cyber Essentials Readiness'],
    ['website_security', 'Website Security'],
    ['identity_exposure', 'Identity Exposure'],
    ['shadow_it_unmanaged_technology', 'Shadow IT & Unmanaged Technology'],
  ].map(([domain_key, display_name]) => ({
    domain_key,
    display_name,
    state: ['brand_protection', 'attack_surface', 'cyber_essentials_readiness', 'identity_exposure']
      .includes(domain_key) ? 'customer_input_required' : 'evidence_insufficient',
    display_state: ['brand_protection', 'attack_surface', 'cyber_essentials_readiness', 'identity_exposure']
      .includes(domain_key) ? 'input_required' : 'evidence_insufficient',
    coverage: 'partial',
    severity: null,
    headline_count: null,
    count_kind: 'input_required',
    samples: [],
    locked_count: 0,
    unlock_required: true,
    limitation: `${display_name} bounded-preview limitation.`,
  }))
  return {
    domain: 'example.com',
    score: null,
    risk_level: null,
    severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    total_findings: 0,
    preview_findings: [],
    shown_findings: [],
    exposed_finding_count: 0,
    hidden_count: 0,
    locked_count: 0,
    cyber_mot_domains: cyberMotDomains,
    modules_attempted: moduleEvidence.map(entry => entry.module),
    modules_scanned: moduleEvidence
      .filter(entry => entry.state === 'completed')
      .map(entry => entry.module),
    module_evidence: moduleEvidence,
    monitoring_states: {
      version: 'signal-monitoring-state-v2',
      signals: {
        dns: {
          state: 'monitoring_healthy',
          message: 'DNS checks completed normally in this run.',
        },
        website_security: {
          state: coverageState,
          message: 'Website security checks did not complete in this run.',
        },
        email_protection: {
          state: 'monitoring_healthy',
          message: 'Email protection checks completed normally in this run.',
        },
      },
    },
    evidence_coverage: {
      state: coverageState,
      complete: false,
      messages: ['Website security checks did not complete in this run.'],
    },
    preview_state: 'evidence_incomplete',
    scanned_at: '2026-07-27T10:00:00.000Z',
  }
}

function allProbesFailedResponse() {
  const payload = responseFor({
    moduleState: 'unavailable',
    coverageState: 'evidence_incomplete',
  })
  payload.module_evidence = [
    { module: 'dns', label: 'DNS', attempted: true, state: 'failed' },
    { module: 'ssl', label: 'TLS', attempted: true, state: 'unavailable' },
    { module: 'headers', label: 'Headers', attempted: true, state: 'incomplete' },
    { module: 'email_security', label: 'Email', attempted: true, state: 'unavailable' },
    { module: 'technology_detection', label: 'Technology', attempted: true, state: 'incomplete' },
  ]
  payload.modules_scanned = []
  payload.score = null
  payload.risk_level = null
  payload.preview_state = 'evidence_incomplete'
  payload.monitoring_states.signals.dns = {
    state: 'evidence_incomplete',
    message: 'DNS checks did not complete in this run.',
  }
  payload.monitoring_states.signals.email_protection = {
    state: 'signal_unavailable',
    message: 'Email protection checks were unavailable in this run.',
  }
  return payload
}

async function renderResult(payload, heading = 'Evidence incomplete') {
  vi.stubGlobal('fetch', vi.fn(async () => ({
    ok: true,
    json: async () => payload,
  })))
  Element.prototype.scrollIntoView = vi.fn()
  render(<MemoryRouter initialEntries={['/free-scan']}><FreeScanPage /></MemoryRouter>)
  fireEvent.change(screen.getByPlaceholderText('yourbusiness.co.uk'), {
    target: { value: 'example.com' },
  })
  fireEvent.click(screen.getByRole('button', { name: /Run my free Cyber MOT/i }))
  await screen.findByRole('heading', { name: heading })
}

function withFindings(severities) {
  const payload = responseFor({ moduleState: 'completed', coverageState: 'monitoring_degraded' })
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  severities.forEach(severity => { counts[severity] += 1 })
  const shown = severities.slice(0, 2).map((severity, index) => ({
    id: `f${index}`, severity, title: `Finding ${index}`, description: 'Observed.',
  }))
  return {
    ...payload,
    preview_state: 'issues_observed',
    severity_counts: counts,
    total_findings: severities.length,
    shown_findings: shown,
    preview_findings: shown,
    exposed_finding_count: shown.length,
    locked_count: severities.length - shown.length,
    hidden_count: severities.length - shown.length,
  }
}

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('FreeScanPage evidence honesty', () => {
  it('fails closed for a legacy/unknown response even when it contains a score and zero findings', () => {
    const presentation = deriveFreeScanPresentation({
      score: 100,
      total_findings: 0,
      modules_scanned: ['dns', 'ssl', 'headers', 'email_security'],
    })
    expect(presentation.headline).toBe('Evidence incomplete')
    expect(presentation.showScore).toBe(false)
    expect(presentation.moduleEvidence.every(entry => entry.state === 'incomplete')).toBe(true)
  })

  it('renders a failed probe distinctly and never renders a healthy/Excellent zero-finding verdict', async () => {
    await renderResult(responseFor({
      moduleState: 'failed',
      coverageState: 'evidence_incomplete',
    }))

    expect(screen.getByText('TLS · Failed')).toBeInTheDocument()
    expect(screen.getByText(/Evidence remains incomplete, so this is not a healthy verdict/i)).toBeInTheDocument()
    expect(screen.queryByText(/Your Cyber MOT looks healthy/i)).not.toBeInTheDocument()
    expect(screen.queryByText('Excellent')).not.toBeInTheDocument()
    expect(screen.queryByText(/out of 100/i)).not.toBeInTheDocument()
  })

  it('keeps partial distinct through the rendered module list', async () => {
    await renderResult(responseFor({
      moduleState: 'partial',
      coverageState: 'monitoring_degraded',
    }))

    expect(screen.getByText('TLS · Partial')).toBeInTheDocument()
    expect(screen.queryByText('TLS · Completed')).not.toBeInTheDocument()
    await waitFor(() => {
      expect(fetch).toHaveBeenCalledWith(
        'http://localhost/api/free-scan',
        expect.objectContaining({ method: 'POST' }),
      )
    })
  })

  it('a result can be reported: "Something wrong?" sits under the snapshot (founder, 20 Oct 2026)', async () => {
    await renderResult(allProbesFailedResponse())
    expect(screen.getByRole('button', { name: 'Something wrong?' })).toBeInTheDocument()
  })

  it('a failed snapshot can be reported with its error code attached', async () => {
    const fetchMock = vi.fn(async (url) => String(url).endsWith('/feedback')
      ? new Response('{}', { status: 202 })
      : { ok: false, status: 429, json: async () => ({ error: 'Too many free checks from this connection.', code: 'rate_limited' }) })
    vi.stubGlobal('fetch', fetchMock)
    render(<MemoryRouter><FreeScanPage /></MemoryRouter>)
    fireEvent.change(screen.getByPlaceholderText('yourbusiness.co.uk'), { target: { value: 'example.com' } })
    fireEvent.click(screen.getByRole('button', { name: /Run my free Cyber MOT/i }))
    await screen.findByRole('alert')
    fireEvent.click(screen.getByRole('button', { name: 'Something wrong?' }))
    fireEvent.change(screen.getByLabelText('Tell us what looks wrong'), { target: { value: 'I only ran one check' } })
    fireEvent.click(screen.getByRole('button', { name: 'Send' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([u]) => String(u).endsWith('/feedback'))).toBe(true))
    const [, init] = fetchMock.mock.calls.find(([u]) => String(u).endsWith('/feedback'))
    expect(JSON.parse(init.body)).toMatchObject({ surface: 'free_scan', error_code: 'rate_limited', message: 'I only ran one check', tool: null })
  })

  it('renders the all-probes-failed contract without a score or healthy/no-issues verdict', async () => {
    await renderResult(allProbesFailedResponse())

    expect(screen.getByText('DNS · Failed')).toBeInTheDocument()
    expect(screen.getByText('TLS · Unavailable')).toBeInTheDocument()
    expect(screen.getByText('Headers · Incomplete')).toBeInTheDocument()
    expect(screen.getByText('Email · Unavailable')).toBeInTheDocument()
    expect(screen.queryByText(/Four-module preview score/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/out of 100/i)).not.toBeInTheDocument()
    expect(screen.queryByText('Assessed — no issue observed')).not.toBeInTheDocument()
    expect(screen.queryByText('Excellent')).not.toBeInTheDocument()
    expect(screen.queryByText(/No issues observed/i)).not.toBeInTheDocument()
  })

  it('renders exactly eight honest domain cards and keeps the full report behind ownership verification', async () => {
    await renderResult(responseFor({
      moduleState: 'partial',
      coverageState: 'monitoring_degraded',
    }))

    expect(screen.getAllByRole('article')).toHaveLength(8)
    expect(screen.getByRole('heading', { name: 'Email Protection' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Shadow IT & Unmanaged Technology' })).toBeInTheDocument()
    expect(screen.getAllByText('Unlock to assess').length).toBeGreaterThan(0)
    expect(screen.getByText('Shown in your 14-day trial, once you verify you own the domain.')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Start my 14-day trial/i })).toHaveAttribute(
      'href',
      '/signup?domain=example.com',
    )
  })
})

describe('FreeScanPage result summary', () => {
  it('takes the badge from the backend preview state, failing closed to incomplete', () => {
    expect(deriveFreeScanPresentation(withFindings(['medium'])).badge).toBe('Findings observed')
    expect(deriveFreeScanPresentation(responseFor({ moduleState: 'completed', coverageState: 'complete' })).badge)
      .toBe('Evidence incomplete')
    expect(deriveFreeScanPresentation({ preview_state: 'no_issues_observed', evidence_coverage: { complete: false } }).badge)
      .toBe('Evidence incomplete')
    expect(deriveFreeScanPresentation({ preview_state: 'something_new' }).badge).toBe('Evidence incomplete')
  })

  it('does not call informational signals issues', async () => {
    await renderResult(withFindings(['info', 'info', 'info', 'info']), 'Only informational signals in the preview checks')
    expect(screen.getByTestId('preview-badge')).toHaveTextContent('Findings observed')
    expect(screen.getByTestId('preview-badge')).toHaveAttribute('data-tone', 'info')
    expect(screen.getByText(/so this is not a healthy verdict/)).toBeInTheDocument()
    expect(screen.queryByText('Issues observed in the preview checks')).not.toBeInTheDocument()
    expect(screen.getByText('2 more findings in the trial')).toBeInTheDocument()
  })

  it('keeps the issues headline when anything is rated low or above, or counts are missing', () => {
    expect(deriveFreeScanPresentation(withFindings(['info', 'low'])).headline).toBe('Issues observed in the preview checks')
    const noCounts = { ...withFindings(['info']), severity_counts: undefined }
    expect(deriveFreeScanPresentation(noCounts).headline).toBe('Issues observed in the preview checks')
  })
})

describe('FreeScanPage hand-over from the landing page', () => {
  it('explains the five-check preview, eight-area summary and retained abuse counters', () => {
    render(<MemoryRouter><FreeScanPage /></MemoryRouter>)
    expect(screen.getByText(/Five bounded public checks, summarised across your external posture/)).toBeInTheDocument()
    expect(screen.getByText('No scan report saved')).toBeInTheDocument()
    expect(screen.getByText(/Limited rate-limit records are kept to prevent misuse/)).toHaveTextContent('These five checks may leave some areas unassessed')
    expect(document.body.textContent).not.toContain('Nothing stored')
  })
  it('runs the check once for a valid ?domain= and drops the parameter', async () => {
    const fetchMock = vi.fn(async () => ({ ok: true, json: async () => responseFor({ moduleState: 'completed', coverageState: 'complete' }) }))
    vi.stubGlobal('fetch', fetchMock)
    Element.prototype.scrollIntoView = vi.fn()
    window.history.pushState({}, '', '/free-scan?domain=Example.co.uk')
    render(<MemoryRouter><FreeScanPage /></MemoryRouter>)
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ domain: 'example.co.uk' })
    expect(window.location.search).toBe('')
    window.history.pushState({}, '', '/')
  })

  it('checks the apex for a www address, from the landing page and the form', async () => {
    const fetchMock = vi.fn(async () => ({ ok: true, json: async () => responseFor({ moduleState: 'completed', coverageState: 'complete' }) }))
    vi.stubGlobal('fetch', fetchMock)
    Element.prototype.scrollIntoView = vi.fn()
    window.history.pushState({}, '', '/free-scan?domain=https://www.Example.co.uk/')
    render(<MemoryRouter><FreeScanPage /></MemoryRouter>)
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ domain: 'example.co.uk' })
    window.history.pushState({}, '', '/')
    expect(apexOf('www.example.com')).toBe('example.com')
    expect(apexOf('www.com')).toBe('www.com')
    expect(apexOf('wwwexample.com')).toBe('wwwexample.com')
    expect(apexOf('shop.www.example.com')).toBe('shop.www.example.com')
  })

  it('ignores an invalid domain parameter and waits for the visitor', () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    window.history.pushState({}, '', '/free-scan?domain=%3Cscript%3E')
    render(<MemoryRouter><FreeScanPage /></MemoryRouter>)
    expect(fetchMock).not.toHaveBeenCalled()
    expect(screen.getByPlaceholderText('yourbusiness.co.uk')).toHaveValue('')
    window.history.pushState({}, '', '/')
  })
})

describe('FreeScanPage offer wording', () => {
  it('uses one term for the offer and no "sealed" wording', async () => {
    await renderResult(withFindings(['medium', 'low', 'low']), 'Issues observed in the preview checks')
    const text = document.body.textContent
    expect(text).not.toMatch(/sealed/i)
    expect(text).not.toMatch(/free account/i)
    expect(screen.getByText('More findings in the trial')).toBeInTheDocument()
    expect(screen.getByText('A bounded finding preview. The full list comes with the trial.')).toBeInTheDocument()
  })

  it('names the unit of every "more" count, so signals never read as findings', () => {
    expect(moreInTrialCopy(3, 'observation')).toBe('3 more public signals in the trial')
    expect(moreInTrialCopy(1, 'observation')).toBe('1 more public signal in the trial')
    expect(moreInTrialCopy(1, 'finding')).toBe('1 more finding in the trial')
    expect(moreInTrialCopy(2)).toBe('2 more findings in the trial')
  })
})

describe('FreeScanPage for a signed-in visitor', () => {
  afterEach(() => {
    auth.isAuthenticated = false
    vi.mocked(api.getWorkspaces).mockReset()
    vi.mocked(api.getWorkspaceDomains).mockReset()
  })

  it('anonymous visitors make no workspace request and keep the trial offer', async () => {
    await renderResult(withFindings(['medium']), 'Issues observed in the preview checks')
    expect(api.getWorkspaces).not.toHaveBeenCalled()
    expect(api.getWorkspaceDomains).not.toHaveBeenCalled()
    expect(screen.getByRole('link', { name: 'Start my 14-day trial' })).toHaveAttribute('href', '/signup?domain=example.com')
    // The site's own header: sign in, pricing and (in the footer) the free tools.
    expect(screen.getAllByRole('link', { name: 'Sign in' }).length).toBeGreaterThan(0)
    expect(screen.getAllByRole('link', { name: 'Pricing' }).length).toBeGreaterThan(0)
    expect(screen.getAllByRole('link', { name: 'Free tools' }).length).toBeGreaterThan(0)
    // On the free check itself, the header does not offer "Run a free check".
    expect(screen.queryByRole('link', { name: 'Run a free check' })).toBeNull()
    expect(screen.queryByTestId('free-scan-own-workspace')).toBeNull()
  })

  it('replaces the trial offer when the domain is verified in one of their workspaces', async () => {
    auth.isAuthenticated = true
    vi.mocked(api.getWorkspaces).mockResolvedValue({ workspaces: [{ id: 'ws_a', name: 'Other' }, { id: 'ws_b', name: 'Example Ltd' }] })
    vi.mocked(api.getWorkspaceDomains).mockImplementation(async (id) => ({
      domains: id === 'ws_b' ? [{ domain: 'www.Example.com', verification_status: 'verified' }] : [{ domain: 'unrelated.test', verification_status: 'verified' }],
    }))
    await renderResult(withFindings(['medium']), 'Issues observed in the preview checks')
    expect(await screen.findByRole('heading', { name: 'You already monitor this domain' })).toBeInTheDocument()
    expect(screen.getByText(/example\.com is verified in Example Ltd/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open workspace' })).toHaveAttribute('href', '/workspaces/ws_b')
    expect(screen.queryByRole('link', { name: 'Start my 14-day trial' })).toBeNull()
    expect(screen.getAllByRole('link', { name: 'Dashboard' })[0]).toHaveAttribute('href', '/dashboard')
    expect(document.body.textContent).not.toMatch(/in the trial|with the trial/)
    expect(screen.getByText('More findings in your workspace')).toBeInTheDocument()
    expect(screen.getByText('Open the workspace to see every finding.')).toBeInTheDocument()
  })

  it('says so when the domain is in their workspace but not verified yet', async () => {
    auth.isAuthenticated = true
    vi.mocked(api.getWorkspaces).mockResolvedValue({ workspaces: [{ id: 'ws_a', name: 'Example Ltd' }] })
    vi.mocked(api.getWorkspaceDomains).mockResolvedValue({ domains: [{ domain: 'example.com', verification_status: 'pending' }] })
    await renderResult(withFindings(['medium']), 'Issues observed in the preview checks')
    expect(await screen.findByRole('heading', { name: 'This domain is in your workspace' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open workspace' })).toHaveAttribute('href', '/workspaces/ws_a')
  })

  it('keeps today\'s page when there is no match or the lookup fails', async () => {
    auth.isAuthenticated = true
    vi.mocked(api.getWorkspaces).mockResolvedValue({ workspaces: [{ id: 'ws_a', name: 'Mine' }] })
    vi.mocked(api.getWorkspaceDomains).mockRejectedValue(new Error('Request failed'))
    await renderResult(withFindings(['medium']), 'Issues observed in the preview checks')
    await waitFor(() => expect(api.getWorkspaceDomains).toHaveBeenCalledWith('ws_a'))
    expect(screen.getByRole('link', { name: 'Start my 14-day trial' })).toBeInTheDocument()
    expect(screen.queryByTestId('free-scan-own-workspace')).toBeNull()
  })
})
