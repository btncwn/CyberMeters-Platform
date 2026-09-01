import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import FreeScanPage from '../FreeScanPage'
import { deriveFreeScanPresentation } from '../../lib/freeScanPresentation'

function responseFor({ moduleState, coverageState }) {
  const moduleEvidence = [
    { module: 'dns', label: 'DNS', attempted: true, state: 'completed' },
    { module: 'ssl', label: 'TLS', attempted: true, state: moduleState },
    { module: 'headers', label: 'Headers', attempted: true, state: 'completed' },
    { module: 'email_security', label: 'Email', attempted: true, state: 'completed' },
    { module: 'subdomains', label: 'Certificate Transparency', attempted: true, state: 'completed' },
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
      version: 'signal-monitoring-state-v1',
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
        certificate_transparency: {
          state: 'monitoring_healthy',
          message: 'Certificate transparency checks completed normally in this run.',
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
    { module: 'subdomains', label: 'Certificate Transparency', attempted: true, state: 'failed' },
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

async function renderResult(payload) {
  vi.stubGlobal('fetch', vi.fn(async () => ({
    ok: true,
    json: async () => payload,
  })))
  Element.prototype.scrollIntoView = vi.fn()
  render(<MemoryRouter><FreeScanPage /></MemoryRouter>)
  fireEvent.change(screen.getByPlaceholderText('yourbusiness.co.uk'), {
    target: { value: 'example.com' },
  })
  fireEvent.click(screen.getByRole('button', { name: /Run my free Cyber MOT/i }))
  await screen.findByRole('heading', { name: 'Evidence incomplete' })
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
    expect(screen.getByText(/canonical domain-ownership verification/i)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Start my 14-day trial/i })).toHaveAttribute(
      'href',
      '/signup?domain=example.com',
    )
  })
})
