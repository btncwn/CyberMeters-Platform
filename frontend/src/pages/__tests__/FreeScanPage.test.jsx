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
  ]
  return {
    domain: 'example.com',
    score: null,
    risk_level: null,
    severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    total_findings: 0,
    preview_findings: [],
    hidden_count: 0,
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
  fireEvent.click(screen.getByRole('button', { name: /Start free check/i }))
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

    expect(screen.getByText('TLS: Failed')).toBeInTheDocument()
    expect(screen.getByText(/No findings were produced, but some checks did not complete/i)).toBeInTheDocument()
    expect(screen.queryByText(/Your Cyber MOT looks healthy/i)).not.toBeInTheDocument()
    expect(screen.queryByText('Excellent')).not.toBeInTheDocument()
    expect(screen.queryByText(/Four-module preview score/i)).not.toBeInTheDocument()
  })

  it('keeps partial distinct through the rendered module list', async () => {
    await renderResult(responseFor({
      moduleState: 'partial',
      coverageState: 'monitoring_degraded',
    }))

    expect(screen.getByText('TLS: Partial')).toBeInTheDocument()
    expect(screen.queryByText('TLS: Completed')).not.toBeInTheDocument()
    await waitFor(() => {
      expect(fetch).toHaveBeenCalledWith(
        'http://localhost/api/free-scan',
        expect.objectContaining({ method: 'POST' }),
      )
    })
  })
})
