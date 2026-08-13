import '@testing-library/jest-dom/vitest'
import { render, screen, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import WorkspaceDetailPage from '../WorkspaceDetailPage'
import { api } from '../../api'

vi.mock('../../api', () => ({
  api: {
    getWorkspace: vi.fn(),
    getWorkspaceDomains: vi.fn(),
    getWorkspaceAssetsSummary: vi.fn(),
  },
}))

const provisional = (displayScore, quality = 'partial') => ({
  raw_score: displayScore,
  display_score: displayScore,
  display_rating: null,
  quality,
  state: 'provisional',
  provisional: true,
  authoritative: false,
  comparable: false,
  coverage: null,
  message: quality === 'degraded'
    ? 'Some checks or evidence sources were degraded. This score is provisional.'
    : 'Some checks were not completed. This score is provisional.',
})

const established = (displayScore, rating = 'good') => ({
  raw_score: displayScore,
  display_score: displayScore,
  display_rating: rating,
  quality: 'complete',
  state: 'established',
  provisional: false,
  authoritative: true,
  comparable: true,
  coverage: null,
  message: null,
})

const notEstablished = () => ({
  raw_score: null,
  display_score: null,
  display_rating: null,
  quality: 'unknown',
  state: 'not_established',
  provisional: false,
  authoritative: false,
  comparable: false,
  coverage: null,
  message: 'Current posture not yet established.',
})

function domainRow(domain, {
  legacyScore,
  assessment,
  status = 'completed',
  scanId = `scan-${domain}`,
} = {}) {
  return {
    domain_id: `domain-${domain}`,
    domain,
    verification_status: 'verified',
    latest_score: legacyScore,
    latest_rating: legacyScore == null ? null : 'excellent',
    latest_scan_quality: assessment?.quality ?? null,
    latest_status: status,
    latest_assessment: assessment,
    last_scan_id: scanId,
    last_scanned_at: '2026-08-12T12:00:00Z',
  }
}

function renderPage(domains) {
  api.getWorkspace.mockResolvedValue({
    workspace: { id: 'ws-founder', name: 'Founder workspace', role: 'owner' },
    stats: {
      total_domains: domains.length,
      total_scans: domains.length,
      latest_scan: null,
      posture_established: false,
      posture_score: null,
      posture_rating: null,
      posture_message: 'Current posture not yet established.',
    },
  })
  api.getWorkspaceDomains.mockResolvedValue({ domains })
  api.getWorkspaceAssetsSummary.mockRejectedValue(new Error('not needed'))

  return render(
    <MemoryRouter initialEntries={['/workspaces/ws-founder']}>
      <Routes>
        <Route path="/workspaces/:id" element={<WorkspaceDetailPage />} />
      </Routes>
    </MemoryRouter>,
  )
}

async function rowFor(hostname) {
  const cell = await screen.findByText(hostname)
  return cell.closest('tr')
}

describe('WorkspaceDetailPage canonical domain score presentation', () => {
  beforeEach(() => vi.clearAllMocks())

  it.each([
    ['blackbullbarbers.co.uk', 100, 'partial'],
    ['cybermeters.com', 85, 'degraded'],
    ['sheshire.co.uk', 85, 'partial'],
  ])('%s preserves %i and visibly labels it Provisional', async (hostname, score, quality) => {
    renderPage([domainRow(hostname, {
      legacyScore: score,
      assessment: provisional(score, quality),
    })])

    const row = within(await rowFor(hostname))
    expect(row.getByText(String(score))).toBeInTheDocument()
    expect(row.getByText('Provisional')).toBeInTheDocument()
    expect(row.getByText(/This score is provisional\./)).toBeInTheDocument()
  })

  it('renders an established numeric score without a provisional label', async () => {
    renderPage([domainRow('established.example', {
      legacyScore: 100,
      assessment: established(82, 'good'),
    })])

    const row = within(await rowFor('established.example'))
    expect(row.getByText('82')).toBeInTheDocument()
    expect(row.queryByText('100')).not.toBeInTheDocument()
    expect(row.queryByText('Provisional')).not.toBeInTheDocument()
  })

  it('keeps a canonical not-established score as a dash with the honest reason', async () => {
    renderPage([domainRow('not-established.example', {
      legacyScore: null,
      assessment: notEstablished(),
      status: null,
      scanId: null,
    })])

    const row = within(await rowFor('not-established.example'))
    expect(row.getByText('—')).toBeInTheDocument()
    expect(row.getByText('Current posture not yet established.')).toBeInTheDocument()
    expect(row.queryByText('Provisional')).not.toBeInTheDocument()
  })

  it.each([
    ['missing', undefined],
    ['malformed', { display_score: 91, provisional: false }],
  ])('fails a %s canonical assessment closed instead of trusting a legacy score', async (label, assessment) => {
    const hostname = `${label}.example`
    renderPage([domainRow(hostname, { legacyScore: 91, assessment })])

    const row = within(await rowFor(hostname))
    expect(row.getByText('—')).toBeInTheDocument()
    expect(row.queryByText('91')).not.toBeInTheDocument()
    expect(row.queryByText('Provisional')).not.toBeInTheDocument()
  })

  it('preserves the workspace-level not-established Cyber Score contract', async () => {
    renderPage([domainRow('partial.example', {
      legacyScore: 100,
      assessment: provisional(100),
    })])

    const cyberScore = await screen.findByText('Cyber Score')
    const card = cyberScore.closest('.card')
    expect(within(card).getByText('—')).toBeInTheDocument()
    expect(within(card).getByText('Current posture not yet established.')).toBeInTheDocument()
  })
})
