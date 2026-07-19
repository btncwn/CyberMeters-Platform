import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from '../../api'
import CasesQueue from '../CasesQueue'

vi.mock('../../api', () => ({ api: { getCases: vi.fn() } }))

const CASES = [
  { case_id: 'c1', domain_key: 'email_protection', title: 'DMARC missing', canonical_phase: 'assigned', verification_support: 'automated', severity: 'high', owner_ref: 'Security Team', updated_at: '2026-07-02T00:00:00Z' },
  { case_id: 'c2', domain_key: 'identity_exposure', title: 'Exposed login', canonical_phase: 'detected', verification_support: 'manual', severity: 'medium', owner_ref: null, updated_at: '2026-07-01T00:00:00Z' },
]

beforeEach(() => {
  api.getCases.mockReset()
  api.getCases.mockResolvedValue({ cases: CASES })
})

function renderQueue() {
  return render(
    <MemoryRouter initialEntries={['/assets']}>
      <Routes>
        <Route path="/assets" element={<CasesQueue workspaceId="ws1" />} />
        <Route path="/ws/cases/:caseId" element={<div>Detail for {window.__caseMarker}</div>} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('CasesQueue', () => {
  it('shows an Owner column with owner_ref and explicit Unassigned', async () => {
    renderQueue()
    expect(await screen.findByText('Security Team')).toBeInTheDocument()
    expect(screen.getByText('Unassigned')).toBeInTheDocument()
    expect(screen.getByText('Owner')).toBeInTheDocument()
  })

  it('filter lists all eight canonical domains, not only loaded ones', async () => {
    renderQueue()
    await screen.findByText('DMARC missing')
    // A domain with no loaded case must still be selectable (no collapse-to-one).
    expect(screen.getByRole('option', { name: 'Certificates & Trust' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Shadow IT & Unmanaged Technology' })).toBeInTheDocument()
  })

  it('navigates to the canonical case detail on row click', async () => {
    renderQueue()
    const row = (await screen.findByText('DMARC missing')).closest('tr')
    fireEvent.click(row)
    expect(await screen.findByText(/Detail for/i)).toBeInTheDocument()
  })
})
