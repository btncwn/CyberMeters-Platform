import React from 'react'
import { render, screen, fireEvent } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import DomainMaturity from '../DomainMaturity'
import { api } from '../../api'

vi.mock('../../api', () => ({ api: { getMaturityHistory: vi.fn() } }))
beforeEach(() => { vi.resetAllMocks() })

const KEYS = ['identity_exposure', 'attack_surface', 'email_protection', 'website_security', 'shadow_it_unmanaged_technology', 'certificates_trust', 'brand_protection', 'cyber_essentials_readiness']
const domains = KEYS.map((k) => ({
  domain_key: k, display_name: k, maturity_stage: k === 'email_protection' ? 'managed' : 'not_established',
  stage_label: null, stage_description: 'x', capability_ceiling: 'monitored', flags: {},
  established: k === 'email_protection', ...(k === 'email_protection' ? { domain_id: 'd1', domain_name: 'acme.test' } : {}),
}))

describe('DomainMaturity history', () => {
  it('offers history only for an established domain record and shows the ledger verbatim', async () => {
    api.getMaturityHistory.mockResolvedValue({ history: [
      { maturity_stage: 'managed', reason_code: 'recurrence_reopened', assessed_at: '2026-10-10T00:00:00Z', flags: { regressed: true } },
      { maturity_stage: 'verified', reason_code: 'verified_by_observation', assessed_at: '2026-10-01T00:00:00Z', flags: {} },
    ] })
    render(<DomainMaturity domains={domains} workspaceId="ws1" />)
    const buttons = screen.getAllByRole('button', { name: /History/ })
    expect(buttons).toHaveLength(1)
    expect(buttons[0]).toHaveTextContent('History for acme.test')
    fireEvent.click(buttons[0])
    expect(api.getMaturityHistory).toHaveBeenCalledWith('ws1', 'd1', 'email_protection')
    expect(await screen.findByText(/An issue came back; its case was reopened/)).toBeInTheDocument()
    expect(screen.getByText('(recurred)')).toBeInTheDocument()
    expect(screen.getByText(/Fix re-observed by CyberMeters/)).toBeInTheDocument()
  })

  it('no workspace → no history control (other screens unchanged)', () => {
    render(<DomainMaturity domains={domains} />)
    expect(screen.queryByRole('button', { name: /History/ })).toBeNull()
  })

  it('a failed history read is shown, not an empty history', async () => {
    api.getMaturityHistory.mockRejectedValue(new Error('503'))
    render(<DomainMaturity domains={domains} workspaceId="ws1" />)
    fireEvent.click(screen.getByRole('button', { name: /History/ }))
    expect(await screen.findByRole('alert')).toHaveTextContent('History could not be loaded.')
  })
})
