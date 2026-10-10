import { render, screen } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from '../../api'
import IdentityExposureCard from '../IdentityExposureCard'

vi.mock('../../api', () => ({ api: { getIdentityExposure: vi.fn() } }))

beforeEach(() => api.getIdentityExposure.mockReset())

const HIGH = {
  identity_exposure_level: 'High',
  summary: 'Identity exposure is High: 1 domain has no enforcing DMARC policy observed.',
  signals: {
    email_spoofing: { spoofable_domains: 1, policy_gap_domains: 1, checked_domains: 1 },
    impersonation_infrastructure: { active: 1, mail_receiving_domains: 1, can_send_mail: 1, can_host_login: 0 },
    exposed_login_surfaces: { internet_facing: 2 },
  },
}

describe('IdentityExposureCard', () => {
  it('renders the level, summary, and three real signals', async () => {
    api.getIdentityExposure.mockResolvedValue(HIGH)
    render(<IdentityExposureCard workspaceId="ws1" />)
    expect(await screen.findByText('High')).toBeInTheDocument()
    expect(screen.getByText(/no enforcing DMARC/i)).toBeInTheDocument()
    expect(screen.getByText('1 DMARC policy gap')).toBeInTheDocument()
    expect(screen.getByText('1 active lookalike')).toBeInTheDocument()
    expect(screen.getByText('1 with mail-receiving MX records')).toBeInTheDocument()
    expect(screen.queryByText(/send mail as you|Protected/)).not.toBeInTheDocument()
    expect(screen.getByText('0 provider relationships · 0 possible hostnames')).toBeInTheDocument()
    expect(screen.getByText('Endpoint reachability not evaluated')).toBeInTheDocument()
  })

})
