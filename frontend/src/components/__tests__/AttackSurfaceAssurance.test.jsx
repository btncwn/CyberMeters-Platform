import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import AttackSurfaceAssurance from '../AttackSurfaceAssurance'

const base = {
  schema: 'attack-surface-customer-presentation-v1',
  status: 'current',
  domain_id: 'dom1',
  scope_note: 'Signals remain independent.',
  signal_order: ['subdomain_discovery', 'dns_resolution'],
  signals: {
    subdomain_discovery: {
      signal_key: 'subdomain_discovery',
      label: 'Subdomain discovery',
      state: 'unavailable',
      state_label: 'Evidence unavailable',
      customer_message: 'Subdomain discovery evidence was unavailable. No favourable result is inferred.',
    },
    dns_resolution: {
      signal_key: 'dns_resolution',
      label: 'DNS resolution',
      state: 'observed',
      state_label: 'Observed',
      customer_message: 'DNS resolution evidence was observed.',
    },
  },
  lifecycle: {
    status: 'not_recorded',
    records: [],
    customer_message: 'Migration 102 lifecycle fields are not recorded.',
  },
  alert_eligibility: {
    status: 'recorded',
    customer_message: 'Alert eligibility was evaluated per claim.',
    decisions: [{
      event_type: 'asset_reappeared',
      eligible: false,
      reason_code: 'withheld_reappearance_predecessor_unconfirmed',
      reason_message: 'The earlier disappearance was not confirmed.',
    }],
  },
  model_versions: {
    signal_completeness: 'attack-surface-signal-completeness-v1',
    lifecycle_policy: null,
    alert_eligibility: 'asset-alert-eligibility-v1',
  },
}

describe('AttackSurfaceAssurance', () => {
  it('renders backend-owned independent signal, lifecycle and alert wording', () => {
    render(<AttackSurfaceAssurance presentations={[base]} />)
    expect(screen.getByText('Evidence unavailable')).toBeInTheDocument()
    expect(screen.getByText('Observed')).toBeInTheDocument()
    expect(screen.getByText(/Migration 102 lifecycle fields are not recorded/i)).toBeInTheDocument()
    expect(screen.getByText('Alert withheld')).toBeInTheDocument()
    expect(screen.getByText('withheld_reappearance_predecessor_unconfirmed')).toBeInTheDocument()
    expect(screen.queryByText(/^Healthy$/i)).not.toBeInTheDocument()
  })

  it('shows an explicit notice instead of an empty healthy panel', () => {
    render(<AttackSurfaceAssurance presentations={[]} />)
    expect(screen.getByText(/Attack Surface evidence was not recorded/i)).toBeInTheDocument()
    expect(screen.getByText(/No favourable security or availability conclusion is inferred/i)).toBeInTheDocument()
  })

  it('renders bounded lifecycle truncation as partial evidence', () => {
    render(
      <AttackSurfaceAssurance
        presentations={[base]}
        coverage={{
          returned: 200,
          total: 238,
          bound: 200,
          truncated: true,
          status: 'truncated',
          customer_message: 'Lifecycle evidence is truncated: 200 of 238 workspace assets were read within the 200-asset bound.',
        }}
      />,
    )
    expect(screen.getByText(/Partial lifecycle evidence/i)).toBeInTheDocument()
    expect(screen.getByText(/200 of 238 workspace assets/i)).toBeInTheDocument()
    expect(screen.queryByText(/^Healthy$/i)).not.toBeInTheDocument()
  })
})
