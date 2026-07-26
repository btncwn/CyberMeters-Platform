import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import CertificateAssuranceSummary from '../CertificateAssuranceSummary'

const signal = (key, state) => ({
  signal_key: key,
  label: key.replace(/_/g, ' '),
  state,
  state_label: state.replace(/_/g, ' '),
  customer_message: `${key} is ${state}; no favourable state is inferred.`,
  evidence_grade: {
    achieved: 'L0',
    observable_ceiling: 'L3',
    beta_target: 'L1',
    minimum_publishable: 'L1',
    degrade_behavior: 'unknown',
  },
  source_type: 'product_policy',
  provenance: {
    source: 'fixture',
    method: 'injected',
  },
  required_corroboration: ['independent observation'],
  cited_authorities: [{
    standard_id: 'RFC 5280',
    standard_version: 'May 2008',
    section: '§6',
    requirement_type: 'protocol_profile',
  }],
})

describe('CertificateAssuranceSummary', () => {
  it('keeps all five backend states distinct and retains evidence metadata', () => {
    const signals = {
      leaf: signal('leaf', 'observed'),
      chain: signal('chain', 'incomplete'),
      hostname_match: signal('hostname_match', 'unknown'),
      trust_store_validation: signal('trust_store_validation', 'unavailable'),
      revocation_assurance: signal('revocation_assurance', 'not_observed'),
    }
    const { container } = render(
      <CertificateAssuranceSummary
        presentation={{
          signal_order: Object.keys(signals),
          signals,
          summary: {
            ct_only: false,
            trust_ceiling: 'An unexpired leaf alone does not establish verified trust.',
          },
          relationship: {
            customer_message: 'Replacement and parallel context use one explanation.',
          },
          scope_note: 'Every certificate signal has an independent evidence state.',
        }}
        showEvidence
      />
    )

    for (const state of ['observed', 'incomplete', 'unknown', 'unavailable', 'not observed']) {
      expect(screen.getByText(state)).toBeInTheDocument()
    }
    expect(container).toHaveTextContent('Evidence grade L0')
    expect(container).toHaveTextContent('source product_policy')
    expect(container).toHaveTextContent('Provenance:')
    expect(container).toHaveTextContent('Required corroboration: independent observation')
    expect(container).toHaveTextContent('RFC 5280 May 2008 §6 protocol_profile')
    expect(container).not.toHaveTextContent(/\bhealthy\b/i)
    expect(container).not.toHaveTextContent(/\bpassed\b/i)
  })

  it('renders an explicit legacy notice without synthesising a positive result', () => {
    const missing = signal('leaf', 'not_observed')
    render(
      <CertificateAssuranceSummary
        presentation={{
          signal_order: ['leaf'],
          signals: { leaf: missing },
          summary: {},
          scope_note: 'Historical evidence only.',
          historical_notice: 'This signal was not recorded in the historical snapshot.',
        }}
      />
    )

    expect(screen.getByText(/not recorded in the historical snapshot/i)).toBeInTheDocument()
    expect(screen.getByText('not observed')).toBeInTheDocument()
    expect(screen.queryByText(/\bhealthy\b/i)).not.toBeInTheDocument()
  })
})
