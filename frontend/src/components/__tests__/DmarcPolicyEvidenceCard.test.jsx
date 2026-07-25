import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import DmarcPolicyEvidenceCard from '../DmarcPolicyEvidenceCard'

function current(overrides = {}) {
  return {
    schema: 'dmarc-policy-presentation.v1',
    status: 'current',
    headline: 'DMARC requested policy: Quarantine requested',
    customer_message: 'No applicable record was found at the exact domain.',
    policy: {
      effective_requested: 'quarantine',
      effective_requested_label: 'Quarantine requested',
      source_label: 'Organisational-domain record',
      source_domain: 'example.test',
      message: 'The published policy requests quarantine treatment. Receivers retain final handling discretion.',
      inheritance_message: 'RFC 9989 discovery found a policy at example.test; its sp=quarantine preference applies.',
      testing_message: 'The record declares p=reject with t=y; RFC 9989 makes the effective requested policy quarantine while testing.',
      p: { tag: 'p', present: true, raw: 'reject', valid: true },
      sp: { tag: 'sp', present: true, raw: 'quarantine', valid: true },
      np: { tag: 'np', present: false, raw: null, valid: true },
      t: { tag: 't', present: true, raw: 'y', valid: true },
    },
    organisational_domain: { value: 'example.test' },
    legacy_pct: {
      observed: true,
      raw: '25',
      applied_to_effective_policy: false,
      message: 'Legacy pct=25 was observed. RFC 9989 no longer applies this value to the current effective policy.',
    },
    completeness: { core: 'complete', core_label: 'Complete' },
    monitoring: {
      state: 'monitoring_degraded',
      label: 'DMARC monitoring incomplete',
      message: 'DMARC monitoring was incomplete for this scan. CyberMeters has not inferred a configuration change from the incomplete result.',
    },
    external_rua: {
      destinations: [{
        destination_index: 0,
        uri: 'mailto:agg@vendor.test',
        status_label: 'Authorised external destination',
        message: 'The destination published a valid record. This does not prove reports were sent, received, or trusted.',
      }],
    },
    evidence_grade: {
      grade: 'L3',
      basis: 'Complete RFC 9989 policy discovery.',
      limits: ['Receiver enforcement is not observed.'],
    },
    technical_appendix: {
      facts: [{ label: 'Methodology', value: 'rfc9989-treewalk-v1' }],
      lookup_path: [{
        question: { type: 'TXT', name: '_dmarc.example.test' },
        outcome: 'nodata',
        logically_used: true,
      }],
      raw_records: [{ raw: 'v=DMARC1; p=reject; t=y; pct=25' }],
    },
    ...overrides,
  }
}

describe('DmarcPolicyEvidenceCard', () => {
  it('renders backend-owned effective, inherited, testing and legacy meaning', () => {
    render(<DmarcPolicyEvidenceCard presentation={current()} showTechnical />)

    expect(screen.getByText('DMARC requested policy: Quarantine requested')).toBeInTheDocument()
    expect(screen.getByText(/sp=quarantine preference applies/)).toBeInTheDocument()
    expect(screen.getByText(/effective requested policy quarantine while testing/)).toBeInTheDocument()
    expect(screen.getByText(/Legacy pct=25/)).toBeInTheDocument()
    expect(screen.getByText('Evidence Grade L3')).toBeInTheDocument()
    expect(screen.getByText(/does not prove how every receiver handled mail/)).toBeInTheDocument()
  })

  it('keeps each external destination and its trust limitation visible', () => {
    render(<DmarcPolicyEvidenceCard presentation={current()} />)

    expect(screen.getByText('mailto:agg@vendor.test')).toBeInTheDocument()
    expect(screen.getByText('Authorised external destination')).toBeInTheDocument()
    expect(screen.getByText(/does not prove reports were sent/)).toBeInTheDocument()
  })

  it('renders the approved historical notice without current fields', () => {
    render(
      <DmarcPolicyEvidenceCard presentation={{
        schema: 'dmarc-policy-presentation.v1',
        status: 'legacy_snapshot',
        headline: 'Historical DMARC methodology',
        customer_message: 'This report preserves the DMARC methodology and conclusions used when the scan completed.',
      }} />,
    )

    expect(screen.getByText('Historical DMARC methodology')).toBeInTheDocument()
    expect(screen.getByText(/preserves the DMARC methodology/)).toBeInTheDocument()
    expect(screen.queryByText(/Effective requested policy/)).not.toBeInTheDocument()
  })

  it('renders integrity failure as unavailable rather than healthy or absent', () => {
    render(
      <DmarcPolicyEvidenceCard presentation={{
        schema: 'dmarc-policy-presentation.v1',
        status: 'integrity_error',
        headline: 'DMARC evidence unavailable',
        customer_message: 'Stored evidence did not pass its integrity contract. This is not a healthy or missing-record result.',
      }} />,
    )

    expect(screen.getByText('DMARC evidence unavailable')).toBeInTheDocument()
    expect(screen.getByText(/not a healthy or missing-record result/)).toBeInTheDocument()
  })
})
