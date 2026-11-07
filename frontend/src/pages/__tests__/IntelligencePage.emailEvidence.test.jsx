import React from 'react'
import { render, screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { EmailIntelSection } from '../IntelligencePage'

const observed = () => ({
  evidence_publishable: true,
  spf: { status: 'PASS', record: 'v=spf1 -all', issue: '' },
  dmarc: { status: 'FULLY_PROTECTED', policy: 'reject', message: 'Observed reject policy' },
  dkim: { status: 'VERIFIED', selector: 'selector1' },
  mta_sts: { enabled: true },
  tls_rpt: { enabled: true, observation_state: 'present' },
})

function renderEmail(intel, dmarcPresentation = null) {
  render(<EmailIntelSection intel={intel} dmarcPresentation={dmarcPresentation} />)
  const card = screen.getByRole('heading', { name: 'Email Security Intelligence' }).closest('.card')
  expect(card).not.toBeNull()
  return within(card)
}

describe('Intelligence page probe-specific email evidence', () => {
  it('does not publish absence or failed-verification labels for explicitly unavailable probes', async () => {
    const intel = observed()
    intel.spf = { status: 'MISSING', record: null, issue: 'No SPF record found.', observation_unavailable: true }
    intel.dmarc = { status: 'MISSING', policy: 'none', message: 'Publish a DMARC record', observation_unavailable: true }
    intel.dkim = { status: 'NOT_VERIFIED', observation_unavailable: true }
    const card = await renderEmail(intel)
    expect(card.getAllByText('Not assessed')).toHaveLength(3)
    for (const label of card.getAllByText('Not assessed')) {
      expect(label).toHaveClass('text-gray-500')
      expect(label).not.toHaveClass('text-red-700')
    }
    expect(card.queryByText('MISSING')).not.toBeInTheDocument()
    expect(card.queryByText('Not verified')).not.toBeInTheDocument()
    expect(card.queryByText('No SPF record found.')).not.toBeInTheDocument()
    expect(card.queryByText(/Legacy exact p/)).not.toBeInTheDocument()
    expect(card.queryByText('Publish a DMARC record')).not.toBeInTheDocument()
    expect(card.getByText('SPF observation was unavailable in this scan.')).toBeInTheDocument()
    expect(card.getByText('DMARC observation was unavailable in this scan.')).toBeInTheDocument()
  })

  for (const probe of ['spf', 'dmarc', 'dkim']) {
    it(`lets the explicit unavailable flag bound a contradictory positive ${probe} row`, async () => {
      const intel = observed()
      intel[probe].observation_unavailable = true
      const card = await renderEmail(intel)
      expect(card.getAllByText('Not assessed')).toHaveLength(1)
      const staleLabel = { spf: 'PASS', dmarc: 'FULLY PROTECTED', dkim: 'Verified' }[probe]
      expect(card.queryByText(staleLabel)).not.toBeInTheDocument()
      if (probe === 'spf') expect(card.queryByText('v=spf1 -all')).not.toBeInTheDocument()
      if (probe === 'dmarc') expect(card.queryByText(/Legacy exact p/)).not.toBeInTheDocument()
    })
  }

  for (const flag of [undefined, false]) {
    it(`preserves genuinely observed absence with unavailable=${flag}`, async () => {
      const intel = observed()
      intel.spf = { status: 'MISSING', issue: 'No SPF record found.', observation_unavailable: flag }
      intel.dmarc = { status: 'MISSING', message: 'Observed no DMARC record', observation_unavailable: flag }
      intel.dkim = { status: 'NOT_VERIFIED', observation_unavailable: flag }
      const card = await renderEmail(intel)
      expect(card.getAllByText('MISSING')).toHaveLength(2)
      expect(card.getByText('Not verified')).toBeInTheDocument()
      expect(card.getByText('No SPF record found.')).toBeInTheDocument()
      expect(card.getByText('Observed no DMARC record')).toBeInTheDocument()
      expect(card.queryByText('Not assessed')).not.toBeInTheDocument()
    })
  }

  it('preserves observed records and verified DKIM', async () => {
    const card = await renderEmail(observed())
    expect(card.getByText('PASS')).toBeInTheDocument()
    expect(card.getByText('v=spf1 -all')).toBeInTheDocument()
    expect(card.getByText('FULLY PROTECTED')).toBeInTheDocument()
    expect(card.getByText('Verified')).toBeInTheDocument()
    expect(card.queryByText('Not assessed')).not.toBeInTheDocument()
  })

  it('keeps the independent canonical DMARC presentation intact', async () => {
    const intel = observed()
    intel.dmarc = { status: 'MISSING', message: 'Legacy missing label', observation_unavailable: true }
    const card = await renderEmail(intel, {
      status: 'historical', headline: 'Independent canonical methodology notice',
      customer_message: 'Recorded canonical policy evidence remains visible.',
    })
    expect(card.getByText('Independent canonical methodology notice')).toBeInTheDocument()
    expect(card.getByText('Recorded canonical policy evidence remains visible.')).toBeInTheDocument()
    expect(card.getByText('Not assessed')).toBeInTheDocument()
    expect(card.queryByText('Legacy missing label')).not.toBeInTheDocument()
  })

  it('retains the whole-module publishability gate', async () => {
    const intel = observed()
    intel.evidence_publishable = false
    const card = await renderEmail(intel)
    expect(card.getByText('No email intelligence data')).toBeInTheDocument()
    expect(card.queryByText('PASS')).not.toBeInTheDocument()
    expect(card.queryByText('MISSING')).not.toBeInTheDocument()
  })
})
