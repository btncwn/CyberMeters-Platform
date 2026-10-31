import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { buildScanReportPdf } from '../../../../workers/scan-api/src/engines/pdf.js'
import { MailTransportCard } from '../MailTransportCard'

// MTA-STS and TLS-RPT through the real PDF renderer: the report states what the
// scan recorded, in the card's words. The immutable snapshot does not carry these
// details; they come from the stored report the snapshot points at
// (read.customerModules).

function snapshot() {
  return {
    snapshot: { snapshot_id: 'snap_example', domain: 'mail.example.test', scan_id: 'scan_example', as_of: '2026-07-25T20:00:00.000Z', built_at: '2026-07-25T20:00:01.000Z', provenance: 'scan_finalize' },
    methodology: {},
    overall: {
      cyber_metrics_score: null,
      score_band: null,
      assessment: { provisional: true, comparable: false, quality: 'partial', message: 'Example.' },
      business_risk_indicator: {},
      summary: 'Example.',
      evidence_completeness: {},
    },
    domains: [],
    observed_findings: [],
    observations: [],
    remediation_actions: [],
    monitoring_states: {},
    limitations: [],
  }
}

const renderBytes = (modules, snap = snapshot()) => buildScanReportPdf(
  { id: 'scan_example', domain: 'mail.example.test' },
  { snapshot: snap, customerSnapshot: snap, customerModules: modules, dmarcPolicy: null },
)

// The writer wraps long lines, so assertions read the text operators joined.
const pdfText = (modules) => [...new TextDecoder().decode(renderBytes(modules)).matchAll(/\(((?:\\.|[^\\)])*)\) Tj/g)]
  .map((match) => match[1].replace(/\\([()\\])/g, '$1'))
  .join(' ')

const email = (mtaSts, tlsRpt) => ({ email_security: { mta_sts_detail: mtaSts, tls_rpt_detail: tlsRpt } })

describe('technical PDF mail transport records', () => {
  it.each([
    ['enforce', { policy_found: true, mode: 'enforce' }, 'MTA-STS: enforce policy observed; DNS activation not separately checked.'],
    ['testing', { policy_found: true, mode: 'testing' }, 'MTA-STS: testing policy observed; DNS activation not separately checked.'],
    ['absent', { policy_found: false, observation_state: 'definitive_absent' }, 'MTA-STS: enforcement not confirmed; no policy file was confirmed.'],
    ['unknown', { policy_found: null, observation_state: 'unavailable' }, 'MTA-STS: enforcement not confirmed; the check did not conclude.'],
    ['not recorded', undefined, 'MTA-STS: enforcement not confirmed; not recorded for this check.'],
  ])('MTA-STS %s reads the same in the PDF and on the card', (_name, detail, line) => {
    expect(pdfText(email(detail, undefined))).toContain(line)
    render(<MailTransportCard mtaSts={detail} />)
    expect(screen.getByText(line)).toBeInTheDocument()
  })

  it.each([
    ['present', { record_found: true, observation_state: 'present' }, 'TLS-RPT: reporting record observed in DNS; this does not show that TLS reports were received.'],
    ['absent', { record_found: false, observation_state: 'definitive_absent' }, 'TLS-RPT: reporting record not found.'],
    ['older false', { record_found: false }, 'TLS-RPT: reporting record not confirmed.'],
    ['unknown', { record_found: null, observation_state: 'unavailable' }, 'TLS-RPT: reporting record not confirmed; the lookup did not conclude.'],
    ['not recorded', undefined, 'TLS-RPT: reporting record not confirmed; not recorded for this check.'],
  ])('TLS-RPT %s reads the same in the PDF and on the card', (_name, detail, line) => {
    expect(pdfText(email(undefined, detail))).toContain(line)
    render(<MailTransportCard tlsRpt={detail} />)
    expect(screen.getByText(line)).toBeInTheDocument()
  })

  it('an unconcluded check never reads as absent', () => {
    const text = pdfText(email({ policy_found: null }, { record_found: null }))
    expect(text).not.toContain('no policy file was confirmed')
    expect(text).not.toContain('reporting record not found')
  })

  it('a report whose source could not be read says the details were not recorded', () => {
    const text = pdfText({})
    expect(text).toContain('Mail transport records  .....')
    expect(text).toContain('MTA-STS: enforcement not confirmed; not recorded for this check.')
  })

  it('leaves the snapshot unchanged and renders the same bytes twice', () => {
    const frozen = snapshot()
    const before = JSON.stringify(frozen)
    const modules = email({ policy_found: true, mode: 'enforce' }, { record_found: true })
    const first = renderBytes(modules, frozen)
    expect(JSON.stringify(frozen)).toBe(before)
    expect(Buffer.compare(Buffer.from(first), Buffer.from(renderBytes(modules, frozen)))).toBe(0)
  })
})
