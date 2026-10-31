import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { MailTransportCard } from '../MailTransportCard'

describe('MailTransportCard MTA-STS and TLS-RPT lines', () => {
  it.each([
    [{ policy_found: true, mode: 'enforce' }, 'MTA-STS: enforce policy observed; DNS activation not separately checked.'],
    [{ policy_found: true, mode: 'testing' }, 'MTA-STS: testing policy observed; DNS activation not separately checked.'],
    [{ policy_found: true, mode: 'unknown' }, 'MTA-STS: policy observed, mode not recorded; DNS activation not separately checked.'],
    [{ policy_found: false }, 'MTA-STS: enforcement not confirmed; no policy file was confirmed.'],
    [{ policy_found: null }, 'MTA-STS: enforcement not confirmed; the check did not conclude.'],
    [undefined, 'MTA-STS: enforcement not confirmed; not recorded for this check.'],
  ])('MTA-STS %j', (mtaSts, line) => {
    render(<MailTransportCard mtaSts={mtaSts} />)
    expect(screen.getByText(line)).toBeInTheDocument()
  })

  it.each([
    [{ record_found: true }, 'TLS-RPT: reporting record observed in DNS; this does not show that TLS reports were received.'],
    [{ record_found: false, observation_state: 'definitive_absent' }, 'TLS-RPT: reporting record not found.'],
    [{ record_found: false }, 'TLS-RPT: reporting record not confirmed.'],
    [{ record_found: null, observation_state: 'unavailable' }, 'TLS-RPT: reporting record not confirmed; the lookup did not conclude.'],
    [undefined, 'TLS-RPT: reporting record not confirmed; not recorded for this check.'],
  ])('TLS-RPT %j', (tlsRpt, line) => {
    render(<MailTransportCard tlsRpt={tlsRpt} />)
    expect(screen.getByText(line)).toBeInTheDocument()
  })
})
