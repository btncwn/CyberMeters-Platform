import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MailTransportCard } from '../MailTransportCard'

// 21 Oct 2026: a cancelled tenant's MX host read only "not tested". A host the
// scan proved does not exist (two resolvers, NXDOMAIN) says so plainly.
describe('MailTransportCard dead MX wording', () => {
  it('says mail cannot be delivered to an MX host that does not exist', () => {
    render(<MailTransportCard transport={{ hosts: [{ host: 'tenant.mail.protection.example.net', state: 'no_address', reason: 'mx_host_does_not_exist' }] }} />)
    expect(screen.getByText(/does not exist in public DNS, so mail sent to this domain cannot be delivered to it/)).toBeInTheDocument()
    expect(screen.queryByText(/Not tested/)).not.toBeInTheDocument()
  })

  it('keeps an unproven host as not tested', () => {
    render(<MailTransportCard transport={{ hosts: [{ host: 'mx.example.net', state: 'not_tested', reason: 'probe_unavailable' }] }} />)
    expect(screen.getByText(/Not tested — connection or TLS evidence unavailable/)).toBeInTheDocument()
  })
})
