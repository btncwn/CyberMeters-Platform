import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { MailTransportCard } from '../MailTransportCard'

describe('MailTransportCard MTA-STS mode', () => {
  it('a policy with no recognised mode does not read as enforcement', () => {
    render(<MailTransportCard mtaSts={{ policy_found: true, mode: 'unknown' }} />)
    expect(screen.getByText('MTA-STS: policy observed, mode not recorded; DNS activation not separately checked.')).toBeInTheDocument()
  })
})
