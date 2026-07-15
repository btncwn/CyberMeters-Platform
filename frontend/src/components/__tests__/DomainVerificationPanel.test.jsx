import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import DomainVerificationPanel from '../DomainVerificationPanel'

const dns = {
  record_type: 'TXT',
  host: '_cybermeters.cybermeters.com',
  value: 'cybermeters-verification=abc123def456',
  ttl: 'Leave TTL on Auto (or 300 seconds). DNS changes usually apply within minutes, but can take up to 48 hours.',
  provider_path: 'Cloudflare: DNS → Records → Add record → TXT',
}

describe('DomainVerificationPanel shows the exact record to publish', () => {
  it('displays type, host, value and TTL guidance', () => {
    render(<DomainVerificationPanel domain="cybermeters.com" dns={dns} state="instructions" onVerify={() => {}} />)
    expect(screen.getByText('TXT')).toBeInTheDocument()
    expect(screen.getByText('_cybermeters.cybermeters.com')).toBeInTheDocument()
    expect(screen.getByText('cybermeters-verification=abc123def456')).toBeInTheDocument()
    expect(screen.getByText(/Leave TTL on Auto/)).toBeInTheDocument()
  })

  it('shows the Cloudflare navigation path', () => {
    render(<DomainVerificationPanel domain="cybermeters.com" dns={dns} state="instructions" onVerify={() => {}} />)
    expect(screen.getByText('Cloudflare: DNS → Records → Add record → TXT')).toBeInTheDocument()
  })

  it('offers Copy host and Copy value controls', () => {
    render(<DomainVerificationPanel domain="cybermeters.com" dns={dns} state="instructions" onVerify={() => {}} />)
    expect(screen.getByLabelText('Copy host')).toBeInTheDocument()
    expect(screen.getByLabelText('Copy value')).toBeInTheDocument()
  })

  it('copies the exact host and value to the clipboard', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.assign(navigator, { clipboard: { writeText } })
    render(<DomainVerificationPanel domain="cybermeters.com" dns={dns} state="instructions" onVerify={() => {}} />)
    await userEvent.click(screen.getByLabelText('Copy host'))
    expect(writeText).toHaveBeenCalledWith('_cybermeters.cybermeters.com')
    await userEvent.click(screen.getByLabelText('Copy value'))
    expect(writeText).toHaveBeenCalledWith('cybermeters-verification=abc123def456')
  })

  it('shows the verify action with the required wording', () => {
    render(<DomainVerificationPanel domain="cybermeters.com" dns={dns} state="instructions" onVerify={() => {}} />)
    expect(screen.getByRole('button', { name: /I.ve added the DNS record — Verify domain/i })).toBeInTheDocument()
  })

  it('invokes the canonical verify handler', async () => {
    const onVerify = vi.fn()
    render(<DomainVerificationPanel domain="cybermeters.com" dns={dns} state="instructions" onVerify={onVerify} />)
    await userEvent.click(screen.getByRole('button', { name: /Verify domain/i }))
    expect(onVerify).toHaveBeenCalledOnce()
  })
})

describe('never strands the customer', () => {
  it('keeps the record on screen when the check fails', () => {
    render(
      <DomainVerificationPanel
        domain="cybermeters.com" dns={dns} state="check_failed"
        note="We could not find that TXT record yet. DNS can take a few minutes to propagate — check the record below and try again."
        onVerify={() => {}}
      />,
    )
    // The instruction must survive the failure, or there is no way to finish.
    expect(screen.getByText('_cybermeters.cybermeters.com')).toBeInTheDocument()
    expect(screen.getByText('cybermeters-verification=abc123def456')).toBeInTheDocument()
    expect(screen.getByText(/could not find that TXT record yet/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Verify domain/i })).toBeEnabled()
  })

  it('keeps the record visible while checking, and disables the button', () => {
    render(<DomainVerificationPanel domain="cybermeters.com" dns={dns} state="checking" onVerify={() => {}} />)
    expect(screen.getByText('_cybermeters.cybermeters.com')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Checking DNS/i })).toBeDisabled()
  })

  it('never renders a raw machine code', () => {
    const { container } = render(
      <DomainVerificationPanel domain="cybermeters.com" dns={dns} state="check_failed"
        note="We could not find that TXT record yet." onVerify={() => {}} />,
    )
    expect(container.textContent).not.toMatch(/domain_verification_required/)
    expect(container.textContent).not.toMatch(/verification_failed/)
  })

  it('shows a preparing state before the token arrives, with no verify button', () => {
    render(<DomainVerificationPanel domain="cybermeters.com" dns={null} state="needs_setup" onVerify={() => {}} />)
    expect(screen.getByText(/Preparing your verification record/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Verify domain/i })).toBeNull()
  })
})

describe('verified state', () => {
  it('confirms ownership and stops asking for DNS', () => {
    render(<DomainVerificationPanel domain="cybermeters.com" dns={dns} state="verified" onVerify={() => {}} />)
    expect(screen.getByText('Domain ownership verified')).toBeInTheDocument()
    expect(screen.queryByText('_cybermeters.cybermeters.com')).toBeNull()
    expect(screen.queryByRole('button', { name: /Verify domain/i })).toBeNull()
  })
})
