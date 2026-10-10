import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import WebsiteResponseEvidence from '../WebsiteResponseEvidence'

describe('WebsiteResponseEvidence', () => {
  it('shows captured evidence without cookies, credentials or query tokens', () => {
    const { container } = render(<WebsiteResponseEvidence headers={{ checked_paths: [{
      status: 'ok', requested_url: 'https://user:password@example.com/login?token=secret#private',
      final_url: 'https://example.com/login?session=secret', status_code: 200,
      headers_observed: { 'strict-transport-security': 'max-age=31536000', 'set-cookie': 'session=secret', authorization: 'Bearer secret' },
    }] }} />)
    expect(screen.getByText('max-age=31536000')).toBeInTheDocument()
    expect(screen.getByText('Result: ok · HTTP 200')).toBeInTheDocument()
    expect(container.textContent).not.toMatch(/secret|password|Bearer|set-cookie/)
    expect(container.querySelector('details')).not.toHaveAttribute('open')
  })
  it('does not call unavailable checks missing headers or clean', () => {
    render(<WebsiteResponseEvidence headers={{ checked_paths: [{ requested_url: 'https://example.com', status: 'not_executed', headers_observed: { 'content-security-policy': null } }] }} />)
    expect(screen.getByText('Result: not executed')).toBeInTheDocument()
    expect(screen.queryByText('content-security-policy')).toBeNull()
    expect(screen.queryByText(/missing|clean/i)).toBeNull()
  })
  it('does not manufacture request evidence for an old report', () => {
    render(<WebsiteResponseEvidence headers={{}} />)
    expect(screen.getByText(/Per-request evidence was not recorded/)).toBeInTheDocument()
  })
})
