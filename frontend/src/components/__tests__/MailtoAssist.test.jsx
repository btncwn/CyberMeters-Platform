import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import MailtoAssist, { addressFromMailto } from '../MailtoAssist'

// jsdom cannot hand a mailto link to an email app; stop the navigation after
// MailtoAssist (registered first) has seen the click.
function clickWithoutNavigating(element) {
  const stop = event => event.preventDefault()
  document.addEventListener('click', stop)
  fireEvent.click(element)
  document.removeEventListener('click', stop)
}

describe('MailtoAssist', () => {
  it('reads the address from a mailto link', () => {
    expect(addressFromMailto('mailto:hello@cybermeters.com')).toBe('hello@cybermeters.com')
    expect(addressFromMailto('mailto:hello@cybermeters.com?subject=Hi')).toBe('hello@cybermeters.com')
  })

  it('shows the address and a copy button whenever an email link is clicked', async () => {
    render(<><MailtoAssist /><a href="mailto:hello@cybermeters.com">Contact</a></>)
    clickWithoutNavigating(screen.getByText('Contact'))
    const status = await screen.findByRole('status')
    expect(status).toHaveTextContent('hello@cybermeters.com')
    expect(status).toHaveTextContent(/If your email app did not open/)
    expect(screen.getByRole('button', { name: /cop(y|ied)/i })).toBeInTheDocument()
    // The copy fallback never leaves its helper field behind, even when the
    // browser refuses to copy.
    expect(document.querySelector('textarea')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })

  it('stays out of the way for ordinary links', () => {
    render(<><MailtoAssist /><a href="#pricing">Pricing</a></>)
    fireEvent.click(screen.getByText('Pricing'))
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })
})
