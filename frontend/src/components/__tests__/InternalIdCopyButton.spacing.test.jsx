import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import InternalIdCopyButton from '../InternalIdCopyButton'
import { formatLocalDateTime } from '../../utils/dates'

// Founder live finding (24 Oct 2026): "blackbullbarbers.co.ukCopy ID".
describe('Copy ID has its own space', () => {
  it('is a separate small button with a gap, an icon and no wrap inside it', () => {
    render(<p><span>example.co.uk</span><InternalIdCopyButton id="scan_1" label="scan" /></p>)
    const button = screen.getByRole('button', { name: 'Copy scan ID' })
    expect(button).toHaveClass('ml-2', 'border', 'rounded-md', 'px-2', 'py-0.5', 'inline-flex', 'whitespace-nowrap', 'shrink-0')
    expect(button.querySelector('svg')).not.toBeNull()
    expect(button).toHaveTextContent(/^Copy ID$/)
    expect(button).toHaveAttribute('title', 'scan_1')
  })
})

describe('one customer time rule: local time, zone named', () => {
  it('reads "24 Oct 2026 at 01:34 BST" for 00:34 UTC in London', () => {
    expect(formatLocalDateTime('2026-10-24T00:34:00Z', '—', { timeZone: 'Europe/London' })).toBe('24 Oct 2026 at 01:34 BST')
    expect(formatLocalDateTime('2026-10-24 00:34:00', '—', { timeZone: 'UTC' })).toBe('24 Oct 2026 at 00:34 UTC')
    expect(formatLocalDateTime(null)).toBe('—')
  })
})
