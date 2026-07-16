import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import RiskBadge from '../RiskBadge'

// RiskBadge fell back to `?? 'badge-low'` for anything it did not recognise. The
// backend's honest 'unknown' — emitted for a workspace with no assessment at all —
// therefore rendered in low-risk blue, on 15 surfaces. A customer we knew nothing
// about looked exactly like a customer verified to be fine.
describe('RiskBadge — an unrecognised level is unknown, not low risk', () => {
  it.each([
    ['critical', 'badge-critical'],
    ['high', 'badge-high'],
    ['medium', 'badge-medium'],
    ['low', 'badge-low'],
  ])('renders the real band %s with its own class', (level, cls) => {
    render(<RiskBadge level={level} />)
    expect(screen.getByText(level)).toHaveClass(cls)
  })

  it('is case-insensitive for real bands', () => {
    render(<RiskBadge level="CRITICAL" />)
    expect(screen.getByText('CRITICAL')).toHaveClass('badge-critical')
  })

  // The defect, pinned.
  it("renders the backend's 'unknown' as unknown — NOT as low risk", () => {
    render(<RiskBadge level="unknown" />)
    const el = screen.getByText('unknown')
    expect(el).toHaveClass('badge-unknown')
    expect(el).not.toHaveClass('badge-low')
  })

  it.each(['nonsense', 'info', 'none', 'pending', 'not_assessed'])(
    'renders unrecognised level %s as unknown rather than claiming it is benign', (level) => {
      render(<RiskBadge level={level} />)
      const el = screen.getByText(level)
      expect(el).toHaveClass('badge-unknown')
      expect(el).not.toHaveClass('badge-low')
      expect(el).not.toHaveClass('badge-medium')
    })

  it.each([null, undefined, ''])('renders an em dash for %p', (level) => {
    const { container } = render(<RiskBadge level={level} />)
    expect(container.textContent).toBe('—')
  })

  // A non-string level used to throw on `.toLowerCase()`.
  it('does not throw on a non-string level', () => {
    expect(() => render(<RiskBadge level={42} />)).not.toThrow()
  })
})
