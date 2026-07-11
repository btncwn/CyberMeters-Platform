import { render, screen } from '@testing-library/react'
import StatusBadge from '../StatusBadge'

describe('StatusBadge', () => {
  it.each([
    ['queued', 'Queued'],
    ['running', 'Running'],
    ['processing', 'Processing'],
    ['completed', 'Completed'],
    ['failed', 'Failed'],
    ['error', 'Error'],
  ])('renders %s as %s', (status, label) => {
    render(<StatusBadge status={status} />)
    expect(screen.getByText(label)).toBeInTheDocument()
  })

  it('handles case-insensitive and unknown statuses', () => {
    const { rerender } = render(<StatusBadge status="COMPLETED" />)
    expect(screen.getByText('Completed')).toBeInTheDocument()

    rerender(<StatusBadge status="paused" />)
    expect(screen.getByText('Unknown')).toBeInTheDocument()
  })
})
