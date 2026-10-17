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

  it('shows a completed run whose checks did not all complete as partial results, never as completed', () => {
    const { rerender } = render(<StatusBadge status="completed" quality="partial" />)
    expect(screen.getByText('Partial results')).toBeInTheDocument()
    expect(screen.queryByText('Completed')).toBeNull()
    rerender(<StatusBadge status="completed" quality="degraded" />)
    expect(screen.getByText('Partial results')).toBeInTheDocument()
    rerender(<StatusBadge status="completed" quality="complete" />)
    expect(screen.getByText('Completed')).toBeInTheDocument()
    // Quality only qualifies a completed run; it never relabels a failure.
    rerender(<StatusBadge status="failed" quality="partial" />)
    expect(screen.getByText('Failed')).toBeInTheDocument()
  })

  it('never breaks onto two lines', () => {
    render(<StatusBadge status="completed" quality="partial" />)
    expect(screen.getByText('Partial results')).toHaveClass('whitespace-nowrap')
  })

  it('handles case-insensitive and unknown statuses', () => {
    const { rerender } = render(<StatusBadge status="COMPLETED" />)
    expect(screen.getByText('Completed')).toBeInTheDocument()

    rerender(<StatusBadge status="paused" />)
    expect(screen.getByText('Unknown')).toBeInTheDocument()
  })
})
