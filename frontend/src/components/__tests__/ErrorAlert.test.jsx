import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import ErrorAlert from '../ErrorAlert'

describe('ErrorAlert', () => {
  it('renders a customer-safe title and message', () => {
    render(<ErrorAlert title="Could not load workspace" message="Try again in a moment." />)

    expect(screen.getByText('Could not load workspace')).toBeInTheDocument()
    expect(screen.getByText('Try again in a moment.')).toBeInTheDocument()
  })

  it('omits the message block when no message is provided', () => {
    render(<ErrorAlert title="Could not load workspace" />)

    expect(screen.getByText('Could not load workspace')).toBeInTheDocument()
    expect(screen.queryByText(/try again/i)).not.toBeInTheDocument()
  })

  it('calls the retry handler with custom retry copy', async () => {
    const onRetry = vi.fn()
    const user = userEvent.setup()
    render(<ErrorAlert message="Temporary problem" onRetry={onRetry} retryLabel="Reload" />)

    await user.click(screen.getByRole('button', { name: 'Reload' }))

    expect(onRetry).toHaveBeenCalledTimes(1)
  })
})
