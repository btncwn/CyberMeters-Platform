import { render, screen } from '@testing-library/react'
import SafeBoundary from '../SafeBoundary'

function Boom() {
  throw new Error('widget exploded')
}

describe('SafeBoundary', () => {
  it('renders children when they are healthy', () => {
    render(
      <SafeBoundary>
        <p>sidebar content</p>
      </SafeBoundary>,
    )
    expect(screen.getByText('sidebar content')).toBeInTheDocument()
  })

  it('contains a throwing child and renders the fallback instead of crashing', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    render(
      <SafeBoundary fallback={<p>degraded</p>}>
        <Boom />
      </SafeBoundary>,
    )
    expect(screen.getByText('degraded')).toBeInTheDocument()
    spy.mockRestore()
  })

  it('defaults to rendering nothing (no raw error ever shown)', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const { container } = render(
      <SafeBoundary>
        <Boom />
      </SafeBoundary>,
    )
    expect(container).toBeEmptyDOMElement()
    expect(container.textContent).not.toContain('widget exploded')
    spy.mockRestore()
  })
})
