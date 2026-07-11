import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import WorkspaceNav from '../WorkspaceNav'
import { SERVICE_COLORS } from '../../theme/serviceColors'

// Small helper: jsdom reports colours as rgb(), so compare hex → rgb.
function hexToRgb(hex) {
  const n = parseInt(hex.slice(1), 16)
  return `rgb(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255})`
}

// Keep the test hermetic: hovering/clicking nav entries must not actually
// dynamic-import route modules.
vi.mock('../../utils/preload', () => ({ preloadComponent: vi.fn() }))
vi.mock('../../utils/preloadMap', () => ({ routePreloadMap: {} }))

function renderNav(path = '/ws/email-protection') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <WorkspaceNav wsName="Deneme" />
    </MemoryRouter>,
  )
}

describe('WorkspaceNav (four-service sidebar)', () => {
  it('shows exactly the four services', () => {
    renderNav()
    expect(screen.getByText('Email Protection')).toBeInTheDocument()
    expect(screen.getByText('Brand Protection')).toBeInTheDocument()
    expect(screen.getByText('Attack Surface')).toBeInTheDocument()
    expect(screen.getByText('Certificates & Trust')).toBeInTheDocument()
  })

  it('expands only the active service — no cross-service sub-item mixing', () => {
    renderNav('/ws/email-protection')
    expect(screen.getByText('DMARC Setup')).toBeInTheDocument()
    // Brand's sub-items must not leak into an Email context.
    expect(screen.queryByText('Typosquat Candidates')).not.toBeInTheDocument()
  })

  it('accordion: clicking the open service collapses its sub-items (the fixed bug)', () => {
    renderNav('/ws/email-protection')
    expect(screen.getByText('DMARC Setup')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Email Protection'))
    expect(screen.queryByText('DMARC Setup')).not.toBeInTheDocument()
    // …and clicking again reopens it.
    fireEvent.click(screen.getByText('Email Protection'))
    expect(screen.getByText('DMARC Setup')).toBeInTheDocument()
  })

  it('switching service moves the accordion: Brand opens, Email closes', () => {
    renderNav('/ws/email-protection')
    fireEvent.click(screen.getByText('Brand Protection'))
    expect(screen.getByText('Typosquat Candidates')).toBeInTheDocument()
    expect(screen.queryByText('DMARC Setup')).not.toBeInTheDocument()
  })

  it('sub-items inherit their parent service colour', () => {
    renderNav('/ws/email-protection')
    // Derives from the shared palette, so re-theming Email can never silently
    // desync this assertion from the sidebar again.
    expect(screen.getByText('DMARC Setup')).toHaveStyle({ color: hexToRgb(SERVICE_COLORS.email.text) })
  })
})
