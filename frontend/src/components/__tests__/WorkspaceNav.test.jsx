import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import WorkspaceNav from '../WorkspaceNav'

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
    // THEME.email.text — the glacier-blue identity of Email Protection.
    expect(screen.getByText('DMARC Setup')).toHaveStyle({ color: '#1A4FB8' })
  })
})
