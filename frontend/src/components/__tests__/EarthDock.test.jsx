import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import EarthDock from '../shell/EarthDock'
import { api } from '../../api'

// The globe is the notifications control: it carries the unread counter, the
// panel grows out of it, Mark all read and See all activity go to the existing
// routes, and the dock never takes pointer events outside the globe.

vi.mock('../../api', () => ({
  api: { getWorkspaceNotifications: vi.fn(), markNotificationRead: vi.fn().mockResolvedValue({}) },
}))

function fakeFrameContext() {
  return {
    createImageData: (w, h) => ({ data: new Uint8ClampedArray(w * h * 4), width: w, height: h }),
    putImageData() {},
    // texture painting (the scratch canvas shares this prototype in jsdom)
    fillStyle: '', strokeStyle: '', lineWidth: 0, lineJoin: '', globalCompositeOperation: '',
    createLinearGradient: () => ({ addColorStop() {} }), createRadialGradient: () => ({ addColorStop() {} }),
    fillRect() {}, beginPath() {}, moveTo() {}, lineTo() {}, closePath() {}, fill() {}, stroke() {}, drawImage() {},
    getImageData: (x, y, w, h) => ({ data: new Uint8ClampedArray(w * h * 4) }),
  }
}

let raf, caf, getContext
beforeEach(() => {
  localStorage.clear()
  vi.clearAllMocks()
  raf = vi.spyOn(window, 'requestAnimationFrame').mockImplementation(() => 1)
  caf = vi.spyOn(window, 'cancelAnimationFrame').mockImplementation(() => {})
  getContext = vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockImplementation(() => fakeFrameContext())
  window.matchMedia = vi.fn().mockReturnValue({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() })
})
afterEach(() => { raf.mockRestore(); caf.mockRestore(); getContext.mockRestore() })

const renderDock = (props) => render(<MemoryRouter><EarthDock {...props} /></MemoryRouter>)

describe('<EarthDock>', () => {
  it('without a workspace it is an inert globe: no counter, nothing opens', () => {
    renderDock()
    const globe = screen.getByRole('button', { name: 'Notifications' })
    expect(globe.tagName).toBe('CANVAS')
    expect(globe).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByTestId('earth-unread')).not.toBeInTheDocument()
    fireEvent.click(globe)
    expect(screen.queryByRole('dialog', { name: 'Notifications' })).not.toBeInTheDocument()
    expect(screen.getByTestId('earth-dock')).toHaveStyle({ width: '108px', height: '108px' })
  })

  it('is 88px for a phone caller', () => {
    renderDock({ phone: true })
    expect(screen.getByTestId('earth-dock')).toHaveStyle({ width: '88px', height: '88px' })
  })

  it('shows the unread counter on the globe and opens the panel from it, with Mark all read and See all activity', async () => {
    localStorage.setItem('cybermeters_workspace_id', 'ws1')
    api.getWorkspaceNotifications.mockResolvedValue({
      unread_count: 3,
      notifications: [
        { id: 'n1', status: 'unread', severity: 'medium', type: 'dmarc', title: 'DMARC moved to p=quarantine', message: 'Hosted record updated.', created_at: new Date().toISOString(), metadata: { domain_key: 'email_protection' } },
      ],
    })
    renderDock()
    const globe = await screen.findByRole('button', { name: 'Notifications (3 unread)' })
    expect(screen.getByTestId('earth-unread')).toHaveTextContent('3')
    expect(globe).toHaveAttribute('aria-haspopup', 'dialog')
    fireEvent.click(globe)
    const panel = screen.getByRole('dialog', { name: 'Notifications' })
    expect(globe).toHaveAttribute('aria-expanded', 'true')
    expect(globe).toHaveAttribute('aria-controls', panel.id)
    expect(panel.className).toContain('cm-notif')
    expect(await screen.findByText('DMARC moved to p=quarantine')).toBeInTheDocument()
    expect(screen.getByText('Email Protection')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Mark all read' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'See all activity →' })).toHaveAttribute('href', '/notifications')
    fireEvent.click(screen.getByRole('button', { name: 'Mark all read' }))
    await waitFor(() => expect(api.markNotificationRead).toHaveBeenCalledWith('ws1', 'all'))
    await waitFor(() => expect(screen.queryByTestId('earth-unread')).not.toBeInTheDocument())
  })

  it('opens from the keyboard (Enter and Space) and closes on an outside click', async () => {
    localStorage.setItem('cybermeters_workspace_id', 'ws1')
    api.getWorkspaceNotifications.mockResolvedValue({ unread_count: 0, notifications: [] })
    renderDock()
    const globe = await screen.findByRole('button', { name: 'Notifications' })
    fireEvent.keyDown(globe, { key: 'Enter' })
    expect(screen.getByRole('dialog', { name: 'Notifications' })).toBeInTheDocument()
    fireEvent.mouseDown(document.body)
    expect(screen.queryByRole('dialog', { name: 'Notifications' })).not.toBeInTheDocument()
    fireEvent.keyDown(globe, { key: ' ' })
    expect(screen.getByRole('dialog', { name: 'Notifications' })).toBeInTheDocument()
  })

  it('animates when motion is allowed, draws one still frame under reduced motion, and survives a missing 2D context', () => {
    renderDock()
    expect(raf).toHaveBeenCalled()
    raf.mockClear()
    window.matchMedia = vi.fn().mockReturnValue({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() })
    const { unmount } = renderDock()
    expect(raf).not.toHaveBeenCalled()
    unmount()
    getContext.mockImplementation(() => null)
    expect(() => renderDock()).not.toThrow()
  })
})
