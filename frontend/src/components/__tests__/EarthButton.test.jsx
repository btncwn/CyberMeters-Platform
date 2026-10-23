import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import EarthButton, { notificationsLabel } from '../shell/EarthButton'
import { api } from '../../api'

// The globe in the top bar is the one notifications control: a real button
// at the account initial's 44px size (S1-SHELL-V2), "Notifications, N unread" as its name,
// an aqua unread label that disappears at zero, the existing panel opening
// beneath it, Escape closing it with focus back on the globe.

vi.mock('../../api', () => ({
  api: { getWorkspaceNotifications: vi.fn(), markNotificationRead: vi.fn().mockResolvedValue({}) },
}))

function fakeFrameContext() {
  return {
    createImageData: (w, h) => ({ data: new Uint8ClampedArray(w * h * 4), width: w, height: h }),
    putImageData() {},
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

const renderGlobe = () => render(<MemoryRouter><EarthButton /></MemoryRouter>)
const rows = (n) => Array.from({ length: n }, (_, i) => ({ id: `n${i}`, type: 'scan_completed', severity: 'info', title: `Notification ${i}`, message: 'm', status: i % 2 ? 'read' : 'unread', created_at: '2026-10-16T09:00:00Z' }))

describe('notificationsLabel', () => {
  it('reads "Notifications, 12 unread" and plain "Notifications" at zero', () => {
    expect(notificationsLabel(12)).toBe('Notifications, 12 unread')
    expect(notificationsLabel(0)).toBe('Notifications')
    expect(notificationsLabel(undefined)).toBe('Notifications')
  })
})

describe('<EarthButton>', () => {
  it('is a 44px button with an aria-hidden canvas; without a workspace it is inert and shows no label', () => {
    renderGlobe()
    const globe = screen.getByRole('button', { name: 'Notifications' })
    expect(globe.tagName).toBe('BUTTON')
    expect(globe).toHaveClass('cm-earthbtn')
    expect(globe).toHaveStyle({ width: '44px', height: '44px' })
    expect(globe).toHaveAttribute('aria-expanded', 'false')
    expect(globe.querySelector('canvas')).toHaveAttribute('aria-hidden', 'true')
    expect(screen.queryByTestId('earth-unread')).not.toBeInTheDocument()
    fireEvent.click(globe)
    expect(screen.queryByRole('dialog', { name: 'Notifications' })).not.toBeInTheDocument()
  })

  it('names the unread count, shows the aqua label (capped at 99+), and opens the panel beneath it', async () => {
    localStorage.setItem('cybermeters_workspace_id', 'ws1')
    api.getWorkspaceNotifications.mockResolvedValue({ unread_count: 12, notifications: rows(5) })
    renderGlobe()
    const globe = await screen.findByRole('button', { name: 'Notifications, 12 unread' })
    expect(screen.getByTestId('earth-unread')).toHaveTextContent('12')
    expect(screen.getByTestId('earth-unread')).toHaveClass('cm-earth-count')
    fireEvent.click(globe)
    expect(globe).toHaveAttribute('aria-expanded', 'true')
    const panel = screen.getByRole('dialog', { name: 'Notifications' })
    expect(panel).toHaveClass('cm-notif')
    expect(globe).toHaveAttribute('aria-controls', panel.id)
    expect(screen.getByRole('button', { name: 'Mark all read' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'See all activity →' })).toBeInTheDocument()
  })

  it('caps the label at 99+ and hides it once everything is read', async () => {
    localStorage.setItem('cybermeters_workspace_id', 'ws1')
    api.getWorkspaceNotifications.mockResolvedValue({ unread_count: 120, notifications: rows(5) })
    renderGlobe()
    await screen.findByRole('button', { name: 'Notifications, 120 unread' })
    expect(screen.getByTestId('earth-unread')).toHaveTextContent('99+')
    fireEvent.click(screen.getByTestId('shell-earth'))
    fireEvent.click(screen.getByRole('button', { name: 'Mark all read' }))
    await waitFor(() => expect(screen.queryByTestId('earth-unread')).not.toBeInTheDocument())
    expect(screen.getByRole('button', { name: 'Notifications' })).toBeInTheDocument()
  })

  it('Escape closes the panel and returns focus to the globe; an outside click closes it too', async () => {
    localStorage.setItem('cybermeters_workspace_id', 'ws1')
    api.getWorkspaceNotifications.mockResolvedValue({ unread_count: 0, notifications: [] })
    renderGlobe()
    const globe = await screen.findByRole('button', { name: 'Notifications' })
    fireEvent.click(globe)
    expect(screen.getByRole('dialog', { name: 'Notifications' })).toBeInTheDocument()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('dialog', { name: 'Notifications' })).not.toBeInTheDocument()
    expect(document.activeElement).toBe(globe)
    fireEvent.click(globe)
    fireEvent.mouseDown(document.body)
    expect(screen.queryByRole('dialog', { name: 'Notifications' })).not.toBeInTheDocument()
  })

  it('animates when motion is allowed, draws one still frame under reduced motion, and survives a missing 2D context', () => {
    renderGlobe()
    expect(raf).toHaveBeenCalled()
    raf.mockClear()
    window.matchMedia = vi.fn().mockReturnValue({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() })
    const { unmount } = renderGlobe()
    expect(raf).not.toHaveBeenCalled()
    unmount()
    getContext.mockImplementation(() => null)
    expect(() => renderGlobe()).not.toThrow()
  })
})
