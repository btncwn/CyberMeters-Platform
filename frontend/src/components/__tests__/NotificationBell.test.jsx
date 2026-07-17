import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Routes, Route, useLocation } from 'react-router-dom'
import NotificationBell from '../NotificationBell'
import { api } from '../../api'

// The regression this file protects: the list API returns metadata already
// parsed as `metadata` (and sets `metadata_json` undefined). The bell once read
// only `metadata_json`, so clicking a notification silently did nothing.
vi.mock('../../api', () => ({
  api: {
    getWorkspaceNotifications: vi.fn(),
    markNotificationRead: vi.fn().mockResolvedValue({}),
  },
}))

function LocationSpy() {
  const { pathname } = useLocation()
  return <div data-testid="pathname">{pathname}</div>
}

function renderBell() {
  return render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <Routes>
        <Route
          path="*"
          element={(
            <>
              <NotificationBell />
              <LocationSpy />
            </>
          )}
        />
      </Routes>
    </MemoryRouter>,
  )
}

function notification(overrides = {}) {
  return {
    id: 'n1',
    status: 'unread',
    severity: 'high',
    type: 'scan',
    title: 'Scan finished',
    message: 'Your scan completed with 3 findings.',
    created_at: new Date().toISOString(),
    ...overrides,
  }
}

async function openPanel(user) {
  // The bell toggle is the first button in the tree.
  await user.click(screen.getAllByRole('button')[0])
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.setItem('cybermeters_workspace_id', 'ws1')
})

describe('NotificationBell click-through', () => {
  it('navigates to the scan when the API returns parsed `metadata` (the fixed bug)', async () => {
    api.getWorkspaceNotifications.mockResolvedValue({
      notifications: [notification({ metadata: { scan_id: 'scan-123' }, metadata_json: undefined })],
      unread_count: 1,
    })
    const user = userEvent.setup()
    renderBell()
    await openPanel(user)
    await user.click(await screen.findByText('Scan finished'))

    await waitFor(() => expect(screen.getByTestId('pathname')).toHaveTextContent('/scans/scan-123'))
    expect(api.markNotificationRead).toHaveBeenCalledWith('ws1', 'n1')
  })

  it('still supports the legacy raw `metadata_json` string', async () => {
    api.getWorkspaceNotifications.mockResolvedValue({
      notifications: [notification({ metadata_json: JSON.stringify({ scan_id: 'scan-9' }) })],
      unread_count: 1,
    })
    const user = userEvent.setup()
    renderBell()
    await openPanel(user)
    await user.click(await screen.findByText('Scan finished'))

    await waitFor(() => expect(screen.getByTestId('pathname')).toHaveTextContent('/scans/scan-9'))
  })

  it('routes report notifications to /reports', async () => {
    api.getWorkspaceNotifications.mockResolvedValue({
      notifications: [notification({ metadata: { report_id: 'r1' } })],
      unread_count: 1,
    })
    const user = userEvent.setup()
    renderBell()
    await openPanel(user)
    await user.click(await screen.findByText('Scan finished'))

    await waitFor(() => expect(screen.getByTestId('pathname')).toHaveTextContent('/reports'))
  })

  it('routes lifecycle notifications using the canonical metadata link', async () => {
    api.getWorkspaceNotifications.mockResolvedValue({
      notifications: [notification({ metadata: { link: '/ws/website-security?condition=cond-1', domain_key: 'website_security' } })],
      unread_count: 1,
    })
    const user = userEvent.setup()
    renderBell()
    await openPanel(user)
    await user.click(await screen.findByText('Scan finished'))

    await waitFor(() => expect(screen.getByTestId('pathname')).toHaveTextContent('/ws/website-security'))
  })

  it('refuses external metadata links', async () => {
    api.getWorkspaceNotifications.mockResolvedValue({
      notifications: [notification({ metadata: { link: 'https://evil.example/ws/website-security' } })],
      unread_count: 1,
    })
    const user = userEvent.setup()
    renderBell()
    await openPanel(user)
    await user.click(await screen.findByText('Scan finished'))

    expect(screen.getByTestId('pathname')).toHaveTextContent('/dashboard')
    expect(api.markNotificationRead).toHaveBeenCalledWith('ws1', 'n1')
  })

  it('refuses protocol-relative metadata links', async () => {
    api.getWorkspaceNotifications.mockResolvedValue({
      notifications: [notification({ metadata: { link: '//evil.example/ws/website-security' } })],
      unread_count: 1,
    })
    const user = userEvent.setup()
    renderBell()
    await openPanel(user)
    await user.click(await screen.findByText('Scan finished'))

    expect(screen.getByTestId('pathname')).toHaveTextContent('/dashboard')
    expect(api.markNotificationRead).toHaveBeenCalledWith('ws1', 'n1')
  })

  it('stays put (no broken navigation) when a notification has no target', async () => {
    api.getWorkspaceNotifications.mockResolvedValue({
      notifications: [notification({ metadata: null })],
      unread_count: 1,
    })
    const user = userEvent.setup()
    renderBell()
    await openPanel(user)
    await user.click(await screen.findByText('Scan finished'))

    expect(screen.getByTestId('pathname')).toHaveTextContent('/dashboard')
    // Clicking still marks it read even without a click-through target.
    expect(api.markNotificationRead).toHaveBeenCalledWith('ws1', 'n1')
  })
})
