import { act, render, screen, waitFor, within } from '@testing-library/react'
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

const EMPTY_RESULT = {
  notifications: [],
  unread_count: 0,
}

function bellResult(title, overrides = {}) {
  return {
    notifications: [notification({
      id: `n-${title.toLowerCase().replaceAll(' ', '-')}`,
      title,
    })],
    unread_count: 1,
    ...overrides,
  }
}

function deferred() {
  let resolve
  let reject
  const promise = new Promise((next, fail) => {
    resolve = next
    reject = fail
  })
  return { promise, resolve, reject }
}

async function resolveRequest(request, value) {
  await act(async () => {
    request.resolve(value)
    await request.promise
  })
}

async function rejectRequest(request, message) {
  await act(async () => {
    request.reject(new Error(message))
    await request.promise.catch(() => {})
  })
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

describe('NotificationBell failure truth', () => {
  it('shows an accessible first-load failure with Retry instead of an empty state', async () => {
    api.getWorkspaceNotifications.mockRejectedValue(new Error('offline'))
    const user = userEvent.setup()

    renderBell()
    await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalled())
    await openPanel(user)

    expect(await screen.findByRole('alert')).toHaveTextContent(/couldn.t load notifications/i)
    expect(screen.queryByText('No notifications yet.')).not.toBeInTheDocument()

    const callsBeforeRetry = api.getWorkspaceNotifications.mock.calls.length
    await user.click(screen.getByRole('button', { name: 'Retry' }))

    await waitFor(() => {
      expect(api.getWorkspaceNotifications.mock.calls.length).toBeGreaterThan(callsBeforeRetry)
    })
    expect(api.getWorkspaceNotifications).toHaveBeenLastCalledWith('ws1', { limit: 30 })
  })

  it('surfaces a polling failure while preserving the last-known rows and unread badge', async () => {
    let runPoll
    const intervalSpy = vi.spyOn(globalThis, 'setInterval').mockImplementation((fn, delay) => {
      if (delay === 60_000) runPoll = fn
      return 73
    })
    const clearIntervalSpy = vi.spyOn(globalThis, 'clearInterval').mockImplementation(() => {})
    api.getWorkspaceNotifications.mockResolvedValue({
      notifications: [notification({ title: 'Last known bell row' })],
      unread_count: 1,
    })
    const user = userEvent.setup()

    try {
      const view = renderBell()
      await openPanel(user)
      expect(await screen.findByText('Last known bell row')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Notifications (1 unread)' })).toBeInTheDocument()
      expect(runPoll).toBeTypeOf('function')

      api.getWorkspaceNotifications.mockRejectedValue(new Error('poll failed'))
      await act(async () => { await runPoll() })

      expect(await screen.findByRole('alert')).toHaveTextContent(/showing the last known/i)
      expect(screen.getByText('Last known bell row')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Notifications (1 unread)' })).toBeInTheDocument()
      expect(screen.queryByText('No notifications yet.')).not.toBeInTheDocument()

      view.unmount()
    } finally {
      intervalSpy.mockRestore()
      clearIntervalSpy.mockRestore()
    }
  })

  it('keeps mark-read failure recovery through a silent reload', async () => {
    api.getWorkspaceNotifications.mockResolvedValue({
      notifications: [notification({ title: 'Recoverable bell row' })],
      unread_count: 1,
    })
    api.markNotificationRead.mockRejectedValueOnce(new Error('mark failed'))
    const user = userEvent.setup()

    renderBell()
    await openPanel(user)
    await screen.findByText('Recoverable bell row')
    await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(2))

    await user.click(screen.getByTitle('Mark as read'))

    expect(api.markNotificationRead).toHaveBeenCalledWith('ws1', 'n1')
    await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(3))
    expect(screen.getByRole('button', { name: 'Notifications (1 unread)' })).toBeInTheDocument()
  })

  it('M_RECOVERY_CONSUMED_EARLY: replaces a failed-mark recovery invalidated by a later successful mark', async () => {
    const markA = deferred()
    const recoveryR = deferred()
    const markB = deferred()
    const replacementRecovery = deferred()
    const initial = {
      notifications: [
        notification({ id: 'n-recovery-a', title: 'Recovery row A' }),
        notification({ id: 'n-recovery-b', title: 'Recovery row B' }),
      ],
      unread_count: 2,
    }
    const authoritative = {
      notifications: [
        notification({ id: 'n-recovery-a', title: 'Recovery row A', status: 'unread' }),
        notification({ id: 'n-recovery-b', title: 'Recovery row B', status: 'read' }),
      ],
      unread_count: 1,
    }
    api.getWorkspaceNotifications
      .mockResolvedValueOnce(initial)
      .mockResolvedValueOnce(initial)
      .mockImplementationOnce(() => recoveryR.promise)
      .mockImplementationOnce(() => replacementRecovery.promise)
    api.markNotificationRead
      .mockImplementationOnce(() => markA.promise)
      .mockImplementationOnce(() => markB.promise)
    const user = userEvent.setup()

    renderBell()
    await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(1))
    await openPanel(user)
    expect(await screen.findByText('Recovery row A')).toBeInTheDocument()
    await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(2))

    await user.click(within(screen.getByText('Recovery row A').closest('li')).getByTitle('Mark as read'))
    expect(screen.getByRole('button', { name: 'Notifications (1 unread)' })).toBeInTheDocument()

    await rejectRequest(markA, 'mark A failed')
    await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(3))

    await user.click(within(screen.getByText('Recovery row B').closest('li')).getByTitle('Mark as read'))
    expect(screen.getByRole('button', { name: 'Notifications' })).toBeInTheDocument()
    expect(within(screen.getByText('Recovery row A').closest('li')).queryByTitle('Mark as read')).not.toBeInTheDocument()

    await resolveRequest(recoveryR, authoritative)
    expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(3)
    expect(screen.getByRole('button', { name: 'Notifications' })).toBeInTheDocument()
    expect(within(screen.getByText('Recovery row A').closest('li')).queryByTitle('Mark as read')).not.toBeInTheDocument()

    await resolveRequest(markB, {})
    await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(4))
    expect(api.getWorkspaceNotifications).toHaveBeenNthCalledWith(4, 'ws1', { limit: 30 })
    expect(screen.getByRole('button', { name: 'Notifications' })).toBeInTheDocument()

    await resolveRequest(replacementRecovery, authoritative)
    expect(screen.getByRole('button', { name: 'Notifications (1 unread)' })).toBeInTheDocument()
    expect(within(screen.getByText('Recovery row A').closest('li')).getByTitle('Mark as read')).toBeInTheDocument()
    expect(within(screen.getByText('Recovery row B').closest('li')).queryByTitle('Mark as read')).not.toBeInTheDocument()
  })

  it('M_EMPTY_STATE_ON_ERROR: suppresses the empty-success claim after a prior empty success', async () => {
    const successfulMount = deferred()
    api.getWorkspaceNotifications
      .mockImplementationOnce(() => successfulMount.promise)
      .mockRejectedValueOnce(new Error('open refresh failed'))
    const user = userEvent.setup()

    renderBell()
    await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(1))
    await resolveRequest(successfulMount, EMPTY_RESULT)
    await openPanel(user)

    expect(await screen.findByRole('alert')).toHaveTextContent(/showing the last known/i)
    expect(screen.queryByText('No notifications yet.')).not.toBeInTheDocument()
  })
})

describe('NotificationBell latest request generation', () => {
  it.each(['older-first', 'current-first'])(
    'M_BELL_STALE_GENERATION: panel-open success owns state when %s completion settles first',
    async (completionOrder) => {
      const olderMount = deferred()
      const currentOpen = deferred()
      api.getWorkspaceNotifications
        .mockImplementationOnce(() => olderMount.promise)
        .mockImplementationOnce(() => currentOpen.promise)
      const user = userEvent.setup()

      renderBell()
      await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(1))
      await openPanel(user)
      await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(2))

      if (completionOrder === 'older-first') {
        await rejectRequest(olderMount, 'obsolete mount failure')
        expect(screen.queryByRole('alert')).not.toBeInTheDocument()
        await resolveRequest(currentOpen, bellResult('Current open row'))
      } else {
        await resolveRequest(currentOpen, bellResult('Current open row'))
        expect(await screen.findByText('Current open row')).toBeInTheDocument()
        await rejectRequest(olderMount, 'obsolete mount failure')
      }

      expect(screen.getByText('Current open row')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Notifications (1 unread)' })).toBeInTheDocument()
      expect(screen.queryByRole('alert')).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
    },
  )

  it.each(['older-first', 'current-first'])(
    'M_BELL_STALE_GENERATION: panel-open failure owns error and Retry when %s completion settles first',
    async (completionOrder) => {
      const olderMount = deferred()
      const currentOpen = deferred()
      api.getWorkspaceNotifications
        .mockImplementationOnce(() => olderMount.promise)
        .mockImplementationOnce(() => currentOpen.promise)
      const user = userEvent.setup()

      renderBell()
      await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(1))
      await openPanel(user)
      await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(2))

      if (completionOrder === 'older-first') {
        await resolveRequest(olderMount, bellResult('Obsolete mount row'))
        expect(screen.queryByText('Obsolete mount row')).not.toBeInTheDocument()
        await rejectRequest(currentOpen, 'current open failure')
      } else {
        await rejectRequest(currentOpen, 'current open failure')
        expect(await screen.findByRole('alert')).toHaveTextContent(/couldn.t load notifications/i)
        await resolveRequest(olderMount, bellResult('Obsolete mount row'))
      }

      expect(await screen.findByRole('alert')).toHaveTextContent(/couldn.t load notifications/i)
      expect(screen.queryByText('Obsolete mount row')).not.toBeInTheDocument()
      expect(screen.queryByText('No notifications yet.')).not.toBeInTheDocument()

      api.getWorkspaceNotifications.mockResolvedValueOnce(bellResult('Owned retry row'))
      await user.click(screen.getByRole('button', { name: 'Retry' }))

      expect(await screen.findByText('Owned retry row')).toBeInTheDocument()
      expect(api.getWorkspaceNotifications).toHaveBeenNthCalledWith(3, 'ws1', { limit: 30 })
    },
  )

  it.each([
    ['before-mark', 'poll-first'],
    ['before-mark', 'mark-first'],
    ['during-mark', 'poll-first'],
    ['during-mark', 'mark-first'],
  ])(
    'M_BELL_STALE_POLL: a %s poll cannot restore unread when %s completion settles first',
    async (pollTiming, completionOrder) => {
      let runPoll
      const intervalSpy = vi.spyOn(globalThis, 'setInterval').mockImplementation((fn, delay) => {
        if (delay === 60_000) runPoll = fn
        return 91
      })
      const clearIntervalSpy = vi.spyOn(globalThis, 'clearInterval').mockImplementation(() => {})
      const pollRequest = deferred()
      const markRequest = deferred()
      api.getWorkspaceNotifications
        .mockResolvedValueOnce(bellResult('Unread race row'))
        .mockResolvedValueOnce(bellResult('Unread race row'))
        .mockImplementationOnce(() => pollRequest.promise)
      api.markNotificationRead.mockImplementationOnce(() => markRequest.promise)
      const user = userEvent.setup()

      try {
        const view = renderBell()
        await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(1))
        await openPanel(user)
        expect(await screen.findByText('Unread race row')).toBeInTheDocument()
        await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(2))
        expect(runPoll).toBeTypeOf('function')

        if (pollTiming === 'before-mark') {
          act(() => { runPoll() })
          await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(3))
        }

        await user.click(screen.getByTitle('Mark as read'))
        await waitFor(() => expect(api.markNotificationRead).toHaveBeenCalledWith('ws1', 'n-unread-race-row'))
        expect(screen.getByRole('button', { name: 'Notifications' })).toBeInTheDocument()
        expect(screen.queryByTitle('Mark as read')).not.toBeInTheDocument()

        if (pollTiming === 'during-mark') {
          act(() => { runPoll() })
          await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(3))
        }

        if (completionOrder === 'poll-first') {
          await resolveRequest(pollRequest, bellResult('Unread race row'))
          expect(screen.getByRole('button', { name: 'Notifications' })).toBeInTheDocument()
          expect(screen.queryByTitle('Mark as read')).not.toBeInTheDocument()
          await resolveRequest(markRequest, {})
        } else {
          await resolveRequest(markRequest, {})
          expect(screen.getByRole('button', { name: 'Notifications' })).toBeInTheDocument()
          await resolveRequest(pollRequest, bellResult('Unread race row'))
        }

        expect(screen.getByRole('button', { name: 'Notifications' })).toBeInTheDocument()
        expect(screen.queryByTitle('Mark as read')).not.toBeInTheDocument()
        view.unmount()
      } finally {
        intervalSpy.mockRestore()
        clearIntervalSpy.mockRestore()
      }
    },
  )
})
