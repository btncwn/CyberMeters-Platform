import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import NotificationsPage from '../NotificationsPage'
import { api } from '../../api'

vi.mock('../../api', () => ({
  api: {
    getWorkspaceNotifications: vi.fn(),
    markNotificationRead: vi.fn().mockResolvedValue({}),
  },
}))

const EMPTY_RESULT = {
  notifications: [],
  unread_count: 0,
  count: 0,
}

function notification(overrides = {}) {
  return {
    id: 'n-page-1',
    status: 'unread',
    severity: 'high',
    type: 'scan_completed',
    title: 'Known notification',
    message: 'This row came from the last successful load.',
    created_at: new Date().toISOString(),
    ...overrides,
  }
}

function renderPage() {
  return render(
    <MemoryRouter>
      <NotificationsPage />
    </MemoryRouter>,
  )
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

function resultWith(title, overrides = {}) {
  return {
    notifications: [notification({
      id: `n-${title.toLowerCase().replaceAll(' ', '-')}`,
      title,
    })],
    unread_count: 1,
    count: 1,
    ...overrides,
  }
}

function fullPageResult() {
  return {
    notifications: Array.from({ length: 50 }, (_, index) => notification({
      id: `n-page-${index}`,
      title: `Page row ${index}`,
    })),
    unread_count: 50,
    count: 50,
  }
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

async function startFilterRace(olderRequest, currentRequest) {
  api.getWorkspaceNotifications
    .mockImplementationOnce(() => olderRequest.promise)
    .mockImplementationOnce(() => currentRequest.promise)
  const user = userEvent.setup()

  renderPage()
  await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(1))
  await user.click(screen.getByRole('button', { name: /^Unread/ }))
  await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(2))

  return user
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.setItem('cybermeters_workspace_id', 'ws-page')
})

describe('NotificationsPage failure truth', () => {
  it('M_SILENT_CATCH: exposes an accessible first-load failure', async () => {
    api.getWorkspaceNotifications.mockRejectedValue(new Error('offline'))

    renderPage()

    expect(await screen.findByRole('alert')).toHaveTextContent(/couldn.t load notifications/i)
    expect(screen.getByRole('button', { name: 'Retry' })).toBeEnabled()
    expect(screen.queryByText('No notifications yet')).not.toBeInTheDocument()
    expect(screen.queryByText('All caught up')).not.toBeInTheDocument()
  })

  it('M_EMPTY_STATE_ON_ERROR: suppresses empty-success claims after a prior empty success', async () => {
    api.getWorkspaceNotifications
      .mockResolvedValueOnce(EMPTY_RESULT)
      .mockRejectedValueOnce(new Error('unread refresh failed'))
    const user = userEvent.setup()

    renderPage()
    await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(1))
    await user.click(screen.getByRole('button', { name: /^Unread/ }))

    expect(await screen.findByRole('alert')).toHaveTextContent(/showing the last known/i)
    expect(screen.queryByText('No notifications yet')).not.toBeInTheDocument()
    expect(screen.queryByText('All caught up')).not.toBeInTheDocument()
  })

  it('M_LAST_KNOWN_ZEROED: preserves the last rows and badge after a later filtered load fails', async () => {
    api.getWorkspaceNotifications
      .mockResolvedValueOnce({
        notifications: [notification()],
        unread_count: 1,
        count: 1,
      })
      .mockRejectedValueOnce(new Error('refresh failed'))
    const user = userEvent.setup()

    renderPage()
    expect(await screen.findByText('Known notification')).toBeInTheDocument()
    expect(screen.getByText('1 total · 1 unread')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /^Unread/ }))

    expect(await screen.findByRole('alert')).toHaveTextContent(/showing the last known/i)
    expect(screen.getByText('Known notification')).toBeInTheDocument()
    expect(screen.getByText('1 total · 1 unread')).toBeInTheDocument()
    expect(screen.queryByText('All caught up')).not.toBeInTheDocument()
  })

  it('M_ERROR_CLEARED_BEFORE_SUCCESS: keeps the failure visible while Retry is pending', async () => {
    const retryResult = deferred()
    api.getWorkspaceNotifications
      .mockRejectedValueOnce(new Error('offline'))
      .mockImplementationOnce(() => retryResult.promise)
    const user = userEvent.setup()

    renderPage()
    const alert = await screen.findByRole('alert')

    await user.click(screen.getByRole('button', { name: 'Retry' }))

    expect(alert).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Retrying…' })).toBeDisabled()

    await act(async () => {
      retryResult.resolve(EMPTY_RESULT)
      await retryResult.promise
    })

    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument())
    expect(screen.getAllByText('No notifications yet').length).toBeGreaterThan(0)
  })

  it('M_RETRY_DROPPED: Retry repeats a failed request', async () => {
    api.getWorkspaceNotifications.mockRejectedValue(new Error('offline'))
    const user = userEvent.setup()

    renderPage()
    await screen.findByRole('alert')
    expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(1)

    await user.click(screen.getByRole('button', { name: 'Retry' }))

    await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(2))
  })

  it('M_RETRY_WRONG_QUERY: Retry repeats the exact failed status filter', async () => {
    api.getWorkspaceNotifications
      .mockResolvedValueOnce(EMPTY_RESULT)
      .mockRejectedValueOnce(new Error('unread failed'))
      .mockResolvedValueOnce({
        notifications: [notification({ title: 'Unread retry result' })],
        unread_count: 1,
        count: 1,
      })
    const user = userEvent.setup()

    renderPage()
    await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(1))

    await user.click(screen.getByRole('button', { name: /^Unread/ }))
    await screen.findByRole('alert')
    expect(api.getWorkspaceNotifications).toHaveBeenNthCalledWith(
      2,
      'ws-page',
      { limit: 50, status: 'unread' },
    )

    await user.click(screen.getByRole('button', { name: 'Retry' }))

    expect(await screen.findByText('Unread retry result')).toBeInTheDocument()
    expect(api.getWorkspaceNotifications).toHaveBeenNthCalledWith(
      3,
      'ws-page',
      { limit: 50, status: 'unread' },
    )
  })

  it('keeps mark-read failure recovery on the current page query', async () => {
    const lastKnown = {
      notifications: [notification()],
      unread_count: 1,
      count: 1,
    }
    api.getWorkspaceNotifications.mockResolvedValue(lastKnown)
    api.markNotificationRead.mockRejectedValueOnce(new Error('mark failed'))
    const user = userEvent.setup()

    renderPage()
    await screen.findByText('Known notification')
    expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(1)

    await user.click(screen.getByText('Known notification'))

    expect(api.markNotificationRead).toHaveBeenCalledWith('ws-page', 'n-page-1')
    await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(2))
    expect(api.getWorkspaceNotifications).toHaveBeenLastCalledWith('ws-page', { limit: 50 })
    expect(screen.getByText('1 total · 1 unread')).toBeInTheDocument()
  })
})

describe('NotificationsPage latest request generation', () => {
  it.each(['older-first', 'current-first'])(
    'M_PAGE_STALE_GENERATION: current filtered success owns state when %s completion settles first',
    async (completionOrder) => {
      const olderRequest = deferred()
      const currentRequest = deferred()
      await startFilterRace(olderRequest, currentRequest)

      if (completionOrder === 'older-first') {
        await rejectRequest(olderRequest, 'obsolete all failure')
        expect(screen.queryByRole('alert')).not.toBeInTheDocument()
        await resolveRequest(currentRequest, resultWith('Current unread result'))
      } else {
        await resolveRequest(currentRequest, resultWith('Current unread result'))
        expect(await screen.findByText('Current unread result')).toBeInTheDocument()
        await rejectRequest(olderRequest, 'obsolete all failure')
      }

      expect(screen.getByText('Current unread result')).toBeInTheDocument()
      expect(screen.queryByRole('alert')).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
    },
  )

  it.each(['older-first', 'current-first'])(
    'M_PAGE_STALE_GENERATION: current filtered failure owns error and Retry when %s completion settles first',
    async (completionOrder) => {
      const olderRequest = deferred()
      const currentRequest = deferred()
      const user = await startFilterRace(olderRequest, currentRequest)

      if (completionOrder === 'older-first') {
        await resolveRequest(olderRequest, resultWith('Obsolete all result'))
        expect(screen.queryByText('Obsolete all result')).not.toBeInTheDocument()
        await rejectRequest(currentRequest, 'current unread failure')
      } else {
        await rejectRequest(currentRequest, 'current unread failure')
        expect(await screen.findByRole('alert')).toHaveTextContent(/couldn.t load notifications/i)
        await resolveRequest(olderRequest, resultWith('Obsolete all result'))
      }

      expect(await screen.findByRole('alert')).toHaveTextContent(/couldn.t load notifications/i)
      expect(screen.queryByText('Obsolete all result')).not.toBeInTheDocument()
      expect(screen.queryByText('No notifications yet')).not.toBeInTheDocument()
      expect(screen.queryByText('All caught up')).not.toBeInTheDocument()

      api.getWorkspaceNotifications.mockResolvedValueOnce(resultWith('Owned retry result'))
      await user.click(screen.getByRole('button', { name: 'Retry' }))

      expect(await screen.findByText('Owned retry result')).toBeInTheDocument()
      expect(api.getWorkspaceNotifications).toHaveBeenNthCalledWith(
        3,
        'ws-page',
        { limit: 50, status: 'unread' },
      )
    },
  )

  it.each(['older-first', 'current-first'])(
    'M_PAGE_STALE_LOAD_MORE: filtered reset owns rows and counts when %s completion settles first',
    async (completionOrder) => {
      const staleLoadMore = deferred()
      const currentReset = deferred()
      api.getWorkspaceNotifications
        .mockResolvedValueOnce(fullPageResult())
        .mockImplementationOnce(() => staleLoadMore.promise)
        .mockImplementationOnce(() => currentReset.promise)
      const user = userEvent.setup()

      renderPage()
      await user.click(await screen.findByRole('button', { name: 'Load more' }))
      await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(2))
      await user.click(screen.getByRole('button', { name: /^Unread/ }))
      await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(3))

      if (completionOrder === 'older-first') {
        await resolveRequest(staleLoadMore, resultWith('Stale appended row', {
          unread_count: 51,
          count: 51,
        }))
        expect(screen.getByText('50 total · 50 unread')).toBeInTheDocument()
        expect(screen.queryByText('51 total · 51 unread')).not.toBeInTheDocument()
        await resolveRequest(currentReset, resultWith('Current reset row'))
      } else {
        await resolveRequest(currentReset, resultWith('Current reset row'))
        expect(await screen.findByText('Current reset row')).toBeInTheDocument()
        await resolveRequest(staleLoadMore, resultWith('Stale appended row', {
          unread_count: 51,
          count: 51,
        }))
      }

      expect(await screen.findByText('Current reset row')).toBeInTheDocument()
      expect(screen.queryByText('Stale appended row')).not.toBeInTheDocument()
      expect(screen.getByText('1 total · 1 unread')).toBeInTheDocument()
      expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    },
  )

  it.each(['older-first', 'current-first'])(
    'M_PAGE_STALE_LOAD_MORE: stale failure cannot install Retry when %s completion settles first',
    async (completionOrder) => {
      const staleLoadMore = deferred()
      const currentReset = deferred()
      api.getWorkspaceNotifications
        .mockResolvedValueOnce(fullPageResult())
        .mockImplementationOnce(() => staleLoadMore.promise)
        .mockImplementationOnce(() => currentReset.promise)
      const user = userEvent.setup()

      renderPage()
      await user.click(await screen.findByRole('button', { name: 'Load more' }))
      await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(2))
      await user.click(screen.getByRole('button', { name: /^Unread/ }))
      await waitFor(() => expect(api.getWorkspaceNotifications).toHaveBeenCalledTimes(3))

      if (completionOrder === 'older-first') {
        await rejectRequest(staleLoadMore, 'obsolete load-more failure')
        expect(screen.queryByRole('alert')).not.toBeInTheDocument()
        expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
        await resolveRequest(currentReset, resultWith('Current reset row'))
      } else {
        await resolveRequest(currentReset, resultWith('Current reset row'))
        await rejectRequest(staleLoadMore, 'obsolete load-more failure')
      }

      expect(await screen.findByText('Current reset row')).toBeInTheDocument()
      expect(screen.queryByRole('alert')).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
    },
  )
})
