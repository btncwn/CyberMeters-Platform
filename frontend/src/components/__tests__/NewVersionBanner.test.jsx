import { act, fireEvent, render, screen } from '@testing-library/react'
import { Link, MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import NewVersionBanner from '../NewVersionBanner'
import { fetchDeployedBuildId, isDifferentBuild } from '../../lib/appVersion'
import { resetUnsavedInputTracker } from '../../lib/unsavedInput'

// Seen live 19 Oct 2026: a tab left open across a deploy kept running the old
// bundle and the company form looked broken until a hard refresh.

let now
beforeEach(() => {
  now = 1_000_000
  vi.spyOn(Date, 'now').mockImplementation(() => now)
})
afterEach(() => {
  vi.restoreAllMocks()
  resetUnsavedInputTracker()
})

function setup({ deployed = 'build-new', running = 'build-old', interval = 60_000, start = '/account' } = {}) {
  const fetchBuildId = vi.fn().mockResolvedValue(deployed)
  const reload = vi.fn()
  render(
    <MemoryRouter initialEntries={[start]}>
      <Link to="/dashboard">Dashboard</Link>
      <Link to="/onboarding/step-2">Next step</Link>
      <Link to="/account">Account</Link>
      <form onSubmit={(e) => e.preventDefault()}>
        <input aria-label="Company name" />
        <button type="submit">Save</button>
      </form>
      <NewVersionBanner runningBuildId={running} fetchBuildId={fetchBuildId} minCheckIntervalMs={interval} reload={reload} />
    </MemoryRouter>,
  )
  return { fetchBuildId, reload }
}

async function navigate(name) {
  await act(async () => { fireEvent.click(screen.getByRole('link', { name })) })
}

async function focusTab() {
  await act(async () => { window.dispatchEvent(new Event('focus')) })
}

describe('new version banner', () => {
  it('does not check on load, and offers a refresh when navigation finds a newer build', async () => {
    const { fetchBuildId } = setup()
    expect(fetchBuildId).not.toHaveBeenCalled()
    now += 60_000
    await navigate('Dashboard')
    expect(fetchBuildId).toHaveBeenCalledTimes(1)
    expect(await screen.findByRole('status')).toHaveTextContent('A new version is available')
    expect(screen.getByRole('button', { name: 'Refresh' })).toBeInTheDocument()
  })

  it('checks when the tab regains focus, at most once a minute', async () => {
    const { fetchBuildId } = setup({ deployed: 'build-old' })
    now += 60_000
    await focusTab()
    await focusTab()
    expect(fetchBuildId).toHaveBeenCalledTimes(1)
    expect(screen.queryByTestId('new-version-banner')).toBeNull()
    now += 60_000
    await focusTab()
    expect(fetchBuildId).toHaveBeenCalledTimes(2)
  })

  it('stays hidden when the deployed build is the same or cannot be read, and is off without a build id', async () => {
    setup({ deployed: null })
    now += 60_000
    await focusTab()
    expect(screen.queryByTestId('new-version-banner')).toBeNull()
    expect(isDifferentBuild('a', 'a')).toBe(false)
    expect(isDifferentBuild(null, 'b')).toBe(false)
    expect(isDifferentBuild('a', 'b')).toBe(true)
  })

  it('never fetches in a build without an id (dev and tests)', async () => {
    const { fetchBuildId } = setup({ running: null })
    now += 60_000
    await focusTab()
    await navigate('Dashboard')
    expect(fetchBuildId).not.toHaveBeenCalled()
  })

  it('reloads only when the person clicks Refresh', async () => {
    const { reload } = setup()
    now += 60_000
    await focusTab()
    await screen.findByRole('status')
    expect(reload).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }))
    expect(reload).toHaveBeenCalledTimes(1)
  })

  it('warns about unsaved input first, and refreshes only on "Refresh anyway"', async () => {
    const { reload } = setup()
    fireEvent.input(screen.getByLabelText('Company name'), { target: { value: 'Acme' } })
    now += 60_000
    await focusTab()
    fireEvent.click(await screen.findByRole('button', { name: 'Refresh' }))
    expect(reload).not.toHaveBeenCalled()
    expect(screen.getByRole('status')).toHaveTextContent('You have unsaved changes on this page. Save them first, then refresh.')
    fireEvent.click(screen.getByRole('button', { name: 'Refresh anyway' }))
    expect(reload).toHaveBeenCalledTimes(1)
  })

  it('treats a submitted form as saved', async () => {
    const { reload } = setup()
    fireEvent.input(screen.getByLabelText('Company name'), { target: { value: 'Acme' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    now += 60_000
    await focusTab()
    fireEvent.click(await screen.findByRole('button', { name: 'Refresh' }))
    expect(reload).toHaveBeenCalledTimes(1)
  })

  it('"Later" hides it on this page; it returns on the next page', async () => {
    setup()
    now += 60_000
    await focusTab()
    fireEvent.click(await screen.findByRole('button', { name: 'Later' }))
    expect(screen.queryByTestId('new-version-banner')).toBeNull()
    await navigate('Dashboard')
    expect(screen.getByTestId('new-version-banner')).toBeInTheDocument()
  })
})

describe('new version banner never interrupts or covers content', () => {
  it('is a bar in the page flow, never a floating overlay', async () => {
    setup()
    now += 60_000
    await focusTab()
    const bar = await screen.findByTestId('new-version-banner')
    expect(bar.className).not.toMatch(/\bfixed\b|\babsolute\b/)
  })

  it('during onboarding: no banner, and the new version loads on the next navigation', async () => {
    const { reload } = setup({ start: '/onboarding' })
    now += 60_000
    await focusTab()
    expect(screen.queryByTestId('new-version-banner')).toBeNull()
    expect(reload).not.toHaveBeenCalled()
    await navigate('Next step')
    expect(reload).toHaveBeenCalledTimes(1)
  })

  it('during onboarding, unsaved input is never lost to the quiet update', async () => {
    const { reload } = setup({ start: '/onboarding' })
    fireEvent.input(screen.getByLabelText('Company name'), { target: { value: 'Acme' } })
    now += 60_000
    await focusTab()
    await navigate('Next step')
    expect(reload).not.toHaveBeenCalled()
  })
})

describe('fetchDeployedBuildId', () => {
  it('reads build_id from an uncached /version.json', async () => {
    const fetchImpl = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ build_id: 'b1' }) })
    expect(await fetchDeployedBuildId(fetchImpl)).toBe('b1')
    expect(fetchImpl).toHaveBeenCalledWith('/version.json', expect.objectContaining({ cache: 'no-store' }))
  })

  it('returns null for an error, the SPA fallback page, or a manifest without an id', async () => {
    expect(await fetchDeployedBuildId(vi.fn().mockResolvedValue({ ok: false }))).toBeNull()
    expect(await fetchDeployedBuildId(vi.fn().mockResolvedValue({ ok: true, json: async () => { throw new SyntaxError('Unexpected token <') } }))).toBeNull()
    expect(await fetchDeployedBuildId(vi.fn().mockResolvedValue({ ok: true, json: async () => ({ commit: 'abc' }) }))).toBeNull()
    expect(await fetchDeployedBuildId(vi.fn().mockRejectedValue(new TypeError('offline')))).toBeNull()
  })
})
