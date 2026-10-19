import { describe, it, expect, vi } from 'vitest'
import { Suspense } from 'react'
import { render, screen } from '@testing-library/react'
import { preloadableLazy } from '../preloadableLazy'

const page = (text) => ({ default: ({ label }) => <h1>{text}{label ? ` ${label}` : ''}</h1> })

function renderInSuspense(ui) {
  return render(<Suspense fallback={<p>Loading</p>}>{ui}</Suspense>)
}

describe('preloadableLazy', () => {
  it('renders the page on the first render, with no loading fallback, once it was loaded', async () => {
    const Page = preloadableLazy(() => Promise.resolve(page('Home')))
    await Page.load()
    renderInSuspense(<Page label="ready" />)
    expect(screen.getByRole('heading', { name: 'Home ready' })).toBeInTheDocument()
    expect(screen.queryByText('Loading')).not.toBeInTheDocument()
  })

  it('behaves as a lazy page when nothing loaded it first', async () => {
    const Page = preloadableLazy(() => Promise.resolve(page('Later')))
    renderInSuspense(<Page />)
    expect(screen.getByText('Loading')).toBeInTheDocument()
    expect(await screen.findByRole('heading', { name: 'Later' })).toBeInTheDocument()
  })

  it('downloads the page once, however often it is asked for', async () => {
    const factory = vi.fn(() => Promise.resolve(page('Once')))
    const Page = preloadableLazy(factory)
    await Promise.all([Page.load(), Page.load()])
    renderInSuspense(<Page />)
    await Page.load()
    expect(factory).toHaveBeenCalledTimes(1)
  })

  it('tries again after a failed download instead of keeping the failure', async () => {
    const factory = vi.fn()
      .mockImplementationOnce(() => Promise.reject(new Error('chunk failed')))
      .mockImplementationOnce(() => Promise.resolve(page('Recovered')))
    const Page = preloadableLazy(factory)
    await expect(Page.load()).rejects.toThrow('chunk failed')
    await Page.load()
    renderInSuspense(<Page />)
    expect(screen.getByRole('heading', { name: 'Recovered' })).toBeInTheDocument()
    expect(factory).toHaveBeenCalledTimes(2)
  })
})
