import { beforeEach, describe, expect, it, vi } from 'vitest'
import { preloadComponent } from '../preload'

describe('preloadComponent', () => {
  beforeEach(() => {
    vi.useRealTimers()
    delete window.requestIdleCallback
  })

  it('does nothing outside a browser window', async () => {
    const originalWindow = globalThis.window
    const importFn = vi.fn()
    Object.defineProperty(globalThis, 'window', { value: undefined, configurable: true })

    preloadComponent(importFn)

    expect(importFn).not.toHaveBeenCalled()
    Object.defineProperty(globalThis, 'window', { value: originalWindow, configurable: true })
  })

  it('uses requestIdleCallback when available', () => {
    const importFn = vi.fn().mockResolvedValue({})
    window.requestIdleCallback = vi.fn((cb) => cb())

    preloadComponent(importFn)

    expect(window.requestIdleCallback).toHaveBeenCalledWith(expect.any(Function), { timeout: 2000 })
    expect(importFn).toHaveBeenCalledTimes(1)
  })

  it('falls back to setTimeout and swallows import failures', async () => {
    vi.useFakeTimers()
    const importFn = vi.fn().mockRejectedValue(new Error('network dropped'))

    preloadComponent(importFn)
    await vi.runAllTimersAsync()

    expect(importFn).toHaveBeenCalledTimes(1)
  })
})
