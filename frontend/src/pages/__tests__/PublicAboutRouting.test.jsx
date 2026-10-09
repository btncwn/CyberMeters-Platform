// @vitest-environment-options {"url":"https://cybermeters.com/about"}
import React from 'react'
import { render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from '../../App'
vi.mock('../../context/AuthContext', () => ({ AuthProvider: ({ children }) => children, useAuth: () => ({ isAuthenticated: false, isLoading: false }) }))
vi.mock('../../components/MaintenanceOverlay', () => ({ default: () => null }))
afterEach(() => vi.unstubAllGlobals())
describe('Public About route', () => {
  it('opens /about without an account and navigates to the real trust page', async () => {
    // Any unexpected network request fails: these factual pages are static.
    vi.stubGlobal('fetch', vi.fn(() => { throw new Error('Unexpected network request') }))
    window.history.replaceState({}, '', '/about')
    render(<App />)
    expect(await screen.findByRole('heading', { name: 'Built and operated by Turhan Acar' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /See our own-domain check/ })).toHaveAttribute('href', '/trust')
    expect(fetch).not.toHaveBeenCalled()
  })
})
