import { render, screen } from '@testing-library/react'
import { MemoryRouter, Routes, Route, Navigate } from 'react-router-dom'
import fs from 'node:fs'
import path from 'node:path'

// One home per thing (founder, 17 Oct 2026): the retired routes redirect to
// the page that owns them now. The router carries each pair below as a
// <Navigate replace>; this test renders the same pairs and pins the source.

export const LEGACY_REDIRECTS = [
  ['/services',        '/dashboard'],
  ['/settings',        '/account'],
  ['/ws/dashboard',    '/ws/members'],
  ['/ws/vendors',      '/ws/third-parties'],
  ['/ws/third-party',  '/ws/third-parties'],
  ['/ws/supply-chain', '/ws/third-parties'],
]

const app = fs.readFileSync(path.resolve(__dirname, '../App.jsx'), 'utf8')

describe('legacy route redirects', () => {
  it.each(LEGACY_REDIRECTS)('%s → %s', (from, to) => {
    render(
      <MemoryRouter initialEntries={[from]}>
        <Routes>
          <Route path={from} element={<Navigate to={to} replace />} />
          <Route path={to} element={<div data-testid="target">{to}</div>} />
        </Routes>
      </MemoryRouter>,
    )
    expect(screen.getByTestId('target')).toHaveTextContent(to)
    // The real router declares exactly this redirect.
    const seg = from.replace(/^\//, '')
    expect(app).toMatch(new RegExp(`path="${seg}"\\s+element=\\{<Navigate to="${to}" replace />\\}`))
  })

  it('the retired pages are gone from the router and the preload map', () => {
    for (const gone of ['ServiceLauncher', 'SettingsPage', 'WorkspaceDashboard', 'VendorsPage', 'ThirdPartyPage', 'WorkspaceSupplyChainPage']) {
      expect(app).not.toMatch(new RegExp(`\\b${gone}\\b`))
    }
    const preload = fs.readFileSync(path.resolve(__dirname, '../utils/preloadMap.js'), 'utf8')
    expect(preload).not.toMatch(/\/ws\/dashboard|\/settings|ThirdPartyPage/)
    expect(preload).toMatch(/\/ws\/third-parties/)
  })
})
