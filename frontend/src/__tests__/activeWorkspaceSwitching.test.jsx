// Codex C-45 W02–W04 (with the founder's wrong-workspace-card P1): every
// workspace switch goes through setActiveWorkspace (id AND name, one in-page
// event), and a late workspace-detail response never rolls the selection back.
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api'
import { ACTIVE_WORKSPACE_EVENT } from '../lib/activeWorkspace'
import PortfolioRiskPage from '../pages/PortfolioRiskPage'
import WorkspaceDetailPage from '../pages/WorkspaceDetailPage'

vi.mock('../api', () => ({
  api: { getPortfolioRisk: vi.fn(), getWorkspace: vi.fn(), getWorkspaceDomains: vi.fn(), getWorkspaceAssetsSummary: vi.fn() },
}))

beforeEach(() => { vi.clearAllMocks(); localStorage.clear() })

describe('W02: no page writes the active workspace around the notifying writer', () => {
  it('no source file sets cybermeters_workspace_id / _name directly', () => {
    const files = ['WorkspacesPage', 'WorkspaceDetailPage', 'PortfolioPage', 'OnboardingPage', 'InvitationLandingPage', 'PortfolioRiskPage']
    for (const f of files) {
      const src = readFileSync(resolve(__dirname, `../pages/${f}.jsx`), 'utf8')
      expect(src, f).not.toMatch(/localStorage\.setItem\(\s*['"]cybermeters_workspace_(id|name)['"]/)
    }
  })
})

describe('W04: opening a customer from portfolio risk sets the id AND the name', () => {
  it('both keys and one in-page event', async () => {
    localStorage.setItem('cybermeters_workspace_id', 'ws_old')
    localStorage.setItem('cybermeters_workspace_name', 'Old Customer')
    const seen = vi.fn()
    window.addEventListener(ACTIVE_WORKSPACE_EVENT, seen)
    api.getPortfolioRisk.mockResolvedValue({
      workspace_count: 1, high_risk_workspaces: 0, critical_workspaces: 0,
      risk_rankings: [{ workspace_id: 'ws_she', workspace_name: 'She.Shire', risk_score: 40, risk_level: 'medium', rank: 1 }],
      trending: { improving: [], deteriorating: [] }, portfolio_alerts: [], shared_dependencies: [], calculated_at: '2026-10-23T00:00:00Z',
    })
    render(<MemoryRouter><PortfolioRiskPage /></MemoryRouter>)
    fireEvent.click(await screen.findByRole('button', { name: 'Open She.Shire' }))
    expect(localStorage.getItem('cybermeters_workspace_id')).toBe('ws_she')
    expect(localStorage.getItem('cybermeters_workspace_name')).toBe('She.Shire')
    expect(seen).toHaveBeenCalled()
    window.removeEventListener(ACTIVE_WORKSPACE_EVENT, seen)
  })
})

describe('W03: a late workspace-detail response never rolls the selection back', () => {
  it('leaving A before its detail answers keeps B active', async () => {
    let releaseA
    api.getWorkspace.mockImplementation((id) => (id === 'ws_a'
      ? new Promise((r) => { releaseA = () => r({ workspace: { id: 'ws_a', name: 'A Customer', role: 'owner' }, stats: {} }) })
      : Promise.resolve({ workspace: { id: 'ws_b', name: 'B Customer', role: 'owner' }, stats: {} })))
    api.getWorkspaceDomains.mockResolvedValue({ domains: [] })
    api.getWorkspaceAssetsSummary.mockResolvedValue({})
    const tree = (id) => (
      <MemoryRouter initialEntries={[`/workspaces/${id}`]}>
        <Routes><Route path="/workspaces/:id" element={<WorkspaceDetailPage />} /></Routes>
      </MemoryRouter>
    )
    const view = render(tree('ws_a'))
    view.unmount()
    render(tree('ws_b'))
    await waitFor(() => expect(localStorage.getItem('cybermeters_workspace_id')).toBe('ws_b'))
    releaseA()
    await new Promise((r) => setTimeout(r, 20))
    expect(localStorage.getItem('cybermeters_workspace_id')).toBe('ws_b')
    expect(localStorage.getItem('cybermeters_workspace_name')).toBe('B Customer')
  })
})
