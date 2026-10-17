import { render, screen, fireEvent, within } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import WorkspaceMenu, { workspaceInitial } from '../shell/WorkspaceMenu'
import { api } from '../../api'

// The workspace card deck (bottom-left): the serif initial and a WORKSPACE
// label on the front card, and the existing popover — Switch, Manage
// workspaces, Members & roles — nothing else.

vi.mock('../../api', () => ({ api: { getWorkspaces: vi.fn() } }))

function renderMenu({ wsId = 'ws1', wsName = 'Deneme', size } = {}) {
  return render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <Routes><Route path="*" element={<WorkspaceMenu wsId={wsId} wsName={wsName} size={size} />} /></Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  api.getWorkspaces.mockResolvedValue({ workspaces: [{ id: 'ws1', name: 'Deneme' }, { id: 'ws2', name: 'Other' }] })
})

describe('workspace card deck', () => {
  it('shows the serif initial and the WORKSPACE label on the front card', () => {
    renderMenu()
    const b = screen.getByTestId('workspace-dock-button')
    expect(b.className).toContain('cm-wsbtn')
    expect(b).toHaveAccessibleName('Workspace: Deneme')
    expect(within(b).getByText('D').className).toContain('cm-wsbtn-initial')
    expect(within(b).getByText('Workspace').className).toContain('cm-wsbtn-label')
    expect(workspaceInitial('black bull barbers')).toBe('B')
    expect(workspaceInitial('')).toBe('?')
  })

  it('the mini card for the top bar keeps the initial, drops the label and opens the same popover downwards', async () => {
    renderMenu({ size: 'mini' })
    const b = screen.getByTestId('workspace-mini-button')
    expect(b).toHaveClass('cm-wsmini')
    expect(b).toHaveAccessibleName('Workspace: Deneme')
    expect(within(b).getByText('D')).toBeInTheDocument()
    expect(within(b).queryByText('Workspace')).not.toBeInTheDocument()
    fireEvent.click(b)
    const menu = screen.getByRole('menu', { name: 'Workspace' })
    expect(menu.className).toContain('top-full')
    expect(await within(menu).findByRole('menuitem', { name: 'Manage workspaces' })).toBeInTheDocument()
  })

  it('names the active workspace, lists workspaces on open, and offers Manage workspaces and Members & roles only', async () => {
    renderMenu()
    const b = screen.getByRole('button', { name: 'Workspace: Deneme' })
    expect(b).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(b)
    expect(b).toHaveAttribute('aria-expanded', 'true')
    const menu = screen.getByRole('menu', { name: 'Workspace' })
    expect(within(menu).getByTestId('active-workspace-name')).toHaveTextContent('Deneme')
    expect(await within(menu).findByRole('menuitem', { name: /Other/ })).toBeInTheDocument()
    expect(within(menu).getByRole('menuitem', { name: /Deneme/ })).toHaveAttribute('aria-current', 'true')
    expect(within(menu).getByRole('menuitem', { name: 'Manage workspaces' })).toHaveAttribute('href', '/workspaces')
    expect(within(menu).getByRole('menuitem', { name: 'Members & roles' })).toHaveAttribute('href', '/ws/members')
    expect(within(menu).getAllByRole('menuitem').map(i => i.textContent)).toEqual(['Deneme', 'Other', 'Manage workspaces', 'Members & roles'])
    for (const gone of ['Clear selection', 'Administration', 'Scorecard', 'Executive dashboard', 'Operations', 'Related changes', 'Audit log', 'Alert channels', 'Usage & retention', 'Settings']) {
      expect(within(menu).queryByRole('menuitem', { name: gone })).not.toBeInTheDocument()
    }
    expect(api.getWorkspaces).toHaveBeenCalledTimes(1)
  })

  it('without a workspace the button says so and still offers Manage workspaces', () => {
    renderMenu({ wsId: null, wsName: '' })
    const b = screen.getByRole('button', { name: 'Select a workspace' })
    expect(within(b).getByText('?')).toBeInTheDocument()
    fireEvent.click(b)
    const menu = screen.getByRole('menu', { name: 'Workspace' })
    expect(within(menu).getByTestId('active-workspace-name')).toHaveTextContent('No workspace selected')
    expect(within(menu).getByRole('menuitem', { name: 'Manage workspaces' })).toBeInTheDocument()
  })

  it('switching writes the workspace; Escape returns focus to the button', async () => {
    localStorage.clear()
    renderMenu()
    const b = screen.getByRole('button', { name: 'Workspace: Deneme' })
    fireEvent.click(b)
    fireEvent.click(await screen.findByRole('menuitem', { name: /Other/ }))
    expect(localStorage.getItem('cybermeters_workspace_id')).toBe('ws2')
    expect(screen.queryByRole('menu', { name: 'Workspace' })).not.toBeInTheDocument()
    expect(document.activeElement).toBe(b)
    fireEvent.click(b)
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('menu', { name: 'Workspace' })).not.toBeInTheDocument()
    expect(document.activeElement).toBe(b)
  })
})
