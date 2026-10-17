import React from 'react'
import { createRoot } from 'react-dom/client'
import { MemoryRouter } from 'react-router-dom'
import WorkspaceMenu from '../../src/components/shell/WorkspaceMenu'
import '../../src/index.css'

// The workspace card deck of the app shell v2, in the bottom-left dock, on a
// page tall enough to scroll — the phone layout check in workspace-menu-mobile.spec.js.
createRoot(document.getElementById('root')).render(
  <MemoryRouter>
    <main style={{ minHeight: '140vh' }}>Workspace menu layout test</main>
    <div className="cm-dock cm-dock-left" data-testid="workspace-dock">
      <WorkspaceMenu wsId="ws-a" wsName="Customer A" />
    </div>
  </MemoryRouter>,
)
