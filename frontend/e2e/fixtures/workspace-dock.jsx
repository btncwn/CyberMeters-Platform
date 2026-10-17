import React from 'react'
import { createRoot } from 'react-dom/client'
import { MemoryRouter } from 'react-router-dom'
import WorkspaceMenu from '../../src/components/shell/WorkspaceMenu'
import '../../src/index.css'

// The workspace card at 390px: below 1280px the shell renders the 36px mini
// card in the top bar (the bottom-left deck is not rendered), so the phone
// layout check in workspace-menu-mobile.spec.js mounts exactly that.
createRoot(document.getElementById('root')).render(
  <MemoryRouter>
    <header className="cm-top" style={{ position: 'sticky', top: 0 }}>
      <div className="cm-top-inner">
        <span className="cm-brand-word">CyberMeters</span>
        <div className="cm-top-account">
          <WorkspaceMenu wsId="ws-a" wsName="Customer A" size="mini" />
        </div>
      </div>
    </header>
    <main style={{ minHeight: '140vh' }}>Workspace menu layout test</main>
  </MemoryRouter>,
)
