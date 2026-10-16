import React from 'react'
import { createRoot } from 'react-dom/client'
import { MemoryRouter } from 'react-router-dom'
import WorkspaceNav from '../../src/components/WorkspaceNav'
import '../../src/index.css'

createRoot(document.getElementById('root')).render(
  <MemoryRouter>
    <main style={{ minHeight: '100vh' }}>Workspace menu layout test</main>
    <WorkspaceNav wsId="ws-a" wsName="Customer A" />
  </MemoryRouter>,
)
