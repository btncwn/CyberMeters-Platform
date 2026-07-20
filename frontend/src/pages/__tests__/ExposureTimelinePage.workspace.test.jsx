// ── Exposure Timeline — digest deep link opens the DIGEST'S workspace ─────────
// Digest-truth episode: the weekly digest CTA is /exposure?ws=<id>. The page must
// honour a requested workspace only after the server-authoritative list confirms
// access, never trust the URL or stale localStorage first, and fall back safely
// when the requested workspace is inaccessible or absent.
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { beforeEach, describe, it, expect, vi } from 'vitest'
import ExposureTimelinePage from '../ExposureTimelinePage'
import { useWorkspace } from '../../hooks/useWorkspace'

vi.mock('../../hooks/useWorkspace', () => ({ useWorkspace: vi.fn() }))
vi.mock('../../components/ExposureTimeline', () => ({
  default: ({ workspaceId }) => <div data-testid="timeline">timeline:{workspaceId}</div>,
}))

const WORKSPACES = [
  { id: 'ws_digest', name: 'Digest Workspace' },
  { id: 'ws_last', name: 'Last Selected' },
]

function mount(path) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes><Route path="/exposure" element={<ExposureTimelinePage />} /></Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => { vi.clearAllMocks() })

describe('ExposureTimelinePage — workspace-scoped digest CTA', () => {
  it('opens the requested workspace when the validated list confirms access', () => {
    useWorkspace.mockReturnValue({ wsId: 'ws_last', workspaces: WORKSPACES, loading: false, setWorkspace: vi.fn() })
    mount('/exposure?ws=ws_digest')
    expect(screen.getByTestId('timeline')).toHaveTextContent('timeline:ws_digest')
  })

  it('switches the active selection to the validated requested workspace', () => {
    const setWorkspace = vi.fn()
    useWorkspace.mockReturnValue({ wsId: 'ws_last', workspaces: WORKSPACES, loading: false, setWorkspace })
    mount('/exposure?ws=ws_digest')
    expect(setWorkspace).toHaveBeenCalledWith('ws_digest', 'Digest Workspace')
  })

  it('falls back to the active workspace when the requested one is inaccessible, with a notice', () => {
    useWorkspace.mockReturnValue({ wsId: 'ws_last', workspaces: WORKSPACES, loading: false, setWorkspace: vi.fn() })
    mount('/exposure?ws=ws_foreign')
    expect(screen.getByTestId('timeline')).toHaveTextContent('timeline:ws_last')
    expect(screen.getByText(/isn't available on your account/i)).toBeInTheDocument()
  })

  it('never selects a foreign workspace: the timeline is not rendered for the requested id', () => {
    const setWorkspace = vi.fn()
    useWorkspace.mockReturnValue({ wsId: 'ws_last', workspaces: WORKSPACES, loading: false, setWorkspace })
    mount('/exposure?ws=ws_foreign')
    expect(screen.queryByText('timeline:ws_foreign')).not.toBeInTheDocument()
    expect(setWorkspace).not.toHaveBeenCalled()
  })

  it('waits for the validated list instead of trusting stale selection while loading', () => {
    useWorkspace.mockReturnValue({ wsId: 'ws_last', workspaces: [], loading: true, setWorkspace: vi.fn() })
    mount('/exposure?ws=ws_digest')
    expect(screen.queryByTestId('timeline')).not.toBeInTheDocument()
    expect(screen.getByText(/Loading…/)).toBeInTheDocument()
  })

  it('without ?ws renders the active workspace as before', () => {
    useWorkspace.mockReturnValue({ wsId: 'ws_last', workspaces: WORKSPACES, loading: false, setWorkspace: vi.fn() })
    mount('/exposure')
    expect(screen.getByTestId('timeline')).toHaveTextContent('timeline:ws_last')
  })
})
