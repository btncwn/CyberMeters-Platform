// S1-SHELL-V2b (Cyber Essentials), R1 rules: "What we observed" shows backend
// facts only — never 0 or a score the summary itself would hide — and a
// workspace switch never shows the previous workspace's control records.
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import WorkspaceCyberEssentialsPage from '../WorkspaceCyberEssentialsPage'
import { ceSummaryFigures } from '../../../lib/ceSummary'
import { api } from '../../../api'
import { useWorkspace } from '../../../hooks/useWorkspace'

vi.mock('../../../api', () => ({
  api: {
    getWorkspaceCyberEssentialsAnswers: vi.fn(), getWorkspaceCyberEssentialsReadiness: vi.fn(),
    getCyberEssentialsControls: vi.fn(), saveWorkspaceCyberEssentialsAnswers: vi.fn(),
  },
}))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: vi.fn() }))

const values = (f) => Object.fromEntries(f.map((x) => [x.id, x.value]))
const base = { readinessLoaded: true, progress: { answered: 12, total: 20 }, controls: { items: [{}, {}] }, controlsError: null }

describe('ceSummaryFigures', () => {
  it('the backend score, the self-declared progress and the observed records, each anchored', () => {
    expect(values(ceSummaryFigures({ ...base, readiness: { score: 64, status: 'partial', questionnaire: { complete: true } } }))).toEqual({
      'ce-score': '64/100', 'ce-answered': '12 of 20', 'ce-observed': 2,
    })
  })
  it('mirrors the summary: "Not assessed" when the backend says so; hidden until the questionnaire is complete', () => {
    // The page passes its own readinessIsNotAssessed() (the rule stays in the page).
    expect(ceSummaryFigures({ ...base, notAssessed: true, readiness: { assessable: false, status: 'not_assessed', score: null } })[0].value).toBe('Not assessed')
    expect(ceSummaryFigures({ ...base, readiness: { score: 80, questionnaire: { complete: false } } })[0].value).toBe('Questionnaire first')
  })
  it('unknown is never 0: readiness failed, no question set, controls loading or failed', () => {
    expect(values(ceSummaryFigures({ readiness: null, readinessLoaded: false, progress: { answered: 0, total: 0 }, controls: null, controlsError: null }))).toEqual({
      'ce-score': 'Not available', 'ce-answered': 'Not available', 'ce-observed': 'Loading…',
    })
    expect(ceSummaryFigures({ ...base, readiness: { score: 64 }, controls: null, controlsError: 'x' })[2].value).toBe('Not available')
    expect(ceSummaryFigures({ ...base, readiness: { score: null, status: 'partial' } })[0].value).toBe('Not available')
  })
})

describe('workspace switch', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useWorkspace.mockReturnValue({ wsId: 'ws-1', wsName: 'One', loading: false })
    api.getWorkspaceCyberEssentialsAnswers.mockResolvedValue({ questions: [], answers: {} })
    api.getWorkspaceCyberEssentialsReadiness.mockResolvedValue({ score: 64, status: 'partial', questionnaire: { complete: true } })
    api.getCyberEssentialsControls.mockResolvedValue({ items: [{ id: 'c1', control_key: 'secure_configuration', control_label: 'Secure configuration ws-1', readiness_state: 'gaps', external_coverage: 'partial', evidence: [], unknown_signals: [] }] })
  })
  it('never shows the previous workspace\'s control records while the new ones load', async () => {
    const tree = () => <MemoryRouter initialEntries={['/ws/cyber-essentials']}><WorkspaceCyberEssentialsPage /></MemoryRouter>
    const view = render(tree())
    expect(await screen.findByText('Secure configuration ws-1')).toBeInTheDocument()
    let release
    api.getCyberEssentialsControls.mockImplementation(() => new Promise((r) => { release = () => r({ items: [] }) }))
    useWorkspace.mockReturnValue({ wsId: 'ws-2', wsName: 'Two', loading: false })
    view.rerender(tree())
    await waitFor(() => expect(api.getCyberEssentialsControls).toHaveBeenLastCalledWith('ws-2'))
    await waitFor(() => expect(screen.queryByText('Secure configuration ws-1')).toBeNull())
    release()
    expect(await screen.findByText(/Nothing observed for these controls yet/)).toBeInTheDocument()
  })
})
