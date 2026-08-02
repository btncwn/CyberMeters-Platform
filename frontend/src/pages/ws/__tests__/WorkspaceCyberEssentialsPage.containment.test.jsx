import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import WorkspaceCyberEssentialsPage from '../WorkspaceCyberEssentialsPage'
import { api } from '../../../api'
import { useWorkspace } from '../../../hooks/useWorkspace'

vi.mock('../../../api', () => ({
  api: {
    getWorkspaceCyberEssentialsAnswers: vi.fn(),
    getWorkspaceCyberEssentialsReadiness: vi.fn(),
    getCyberEssentialsControls: vi.fn(),
    saveWorkspaceCyberEssentialsAnswers: vi.fn(),
  },
}))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: vi.fn() }))

const WS_ID = 'ws_ce_containment'

const selfControl = {
  control_key: 'secure_configuration',
  label: 'Secure configuration',
  external_coverage: 'partial',
  evidence: 'externally_corroborated',
  readiness: 'ready',
  measured_score: null,
  measured_gaps: [],
  self_attestation: { answered: 4, total: 4, gaps: [] },
  contradiction: null,
}

function readiness(overrides = {}) {
  return {
    workspace_id: WS_ID,
    assessable: false,
    score: null,
    grade: null,
    status: 'not_assessed',
    categories: [],
    top_gaps: [],
    recommendations: [],
    canonical_remediations: [],
    summary: 'Cyber Essentials readiness cannot currently be assessed for this workspace.',
    self_assessment: { controls: [] },
    ...overrides,
  }
}

function controls(items = []) {
  return { items, pagination: { total: items.length }, scope_note: 'Indicative readiness only.' }
}

function mount() {
  return render(<MemoryRouter><WorkspaceCyberEssentialsPage /></MemoryRouter>)
}

beforeEach(() => {
  vi.clearAllMocks()
  useWorkspace.mockReturnValue({ wsId: WS_ID, wsName: 'Containment workspace', loading: false })
  api.getWorkspaceCyberEssentialsAnswers.mockResolvedValue({ questions: [], answers: {} })
  api.getCyberEssentialsControls.mockResolvedValue(controls())
})

describe('WorkspaceCyberEssentialsPage — Stage-1 containment', () => {
  it('CE-NOT-ASSESSED-GREEN-ZERO-GAPS: assessable false stays neutral without the green zero-gaps claim', async () => {
    // Deliberately no containment_reason: this proves the pre-existing false-healthy
    // class independently of multi-domain containment.
    api.getWorkspaceCyberEssentialsReadiness.mockResolvedValue(readiness())
    mount()

    expect((await screen.findAllByText(/Readiness cannot currently be assessed for this workspace/i)).length).toBeGreaterThanOrEqual(1)
    expect(screen.queryByText(/No major readiness gaps found/i)).not.toBeInTheDocument()
    expect(screen.getByText(/Priority gaps will appear when current external evidence is available/i)).toBeInTheDocument()
  })

  it('contained live and durable control cards show not assessed and never present recorded ready as current', async () => {
    api.getWorkspaceCyberEssentialsReadiness.mockResolvedValue(readiness({
      containment_reason: 'workspace_multi_domain_not_aggregatable',
      self_assessment: { controls: [selfControl] },
    }))
    api.getCyberEssentialsControls.mockResolvedValue(controls([{
      id: 'cec-ready-history',
      control_key: 'secure_configuration',
      control_label: 'Secure configuration',
      readiness_state: 'unknown',
      readiness_reason: 'workspace_multi_domain_not_aggregatable',
      external_coverage: 'partial',
      evidence: [],
      unknown_signals: [{ signal: 'workspace_domain_scope', reason: 'workspace_multi_domain_not_aggregatable' }],
      containment_active: true,
      recorded_readiness_state: 'ready',
      recorded_readiness_reason: 'external_evidence_supports_readiness',
      recorded_evidence: [{ remediation_id: 'historical-only' }],
    }, {
      id: 'cec-stale-non-external',
      control_key: 'access_control',
      control_label: 'Access control',
      readiness_state: 'not_externally_assessable',
      readiness_reason: 'control_not_externally_observable',
      external_coverage: 'none',
      evidence: [],
      unknown_signals: ['control_not_externally_observable'],
      containment_active: true,
      recorded_readiness_state: 'ready',
      recorded_readiness_reason: 'historical-stale-ready',
      recorded_evidence: [{ remediation_id: 'historical-non-external' }],
    }]))
    mount()

    await waitFor(() => expect(screen.getAllByText(/Not assessed/i).length).toBeGreaterThanOrEqual(2))
    expect(screen.queryByText(/Externally aligned/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/Checked by Cyber MOT/i)).not.toBeInTheDocument()
    expect(screen.getAllByText(/Not visible externally/i).length).toBeGreaterThanOrEqual(1)
    expect(screen.queryByText(/historical-only/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/historical-non-external/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/historical-stale-ready/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/workspace_multi_domain_not_aggregatable/i)).not.toBeInTheDocument()
  })

  it('single-domain positive readiness and control presentation remains available', async () => {
    api.getWorkspaceCyberEssentialsReadiness.mockResolvedValue(readiness({
      assessable: true,
      score: 100,
      grade: 'A',
      status: 'likely_ready',
      summary: 'External evidence supports the current readiness indicator.',
      self_assessment: { controls: [selfControl] },
    }))
    api.getCyberEssentialsControls.mockResolvedValue(controls([{
      id: 'cec-current-ready',
      control_key: 'secure_configuration',
      control_label: 'Secure configuration',
      readiness_state: 'ready',
      readiness_reason: 'external_evidence_supports_readiness',
      external_coverage: 'partial',
      evidence: [],
      unknown_signals: [],
    }]))
    mount()

    expect(await screen.findByText(/No major readiness gaps found/i)).toBeInTheDocument()
    expect(screen.getByText(/Externally aligned/i)).toBeInTheDocument()
    expect(screen.getByText(/Checked by Cyber MOT/i)).toBeInTheDocument()
  })
})
