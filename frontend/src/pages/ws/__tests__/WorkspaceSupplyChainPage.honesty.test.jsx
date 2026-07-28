import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import WorkspaceSupplyChainPage from '../WorkspaceSupplyChainPage'
import { api } from '../../../api'

vi.mock('../../../api', () => ({
  api: { getWorkspaceSupplyChain: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({
  useWorkspace: () => ({ wsId: 'ws', wsName: 'Founder Workspace' }),
}))

const sharedEvidence = {
  operational_resilience_score: 82,
  concentration_level: 'medium',
  critical_vendor_count: 1,
  tier1_count: 1,
  tier2_count: 0,
  tier3_count: 0,
  spof_count: 1,
  critical_vendors: [{
    name: 'Identity Provider',
    category: 'identity_provider',
    tier: 1,
    risk_level: 'high',
    parent_company: null,
  }],
  dependency_graph: {},
  cascading_risks: [],
  concentration: { top_parents: [], spofs: ['Identity Provider'] },
}

const incompletePayload = {
  ...sharedEvidence,
  supply_chain_score_state: 'incomplete',
  supply_chain_score: null,
  supply_chain_score_reason:
    'Supply Chain Score is incomplete because ASM maturity requires a current complete Business Risk Score.',
  brs_state: 'basis_unproven',
  brs_score: null,
  compliance_readiness: {
    state: 'incomplete',
    state_reason:
      'Compliance readiness is incomplete because a current complete Business Risk Score is unavailable.',
    gdpr: null,
    security_governance: null,
    pci_dss: null,
    coverage: {
      gdpr: { state: 'incomplete', missing_components: ['business_risk_score'] },
      security_governance: { state: 'incomplete', missing_components: ['business_risk_score'] },
      pci_dss: { state: 'incomplete', missing_components: ['business_risk_score'] },
    },
  },
  asm_maturity: {
    state: 'incomplete',
    state_reason:
      'ASM maturity is incomplete because a current complete Business Risk Score is unavailable.',
    score: null,
    level: null,
    observed_subtotal: 23,
    observed_max_score: 65,
    observed_components: [
      { component: 'scan_cadence', score: 8, max_score: 25 },
      { component: 'vendor_visibility', score: 6, max_score: 20 },
      { component: 'asset_visibility', score: 9, max_score: 20 },
    ],
    missing_components: ['business_risk_score'],
  },
}

const renderPage = async (payload) => {
  api.getWorkspaceSupplyChain.mockResolvedValue(payload)
  render(<MemoryRouter><WorkspaceSupplyChainPage /></MemoryRouter>)
  await waitFor(() => expect(api.getWorkspaceSupplyChain).toHaveBeenCalledWith('ws'))
}

beforeEach(() => vi.clearAllMocks())

describe('WorkspaceSupplyChainPage BRS completeness', () => {
  it('does not convert an unavailable BRS-derived composite into 0, initial or low', async () => {
    await renderPage(incompletePayload)
    await waitFor(() => expect(screen.getByText('Supply Chain Score unavailable')).toBeInTheDocument())
    expect(screen.getByText('ASM maturity unavailable')).toBeInTheDocument()
    expect(screen.getAllByText('Incomplete')).toHaveLength(3)
    expect(document.body.textContent).not.toMatch(/0\/100|Maturity Score|initial/i)
    expect(screen.queryByText('low')).not.toBeInTheDocument()
  })

  it('keeps independently trustworthy sibling evidence visible', async () => {
    await renderPage(incompletePayload)
    await waitFor(() => expect(screen.getAllByText('82').length).toBeGreaterThan(0))
    expect(screen.getByText('Identity Provider')).toBeInTheDocument()
    expect(screen.getByText(/23\/65 observed points/)).toBeInTheDocument()
    expect(screen.getAllByText(/Single Points of Failure/).length).toBeGreaterThan(0)
  })

  it('preserves the assessed-BRS positive control', async () => {
    await renderPage({
      ...sharedEvidence,
      supply_chain_score_state: 'assessed',
      supply_chain_score: 75,
      supply_chain_score_reason: null,
      brs_state: 'assessed',
      brs_score: 80,
      compliance_readiness: {
        state: 'assessed',
        state_reason: null,
        gdpr: 'high',
        security_governance: 'medium',
        pci_dss: 'low',
        coverage: {
          gdpr: { state: 'assessed', missing_components: [] },
          security_governance: { state: 'assessed', missing_components: [] },
          pci_dss: { state: 'assessed', missing_components: [] },
        },
      },
      asm_maturity: {
        state: 'assessed',
        state_reason: null,
        score: 58,
        level: 'defined',
        missing_components: [],
      },
    })
    await waitFor(() => expect(screen.getAllByText('75').length).toBeGreaterThan(0))
    expect(screen.getByText('defined')).toBeInTheDocument()
    expect(screen.getAllByText('high').length).toBeGreaterThan(0)
    expect(screen.getByText('medium')).toBeInTheDocument()
    expect(screen.getByText('low')).toBeInTheDocument()
    expect(screen.queryByText('Supply Chain Score unavailable')).not.toBeInTheDocument()
  })
})
