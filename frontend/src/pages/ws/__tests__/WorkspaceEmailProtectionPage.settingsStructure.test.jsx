import { render, screen, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { DmarcSetupWizard, ManagedMtaStsCard, hostedStatusMeta, pageTime } from '../WorkspaceEmailProtectionPage'
import { api } from '../../../api'

vi.mock('../../../api', () => ({
  api: {
    getDmarcIngestEndpoint: vi.fn(),
    createDmarcIngestEndpoint: vi.fn(),
    verifyDmarcDns: vi.fn(),
    getHostedDmarc: vi.fn(),
    getHostedTlsRpt: vi.fn(),
    getHostedMtaSts: vi.fn(),
    createHostedMtaSts: vi.fn(),
    getTlsRptReports: vi.fn(),
  },
  BASE: 'https://api.example.test/api',
}))

beforeEach(() => {
  vi.clearAllMocks()
  api.getDmarcIngestEndpoint.mockResolvedValue({ endpoint: null })
  api.getHostedDmarc.mockResolvedValue({ record: null })
  api.getHostedTlsRpt.mockResolvedValue({ record: null })
  api.getHostedMtaSts.mockResolvedValue({ record: null })
  api.getTlsRptReports.mockResolvedValue({ reports: [], totals: {} })
})

// Seat 2's diagnosis (21 Oct 2026): the hosted DMARC / TLS-RPT / MTA-STS cards
// sat inside the DMARC wizard, above its stepper, so the five reporting steps
// read as if they belonged to "MTA-STS readiness".
describe('Email Protection settings structure', () => {
  it('the reporting stepper and the hosted records are separate, headed sections', async () => {
    render(<DmarcSetupWizard wsId="ws_1" domain="example.test" dmarcDetail={null} hasScanData totalMessages={null} />)
    const setup = await screen.findByRole('region', { name: 'DMARC reporting setup' })
    const hosted = screen.getByRole('region', { name: 'Records CyberMeters can host for you' })
    expect(await within(hosted).findByText('MTA-STS readiness')).toBeInTheDocument()
    expect(within(setup).queryByText('MTA-STS readiness')).not.toBeInTheDocument()
    expect(within(setup).queryByText(/Let CyberMeters manage this record/)).not.toBeInTheDocument()
    // The setup section comes first, the hosted records after it.
    expect(setup.compareDocumentPosition(hosted) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(screen.queryByText('DMARC setup wizard')).not.toBeInTheDocument()
  })

  it('the MTA-STS action reads "Set up MTA-STS"', async () => {
    render(<ManagedMtaStsCard wsId="ws_1" domain="example.test" />)
    expect(await screen.findByRole('button', { name: 'Set up MTA-STS' })).toBeInTheDocument()
    expect(screen.queryByText(/Generate MTA-STS guidance/)).not.toBeInTheDocument()
  })

  it('each hosted record has its own connected and disconnected hint', () => {
    expect(hostedStatusMeta('dmarc', 'connected').hint).toMatch(/DMARC record/)
    expect(hostedStatusMeta('tlsrpt', 'connected').hint).toMatch(/TLS-RPT record/)
    expect(hostedStatusMeta('tlsrpt', 'connected').hint).not.toMatch(/DMARC/)
    expect(hostedStatusMeta('mtasts', 'connected').hint).toMatch(/MTA-STS policy ID/)
    expect(hostedStatusMeta('mtasts', 'disconnected').hint).not.toMatch(/DMARC/)
    expect(hostedStatusMeta('tlsrpt', 'connected').label).toBe('Connected')
    expect(hostedStatusMeta('tlsrpt', 'awaiting_cname')).toEqual(hostedStatusMeta('dmarc', 'awaiting_cname'))
  })

  it('times on the page are UTC and say so', () => {
    expect(pageTime('2026-10-20 10:16:00')).toMatch(/10:16 UTC$/)
    expect(pageTime(null)).toBeNull()
  })
})
