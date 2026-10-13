import React from 'react'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import IntelligencePage from '../IntelligencePage'
import { api } from '../../api'

vi.mock('../../api', () => ({
  api: {
    getWorkspaceScans: vi.fn(),
    getScanReport: vi.fn(),
  },
}))

const VULNERABILITY_STATEMENT =
  'Reported software versions are not matched against outside vulnerability databases. A version the server reports is shown as a disclosure, never as a confirmed vulnerability.'
const EXPLOITED_STATEMENT =
  'Outside lists of exploited vulnerabilities and exploit-likelihood scores are not used, shown or counted in the score.'

// The two module results a scan records when its check pack does not use
// outside vulnerability data (backend: check-pack.js moduleNotInCheckPack,
// projected by phase5-evidence.js).
const notInCheckPack = (source, statement) => ({
  executed: false,
  outcome: 'not_in_check_pack',
  reason: 'outside_vulnerability_data_not_used',
  source,
  check_pack_version: '2026.10.1',
  customer_message: statement,
  findings: [],
  evidence_publishable: false,
})

const COMPLETE_ASSESSMENT = Object.freeze({
  display_score: 82,
  display_rating: 'good',
  quality: 'complete',
  provisional: false,
  authoritative: true,
  comparable: true,
  message: null,
})

const scan = Object.freeze({
  id: 'scan-check-pack',
  domain: 'checkpack.example',
  status: 'completed',
  score: 82,
  rating: 'good',
  created_at: '2026-10-13T10:00:00Z',
})

const CHECK_PACK = Object.freeze({
  version: '2026.10.1',
  outside_sources: [
    { id: 'public_dns_resolver', required: true, what: 'DNS questions about the scanned domain are asked over HTTPS to a public resolver.' },
    { id: 'registry_rdap', required: false, what: "The domain's registration and expiry dates are read from the registry's RDAP service." },
  ],
  not_in_check_pack: ['vulnerability_database_matching', 'exploited_vulnerability_data', 'certificate_history'],
})

const report = (modules, extra = {}) => ({
  scan_id: scan.id,
  domain: scan.domain,
  status: 'completed',
  cyber_metrics_score: 82,
  risk_level: 'good',
  assessment: COMPLETE_ASSESSMENT,
  scan_quality: { status: 'complete', modules_skipped: [], warnings: [] },
  modules: {
    email_security_intelligence: {
      executed: false,
      incomplete: true,
      outcome: 'unavailable',
      source: 'email_security_intelligence',
      evidence_publishable: false,
    },
    risk_intelligence: {
      overall_risk_level: 'Low',
      narrative: null,
      finding_counts: { critical: 0, high: 0, medium: 0, low: 0 },
      risk_categories: {},
    },
    remediation_plan: {
      summary: { p1_count: 0, p2_count: 0, p3_count: 0, total: 0 },
      p1_immediate: [],
      p2_high: [],
      p3_medium_low: [],
    },
    ...modules,
  },
  ...extra,
})

async function renderReport(value) {
  api.getWorkspaceScans.mockResolvedValue({ scans: [scan] })
  api.getScanReport.mockResolvedValue(value)
  render(<MemoryRouter><IntelligencePage /></MemoryRouter>)
  await screen.findByText('Full Report')
  await waitFor(() => expect(api.getScanReport).toHaveBeenCalledWith(scan.id))
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.setItem('cybermeters_workspace_id', 'ws-check-pack')
  localStorage.setItem('cybermeters_workspace_name', 'Check Pack Workspace')
})

describe('IntelligencePage and the check pack', () => {
  it('states that outside vulnerability data is not used instead of showing empty CVE / KEV panels', async () => {
    await renderReport(report({
      cve_intelligence: notInCheckPack('vulnerability_database_matching', VULNERABILITY_STATEMENT),
      known_exploited_vulnerabilities: notInCheckPack('exploited_vulnerability_data', EXPLOITED_STATEMENT),
    }, { check_pack: CHECK_PACK }))

    expect(screen.getByText('Outside vulnerability data')).toBeInTheDocument()
    expect(screen.getByText(VULNERABILITY_STATEMENT)).toBeInTheDocument()
    expect(screen.getByText(EXPLOITED_STATEMENT)).toBeInTheDocument()
    expect(screen.getByText('Check version 2026.10.1')).toBeInTheDocument()
    // The outside services the scan asked are named, with whether each is required.
    expect(screen.getByText('Services outside your domain this scan asked')).toBeInTheDocument()
    expect(screen.getByText(CHECK_PACK.outside_sources[0].what, { exact: false })).toBeInTheDocument()
    expect(screen.getByText(CHECK_PACK.outside_sources[1].what, { exact: false })).toBeInTheDocument()
    expect(screen.getByText('(optional)')).toBeInTheDocument()
    expect(screen.getByText('(required)')).toBeInTheDocument()
    // No figure, no empty panel and no failure wording for a check that is not part of the pack.
    expect(screen.queryByText('CVE / KEV')).not.toBeInTheDocument()
    expect(screen.queryByText('CVE Intelligence')).not.toBeInTheDocument()
    expect(screen.queryByText('CISA KEV Matches')).not.toBeInTheDocument()
    expect(screen.queryByText('No CVE data')).not.toBeInTheDocument()
    expect(screen.queryByText('No KEV data')).not.toBeInTheDocument()
    expect(screen.queryByText(/could not complete the vulnerability assessment/i)).not.toBeInTheDocument()
  })

  it('keeps a stored scan that used outside vulnerability data readable as it was', async () => {
    await renderReport(report({
      cve_intelligence: {
        evidence_publishable: true,
        total_count_publishable: true,
        critical_count: 0,
        high_count: 1,
        total_cves: 1,
        technologies_checked: ['nginx'],
        results: { nginx: [{ cve_id: 'CVE-2099-10001', severity: 'HIGH', description: 'Historical match.' }] },
      },
      known_exploited_vulnerabilities: { evidence_publishable: true, matched: 0, matches: [], checked: 1200 },
    }))

    expect(screen.getByText('CVE / KEV')).toBeInTheDocument()
    expect(screen.getByText('CVE Intelligence')).toBeInTheDocument()
    expect(screen.getByText('CISA KEV Matches')).toBeInTheDocument()
    expect(screen.getByText('CVE-2099-10001')).toBeInTheDocument()
    expect(screen.queryByText('Outside vulnerability data')).not.toBeInTheDocument()
  })
})
