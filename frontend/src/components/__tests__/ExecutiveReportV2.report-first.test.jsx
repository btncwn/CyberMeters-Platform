import { render, screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { execFileSync } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import ExecutiveReportV2 from '../ExecutiveReportV2'
import { CYBER_MOT_DISPLAY_ORDER } from '../../lib/cyberMotDisplay'
import { composeSnapshot } from '../../../../workers/scan-api/src/engines/report-snapshot.js'
import { buildExecutiveReportV2 } from '../../../../workers/scan-api/src/engines/executive-report.js'
import { buildDseFindings } from '../../../../workers/scan-api/src/engines/dse-findings.js'
import { computeScore } from '../../../../workers/scan-api/src/engines/scoring.js'
import { normalizeFindingSchema } from '../../../../workers/scan-api/src/engines/findings.js'

const repoRoot = process.env.B2B_PROOF_REPO_ROOT ||
  path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..')
const b2bValidator = path.join(repoRoot, 'scripts/validate-email-deadline-evidence.js')

function loadB2bCustomerProof(mode) {
  return JSON.parse(String(execFileSync(process.execPath, [b2bValidator, `--child=${mode}`], {
    cwd: repoRoot,
    timeout: 180_000,
    maxBuffer: 4 * 1024 * 1024,
  })))
}

const evidenceGrade = {
  grade: 'L1',
  source_type: 'product_policy',
  basis: 'Recorded external evidence.',
  limits: ['Limited to the evidence recorded in this assessment.'],
  repeat_confirmed: false,
}

const actions = [
  { remediation_id: 'a.critical', priority: 'critical', title: 'First action', action: 'Do first.' },
  { remediation_id: 'a.high', priority: 'high', title: 'Second action', action: 'Do second.' },
  { remediation_id: 'a.medium', priority: 'medium', title: 'Third action', action: 'Do third.' },
  { remediation_id: 'a.low', priority: 'low', title: 'Fourth action', action: 'Do fourth.' },
]

function reportFixture() {
  return {
    domain: { name: 'example.test' },
    assessed_at: '2026-08-30T10:00:00.000Z',
    cyber_metrics_score: {
      value: 81,
      rating: 'good',
      evidence_grade: evidenceGrade,
    },
    business_risk_indicator: {
      band: 'low',
      explanation: 'Evidence-bounded indicator.',
      evidence_grade: evidenceGrade,
    },
    executive_summary: {
      summary: 'Backend-owned summary.',
      evidence_grade: evidenceGrade,
      observed_findings_count: 1,
      observations_count: 1,
      priority_actions: actions,
    },
    evidence_completeness: {
      scan_quality: 'partial',
      assessment_quality: 'incomplete',
      monitoring_state: 'monitoring_degraded',
      modules_skipped: ['asset_exposure'],
      skipped_score_bearing_modules: ['asset_exposure'],
      monitoring_degraded_signals: [
        { signal: 'certificate_transparency', state: 'signal_unavailable', message: 'Provider evidence was unavailable.' },
      ],
    },
    cyber_mot_domains: CYBER_MOT_DISPLAY_ORDER.map((domain) => ({
      ...domain,
      state: 'evidence_insufficient',
      coverage: 'partial',
      summary: 'Further evidence is required.',
      finding_count: 0,
      evidence_grade: evidenceGrade,
    })),
    observed_findings: [{
      finding_id: 'finding-1',
      title: 'Actionable signal',
      explanation: 'The signal passed its evidence contract.',
      severity: 'high',
      confidence: 91,
      evidence_grade: evidenceGrade,
    }],
    observations: [{
      finding_id: 'observation-1',
      title: 'Critical observation',
      explanation: 'This remains explicitly classified as an observation.',
      severity: 'critical',
      confidence: 70,
      evidence_grade: { ...evidenceGrade, grade: 'L0' },
    }],
    remediation_actions: actions,
    limitations: [],
  }
}

const healthyMonitoring = () => ({
  version: 'signal-monitoring-state-v1',
  signals: Object.fromEntries([
    'dns',
    'certificate_transparency',
    'website_security',
    'email_protection',
    'attack_surface',
    'technology_visibility',
    'vulnerability_intelligence',
    'registration_data',
  ].map((signal) => [signal, {
    state: 'monitoring_healthy',
    message: `${signal} checks completed normally in this run.`,
    evidence: { modules: [], incomplete_modules: [], providers: {} },
  }])),
})

const completeModules = () => ({
  dns: { has_mx: true },
  email_security: { spf: { present: true }, dmarc: { present: true, policy: 'reject' } },
  headers: { values: {} },
  ssl: { https_available: true, https_probe_executed: true },
  subdomains: { count: 1 },
  admin_surface_detection: {},
  cloud_storage_discovery: {},
  certificate_intelligence: { total_certificates: 1 },
  brand_monitoring: { candidates: [] },
  identity_discovery: { high_risk_count: 0 },
  saas_exposure: { count: 0 },
  third_party_discovery: { count: 0 },
  technology_detection: { count: 0 },
  vendor_relationships: { high_confidence: 0 },
})

const dseEvidence = ({ shortHsts = false, noSameSite = false } = {}) => ({
  caa: { present: true, records: ['0 issue "example-ca.test"'], issuers: ['example-ca.test'], error: null },
  hsts: shortHsts
    ? { present: true, max_age: 86_400, include_subdomains: true, preload_directive: true, preload_eligible: false, error: null }
    : { present: true, max_age: 31_536_000, include_subdomains: true, preload_directive: true, preload_eligible: true, error: null },
  cookies: {
    found: noSameSite ? 1 : 0,
    cookies: noSameSite ? [{ name: 'session' }] : [],
    insecure_count: 0,
    no_httponly: 0,
    no_samesite: noSameSite ? 1 : 0,
    error: null,
  },
  source: 'dns_headers_analysis',
  error: null,
})

const rawDseFinding = (findingId, evidence) => {
  const row = buildDseFindings(evidence, 'example.test')
    .find((finding) => finding.id === findingId)
  if (!row) throw new Error(`B1 producer did not emit ${findingId}`)
  return row
}

const cspProducer = (policy) => {
  const modules = {
    ...completeModules(),
    dns: { resolves: true, has_mx: true },
    ssl: { https_available: true, https_probe_executed: true },
    headers: {
      accessible: true,
      final_https: true,
      validation_uncertain: false,
      status_code: 200,
      response_url: 'https://example.test/',
      values: {
        'strict-transport-security': 'max-age=31536000; includeSubDomains',
        'content-security-policy': policy,
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
        'permissions-policy': 'geolocation=()',
      },
    },
  }
  const scored = computeScore(modules, 'example.test')
  const produced = scored.findings.find((row) => row.id === 'csp_weak_policy')
  if (!produced) throw new Error(`CSP producer did not emit csp_weak_policy for ${policy}`)
  return { modules, score: scored.score, finding: normalizeFindingSchema(produced) }
}

const hstsFinding = rawDseFinding('dse_hsts_short_maxage', dseEvidence({ shortHsts: true }))
const sameSiteFinding = rawDseFinding('dse_cookie_no_samesite', dseEvidence({ noSameSite: true }))

function b3ReportFixture(name, { findings = [], quality = 'complete', mutateReport = null } = {}) {
  const scanId = `scan-b3-cx-${name}`
  const rawReport = {
    scan_id: scanId,
    domain_id: 'domain-b3-cx',
    domain: 'example.test',
    status: 'completed',
    cyber_metrics_score: 81,
    risk_level: 'good',
    started_at: '2026-08-30T10:00:00.000Z',
    completed_at: '2026-08-30T10:05:00.000Z',
    findings,
    recommendations: [],
    scan_quality: { status: quality, modules_skipped: [], warnings: [] },
    monitoring_states: healthyMonitoring(),
    modules: completeModules(),
  }
  if (mutateReport) mutateReport(rawReport)
  const snapshot = composeSnapshot({
    snapshotId: `snapshot-b3-cx-${name}`,
    workspaceId: 'workspace-b3-cx',
    domainId: rawReport.domain_id,
    scanId,
    domain: rawReport.domain,
    report: rawReport,
    cyberEssentials: null,
    ceReadiness: null,
    caseRows: [],
    questionSetVersions: [],
    certificateLifecycleRecords: [],
    attackSurfaceLifecycleRecords: [],
    supersedesSnapshotId: null,
    builtAt: '2026-08-30T10:06:00.000Z',
  })
  const report = buildExecutiveReportV2({
    scan: { id: scanId, domain_id: rawReport.domain_id, domain: rawReport.domain },
    read: {
      snapshot,
      row: { id: snapshot.snapshot.snapshot_id },
      integrity: { verified: true },
    },
  })
  return { rawReport, snapshot, report }
}

function websiteDomain(candidate) {
  return candidate.report.cyber_mot_domains
    .find((domain) => domain.domain_key === 'website_security')
}

function websiteRow() {
  return screen.getByText('Website Security')
    .closest('.flex.items-start.justify-between')
}

describe('ExecutiveReportV2 report-first corrective', () => {
  it('places the first three canonical actions immediately after the overall summary and keeps the full list', () => {
    const { container } = render(<ExecutiveReportV2 report={reportFixture()} />)

    const priority = screen.getByText('Priority Actions').closest('section')
    const recommended = screen.getByText('Recommended Actions').closest('section')
    expect(priority).not.toBeNull()
    expect(recommended).not.toBeNull()

    expect(within(priority).getByText('First action')).toBeInTheDocument()
    expect(within(priority).getByText('Second action')).toBeInTheDocument()
    expect(within(priority).getByText('Third action')).toBeInTheDocument()
    expect(within(priority).queryByText('Fourth action')).not.toBeInTheDocument()
    expect(within(recommended).getByText('Fourth action')).toBeInTheDocument()

    const text = container.textContent
    expect(text.indexOf('Priority Actions')).toBeLessThan(text.indexOf('Email Protection'))
    expect(text.indexOf('Recommended Actions')).toBeLessThan(text.indexOf('Assessment Score'))
    expect(text.indexOf('Fourth action')).toBeLessThan(text.indexOf('81'))
    expect(screen.getByText('81')).toBeInTheDocument()
  })

  it('renders backend-owned coverage, severity, confidence and evidence grade without reclassifying observations', () => {
    render(<ExecutiveReportV2 report={reportFixture()} />)

    const coverage = screen.getByRole('region', { name: 'Assessment coverage' })
    expect(coverage).toHaveTextContent('partial')
    expect(coverage).toHaveTextContent('incomplete')
    expect(coverage).toHaveTextContent('monitoring_degraded')
    expect(coverage).toHaveTextContent('asset_exposure')
    expect(coverage).toHaveTextContent('signal_unavailable')

    const findingSection = screen.getByText('Observed Findings').closest('section')
    expect(within(findingSection).getByText('Confidence: 91')).toBeInTheDocument()
    expect(within(findingSection).getByText('Evidence grade: L1')).toBeInTheDocument()

    const observationSection = screen.getByText('Observations').closest('section')
    expect(within(observationSection).getByText('Critical observation')).toBeInTheDocument()
    expect(within(observationSection).getByLabelText('Observation severity: critical')).toHaveTextContent('critical')
    expect(within(observationSection).getByText('Confidence: 70')).toBeInTheDocument()
    expect(within(observationSection).getByText('Evidence grade: L0')).toBeInTheDocument()
  })

  it('does not invent an info severity for a legacy observation with no recorded severity', () => {
    const report = reportFixture()
    delete report.observations[0].severity
    render(<ExecutiveReportV2 report={report} />)

    const observationSection = screen.getByText('Observations').closest('section')
    expect(within(observationSection).getByText('Critical observation')).toBeInTheDocument()
    expect(within(observationSection).queryByLabelText(/Observation severity:/)).not.toBeInTheDocument()
    expect(within(observationSection).queryByText(/^info$/i)).not.toBeInTheDocument()
    expect(within(observationSection).getByText('Confidence: 70')).toBeInTheDocument()
    expect(within(observationSection).getByText('Evidence grade: L0')).toBeInTheDocument()
  })

  it.each([
    {
      name: 'low HSTS complete',
      options: { findings: [hstsFinding] },
      findingId: 'dse_hsts_short_maxage',
      findingTitle: 'HSTS max-age Below Recommended Minimum',
      actionId: 'web.header.hsts',
      actionTitle: 'Add or strengthen HSTS',
      coverage: 'complete',
      badge: 'Issue detected',
    },
    {
      name: 'low SameSite complete',
      options: { findings: [sameSiteFinding] },
      findingId: 'dse_cookie_no_samesite',
      findingTitle: '1 Cookie Missing SameSite Attribute',
      actionId: 'web.cookie.flags',
      actionTitle: 'Set secure cookie flags',
      coverage: 'complete',
      badge: 'Issue detected',
    },
    {
      name: 'low HSTS global partial',
      options: { findings: [hstsFinding], quality: 'partial' },
      findingId: 'dse_hsts_short_maxage',
      findingTitle: 'HSTS max-age Below Recommended Minimum',
      actionId: 'web.header.hsts',
      actionTitle: 'Add or strengthen HSTS',
      coverage: 'partial',
      badge: 'Issue detected · provisional',
    },
    {
      name: 'low HSTS required incomplete',
      options: {
        findings: [hstsFinding],
        mutateReport: (report) => {
          report.modules.headers = {
            incomplete: true,
            incomplete_reason: 'origin_error_no_serviceable_response',
          }
        },
      },
      findingId: 'dse_hsts_short_maxage',
      findingTitle: 'HSTS max-age Below Recommended Minimum',
      actionId: 'web.header.hsts',
      actionTitle: 'Add or strengthen HSTS',
      coverage: 'partial',
      badge: 'Issue detected · provisional',
    },
  ])('renders backend-owned $name truth without a frontend verdict', ({
    name, options, findingId, findingTitle, actionId, actionTitle, coverage, badge,
  }) => {
    const candidate = b3ReportFixture(name.replaceAll(' ', '-'), options)
    const website = websiteDomain(candidate)
    expect(website).toMatchObject({
      state: 'issue_detected',
      coverage,
      finding_count: 1,
      finding_ids: [findingId],
    })
    expect(candidate.report.remediation_actions.filter((action) => action.remediation_id === actionId)).toHaveLength(1)

    render(<ExecutiveReportV2 report={candidate.report} />)
    const row = websiteRow()
    expect(row).not.toBeNull()
    expect(within(row).getByText(badge)).toBeInTheDocument()
    expect(within(row).getByText('1 finding')).toBeInTheDocument()
    expect(within(row).queryByText('Healthy')).not.toBeInTheDocument()
    if (coverage === 'partial') expect(row).toHaveTextContent('1 issue detected (provisional evidence).')

    const findings = screen.getByText('Observed Findings').closest('section')
    expect(within(findings).getByText(findingTitle)).toBeInTheDocument()
    expect(within(findings).getByLabelText('Severity: low')).toHaveTextContent('low')

    const priority = screen.getByText('Priority Actions').closest('section')
    const recommended = screen.getByText('Recommended Actions').closest('section')
    expect(within(priority).getByText(actionTitle)).toBeInTheDocument()
    expect(within(recommended).getByText(actionTitle)).toBeInTheDocument()
  })

  it('keeps a critical observation explicit without giving it issue or action authority', () => {
    const candidate = b3ReportFixture('critical-observation', {
      findings: [{
        id: 'csp_weak_policy',
        finding_type: 'observation',
        module: 'headers',
        severity: 'critical',
        confidence: 77,
        score_impact: -100,
        title: 'Critical CSP observation control',
        description: 'Severity is presentation metadata and cannot create finding authority.',
        evidence: [{ type: 'http_header_probe', value: "style-src 'unsafe-inline'" }],
      }],
    })
    expect(websiteDomain(candidate)).toMatchObject({
      state: 'assessed_healthy',
      coverage: 'complete',
      finding_count: 0,
      finding_ids: [],
    })
    expect(candidate.snapshot.observed_findings).toHaveLength(0)
    expect(candidate.snapshot.observations).toHaveLength(1)
    expect(candidate.snapshot.remediation_actions).toHaveLength(0)

    render(<ExecutiveReportV2 report={candidate.report} />)
    const row = websiteRow()
    expect(within(row).getByText('Healthy')).toBeInTheDocument()
    expect(within(row).queryByText(/finding$/)).not.toBeInTheDocument()
    const observations = screen.getByText('Observations').closest('section')
    expect(within(observations).getByText('Critical CSP observation control')).toBeInTheDocument()
    expect(within(observations).getByLabelText('Observation severity: critical')).toHaveTextContent('critical')
    expect(screen.queryByText('Priority Actions')).not.toBeInTheDocument()
  })

  it('renders the real dangerous script/default CSP chain and keeps style-only CSP non-authoritative', () => {
    const dangerous = cspProducer("default-src 'self'; script-src 'unsafe-inline'")
    const candidate = b3ReportFixture('dangerous-csp', {
      findings: [dangerous.finding],
      mutateReport: (report) => {
        report.modules = dangerous.modules
        report.cyber_metrics_score = dangerous.score
      },
    })
    const snapshotFinding = candidate.snapshot.observed_findings
      .find((row) => row.finding_id === 'csp_weak_policy')
    const executiveFinding = candidate.report.observed_findings
      .find((row) => row.finding_id === 'csp_weak_policy')
    expect(dangerous.finding).toMatchObject({
      finding_type: 'finding',
      severity: 'medium',
      confidence: 90,
    })
    expect(websiteDomain(candidate)).toMatchObject({
      state: 'issue_detected',
      finding_count: 1,
      finding_ids: ['csp_weak_policy'],
    })
    expect(candidate.report.remediation_actions
      .filter((action) => action.remediation_id === 'web.header.csp')).toHaveLength(1)
    expect(snapshotFinding.confidence).toBe(dangerous.finding.confidence)
    expect(snapshotFinding.evidence_grade.grade).toBe('L1')
    expect(executiveFinding).toEqual(snapshotFinding)

    const { container } = render(<ExecutiveReportV2 report={candidate.report} />)
    const findings = screen.getByText('Observed Findings').closest('section')
    expect(within(findings).getByText('Weak Content Security Policy')).toBeInTheDocument()
    expect(within(findings).getByLabelText('Severity: medium')).toHaveTextContent('medium')
    expect(within(findings).getByText('Confidence: 90')).toBeInTheDocument()
    expect(within(findings).getByText('Evidence grade: L1')).toBeInTheDocument()
    expect(screen.getAllByText('Add or strengthen the Content Security Policy')).toHaveLength(2)
    expect(container.textContent.indexOf('Add or strengthen the Content Security Policy'))
      .toBeLessThan(container.textContent.indexOf('Assessment Score'))

    const styleOnly = cspProducer("default-src 'self'; script-src 'self'; style-src 'unsafe-inline'")
    const styleCandidate = b3ReportFixture('style-only-csp', {
      findings: [styleOnly.finding],
      mutateReport: (report) => {
        report.modules = styleOnly.modules
        report.cyber_metrics_score = styleOnly.score
      },
    })
    expect(styleOnly.finding).toMatchObject({ finding_type: 'observation', severity: 'low' })
    expect(websiteDomain(styleCandidate)).toMatchObject({ finding_count: 0, finding_ids: [] })
    expect(styleCandidate.snapshot.observed_findings).toHaveLength(0)
    expect(styleCandidate.snapshot.observations
      .filter((row) => row.finding_id === 'csp_weak_policy')).toHaveLength(1)
    expect(styleCandidate.report.remediation_actions
      .filter((action) => action.remediation_id === 'web.header.csp')).toHaveLength(0)
  })

  it('renders the real positive MTA-STS Executive chain with exact metadata and no frontend derivation', () => {
    const candidate = loadB2bCustomerProof('b2c-cx')
    const finding = candidate.snapshot_findings[0]
    expect(candidate.report_findings).toHaveLength(1)
    expect(candidate.email_domain).toMatchObject({
      state: 'issue_detected',
      finding_count: 1,
      finding_ids: ['email_intel_mta_sts_missing'],
    })
    expect(candidate.actions).toHaveLength(1)
    expect(candidate.executive.observed_findings
      .filter((row) => row.finding_id === finding.finding_id)).toEqual([finding])
    expect(candidate.executive.remediation_actions
      .filter((row) => row.remediation_id === 'email.mta_sts.enable')).toHaveLength(1)
    expect(finding.confidence).toBe(candidate.report_findings[0].confidence)
    expect(finding.evidence_grade.grade).toBe('L1')

    const { container } = render(<ExecutiveReportV2 report={candidate.executive} />)
    const findings = screen.getByText('Observed Findings').closest('section')
    const findingRow = within(findings).getByText('MTA-STS policy not published').closest('li')
    expect(findingRow).not.toBeNull()
    expect(within(findingRow).getByLabelText('Severity: low')).toHaveTextContent('low')
    expect(within(findingRow).getByText(`Confidence: ${finding.confidence}`)).toBeInTheDocument()
    expect(within(findingRow).getByText(`Evidence grade: ${finding.evidence_grade.grade}`)).toBeInTheDocument()
    expect(screen.getAllByText('Enable MTA-STS')).toHaveLength(2)
    expect(container.textContent.indexOf('Enable MTA-STS'))
      .toBeLessThan(container.textContent.indexOf('Assessment Score'))
  })

  it.each([
    {
      name: 'clean complete',
      options: {},
      state: 'assessed_healthy',
      coverage: 'complete',
      badge: 'Healthy',
      summary: 'Assessed — no material issue observed.',
    },
    {
      name: 'absent required',
      options: { mutateReport: (report) => { delete report.modules.headers } },
      state: 'not_yet_assessed',
      coverage: 'complete',
      badge: 'Not assessed',
      summary: 'Not yet assessed for this domain — required checks did not run.',
    },
    {
      name: 'attempted incomplete',
      options: {
        mutateReport: (report) => {
          report.modules.headers = {
            incomplete: true,
            incomplete_reason: 'origin_error_no_serviceable_response',
          }
        },
      },
      state: 'evidence_insufficient',
      coverage: 'degraded',
      badge: 'Evidence insufficient',
      summary: 'Required evidence (headers: origin error no serviceable response) was not usable this scan — not enough to assess.',
    },
    {
      name: 'finding-free partial',
      options: { quality: 'partial' },
      state: 'provisional',
      coverage: 'partial',
      badge: 'Provisional',
      summary: "No material issue observed, but this scan's coverage was provisional.",
    },
  ])('renders the exact canonical Website state for $name evidence', ({
    name, options, state, coverage, badge, summary,
  }) => {
    const candidate = b3ReportFixture(name.replaceAll(' ', '-'), options)
    expect(websiteDomain(candidate)).toMatchObject({
      state,
      coverage,
      finding_count: 0,
      finding_ids: [],
      summary,
    })

    render(<ExecutiveReportV2 report={candidate.report} />)
    const row = websiteRow()
    expect(within(row).getByText(badge)).toBeInTheDocument()
    expect(row).toHaveTextContent(summary)
  })

  it('keeps resolver and score methodology stamps independent and historical snapshot bytes immutable', () => {
    const current = b3ReportFixture('version-stamps', { findings: [hstsFinding] })
    expect(current.report.methodology).toMatchObject({
      cyber_mot_resolver_version: '2026-08-30.2',
      cyber_metrics_score_methodology_version: '2026-08-26.1',
    })

    const historicalSnapshot = structuredClone(current.snapshot)
    historicalSnapshot.methodology.cyber_mot_resolver_version = '2026-08-30.1'
    for (const domain of historicalSnapshot.domains) {
      domain.methodology_version = '2026-08-30.1'
      if (domain.trend) domain.trend.resolver_version = '2026-08-30.1'
    }
    const bytesBefore = JSON.stringify(historicalSnapshot)
    const historicalReport = buildExecutiveReportV2({
      scan: { id: historicalSnapshot.snapshot.scan_id, domain: historicalSnapshot.snapshot.domain },
      read: {
        snapshot: historicalSnapshot,
        row: { id: historicalSnapshot.snapshot.snapshot_id },
        integrity: { verified: true },
      },
    })
    expect(JSON.stringify(historicalSnapshot)).toBe(bytesBefore)
    expect(historicalReport.methodology.cyber_mot_resolver_version).toBe('2026-08-30.1')

    render(<ExecutiveReportV2 report={historicalReport} />)
    expect(screen.getByText(/Resolver 2026-08-30\.1 · Score methodology 2026-08-26\.1/)).toBeInTheDocument()
    expect(JSON.stringify(historicalSnapshot)).toBe(bytesBefore)
  })

  it('renders the real isolated-vCenter backend chain verbatim with one canonical action', () => {
    const proof = loadB2bCustomerProof('b2b-cx')
    const candidate = proof.positive
    const finding = candidate.snapshot_admin_findings[0]
    const action = candidate.admin_actions[0]
    const attackSurface = candidate.executive.cyber_mot_domains
      .find((domain) => domain.domain_key === 'attack_surface')

    expect(candidate.raw_services).toMatchObject([{
      hostname: 'vcenter.example.com',
      product: 'VMware vCenter',
      finding_type: 'finding',
      risk_level: 'critical',
    }])
    expect(candidate.report_admin_findings).toHaveLength(1)
    expect(candidate.report_admin_findings[0]).toMatchObject({
      id: 'admin_surface_critical',
      finding_type: 'finding',
      severity: 'critical',
      score_impact: 0,
      title: 'Critical Admin Interface Exposed',
    })
    expect(attackSurface).toMatchObject({
      state: 'issue_detected',
      finding_count: 1,
      finding_ids: ['admin_surface_critical'],
    })
    expect(finding).toMatchObject({
      finding_id: 'admin_surface_critical',
      title: 'Critical Admin Interface Exposed',
      severity: 'critical',
    })
    expect(candidate.admin_actions).toHaveLength(1)
    expect(action).toMatchObject({
      remediation_id: 'asm.exposure.admin',
      title: 'Restrict administrative interfaces',
      finding_ids: ['admin_surface_critical'],
    })
    expect(candidate.admin_cases).toHaveLength(1)
    expect(candidate.score).toBe(candidate.paired_score_control)
    expect(candidate.executive.observed_findings
      .filter((row) => row.finding_id === 'admin_surface_critical')).toHaveLength(1)
    expect(candidate.executive.remediation_actions
      .filter((row) => row.remediation_id === 'asm.exposure.admin')).toHaveLength(1)

    render(<ExecutiveReportV2 report={candidate.executive} />)
    const row = screen.getByText('Attack Surface')
      .closest('.flex.items-start.justify-between')
    expect(within(row).getByText('Issue detected')).toBeInTheDocument()
    expect(within(row).getByText('1 finding')).toBeInTheDocument()

    const findings = screen.getByText('Observed Findings').closest('section')
    expect(within(findings).getByText(finding.title)).toBeInTheDocument()
    expect(within(findings).getByLabelText('Severity: critical')).toHaveTextContent('critical')

    const priority = screen.getByText('Priority Actions').closest('section')
    const recommended = screen.getByText('Recommended Actions').closest('section')
    expect(within(priority).getByText(action.title)).toBeInTheDocument()
    expect(within(recommended).getByText(action.title)).toBeInTheDocument()

    expect(proof.owner.raw_services.filter((service) =>
      service.hostname === 'vcenter-gitlab.example.com'
        && service.finding_type === 'finding')).toHaveLength(2)
    expect(proof.owner.report_admin_findings.filter((row) =>
      row.affected_hosts?.includes('vcenter-gitlab.example.com'))).toHaveLength(1)
    expect(proof.owner.report_admin_findings.some((row) =>
      row.affected_hosts?.includes('phpmyadmin.example.com'))).toBe(false)
    expect(proof.owner.admin_actions).toHaveLength(1)
    expect(proof.owner.admin_cases).toHaveLength(1)
    expect(proof.module_only.module_observations.map((service) => service.product).sort())
      .toEqual(['GitLab', 'OpenVPN Access Server'])
    expect(proof.module_only.attack_surface_domain.finding_ids)
      .toContain('subdomain_sensitive_gitlab_example_com')
    expect(proof.module_only.report_admin_findings).toHaveLength(0)
  })

  it('keeps isolated OpenVPN customer projection and UI byte-identical to its clean control', () => {
    const openvpnProof = loadB2bCustomerProof('b2b-openvpn-only-cx')
    const cleanProof = loadB2bCustomerProof('b2b-clean-control-cx')
    const candidate = openvpnProof.customer
    const clean = cleanProof.customer
    expect(candidate.module_observations).toMatchObject([{
      hostname: 'openvpn.example.com',
      product: 'OpenVPN Access Server',
      finding_type: 'observation',
      confidence: 'low',
      severity: 'high',
    }])
    expect(clean.module_observations).toHaveLength(0)
    expect(candidate.report_admin_findings).toHaveLength(0)
    expect(candidate.snapshot_admin_findings).toHaveLength(0)
    expect(candidate.snapshot_admin_observations).toHaveLength(0)
    expect(candidate.admin_actions).toHaveLength(0)
    expect(candidate.admin_cases).toHaveLength(0)
    expect(candidate.attack_surface_domain).toMatchObject({
      state: 'assessed_healthy',
      finding_count: 0,
      finding_ids: [],
    })
    expect(openvpnProof.full_projection).toEqual(cleanProof.full_projection)

    // Even when a caller appends raw module diagnostics, the component must
    // render only the backend-owned Executive domain/finding/action contract.
    const reportWithModuleDiagnostics = {
      ...candidate.executive,
      modules: {
        admin_surface_detection: {
          services: candidate.module_observations,
          observations: candidate.module_observations,
        },
      },
    }
    const openvpnRender = render(<ExecutiveReportV2 report={reportWithModuleDiagnostics} />)
    const openvpnHtml = openvpnRender.container.innerHTML
    expect(screen.queryByText('OpenVPN Access Server')).not.toBeInTheDocument()
    expect(screen.queryByText('Critical Admin Interface Exposed')).not.toBeInTheDocument()
    expect(screen.queryByText('Restrict administrative interfaces')).not.toBeInTheDocument()
    openvpnRender.unmount()

    const cleanRender = render(<ExecutiveReportV2 report={clean.executive} />)
    expect(openvpnHtml).toBe(cleanRender.container.innerHTML)
  })

  it('renders the real S4 certificate finding and never derives it from raw module diagnostics', () => {
    const proof = loadB2bCustomerProof('b2d-cx')
    const positiveCases = [
      {
        candidate: proof.cert13,
        id: 'certificate_expiring_critical',
        severity: 'high',
        title: 'Logged certificate validity ends within 14 days',
      },
      {
        candidate: proof.cert14,
        id: 'certificate_expiring_soon',
        severity: 'medium',
        title: 'Logged certificate validity ends within 30 days',
      },
      {
        candidate: proof.cert29,
        id: 'certificate_expiring_soon',
        severity: 'medium',
        title: 'Logged certificate validity ends within 30 days',
      },
    ]

    for (const { candidate, id, severity, title } of positiveCases) {
      const producer = candidate.producer_signals.find((row) => row.signal === id)
      const finding = candidate.snapshot_cert_findings[0]
      const action = candidate.cert_actions[0]
      expect(candidate.report_cert_findings).toHaveLength(1)
      expect(candidate.snapshot_cert_findings).toHaveLength(1)
      expect(candidate.snapshot_cert_observations).toHaveLength(0)
      expect(finding).toMatchObject({
        finding_id: id,
        finding_type: 'finding',
        title,
        severity,
        module: 'certificate_intelligence',
        score_impact: 0,
      })
      expect(finding.title).toBe(producer.title)
      expect(finding.explanation).toBe(producer.description)
      expect(candidate.certificates_domain).toMatchObject({
        state: 'issue_detected',
        finding_count: 1,
        finding_ids: [id],
      })
      expect(candidate.cert_actions).toHaveLength(1)
      expect(action).toMatchObject({
        remediation_id: 'cert.expiry.expiring',
        title: 'Renew the certificate before expiry',
        finding_ids: [id],
      })
      expect(candidate.cert_cases.filter((row) => row.id === action.case_id)).toHaveLength(1)
      expect(candidate.executive.observed_findings.filter((row) => row.finding_id === id))
        .toEqual([finding])
      expect(candidate.executive.remediation_actions
        .filter((row) => row.remediation_id === 'cert.expiry.expiring')).toHaveLength(1)

      const rendered = render(<ExecutiveReportV2 report={candidate.executive} />)
      const domainRow = screen.getByText('Certificates & Trust')
        .closest('.flex.items-start.justify-between')
      expect(within(domainRow).getByText('Issue detected')).toBeInTheDocument()
      expect(within(domainRow).getByText('1 finding')).toBeInTheDocument()
      const findings = screen.getByText('Observed Findings').closest('section')
      const findingRow = within(findings).getByText(title).closest('li')
      expect(findingRow).not.toBeNull()
      expect(within(findingRow).getByLabelText(`Severity: ${severity}`)).toHaveTextContent(severity)
      expect(within(findingRow).getByText(producer.description)).toBeInTheDocument()
      expect(within(findings).queryByText('Finding')).not.toBeInTheDocument()
      const priority = screen.getByText('Priority Actions').closest('section')
      const recommended = screen.getByText('Recommended Actions').closest('section')
      expect(within(priority).getAllByText(action.title)).toHaveLength(1)
      expect(within(recommended).getAllByText(action.title)).toHaveLength(1)
      expect(rendered.container).not.toHaveTextContent(/live certificate verified/i)
      rendered.unmount()
    }

    for (const candidate of [proof.cert30, proof.tlsUnavailable]) {
      expect(candidate.snapshot_cert_findings).toHaveLength(0)
      expect(candidate.snapshot_cert_observations).toHaveLength(0)
      expect(candidate.cert_actions).toHaveLength(0)
      const reportWithRawDiagnostics = {
        ...candidate.executive,
        modules: {
          certificate_intelligence: {
            producer_signals: candidate.producer_signals,
            module_evidence: candidate.module_evidence,
          },
        },
      }
      const rendered = render(<ExecutiveReportV2 report={reportWithRawDiagnostics} />)
      const domainRow = screen.getByText('Certificates & Trust')
        .closest('.flex.items-start.justify-between')
      expect(within(domainRow).queryByText('Issue detected')).not.toBeInTheDocument()
      expect(screen.queryByText('Logged certificate validity ends within 14 days'))
        .not.toBeInTheDocument()
      expect(screen.queryByText('Logged certificate validity ends within 30 days'))
        .not.toBeInTheDocument()
      expect(screen.queryByText('Renew the certificate before expiry')).not.toBeInTheDocument()
      rendered.unmount()
    }
  })
})
