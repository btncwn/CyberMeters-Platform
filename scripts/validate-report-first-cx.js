#!/usr/bin/env node

import { buildScanReportPdf } from '../workers/scan-api/src/engines/pdf.js'
import { composeSnapshot } from '../workers/scan-api/src/engines/report-snapshot.js'
import { buildExecutiveReportV2 } from '../workers/scan-api/src/engines/executive-report.js'
import { buildDseFindings } from '../workers/scan-api/src/engines/dse-findings.js'
import { computeScore } from '../workers/scan-api/src/engines/scoring.js'
import { normalizeFindingSchema } from '../workers/scan-api/src/engines/findings.js'

let passed = 0
let failed = 0
const ok = (name, condition, detail = null) => {
  if (condition) passed += 1
  else {
    failed += 1
    console.error(`FAIL ${name}${detail == null ? '' : `: ${JSON.stringify(detail)}`}`)
  }
}

const grade = {
  grade: 'L1',
  source_type: 'product_policy',
  basis: 'Recorded external evidence.',
  limits: ['Limited to the evidence recorded in this assessment.'],
  repeat_confirmed: false,
}

const actions = [
  { remediation_id: 'a.critical', priority: 'critical', title: 'First action', action: 'Do first.', finding_ids: ['f1'] },
  { remediation_id: 'a.high', priority: 'high', title: 'Second action', action: 'Do second.', finding_ids: ['f2'] },
  { remediation_id: 'a.medium', priority: 'medium', title: 'Third action', action: 'Do third.', finding_ids: ['f3'] },
  { remediation_id: 'a.low', priority: 'low', title: 'Fourth action', action: 'Do fourth.', finding_ids: ['f4'] },
]

const pdfPlainText = (bytes) => {
  const source = new TextDecoder('latin1').decode(bytes)
  return [...source.matchAll(/\((.*?)\) Tj/g)]
    .map((match) => match[1].replace(/\\([\\()])/g, '$1'))
    .join('\n')
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
  // The real engine normalises the producer row before report assembly.
  const finding = normalizeFindingSchema(produced)
  return { modules, score: scored.score, finding }
}

const baseB3Report = ({ findings = [], quality = 'complete' } = {}) => ({
  scan_id: 'scan-b3-cx',
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
})

const composeB3Case = (name, { findings = [], quality = 'complete', mutateReport = null } = {}) => {
  const report = baseB3Report({ findings, quality })
  if (mutateReport) mutateReport(report)
  const scanId = `scan-b3-cx-${name}`
  report.scan_id = scanId
  const candidateSnapshot = composeSnapshot({
    snapshotId: `snapshot-b3-cx-${name}`,
    workspaceId: 'workspace-b3-cx',
    domainId: report.domain_id,
    scanId,
    domain: report.domain,
    report,
    cyberEssentials: null,
    ceReadiness: null,
    caseRows: [],
    questionSetVersions: [],
    certificateLifecycleRecords: [],
    attackSurfaceLifecycleRecords: [],
    supersedesSnapshotId: null,
    builtAt: '2026-08-30T10:06:00.000Z',
  })
  const read = {
    snapshot: candidateSnapshot,
    row: { id: candidateSnapshot.snapshot.snapshot_id },
    integrity: { verified: true },
  }
  const scan = { id: scanId, domain_id: report.domain_id, domain: report.domain }
  const executive = buildExecutiveReportV2({ scan, read })
  const pdfBytes = buildScanReportPdf(scan, read)
  return { report, snapshot: candidateSnapshot, executive, pdfBytes, pdfText: pdfPlainText(pdfBytes) }
}

const websiteDomain = (candidate) => candidate.domains
  .find((domain) => domain.domain_key === 'website_security')

const websiteExecutiveDomain = (candidate) => candidate.executive.cyber_mot_domains
  .find((domain) => domain.domain_key === 'website_security')

const actionCount = (candidate, remediationId) => candidate.snapshot.remediation_actions
  .filter((action) => action.remediation_id === remediationId).length

const snapshot = {
  snapshot: {
    snapshot_id: 'snap-report-first-cx',
    domain: 'example.test',
    as_of: '2026-08-30T10:00:00.000Z',
  },
  overall: {
    cyber_metrics_score: 81,
    score_band: 'good',
    assessment: {
      authoritative: false,
      provisional: true,
      message: 'The score is provisional because assessment coverage is incomplete.',
    },
    assessment_evidence_grade: grade,
    evidence_grade: grade,
    business_risk_indicator: {
      band: null,
      provisional: true,
      explanation: 'The indicator is not authoritative.',
      evidence_grade: grade,
    },
    evidence_completeness: {
      scan_quality: 'partial',
      assessment_quality: 'incomplete',
      monitoring_state: 'monitoring_degraded',
      modules_skipped: ['asset_exposure'],
      skipped_score_bearing_modules: ['asset_exposure'],
    },
    not_fully_assessed: [],
  },
  domains: [{
    domain_key: 'website_security',
    display_name: 'Website Security',
    state: 'issue_detected',
    coverage: 'partial',
    state_reason: 'A backend-owned issue was detected.',
    limitations: [],
  }],
  monitoring_states: { signals: {} },
  observed_findings: [{
    finding_id: 'finding-1',
    title: 'Actionable signal',
    explanation: 'The signal passed its evidence contract.',
    severity: 'high',
    confidence: 91,
    evidence_grade: grade,
    score_impact: 0,
    domain_keys: ['website_security'],
  }],
  observations: [{
    finding_id: 'observation-1',
    title: 'Critical observation',
    explanation: 'This remains explicitly classified as an observation.',
    severity: 'critical',
    confidence: 70,
    evidence_grade: { ...grade, grade: 'L0' },
    score_impact: 0,
  }],
  remediation_actions: actions,
  unmapped_finding_types: [],
  limitations: [],
}

const pdf = buildScanReportPdf(
  { id: 'scan-report-first-cx', domain: 'example.test' },
  { snapshot, row: { id: 'snap-report-first-cx' }, integrity: { verified: true } },
)
const plain = pdfPlainText(pdf)
const normalizedPlain = plain.replace(/\s+/g, ' ')

const priorityStart = plain.indexOf('Priority Actions (3)')
const domainsStart = plain.indexOf('Eight-Domain Cyber MOT')
const recommendedStart = plain.indexOf('Recommended Actions (4)')
const assessmentScoreStart = plain.indexOf('Assessment Score')
const priorityBlock = plain.slice(priorityStart, domainsStart)
const recommendedBlock = plain.slice(recommendedStart)

ok('priority section follows overall and precedes domain detail', priorityStart >= 0 && priorityStart < domainsStart)
ok('priority section contains canonical actions one to three',
  ['First action', 'Second action', 'Third action'].every((title) => priorityBlock.includes(title)))
ok('priority section excludes the fourth action', !priorityBlock.includes('Fourth action'))
ok('full action list remains present', recommendedStart >= 0 && recommendedBlock.includes('Fourth action'))
ok('numeric score and assessment band follow evidence, findings and the full action list',
  assessmentScoreStart > recommendedStart &&
  plain.indexOf('Provisional Score: 81 / 100') > recommendedStart &&
  plain.indexOf('CyberMeters assessment band: good') > recommendedStart)
ok('observation severity remains visible without reclassification', plain.includes('[CRITICAL] Critical observation'))
ok('finding confidence and evidence grade are rendered verbatim',
  plain.includes('Confidence: 91 - Evidence grade: L1'))
ok('observation confidence and evidence grade are rendered verbatim',
  plain.includes('Confidence: 70 - Evidence grade: L0'))
ok('backend-owned coverage values are rendered verbatim',
  normalizedPlain.includes('Assessment coverage - scan quality: partial; assessment quality: incomplete; monitoring state: monitoring_degraded.'))
ok('skipped module identities remain visible',
  plain.includes('Modules skipped: asset_exposure.') && plain.includes('Score-bearing modules skipped: asset_exposure.'))
ok('score bytes remain a presentation input, not recalculated', plain.includes('Provisional Score: 81 / 100'))

const legacySeveritySnapshot = structuredClone(snapshot)
delete legacySeveritySnapshot.observations[0].severity
const legacySeverityPdf = buildScanReportPdf(
  { id: 'scan-report-first-cx-legacy-severity', domain: 'example.test' },
  { snapshot: legacySeveritySnapshot, row: { id: 'snap-report-first-cx-legacy-severity' }, integrity: { verified: true } },
)
const legacySeverityPlain = pdfPlainText(legacySeverityPdf)
ok('legacy observation without explicit severity gains no invented info label',
  legacySeverityPlain.includes('Critical observation') &&
  !legacySeverityPlain.includes('[INFO] Critical observation'))

const legacyFindingCases = [
  ['absent', (item) => { delete item.severity }],
  ['null', (item) => { item.severity = null }],
  ['empty', (item) => { item.severity = '' }],
  ['whitespace', (item) => { item.severity = '   ' }],
]

for (const [label, mutate] of legacyFindingCases) {
  const candidate = structuredClone(snapshot)
  const title = `Legacy ${label} finding`
  candidate.observed_findings[0].title = title
  mutate(candidate.observed_findings[0])
  const candidatePlain = pdfPlainText(buildScanReportPdf(
    { id: `scan-report-first-cx-legacy-finding-${label}`, domain: 'example.test' },
    { snapshot: candidate, row: { id: `snap-report-first-cx-legacy-finding-${label}` }, integrity: { verified: true } },
  ))
  const titleOccurrences = candidatePlain.split(title).length - 1
  ok(`legacy ${label} finding has a clean heading in domain detail and Observed Findings`,
    titleOccurrences >= 2 &&
    !candidatePlain.includes(`[] ${title}`) &&
    !candidatePlain.includes(`[INFO] ${title}`))
}

const explicitSeveritySnapshot = structuredClone(snapshot)
explicitSeveritySnapshot.observed_findings[0].title = 'Explicit severity finding'
explicitSeveritySnapshot.observed_findings[0].severity = '  medium  '
const explicitSeverityPlain = pdfPlainText(buildScanReportPdf(
  { id: 'scan-report-first-cx-explicit-finding-severity', domain: 'example.test' },
  { snapshot: explicitSeveritySnapshot, row: { id: 'snap-report-first-cx-explicit-finding-severity' }, integrity: { verified: true } },
))
ok('explicit non-empty finding severity remains visible in domain detail and Observed Findings',
  explicitSeverityPlain.split('[MEDIUM] Explicit severity finding').length - 1 >= 2)

const emptySnapshot = structuredClone(snapshot)
emptySnapshot.remediation_actions = []
const emptyPdf = new TextDecoder('latin1').decode(buildScanReportPdf(
  { id: 'scan-report-first-cx-empty', domain: 'example.test' },
  { snapshot: emptySnapshot, row: { id: 'snap-report-first-cx-empty' }, integrity: { verified: true } },
))
ok('empty priority summary is omitted while the full empty-state remains',
  !emptyPdf.includes('Priority Actions') && emptyPdf.includes('Recommended Actions \\(0\\)'))

// B3 CX/Integration join: every case starts with raw B1 producer-shaped rows and
// traverses the real snapshot, Executive projection and PDF. No repaired domain
// row is authored in this carrier.
const hstsFinding = rawDseFinding('dse_hsts_short_maxage', dseEvidence({ shortHsts: true }))
const sameSiteFinding = rawDseFinding('dse_cookie_no_samesite', dseEvidence({ noSameSite: true }))
const dangerousCsp = cspProducer("default-src 'self'; script-src 'unsafe-inline'")
const styleOnlyCsp = cspProducer("default-src 'self'; script-src 'self'; style-src 'unsafe-inline'")
const criticalObservation = {
  id: 'csp_weak_policy',
  finding_type: 'observation',
  module: 'headers',
  severity: 'critical',
  confidence: 77,
  score_impact: -100,
  title: 'Critical CSP observation control',
  description: 'Severity is presentation metadata and cannot create finding authority.',
  evidence: [{ type: 'http_header_probe', value: "style-src 'unsafe-inline'" }],
}

const cleanComplete = composeB3Case('clean-complete')
const cleanWebsite = websiteDomain(cleanComplete.snapshot)
ok('B3 C1 clean complete Website remains assessed healthy',
  cleanWebsite?.state === 'assessed_healthy' && cleanWebsite?.coverage === 'complete' &&
  cleanWebsite?.finding_count === 0 && JSON.stringify(cleanWebsite?.finding_ids) === '[]')
ok('B3 C1 clean complete state projects unchanged to Executive and PDF',
  websiteExecutiveDomain(cleanComplete)?.state === 'assessed_healthy' &&
  cleanComplete.pdfText.includes('Conclusion: Assessed - no material issue observed'))

const hstsComplete = composeB3Case('hsts-complete', { findings: [hstsFinding] })
const hstsCompleteWebsite = websiteDomain(hstsComplete.snapshot)
ok('B3 low HSTS complete snapshot owns issue/count/identity',
  hstsCompleteWebsite?.state === 'issue_detected' && hstsCompleteWebsite?.coverage === 'complete' &&
  hstsCompleteWebsite?.finding_count === 1 &&
  JSON.stringify(hstsCompleteWebsite?.finding_ids) === '["dse_hsts_short_maxage"]')
ok('B3 low HSTS complete retains one canonical action through Executive projection',
  actionCount(hstsComplete, 'web.header.hsts') === 1 &&
  hstsComplete.executive.remediation_actions.filter((action) => action.remediation_id === 'web.header.hsts').length === 1)
ok('B3 low HSTS complete PDF renders issue, finding and canonical action',
  hstsComplete.pdfText.includes('Conclusion: Issue detected') &&
  hstsComplete.pdfText.includes('[LOW] HSTS max-age Below Recommended Minimum') &&
  hstsComplete.pdfText.includes('Add or strengthen HSTS'))

const sameSiteComplete = composeB3Case('samesite-complete', { findings: [sameSiteFinding] })
const sameSiteWebsite = websiteDomain(sameSiteComplete.snapshot)
ok('B3 low SameSite complete snapshot owns issue/count/identity',
  sameSiteWebsite?.state === 'issue_detected' && sameSiteWebsite?.coverage === 'complete' &&
  sameSiteWebsite?.finding_count === 1 &&
  JSON.stringify(sameSiteWebsite?.finding_ids) === '["dse_cookie_no_samesite"]')
ok('B3 low SameSite remains one canonical action through Executive and PDF',
  actionCount(sameSiteComplete, 'web.cookie.flags') === 1 &&
  sameSiteComplete.executive.remediation_actions.filter((action) => action.remediation_id === 'web.cookie.flags').length === 1 &&
  sameSiteComplete.pdfText.includes('Set secure cookie flags'))

const hstsGlobalPartial = composeB3Case('hsts-global-partial', {
  findings: [hstsFinding],
  quality: 'partial',
})
const hstsGlobalPartialWebsite = websiteDomain(hstsGlobalPartial.snapshot)
ok('B3 low HSTS survives global partial with exact caveated state/count/identity',
  hstsGlobalPartialWebsite?.state === 'issue_detected' && hstsGlobalPartialWebsite?.coverage === 'partial' &&
  hstsGlobalPartialWebsite?.finding_count === 1 &&
  JSON.stringify(hstsGlobalPartialWebsite?.finding_ids) === '["dse_hsts_short_maxage"]' &&
  /provisional evidence/i.test(hstsGlobalPartialWebsite?.summary || ''))
ok('B3 global-partial caveat and finding survive Executive/PDF while score remains backend-owned',
  websiteExecutiveDomain(hstsGlobalPartial)?.coverage === 'partial' &&
  hstsGlobalPartial.executive.cyber_metrics_score.value === hstsGlobalPartial.snapshot.overall.cyber_metrics_score &&
  hstsGlobalPartial.pdfText.includes('1 issue detected (provisional evidence).') &&
  hstsGlobalPartial.pdfText.includes('[LOW] HSTS max-age Below Recommended Minimum'))

const hstsRequiredIncomplete = composeB3Case('hsts-required-incomplete', {
  findings: [hstsFinding],
  mutateReport: (report) => {
    report.modules.headers = {
      incomplete: true,
      incomplete_reason: 'origin_error_no_serviceable_response',
    }
  },
})
const hstsRequiredIncompleteWebsite = websiteDomain(hstsRequiredIncomplete.snapshot)
ok('B3 C2 actionable HSTS outranks required-incomplete evidence with exact tuple',
  hstsRequiredIncompleteWebsite?.state === 'issue_detected' &&
  hstsRequiredIncompleteWebsite?.coverage === 'partial' &&
  hstsRequiredIncompleteWebsite?.finding_count === 1 &&
  JSON.stringify(hstsRequiredIncompleteWebsite?.finding_ids) === '["dse_hsts_short_maxage"]')
ok('B3 required-incomplete caveat and action survive Executive/PDF',
  /provisional evidence/i.test(websiteExecutiveDomain(hstsRequiredIncomplete)?.summary || '') &&
  actionCount(hstsRequiredIncomplete, 'web.header.hsts') === 1 &&
  hstsRequiredIncomplete.pdfText.includes('1 issue detected (provisional evidence).'))

const observationOnly = composeB3Case('critical-observation', { findings: [criticalObservation] })
const observationWebsite = websiteDomain(observationOnly.snapshot)
ok('B3 critical observation owns no issue/count/identity/action authority',
  observationWebsite?.state === 'assessed_healthy' && observationWebsite?.finding_count === 0 &&
  JSON.stringify(observationWebsite?.finding_ids) === '[]' &&
  observationOnly.snapshot.observed_findings.length === 0 && observationOnly.snapshot.observations.length === 1 &&
  observationOnly.snapshot.remediation_actions.length === 0)
ok('B3 critical observation remains explicitly labelled in Executive/PDF without promotion',
  observationOnly.executive.observations[0]?.severity === 'critical' &&
  observationOnly.executive.observed_findings.length === 0 &&
  observationOnly.pdfText.includes('[CRITICAL] Critical CSP observation control') &&
  observationOnly.pdfText.includes('Conclusion: Assessed - no material issue observed'))

const dangerousCspCase = composeB3Case('dangerous-csp', {
  findings: [dangerousCsp.finding],
  mutateReport: (report) => {
    report.modules = dangerousCsp.modules
    report.cyber_metrics_score = dangerousCsp.score
  },
})
const dangerousCspWebsite = websiteDomain(dangerousCspCase.snapshot)
const dangerousCspSnapshotFinding = dangerousCspCase.snapshot.observed_findings
  .find((row) => row.finding_id === 'csp_weak_policy')
const dangerousCspExecutiveFinding = dangerousCspCase.executive.observed_findings
  .find((row) => row.finding_id === 'csp_weak_policy')
ok('CX-A dangerous script/default CSP real producer owns Website issue/count/id and one action',
  dangerousCsp.finding.finding_type === 'finding' && dangerousCsp.finding.severity === 'medium' &&
  dangerousCsp.finding.confidence === 90 &&
  dangerousCspWebsite?.state === 'issue_detected' && dangerousCspWebsite?.finding_count === 1 &&
  JSON.stringify(dangerousCspWebsite?.finding_ids) === '["csp_weak_policy"]' &&
  actionCount(dangerousCspCase, 'web.header.csp') === 1)
ok('CX-A CSP confidence and evidence grade remain exact through snapshot and Executive',
  dangerousCspSnapshotFinding?.confidence === dangerousCsp.finding.confidence &&
  Boolean(dangerousCspSnapshotFinding?.evidence_grade?.grade) &&
  JSON.stringify(dangerousCspExecutiveFinding) === JSON.stringify(dangerousCspSnapshotFinding), {
    producerConfidence: dangerousCsp.finding.confidence,
    snapshot: dangerousCspSnapshotFinding,
    executive: dangerousCspExecutiveFinding,
  })
ok('CX-A dangerous CSP PDF renders exact finding metadata and canonical action before score',
  dangerousCspCase.pdfText.includes('[MEDIUM] Weak Content Security Policy') &&
  dangerousCspCase.pdfText.includes(`Confidence: ${dangerousCsp.finding.confidence} - Evidence grade: ${dangerousCspSnapshotFinding.evidence_grade.grade}`) &&
  dangerousCspCase.pdfText.includes('Add or strengthen the Content Security Policy') &&
  dangerousCspCase.pdfText.indexOf('Add or strengthen the Content Security Policy') <
    dangerousCspCase.pdfText.indexOf('Assessment Score'), {
      grade: dangerousCspSnapshotFinding?.evidence_grade?.grade,
      actionTitles: dangerousCspCase.snapshot.remediation_actions.map((row) => row.title),
    })

const styleOnlyCspCase = composeB3Case('style-only-csp', {
  findings: [styleOnlyCsp.finding],
  mutateReport: (report) => {
    report.modules = styleOnlyCsp.modules
    report.cyber_metrics_score = styleOnlyCsp.score
  },
})
ok('CX-A real style-only CSP remains an observation with no issue or action authority',
  styleOnlyCsp.finding.finding_type === 'observation' && styleOnlyCsp.finding.severity === 'low' &&
  websiteDomain(styleOnlyCspCase.snapshot)?.finding_count === 0 &&
  styleOnlyCspCase.snapshot.observed_findings.length === 0 &&
  styleOnlyCspCase.snapshot.observations.some((row) => row.finding_id === 'csp_weak_policy') &&
  actionCount(styleOnlyCspCase, 'web.header.csp') === 0)

const absentRequired = composeB3Case('absent-required', {
  mutateReport: (report) => { delete report.modules.headers },
})
const absentWebsite = websiteDomain(absentRequired.snapshot)
ok('B3 C3 absent required Website evidence is exactly not_yet_assessed',
  absentWebsite?.state === 'not_yet_assessed' && absentWebsite?.finding_count === 0 &&
  /required checks did not run/i.test(absentWebsite?.summary || '') &&
  absentRequired.pdfText.includes('Conclusion: Not yet assessed'))

const attemptedIncomplete = composeB3Case('attempted-incomplete', {
  mutateReport: (report) => {
    report.modules.headers = {
      incomplete: true,
      incomplete_reason: 'origin_error_no_serviceable_response',
    }
  },
})
const attemptedIncompleteWebsite = websiteDomain(attemptedIncomplete.snapshot)
ok('B3 C3 attempted incomplete Website evidence is exact evidence_insufficient/degraded',
  attemptedIncompleteWebsite?.state === 'evidence_insufficient' &&
  attemptedIncompleteWebsite?.coverage === 'degraded' &&
  attemptedIncompleteWebsite?.finding_count === 0 &&
  /origin error no serviceable response/.test(attemptedIncompleteWebsite?.summary || '') &&
  attemptedIncomplete.pdfText.includes('Conclusion: Evidence insufficient'))

const findingFreePartial = composeB3Case('finding-free-partial', { quality: 'partial' })
const findingFreePartialWebsite = websiteDomain(findingFreePartial.snapshot)
ok('B3 C3 finding-free assessed partial Website evidence is exactly provisional/partial',
  findingFreePartialWebsite?.state === 'provisional' &&
  findingFreePartialWebsite?.coverage === 'partial' &&
  findingFreePartialWebsite?.finding_count === 0 &&
  findingFreePartial.pdfText.includes('Conclusion: Provisional'))

ok('B3 C4 resolver and score methodology stamps remain independent',
  hstsComplete.snapshot.methodology?.cyber_mot_resolver_version === '2026-08-30.2' &&
  hstsComplete.snapshot.methodology?.cyber_metrics_score_methodology_version === '2026-08-26.1' &&
  hstsComplete.executive.methodology?.cyber_mot_resolver_version === '2026-08-30.2' &&
  hstsComplete.executive.methodology?.cyber_metrics_score_methodology_version === '2026-08-26.1')

const historicalSnapshot = structuredClone(cleanComplete.snapshot)
historicalSnapshot.methodology.cyber_mot_resolver_version = '2026-08-30.1'
for (const domain of historicalSnapshot.domains) {
  domain.methodology_version = '2026-08-30.1'
  if (domain.trend) domain.trend.resolver_version = '2026-08-30.1'
}
const historicalBytesBefore = new TextEncoder().encode(JSON.stringify(historicalSnapshot))
const historicalRead = {
  snapshot: historicalSnapshot,
  row: { id: historicalSnapshot.snapshot.snapshot_id },
  integrity: { verified: true },
}
const historicalExecutive = buildExecutiveReportV2({
  scan: { id: historicalSnapshot.snapshot.scan_id, domain: historicalSnapshot.snapshot.domain },
  read: historicalRead,
})
buildScanReportPdf(
  { id: historicalSnapshot.snapshot.scan_id, domain: historicalSnapshot.snapshot.domain },
  historicalRead,
)
const historicalBytesAfter = new TextEncoder().encode(JSON.stringify(historicalSnapshot))
ok('B3 historical snapshot bytes and stored resolver identity remain immutable after Executive/PDF reads',
  historicalBytesBefore.length === historicalBytesAfter.length &&
  historicalBytesBefore.every((byte, index) => byte === historicalBytesAfter[index]) &&
  historicalSnapshot.methodology.cyber_mot_resolver_version === '2026-08-30.1' &&
  historicalExecutive.methodology.cyber_mot_resolver_version === '2026-08-30.1')

console.log(`Report-first CX validation: ${passed} passed, ${failed} failed`)
if (failed) process.exit(1)
