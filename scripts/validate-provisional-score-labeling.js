#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')
const worker = path.join(root, 'workers', 'scan-api', 'src')
const assessmentPath = path.join(worker, 'engines', 'assessment-presentation.js')
const workspacesPath = path.join(worker, 'routes', 'workspaces-core.js')
const pagePath = path.join(root, 'frontend', 'src', 'pages', 'WorkspaceDetailPage.jsx')
const componentPath = path.join(root, 'frontend', 'src', 'components', 'CanonicalScore.jsx')
const frontendContractPath = path.join(root, 'frontend', 'src', 'lib', 'canonical-score-presentation.js')
const phase5Path = path.join(worker, 'engines', 'phase5-evidence.js')
const scoringPath = path.join(worker, 'engines', 'scoring.js')
const executiveReportPath = path.join(worker, 'engines', 'executive-report.js')
const pdfPath = path.join(worker, 'engines', 'pdf.js')

const assessment = await import(pathToFileURL(assessmentPath).href)
const { resolveAssessmentPresentation } = assessment
const { canonicalScoreView } = await import(pathToFileURL(frontendContractPath).href)

let passed = 0
let failed = 0
function ok(name, condition, detail = '') {
  if (condition) {
    passed += 1
    console.log(`PASS ${name}`)
  } else {
    failed += 1
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ''}`)
  }
}
function eq(name, actual, expected) {
  ok(name, Object.is(actual, expected), `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`)
}

const fixtures = [
  ['Blackbull-like partial 100', 100, 'partial'],
  ['CyberMeters-like degraded 85', 85, 'degraded'],
  ['Sheshire-like partial 85', 85, 'partial'],
]
for (const [label, score, quality] of fixtures) {
  const result = resolveAssessmentPresentation({ score, scanQuality: quality, status: 'completed' })
  eq(`${label}: numeric value is preserved`, result.display_score, score)
  eq(`${label}: state is explicitly provisional`, result.state, 'provisional')
  eq(`${label}: provisional flag is true`, result.provisional, true)
  eq(`${label}: no final rating is published`, result.display_rating, null)
  eq(`${label}: methodology identity is explicit`, result.methodology_version, '2026-08-24.1')
}

const monitoringIncomplete = resolveAssessmentPresentation({
  score: 100,
  scanQuality: 'complete',
  status: 'completed',
  monitoringStates: null,
  requireMonitoring: true,
})
eq('complete execution plus incomplete monitoring remains provisional', monitoringIncomplete.state, 'provisional')
eq('high score 100 survives monitoring provisionality', monitoringIncomplete.display_score, 100)

const monitoringHealthy = {
  signals: Object.fromEntries([
    'dns',
    'certificate_transparency',
    'website_security',
    'email_protection',
    'attack_surface',
    'technology_visibility',
    'vulnerability_intelligence',
    'registration_data',
  ].map((signal) => [signal, { state: 'monitoring_healthy', message: `${signal} complete` }])),
}
const established = resolveAssessmentPresentation({
  score: 82,
  scanQuality: 'complete',
  status: 'completed',
  monitoringStates: monitoringHealthy,
  requireMonitoring: true,
})
eq('complete evidence owns the established state', established.state, 'established')
eq('established evidence is not provisional', established.provisional, false)
eq('established evidence keeps its numeric score', established.display_score, 82)

const notEstablished = resolveAssessmentPresentation({ score: null, scanQuality: null, status: null })
eq('missing score state is not established', notEstablished.state, 'not_established')
eq('missing score remains null, never zero', notEstablished.display_score, null)
eq('not-established reason is preserved', notEstablished.message, 'Current posture not yet established.')

for (const malformed of [Number.NaN, '85', {}, undefined]) {
  const result = resolveAssessmentPresentation({ score: malformed, scanQuality: 'complete', status: 'completed' })
  eq(`malformed ${String(malformed)} never becomes established`, result.state, 'not_established')
  eq(`malformed ${String(malformed)} never becomes zero`, result.display_score, null)
}

const provisionalView = canonicalScoreView(resolveAssessmentPresentation({
  score: 100,
  scanQuality: 'partial',
  status: 'completed',
}))
eq('frontend contract preserves canonical provisional 100', provisionalView.score, 100)
eq('frontend contract visibly classifies canonical provisional state', provisionalView.state, 'provisional')
const establishedView = canonicalScoreView(established)
eq('frontend contract preserves canonical established value', establishedView.score, 82)
eq('frontend contract does not force established evidence provisional', establishedView.state, 'established')
for (const [label, envelope] of [
  ['missing envelope', undefined],
  ['missing state', { display_score: 100, provisional: true, authoritative: false }],
  ['missing provisional flag', { state: 'provisional', display_score: 100, authoritative: false }],
  ['inconsistent established flags', { state: 'established', display_score: 100, provisional: true, authoritative: false }],
]) {
  const view = canonicalScoreView(envelope)
  eq(`frontend contract fails ${label} closed`, view.state, 'not_established')
  eq(`frontend contract never fabricates a number for ${label}`, view.score, null)
}

const route = fs.readFileSync(workspacesPath, 'utf8')
const page = fs.readFileSync(pagePath, 'utf8')
const component = fs.existsSync(componentPath) ? fs.readFileSync(componentPath, 'utf8') : ''
const frontendContract = fs.readFileSync(frontendContractPath, 'utf8')
const phase5 = fs.readFileSync(phase5Path, 'utf8')
const scoring = fs.readFileSync(scoringPath, 'utf8')
const executiveReport = fs.readFileSync(executiveReportPath, 'utf8')
const pdf = fs.readFileSync(pdfPath, 'utf8')
const domainGet = route.slice(
  route.indexOf('GET /api/workspaces/:id/domains'),
  route.indexOf('POST /api/workspaces/:id/domains'),
)

ok('workspace domain API exposes the additive canonical latest_assessment contract',
  /^\s*latest_assessment:/m.test(domainGet))
ok('legacy latest_score compatibility field remains present',
  /^\s*latest_score:/m.test(domainGet))
ok('workspace domain API delegates assessment semantics to the existing canonical projection',
  /projectPhase5ScanRowsForCustomer/.test(domainGet) && /\.assessment/.test(domainGet))
ok('phase5 list projection carries frozen monitoring evidence into the canonical resolver',
  /monitoring_states:\s*report\.monitoring_states \?\? null/.test(phase5) &&
    /monitoringStates:\s*outcome\.monitoring_states/.test(phase5))
ok('workspace-domain scan selection is bound to the authorised workspace',
  /workspace_id\s*=\s*wd\.workspace_id/.test(domainGet))
ok('workspace-domain GET remains read-only', !/\b(?:INSERT|UPDATE|DELETE)\b/.test(domainGet))
ok('WorkspaceDetailPage passes backend canonical state to the shared score renderer',
  /<CanonicalScore\s+assessment=\{d\.latest_assessment\}/.test(page))
ok('WorkspaceDetailPage no longer derives a domain-row band from the numeric score',
  !/scoreBand\(d\.latest_score\)/.test(page))
ok('workspace overall Cyber Score remains backend-owned with no domain-row fallback',
  /postureEstablished\s*=\s*stats\?\.posture_established === true/.test(page) &&
    /postureScore != null \? postureScore : '—'/.test(page) &&
    !/postureScore[^\n]{0,120}domains\[/.test(page))
ok('shared renderer delegates to the explicit-state frontend contract',
  /canonicalScoreView\(assessment\)/.test(component) &&
    /assessment\?\.state/.test(frontendContract) &&
    /state\s*===\s*['"]provisional['"]/.test(frontendContract))
ok('shared renderer visibly emits the Provisional label', />Provisional</.test(component))
ok('shared renderer fails missing or malformed state to a dash',
  /Current posture not yet established\./.test(frontendContract) && component.includes('—'))
ok('Executive Report and PDF retain canonical provisional wording parity',
  /provisional:\s*assessment\.provisional \?\? null/.test(executiveReport) &&
    /Provisional Score/.test(pdf))
ok('Cyber Metrics Score algorithm and methodology identity remain unchanged',
  /score \+= f\.score_impact;/.test(scoring) &&
    /CYBER_METRICS_SCORE_METHODOLOGY_VERSION\s*=\s*"2026-08-24\.1"/.test(scoring))

console.log(`\nprovisional-score-labeling: ${passed} passed, ${failed} failed (${passed + failed} total)`)
if (failed) {
  console.error('provisional-score-labeling validation FAILED')
  process.exit(1)
}
console.log('provisional-score-labeling validation passed')
