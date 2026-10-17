#!/usr/bin/env node
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { latestScoreWithheld } from '../workers/scan-api/src/engines/current-posture.js'
import { presentCyberEssentialsQuestionnaireReadiness } from '../workers/scan-api/src/engines/ce-readiness.js'
import { CE_QUESTIONS } from '../workers/scan-api/src/lib/cyber-essentials.js'
import { withShadowItInventoryCount } from '../workers/scan-api/src/routes/executive-dashboard.js'
import { aggregateDmarcTrafficBySource } from '../workers/scan-api/src/routes/email-protection.js'
import { PLAN_FEATURES, PLAN_LIMITS } from '../workers/scan-api/src/engines/entitlements.js'

test('latest withheld score never revives a prior numeric assessment', () => {
  assert.deepEqual(latestScoreWithheld({ display_score: null, message: 'TLS checks did not complete' }), {
    latest_score_withheld: true, latest_score_withheld_reasons: ['TLS checks did not complete'],
  })
  assert.equal(latestScoreWithheld({ display_score: 82 }).latest_score_withheld, false)
})

test('external control alignment cannot publish a grade before all answers exist', () => {
  const categories = [
    ...['boundary_protection', 'secure_configuration'].map((key) => ({ key, assessable: true, score: 100, gaps: [], externally_assessed: true })),
    ...['access_control', 'malware_protection', 'patch_management_readiness'].map((key) => ({ key, assessable: false, score: null })),
  ]
  const base = { assessable: true, score: 100, grade: 'A', status: 'likely_ready', categories }
  const incomplete = presentCyberEssentialsQuestionnaireReadiness(base, {})
  assert.equal(incomplete.score, null)
  assert.equal(incomplete.grade, null)
  assert.equal(incomplete.status, 'questionnaire_incomplete')
  assert.equal(incomplete.summary, '2 of 5 control areas externally aligned · questionnaire not started')
  assert.equal(incomplete.questionnaire.complete, false)
  const answers = Object.fromEntries(CE_QUESTIONS.map((c) => [c.control_key,
    Object.fromEntries(c.questions.map((q) => [q.key, 'yes']))]))
  const complete = presentCyberEssentialsQuestionnaireReadiness(base, answers)
  assert.equal(complete.questionnaire.complete, true)
  assert.equal(complete.grade, 'A')
})

test('Shadow IT evidence count uses the current inventory grain', () => {
  const domains = [{ domain_key: 'shadow_it_unmanaged_technology', evidence_count: 5,
    summary: '5 externally observed technologies/services' }, { domain_key: 'website_security', evidence_count: 3 }]
  const projected = withShadowItInventoryCount(domains, 6, true)
  assert.equal(projected[0].evidence_count, 6)
  assert.match(projected[0].summary, /^6 externally observed technologies\/services in the current inventory/)
  assert.deepEqual(projected[1], domains[1])
  assert.deepEqual(withShadowItInventoryCount(domains, 6, false), domains)
})

test('DMARC evidence reports separate automatically ingested and uploaded traffic', () => {
  const traffic = aggregateDmarcTrafficBySource([
    { report_source: 'inbound_email', disposition: 'none', msgs: 46, aligned: 46 },
    { report_source: 'signed_upload', disposition: 'none', msgs: 4, aligned: 2 },
  ])
  assert.equal(traffic.bySource.auto_ingested.total_messages, 46)
  assert.equal(traffic.bySource.auto_ingested.pass_rate, 100)
  assert.equal(traffic.bySource.customer_uploaded.total_messages, 4)
  assert.equal(traffic.bySource.customer_uploaded.pass_rate, 50)
  const noUpload = aggregateDmarcTrafficBySource([{ report_source: 'inbound_email', msgs: 46, aligned: 46 }])
  assert.equal(noUpload.bySource.customer_uploaded.pass_rate, null)
})

test('plan features and workspace limits agree', () => {
  for (const plan of ['starter', 'professional']) {
    assert.equal(PLAN_LIMITS[plan].workspaces, 1)
    assert.equal(PLAN_FEATURES[plan].includes('multi_workspace'), false)
  }
  assert.ok(PLAN_LIMITS.business.workspaces > 1)
  assert.equal(PLAN_FEATURES.business.includes('multi_workspace'), true)
})
