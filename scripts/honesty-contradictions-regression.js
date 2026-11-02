#!/usr/bin/env node
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { latestScoreWithheld } from '../workers/scan-api/src/engines/current-posture.js'
import { presentCyberEssentialsQuestionnaireReadiness } from '../workers/scan-api/src/engines/ce-readiness.js'
import { CE_QUESTIONS } from '../workers/scan-api/src/lib/cyber-essentials.js'
import { withEvidenceFreshness, withShadowItInventoryCount } from '../workers/scan-api/src/routes/executive-dashboard.js'
import { findingSeveritiesById, resolveSecurityCheckDomainStates } from '../workers/scan-api/src/engines/security-check-domains.js'
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

test('Each finding keeps its own severity; the area rating and the frozen resolver rows are unchanged', () => {
  const report = { scan_quality: { status: 'complete' }, findings: [
    { id: 'email_missing_dmarc', severity: 'high', category: 'email', title: 'Missing DMARC Policy', finding_type: 'finding' },
    { id: 'email_intel_mta_sts_missing', severity: 'low', category: 'email', title: 'MTA-STS policy not published', finding_type: 'finding' },
  ] }
  const severities = findingSeveritiesById(report)
  assert.equal(severities.get('email_missing_dmarc'), 'high')
  assert.equal(severities.get('email_intel_mta_sts_missing'), 'low')
  const rows = resolveSecurityCheckDomainStates(report)
  const email = rows.find((d) => d.domain_key === 'email_protection')
  assert.equal(email.highest_severity, 'high')
  assert.equal('finding_severities' in email, false)
  const projected = withEvidenceFreshness(rows, { findingSeverities: severities }).find((d) => d.domain_key === 'email_protection')
  assert.equal(projected.highest_severity, 'high')
  const bySeverity = Object.fromEntries(projected.finding_details.map((d) => [d.finding_id, d.severity]))
  assert.equal(bySeverity.email_intel_mta_sts_missing, 'low')
  assert.equal(bySeverity.email_missing_dmarc, 'high')
  // No source: unknown stays unknown, never the area rating.
  assert.ok(withEvidenceFreshness(rows).find((d) => d.domain_key === 'email_protection').finding_details.every((d) => d.severity === null))
})

test('Cyber Essentials containment reaches only its own read-route row, never a frozen resolver row', () => {
  const reason = 'workspace_multi_domain_not_aggregatable'
  const rows = resolveSecurityCheckDomainStates({ scan_quality: { status: 'complete' }, findings: [] }, { cyberEssentials: { status: 'not_assessed', containment_reason: reason, summary: 'Contained.' } })
  assert.equal(rows.some((d) => 'containment_reason' in d), false)
  const projected = withEvidenceFreshness(rows, { ceContainmentReason: reason })
  assert.deepEqual(projected.filter((d) => d.containment_reason).map((d) => d.domain_key), ['cyber_essentials_readiness'])
  assert.equal(withEvidenceFreshness(rows).some((d) => 'containment_reason' in d), false)
})

test('Shadow IT evidence count uses the current inventory grain', () => {
  const domains = [{ domain_key: 'shadow_it_unmanaged_technology', evidence_count: 5,
    summary: '5 externally observed technologies/services' }, { domain_key: 'website_security', evidence_count: 3 }]
  const projected = withShadowItInventoryCount(domains, 6, true)
  assert.equal(projected[0].evidence_count, 6)
  assert.match(projected[0].summary, /^6 technologies\/services externally observed in the latest scan\. Compare/)
  assert.deepEqual(projected[1], domains[1])
  assert.deepEqual(withShadowItInventoryCount(domains, 6, false), domains)
  // Items the latest scan did not see are counted apart, never as observed.
  const split = withShadowItInventoryCount(domains, { total: 8, not_seen: 1 }, true)
  assert.equal(split[0].evidence_count, 7)
  assert.equal(split[0].not_seen_count, 1)
  assert.match(split[0].summary, /^7 technologies\/services externally observed in the latest scan\. 1 not seen in the latest scan\./)
  assert.throws(() => withShadowItInventoryCount(domains, { total: 1, not_seen: 2 }, true))
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
