// Canonical projection of bounded exposure receipts. Raw content is never an input
// to this module. Identity includes the rule and original path, never secret values.
import { RULES_BY_ID, EXPOSURE_CATALOG_VERSION, exposurePresentation, EXPOSURE_INDICATORS } from '../../../../shared/exposure/catalog.js';
import { safeExposureUrl } from '../../../../shared/exposure/redaction.js';
import { findingRemediation } from './remediation-registry.js';
import { EXPOSURE_INCOMPLETE_REASONS } from './exposure-jobs.js';

export const EXPOSURE_FINDING_PREFIX = 'external_exposure_';
const KEY = /^external_exposure_([a-z][a-z0-9-]+)__([a-f0-9]{64})$/;
const SAFE_INDICATORS = new Set(EXPOSURE_INDICATORS);
const COST_KEYS = ['requests', 'redirects', 'retries', 'bytes_wire', 'bytes_decoded', 'duration_ms', 'charged_requests', 'charged_bytes', 'unknown_attempts', 'attempts'];
const COVERAGE_KEYS = ['completed', 'pending', 'blocked', 'not_applicable', 'budget_exhausted', 'uncertain',
  'target_unavailable_hosts', 'non_resolving_hosts', 'execution_complete_hosts'];
const INCOMPLETE_REASONS = new Set(EXPOSURE_INCOMPLETE_REASONS);
const JOB_STATES = new Set(['pending', 'running', 'complete', 'cancelled', 'budget_exhausted']);
const HOST_RE = /^[a-z0-9.-]{1,253}$/i;
// A reason this projection does not recognise is still a reason: dropping it to
// null would make the report say the checks never finished. Fail closed to a
// generic incomplete marker instead of inventing or erasing one.
const carriedIncompleteReason = (value) => value == null ? null : INCOMPLETE_REASONS.has(value) ? value : 'coverage_incomplete';
const validIdentity = (identity) => typeof identity === 'string' && /^[a-f0-9]{64}$/.test(identity);
export const exposureFindingType = (ruleId) => `${EXPOSURE_FINDING_PREFIX}${ruleId}`;
export function exposureRuleForCondition(key) {
  const match = KEY.exec(String(key || ''));
  return match ? RULES_BY_ID[match[1]] || null : null;
}
export const isExposureConditionKey = (key) => Boolean(exposureRuleForCondition(key));
export function exposureConditionKey(row) {
  const identity = String(row?.identity || row?.finding?.identity || row?.observation?.identity || '').replace(/^exposure:/, '');
  return RULES_BY_ID[row?.rule_id] && validIdentity(identity)
    ? `${exposureFindingType(row.rule_id)}__${identity}` : null;
}

/** Only an exact rule + original-path identity and conclusive response can clear. */
export function evaluateExposureCondition(key, module) {
  if (!isExposureConditionKey(key) || module?.source !== 'external_exposure') return { state: 'deferred', reason: 'exposure_not_recorded' };
  const matches = (module.checks || []).filter((row) => row.condition_key === key || exposureConditionKey(row) === key);
  if (!matches.length) return { state: 'deferred', reason: 'exact_condition_not_tested' };
  if (matches.some((row) => row.state === 'finding' && row.comparable === true && row.finding)) return { state: 'present', reason: 'content_condition_observed' };
  if (matches.every((row) => row.comparable === true && row.finding === null && (['not_found', 'not_present_soft404'].includes(row.state)
      || row.state === 'observed' && exposurePresentation(row.rule_id, row.observation?.indicators || [])?.observationOnly === true))) return { state: 'clear', reason: 'exact_content_condition_retested_clear' };
  return { state: 'deferred', reason: 'content_retest_inconclusive' };
}

export function externalExposureModule(receipt) {
  if (!receipt || receipt.source !== 'external_exposure') return {
    source: 'external_exposure', version: EXPOSURE_CATALOG_VERSION, quality: 'not_recorded',
    job_state: null, phase_state: null, incomplete_reason: null, hosts_not_applicable: [], host_outcomes: [],
    coverage: null, checks: [], findings: [], costs: null, observed_at: null,
  };
  const projectHit = (hit) => hit ? {
    rule_id: hit.rule_id, severity: hit.severity,
    indicators: (Array.isArray(hit.indicators) ? hit.indicators : []).filter(value => SAFE_INDICATORS.has(value)),
    identity: hit.identity, safe_url: safeExposureUrl(hit.safe_url, Object.values(RULES_BY_ID)),
  } : null;
  const checks = (Array.isArray(receipt.checks) ? receipt.checks : []).filter(row => RULES_BY_ID[row?.rule_id]).map((row) => ({
    rule_id: row.rule_id, url: safeExposureUrl(row.url, Object.values(RULES_BY_ID)),
    identity: row.identity, condition_key: exposureConditionKey(row),
    state: ['finding', 'observed', 'not_found', 'blocked', 'uncertain', 'not_applicable', 'queued', 'budget_exhausted', 'authority_lost'].includes(row.state) ? row.state : 'uncertain',
    observed_at: Number.isFinite(Date.parse(row.observed_at)) ? new Date(row.observed_at).toISOString() : null,
    comparable: row.comparable === true, finding: projectHit(row.finding), observation: projectHit(row.observation),
  }));
  const module = {
    source: 'external_exposure', version: EXPOSURE_CATALOG_VERSION,
    quality: receipt.quality === 'complete' ? 'complete' : 'partial',
    // "finished" (job_state) and "assessed" (quality + incomplete_reason) are
    // separate facts; the domain resolver reads incomplete_reason verbatim.
    job_state: JOB_STATES.has(receipt.job_state) ? receipt.job_state : null,
    phase_state: JOB_STATES.has(receipt.phase_state) ? receipt.phase_state : null,
    incomplete_reason: carriedIncompleteReason(receipt.incomplete_reason),
    hosts_not_applicable: (Array.isArray(receipt.hosts_not_applicable) ? receipt.hosts_not_applicable : [])
      .filter(host => typeof host?.hostname === 'string' && HOST_RE.test(host.hostname) && host.reason === 'authoritative_no_address')
      .map(host => ({ hostname: host.hostname, reason: host.reason, observed_at: Number.isFinite(Date.parse(host.observed_at)) ? new Date(host.observed_at).toISOString() : null })),
    host_outcomes: (Array.isArray(receipt.host_outcomes) ? receipt.host_outcomes : [])
      .filter(host => typeof host?.hostname === 'string' && HOST_RE.test(host.hostname) &&
        ['target_unavailable', 'host_does_not_resolve'].includes(host.state))
      .map(host => ({ hostname: host.hostname, state: host.state,
        reason: ['server_error', 'edge_origin_unreachable', 'authoritative_no_address'].includes(host.reason) ? host.reason : 'unavailable',
        statuses: Array.isArray(host.statuses) ? host.statuses.filter(status => Number.isInteger(status) && status >= 500 && status <= 599).slice(0, 2) : [],
        skipped_checks: Number.isInteger(host.skipped_checks) && host.skipped_checks >= 0 ? host.skipped_checks : 0,
        observed_at: Number.isFinite(Date.parse(host.observed_at)) ? new Date(host.observed_at).toISOString() : null })),
    coverage: receipt.coverage ? Object.fromEntries([...COVERAGE_KEYS, 'recorded_total', 'omitted_checks', 'pending_assets', 'not_applicable_hosts'].map(key => [key, Number.isInteger(receipt.coverage[key]) && receipt.coverage[key] >= 0 ? receipt.coverage[key] : null])) : null,
    checks, findings: [],
    costs: receipt.costs ? Object.fromEntries(COST_KEYS.map(key => [key, Number.isFinite(receipt.costs[key]) && receipt.costs[key] >= 0 ? receipt.costs[key] : null])) : null,
    observed_at: Number.isFinite(Date.parse(receipt.observed_at)) ? new Date(receipt.observed_at).toISOString() : null,
    hostname_references: { candidates: (receipt.hostname_references?.candidates || []).filter(candidate => typeof candidate?.hostname === 'string' && /^[a-z0-9.-]{1,253}$/i.test(candidate.hostname)).map(candidate => ({hostname: candidate.hostname, sources: ['exposure_content']})) },
  };
  const dedupe = new Map();
  for (const row of checks) {
    const rule = RULES_BY_ID[row.rule_id];
    const hit = row.finding || row.observation;
    if (!rule || !row.condition_key || !['finding', 'observed'].includes(row.state) || row.comparable !== true || !hit) continue;
    const indicators = Array.isArray(hit.indicators) ? hit.indicators.filter((value) => SAFE_INDICATORS.has(value)).slice(0, 16) : [];
    if (!indicators.length) continue;
    const presentation = exposurePresentation(rule.id, indicators);
    const severity = presentation.severity;
    const address = safeExposureUrl(hit.safe_url || row.url, Object.values(RULES_BY_ID));
    const observedAt = row.observed_at || module.observed_at;
    const finding = {
      id: row.condition_key, module: 'external_exposure',
      finding_type: row.state === 'observed' || presentation.observationOnly || severity === 'info' ? 'observation' : 'finding',
      severity, confidence: 90, score_impact: 0,
      title: presentation.title || `Public ${rule.family} information observed`,
      description: presentation.observation || presentation.risk,
      evidence: [{ type: 'bounded_http_content', label: 'Public content indicators', value: indicators.join('; '),
        source: 'external_exposure', checked_at: observedAt,
        requested_url: address, rule_id: rule.id, rule_version: rule.version }],
    };
    const remediation = findingRemediation(finding);
    finding.recommendation = remediation?.recommended_action || rule.remediation.join(' ');
    finding.exposure = {
      rule_id: rule.id, affected_url: address,
      observation: finding.description,
      severity_rationale: presentation.risk || 'Severity describes the information observed; it does not prove credential validity, access beyond this response or exploitation.',
      indicators, observed_at: observedAt,
      recommended_action: finding.recommendation,
      retest_state: finding.finding_type === 'finding' ? 'condition_observed' : 'observation_only',
      retest_requirement: 'Run a new domain scan after the change. Only a successful check of this same address and content condition can confirm it is no longer observed; a blocked or unavailable response cannot.',
    };
    dedupe.set(finding.id, finding);
  }
  module.findings = [...dedupe.values()];
  return module;
}
