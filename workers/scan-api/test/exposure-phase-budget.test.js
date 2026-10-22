import assert from 'node:assert/strict';
import { test } from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { EXPOSURE_RULES } from '../../../shared/exposure/catalog.js';
import { exposureIdentity } from '../../../shared/exposure/redaction.js';
import { TLS_POLICY_VERSION, TLS_PROFILE_VERSION, tlsEndpointIdentity } from '../../../shared/tls/catalog.js';
import { projectTlsCollectorReceipt } from '../../network-probe/src/tls-contract.js';
import { externalExposureModule } from '../src/engines/exposure-findings.js';
import { EXPOSURE_JOB_LIMITS, processExposureMessage, readExposureForScan, readTlsAssessmentForScan, sizeExposureJobBudget } from '../src/engines/exposure-jobs.js';
import { resolveSecurityCheckDomainStates } from '../src/engines/security-check-domains.js';
import { deriveSignalMonitoringStates } from '../src/engines/signal-monitoring-state.js';

const domain = 'budget.example.org';
const now = Date.now();
const rule = EXPOSURE_RULES.find(item => item.id === 'env-config');
const checks = Array.from({length: 380}, (_, index) => {
  const host = index < 375 ? domain : `www.${domain}`;
  const url = `https://${host}${rule.paths[0]}?v=${index}`;
  return {rule_id: rule.id, url};
});
const httpResults = checks.map(check => ({...check, identity: exposureIdentity(check.rule_id, check.url),
  state: 'not_found', comparable: true, finding: null, observation: null,
  observed_at: new Date(now).toISOString()}));
const endpoints = Array.from({length: 4}, (_, index) => {
  const hostname = index ? `${index}.${domain}` : domain;
  const endpoint = {hostname, sni: hostname, address: '8.8.8.8', port: 443, transport: 'tcp',
    application_protocol: 'https', dns_addresses: ['8.8.8.8'], dns_observed_at: new Date(now).toISOString()};
  return {endpoint, endpoint_identity: tlsEndpointIdentity(endpoint), scope: {kind: 'standard_https',
    service_authorization_id: null, generation: 0, special_consent: false, consent_version: null}};
});
const tlsCheck = {control: 'protocol', protocol: 'tls1_2', cipher_id: null};
// 103 completed groups (511 checks) plus one last group: 104 TLS slices.
const selected = [];
for (let group = 0; group < 103; group++) {
  const length = group < 99 ? 5 : 4;
  for (let index = 0; index < length; index++) selected.push({endpoint_index: group % 4, check: tlsCheck});
}
selected.push({endpoint_index: 0, check: tlsCheck});

function plan(tlsCursor = 511) {
  const value = {content_state: 'complete', checks, pending_assets: 0, omitted_checks: 0,
    tls: {profile_version: TLS_PROFILE_VERSION, policy_version: TLS_POLICY_VERSION,
      endpoints, selected, static_results: [], results: selected.slice(0, tlsCursor).map(item => ({
        ...item, state: 'accepted', reason: 'handshake_completed', observed_at: new Date(now).toISOString()})),
      cursor: tlsCursor, gaps: [], omitted_checks: 0, omitted_services: 0, state: 'pending'}};
  value.network_budget = sizeExposureJobBudget(value);
  return value;
}

function database() {
  const sql = new DatabaseSync(':memory:');
  sql.exec(`CREATE TABLE workspaces(id TEXT PRIMARY KEY, deleted_at TEXT);
    CREATE TABLE scans(id TEXT PRIMARY KEY, workspace_id TEXT, domain_id TEXT, domain TEXT, status TEXT);
    CREATE TABLE workspace_domains(workspace_id TEXT, domain_id TEXT, verification_status TEXT);
    CREATE TABLE network_targets(id TEXT PRIMARY KEY, workspace_id TEXT, authorization_status TEXT, addresses_json TEXT, scope_state TEXT DEFAULT 'in_scope');`);
  sql.exec(readFileSync(new URL('../../../database/migrations/119-external-exposure-jobs.sql', import.meta.url), 'utf8'));
  sql.exec(readFileSync(new URL('../../../database/migrations/120-tls-authorization.sql', import.meta.url), 'utf8'));
  sql.exec(readFileSync(new URL('../../../database/migrations/135-active-check-consents.sql', import.meta.url), 'utf8'));
  const prepare = (query, args = []) => ({bind: (...values) => prepare(query, values),
    first: async () => sql.prepare(query).get(...args) || null,
    all: async () => ({results: sql.prepare(query).all(...args)}),
    run: async () => ({meta: {changes: sql.prepare(query).run(...args).changes}})});
  const env = {cybermeters_db: {prepare}, SCAN_QUEUE: {send: async () => {}}, TLS_ASSESSMENT_MODE: 'evidence-v1'};
  return {sql, env};
}

function insertJob(sql, scanId, workspaceId, jobPlan, {state = 'pending', chargedRequests = 1015,
  chargedBytes = 5_000_000, attempts = 134, cursor = 380} = {}) {
  sql.prepare('INSERT OR IGNORE INTO workspaces VALUES(?,NULL)').run(workspaceId);
  sql.prepare("INSERT INTO scans VALUES(?,?,? ,?,'queued')").run(scanId, workspaceId, `${scanId}_domain`, domain);
  sql.prepare("INSERT INTO workspace_domains VALUES(?,?,'verified')").run(workspaceId, `${scanId}_domain`);
  sql.prepare(`INSERT INTO external_exposure_jobs
    (scan_id,workspace_id,domain_id,domain,plan_json,results_json,state,cursor,charged_requests,charged_bytes,attempts,created_ms,deadline_ms,updated_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(scanId, workspaceId, `${scanId}_domain`, domain,
    JSON.stringify(jobPlan), JSON.stringify(httpResults), state, cursor, chargedRequests,
    chargedBytes, attempts, now, now + 30 * 60_000, new Date(now).toISOString());
}

const lookupTlsDns = async (_host, type) => type === 'A'
  ? {Status: 0, Answer: [{type: 1, name: `${_host}.`, data: '8.8.8.8'}]}
  : {Status: 0, Answer: []};
const collectTlsAssessment = async (_env, input) => {
  assert.equal(input.checks.length, 1);
  const stamp = new Date(now).toISOString();
  const physical = {connections: 1, bytes_sent: 130, bytes_received: 300, duration_ms: 10};
  const engine = {schema: 'tls-engine-result-v1', engine: {family: 'modern', version: '3.5.9',
    build_id: 'a'.repeat(64), sandboxed: true}, control: 'handshake', protocol: 'tls1_2',
    state: 'accepted', reason: 'handshake_completed', authenticated_finished: true, vulnerability: null,
    negotiated: {version: 'tls1_2', cipher: 'ECDHE-RSA-AES256-GCM-SHA384', cipher_bits: 256,
      group: 'X25519', group_bits: 255, pfs: true, alpn: null, sni_sent: true},
    certificates: null, ocsp: null, extensions: null, telemetry: {connections: 1,
      bytes_sent: 100, bytes_received: 250, duration_ms: 10}, limitations: [], catalog: null};
  return projectTlsCollectorReceipt(input, {schema_version: 'tls-collector-raw-v1', request_id: input.request_id,
    started_at: stamp, finished_at: stamp,
    results: [{check: tlsCheck, engine_result: engine, reason: null, observed_at: stamp,
      physical_telemetry: physical}], telemetry: physical});
};

test('plan-sized budget completes the last TLS slice with headroom', async () => {
  const jobPlan = plan();
  assert.equal(jobPlan.network_budget.requests, 2597);
  assert.equal(jobPlan.network_budget.attempts, 173);
  assert.equal(jobPlan.network_budget.bytes, EXPOSURE_JOB_LIMITS.workspaceBytes);
  assert.ok(jobPlan.network_budget.requests > EXPOSURE_JOB_LIMITS.requests);
  const {sql, env} = database();
  insertJob(sql, 'scan_complete', 'ws_complete', jobPlan);
  const result = await processExposureMessage({kind: 'external_exposure', v: 1,
    scan_id: 'scan_complete', workspace_id: 'ws_complete'}, env,
  {now: () => now, lookupTlsDns, collectTlsAssessment});
  assert.equal(result.outcome, 'complete');
  const row = sql.prepare('SELECT state,charged_requests,attempts FROM external_exposure_jobs WHERE scan_id=?').get('scan_complete');
  assert.equal(row.state, 'complete');
  assert.equal(row.charged_requests, 1016); // 16 reserved, 15 refunded after one connection.
  assert.equal(row.attempts, 135);
});

test('a larger plan still exhausts at the workspace hourly ceiling', async () => {
  const jobPlan = plan();
  jobPlan.tls.selected = Array.from({length: 600}, (_, index) => ({endpoint_index: index % 4, check: tlsCheck}));
  jobPlan.tls.selected[599].endpoint_index = 0;
  jobPlan.tls.results = jobPlan.tls.selected.slice(0, 599).map(item => ({...item, state: 'accepted'}));
  jobPlan.tls.cursor = 599;
  jobPlan.network_budget = sizeExposureJobBudget(jobPlan);
  assert.equal(jobPlan.network_budget.requests, EXPOSURE_JOB_LIMITS.workspaceRequests);
  const {sql, env} = database();
  insertJob(sql, 'scan_cap', 'ws_cap', jobPlan, {chargedRequests: 4088, attempts: 600});
  let calls = 0;
  const result = await processExposureMessage({kind: 'external_exposure', v: 1,
    scan_id: 'scan_cap', workspace_id: 'ws_cap'}, env,
  {now: () => now, lookupTlsDns, collectTlsAssessment: async () => {calls++;}});
  assert.equal(result.outcome, 'tls_network_budget');
  assert.equal(calls, 0);
  assert.equal(sql.prepare('SELECT state FROM external_exposure_jobs WHERE scan_id=?').get('scan_cap').state,
    'budget_exhausted');
});

test('a second job cannot spend beyond the workspace hourly ceiling', async () => {
  const {sql, env} = database();
  insertJob(sql, 'scan_prior', 'ws_shared', plan(), {state: 'complete', chargedRequests: 3080});
  insertJob(sql, 'scan_new', 'ws_shared', plan());
  const result = await processExposureMessage({kind: 'external_exposure', v: 1,
    scan_id: 'scan_new', workspace_id: 'ws_shared'}, env,
  {now: () => now, lookupTlsDns, collectTlsAssessment});
  assert.equal(result.outcome, 'tls_network_budget');
  assert.equal(sql.prepare('SELECT state FROM external_exposure_jobs WHERE scan_id=?').get('scan_new').state,
    'budget_exhausted');
});

test('completed HTTP remains assessable when TLS later exhausts', async () => {
  const {sql, env} = database();
  insertJob(sql, 'scan_partial_tls', 'ws_partial_tls', plan(420), {state: 'budget_exhausted'});
  const exposure = await readExposureForScan(env, {workspaceId: 'ws_partial_tls', scanId: 'scan_partial_tls'});
  const tls = await readTlsAssessmentForScan(env, {workspaceId: 'ws_partial_tls', scanId: 'scan_partial_tls'});
  assert.equal(exposure.job_state, 'budget_exhausted');
  assert.equal(exposure.phase_state, 'complete');
  assert.equal(exposure.quality, 'complete');
  assert.equal(exposure.incomplete_reason, null);
  assert.equal(tls.phase_state, 'budget_exhausted');
  assert.equal(tls.quality, 'partial');
  assert.equal(tls.coverage.completed, 420);
  assert.equal(tls.coverage.uncertain, 92);
  assert.equal(tls.endpoints.flatMap(endpoint => endpoint.checks).filter(check => check.state === 'accepted').length, 420);
  const report = {scan_quality: {status: 'partial', degradations: [],
    modules_incomplete: [{module: 'tls_assessment', incomplete_reason: 'tls_checks_inconclusive'}],
    modules_skipped: ['tls_assessment', 'asset_exposure'],
    warnings: ['Module incomplete: tls_assessment', 'Module skipped (subrequest budget): asset_exposure']},
  modules: {external_exposure: externalExposureModule(exposure), tls_assessment: tls,
    headers: {}, ssl: {https_available: true}, dns: {}, subdomains: {},
    dns_bruteforce: {}, subdomain_takeover: {}, cloud_storage_discovery: {}, admin_surface_detection: {},
    certificate_intelligence: {certificate: {hostname_match: true, trust: 'valid'}},
    asset_exposure: {skipped: true}}, findings: []};
  report.monitoring_states = deriveSignalMonitoringStates({modules: report.modules, scanQuality: report.scan_quality});
  const domains = resolveSecurityCheckDomainStates(report);
  assert.equal(domains.find(item => item.domain_key === 'website_security').state, 'assessed_healthy',
    JSON.stringify(domains.find(item => item.domain_key === 'website_security')));
  // Asset-exposure monitoring really was skipped, so that separate signal
  // remains insufficient even though completed HTTP evidence is retained.
  assert.equal(domains.find(item => item.domain_key === 'attack_surface').state, 'evidence_insufficient');
  assert.ok(domains.find(item => item.domain_key === 'attack_surface').evidence_count > 0);
  assert.equal(domains.find(item => item.domain_key === 'certificates_trust').state, 'evidence_insufficient');
  assert.ok(domains.find(item => item.domain_key === 'certificates_trust').evidence_count > 0);
  // If asset discovery also completed, deep TLS alone cannot downgrade
  // Attack Surface's finished DNS and HTTP observations.
  const tlsOnly = structuredClone(report);
  tlsOnly.modules.asset_exposure = {};
  tlsOnly.scan_quality.modules_skipped = ['tls_assessment'];
  tlsOnly.scan_quality.warnings = ['Module incomplete: tls_assessment'];
  tlsOnly.monitoring_states = deriveSignalMonitoringStates({modules: tlsOnly.modules,
    scanQuality: tlsOnly.scan_quality});
  assert.equal(resolveSecurityCheckDomainStates(tlsOnly).find(item => item.domain_key === 'attack_surface').state,
    'assessed_healthy');
  assert.equal(await readExposureForScan(env, {workspaceId: 'foreign', scanId: 'scan_partial_tls'}), null);
});

test('finished but inconclusive HTTP cites its own evidence gap, not TLS budget', async () => {
  const {sql, env} = database();
  insertJob(sql, 'scan_inconclusive_http', 'ws_inconclusive_http', plan(420), {state: 'budget_exhausted'});
  const inconclusive = httpResults.map((row, index) => index === 0 ? row : {
    ...row, state: 'uncertain', comparable: false, reason: 'origin_response_inconclusive'});
  sql.prepare('UPDATE external_exposure_jobs SET results_json=? WHERE scan_id=?')
    .run(JSON.stringify(inconclusive), 'scan_inconclusive_http');
  const exposure = await readExposureForScan(env,
    {workspaceId: 'ws_inconclusive_http', scanId: 'scan_inconclusive_http'});
  assert.equal(exposure.phase_state, 'complete');
  assert.equal(exposure.quality, 'partial');
  assert.equal(exposure.incomplete_reason, 'checks_inconclusive');
  assert.equal(exposure.coverage.completed, 1);
  const report = {scan_quality: {status: 'partial', degradations: [],
    modules_incomplete: [{module: 'tls_assessment', incomplete_reason: 'tls_checks_inconclusive'}],
    modules_skipped: ['tls_assessment'], warnings: ['Module incomplete: tls_assessment']},
  modules: {external_exposure: externalExposureModule(exposure),
    headers: {}, ssl: {https_available: true}, dns: {}}, findings: []};
  const website = resolveSecurityCheckDomainStates(report).find(item => item.domain_key === 'website_security');
  assert.equal(website.state, 'provisional');
  assert.match(website.summary, /1 of 380 external content checks were conclusive/);
  assert.doesNotMatch(website.summary, /budget exhausted/);
});
