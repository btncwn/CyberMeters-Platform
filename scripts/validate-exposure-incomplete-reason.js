#!/usr/bin/env node
// External exposure: "job finished" is not "assessed", and a name with no
// address is not an HTTP target.
//
// Measured on production scan scan_7d515038 (cybermeters.com, main c246f46c):
// the exposure job reached state=complete with 380 checks, of which 1 was
// comparable and the rest were uncertain (soft-404 controls, a mail-only name
// with no A/AAAA, an origin answering 5xx). The reader returned no
// incomplete_reason, the projection dropped it, and the Executive Report then
// told the customer the checks "did not complete within the scan budget" — a
// sentence whose own contract means "nothing was observed". The job finished.
//
// This harness pins, with real SQLite and the production planner/reader:
//   X1  a finished job with inconclusive checks carries a fixed reason, keeps
//       quality partial, and the Website Security card never utters the
//       budget sentence for it;
//   X2  the reason table for every terminal/non-terminal job state;
//   X3  a mail-only name with CURRENT authoritative no-address evidence is not
//       planned for the HTTP catalogue and is recorded as not applicable;
//   X4  a transient DNS failure, a stale observation, a non-latest observation
//       and an empty ip_addresses column all keep the name planned.
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { exposureIdentity } from '../shared/exposure/redaction.js';
import { EXPOSURE_RULES } from '../shared/exposure/catalog.js';
import { ensureExposureReady, readExposureForScan, readTlsAssessmentForScan, exposureHostHttpApplicability, exposureIncompleteReason, EXPOSURE_JOB_LIMITS, EXPOSURE_INCOMPLETE_REASONS } from '../workers/scan-api/src/engines/exposure-jobs.js';
import { externalExposureModule } from '../workers/scan-api/src/engines/exposure-findings.js';
import { resolveSecurityCheckDomainStates } from '../workers/scan-api/src/engines/security-check-domains.js';
import { buildScanQuality } from '../workers/scan-api/src/engines/scan-engine.js';

let pass = 0, fail = 0;
const ok = (n, c, d = '') => { c ? pass++ : fail++; console.log(`${c ? 'PASS' : 'FAIL'} ${n}${!c && d ? ' — ' + d : ''}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

const NOW = Date.parse('2026-10-15T12:00:00Z');
const iso = (ms) => new Date(ms).toISOString();
const DOMAIN = 'cm-fixture.example.com';
const rule = EXPOSURE_RULES.find(r => r.id === 'env-config');

function harness() {
  const sql = new DatabaseSync(':memory:');
  sql.exec(`CREATE TABLE workspaces(id TEXT PRIMARY KEY,deleted_at TEXT);
    CREATE TABLE scans(id TEXT PRIMARY KEY,workspace_id TEXT,domain_id TEXT,domain TEXT,status TEXT);
    CREATE TABLE workspace_domains(workspace_id TEXT,domain_id TEXT,verification_status TEXT);
    CREATE TABLE workspace_assets(id TEXT,workspace_id TEXT,domain_id TEXT,hostname TEXT,first_seen TEXT,status TEXT,risk_level TEXT,ip_addresses TEXT,last_observation_scan_id TEXT);
    CREATE TABLE asset_lifecycle_observations(id TEXT,workspace_id TEXT,domain_id TEXT,asset_id TEXT,scan_id TEXT,observation_state TEXT,dns_state TEXT,http_state TEXT,source_detail_json TEXT NOT NULL DEFAULT '{}',observed_at TEXT);
    CREATE TABLE website_pages(workspace_id TEXT,domain_id TEXT,path TEXT,last_observation_json TEXT,last_checked_at TEXT);`);
  sql.exec(readFileSync(new URL('../database/migrations/119-external-exposure-jobs.sql', import.meta.url), 'utf8'));
  const prepare = (text, args = []) => ({ bind: (...next) => prepare(text, next), first: async () => sql.prepare(text).get(...args) || null, all: async () => ({ results: sql.prepare(text).all(...args) }), run: async () => ({ meta: { changes: sql.prepare(text).run(...args).changes } }) });
  const env = { EXPOSURE_SCAN_MODE: 'evidence-v1', cybermeters_db: { prepare }, SCAN_QUEUE: { send: async () => {} } };
  const scan = { id: 'scan_fixture', workspace_id: 'ws_fixture', domain_id: 'dom_fixture', domain: DOMAIN, status: 'queued' };
  sql.prepare('INSERT INTO workspaces VALUES(?,NULL)').run(scan.workspace_id);
  sql.prepare('INSERT INTO scans VALUES(?,?,?,?,?)').run(...Object.values(scan));
  sql.prepare("INSERT INTO workspace_domains VALUES(?,?,'verified')").run(scan.workspace_id, scan.domain_id);
  let n = 0;
  // An asset row plus (optionally) its latest lifecycle observation. The
  // observation is written exactly as attack-surface-lifecycle.js persists it.
  function asset(hostname, { observation = null, ip_addresses = null, observedAt = NOW - 3600_000, observationScanId = 'scan_prev', latestScanId = 'scan_prev' } = {}) {
    const id = `asset_${++n}`;
    sql.prepare('INSERT INTO workspace_assets VALUES(?,?,?,?,?,?,?,?,?)')
      .run(id, scan.workspace_id, scan.domain_id, hostname, iso(NOW - 30 * 86400_000), 'active', 'info', ip_addresses, observation ? latestScanId : null);
    if (observation) {
      sql.prepare('INSERT INTO asset_lifecycle_observations VALUES(?,?,?,?,?,?,?,?,?,?)')
        .run(`alo_${n}`, scan.workspace_id, scan.domain_id, id, observationScanId, 'observed', observation.dns.state, observation.http.state,
          JSON.stringify({ dns_resolution: observation.dns, http_https_service: observation.http }), iso(observedAt));
    }
    return id;
  }
  const plan = () => JSON.parse(sql.prepare('SELECT plan_json FROM external_exposure_jobs WHERE scan_id=?').get(scan.id).plan_json);
  const hostsIn = (checks) => [...new Set(checks.map(c => new URL(c.url).hostname))];
  const setJob = (state, results, { cursor = null, plannedChecks = null, pending_assets = 0, omitted = 0, hostsNotApplicable = [], tls = null } = {}) => {
    const plan = { content_state: 'complete', checks: results.slice(0, plannedChecks ?? results.length).map(r => ({ rule_id: r.rule_id, url: r.url })), pending_assets, omitted_checks: omitted, hosts_not_applicable: hostsNotApplicable, ...(tls ? { tls } : {}) };
    sql.prepare('DELETE FROM external_exposure_jobs').run();
    sql.prepare('INSERT INTO external_exposure_jobs(scan_id,workspace_id,domain_id,domain,plan_json,results_json,state,cursor,created_ms,deadline_ms,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
      .run(scan.id, scan.workspace_id, scan.domain_id, scan.domain, JSON.stringify(plan), JSON.stringify(results), state, cursor ?? results.length, NOW, NOW + EXPOSURE_JOB_LIMITS.completionMs, iso(NOW));
  };
  return { sql, env, scan, asset, plan, hostsIn, setJob };
}
const check = (host, i, state, reason, comparable = false) => {
  const url = `https://${host}${rule.paths[i % rule.paths.length]}?v=${i}`;
  return { rule_id: rule.id, url, identity: exposureIdentity(rule.id, url), state, comparable, finding: null, observation: null, indicators: [], reason, observed_at: iso(NOW) };
};
// The lifecycle signals exactly as asset-intel.js emits them.
const SIGNALS = {
  mailOnly:   { dns: { state: 'observed', reason: 'dns_name_without_address', evidence_count: 0 }, http: { state: 'not_observed', reason: 'http_not_applicable_no_address', evidence_count: 0 } },
  nxdomain:   { dns: { state: 'absent', reason: 'authoritative_a_aaaa_absence', evidence_count: 0 }, http: { state: 'not_observed', reason: 'http_not_applicable_no_address', evidence_count: 0 } },
  transient:  { dns: { state: 'unavailable', reason: 'active_dns_evidence_unavailable', evidence_count: 0 }, http: { state: 'not_assessed', reason: 'dns_resolution_unavailable', evidence_count: 0 } },
  addressed:  { dns: { state: 'observed', reason: 'active_dns_records_observed', evidence_count: 2 }, http: { state: 'observed', reason: 'http_response_observed', evidence_count: 1 } },
  notChecked: { dns: { state: 'not_assessed', reason: 'not_checked_this_scan', evidence_count: 0 }, http: { state: 'not_assessed', reason: 'not_checked_this_scan', evidence_count: 0 } },
};
const baseModules = { ssl: { https_available: true, https_probe_executed: true }, headers: { accessible: true, headers_assessed: true }, dns: { resolves: true } };
const quality = { status: 'complete', modules_skipped: [], modules_incomplete: [] };
const card = (exposure) => resolveSecurityCheckDomainStates({ modules: { ...baseModules, external_exposure: exposure }, findings: [], scan_quality: quality }).find(d => d.domain_key === 'website_security');
const BUDGET_SENTENCE = /did not complete within the scan budget/;

// ── X1: the production shape — a FINISHED job whose checks were inconclusive ─
{
  const h = harness();
  const results = [
    ...Array.from({ length: 145 }, (_, i) => check(DOMAIN, i, 'uncertain', 'soft_404_or_common_response')),
    ...Array.from({ length: 134 }, (_, i) => check(`mail-only.${DOMAIN}`, i, 'uncertain', 'dns_no_address')),
    ...Array.from({ length: 98 }, (_, i) => check(`five-xx.${DOMAIN}`, i, 'uncertain', 'server_or_redirect_failure')),
    ...Array.from({ length: 3 }, (_, i) => check(`edge.${DOMAIN}`, i, 'blocked', 'blocked')),
    check(DOMAIN, 999, 'not_found', null, true),
  ];
  h.setJob('complete', results);
  const receipt = await readExposureForScan(h.env, { workspaceId: h.scan.workspace_id, scanId: h.scan.id });
  eq('X1_READ_COVERAGE_MATCHES_PRODUCTION', [receipt.coverage.completed, receipt.coverage.uncertain, receipt.coverage.blocked, receipt.coverage.pending], [1, 377, 3, 0]);
  eq('X1_RECORDED_TOTAL_EXCLUDES_OUT_OF_SCOPE', receipt.coverage.recorded_total, results.length);
  eq('X1_PROJECTED_TOTAL_EXCLUDES_OUT_OF_SCOPE', externalExposureModule(receipt).coverage.recorded_total, results.length);
  eq('X1_READ_QUALITY_PARTIAL', receipt.quality, 'partial');
  eq('X1_READ_JOB_STATE_IS_FINISHED', receipt.job_state, 'complete');
  eq('X1_READ_REASON_INCONCLUSIVE', receipt.incomplete_reason, 'checks_inconclusive');
  const module = externalExposureModule(receipt);
  eq('X1_MODULE_CARRIES_REASON', module.incomplete_reason, 'checks_inconclusive');
  eq('X1_MODULE_CARRIES_JOB_STATE', module.job_state, 'complete');
  eq('X1_MODULE_QUALITY_STAYS_PARTIAL', module.quality, 'partial');
  const ws = card(module);
  eq('X1_CARD_PROVISIONAL_WITH_CONCLUSIVE_SUBSET', ws?.state, 'provisional');
  ok('X1_CARD_NEVER_HEALTHY', ws?.state !== 'assessed_healthy');
  ok('X1_CARD_NO_FALSE_BUDGET_SENTENCE', !BUDGET_SENTENCE.test(ws?.summary || ''), `summary=${ws?.summary}`);
  ok('X1_CARD_STATES_CONCLUSIVE_COUNT', /1 of 381 external content checks/.test(ws?.summary || ''), `summary=${ws?.summary}`);
  // Stored-report shape: a report whose exposure module carries NO reason must
  // still fall back to the budget sentence — that fallback is correct for a job
  // the scan cut off, and this pins that the two cases remain distinguishable.
  const cutOff = card({ ...module, job_state: 'pending', phase_state: 'pending', incomplete_reason: null });
  ok('X1_CONTROL_NO_REASON_STILL_READS_NOT_FINISHED', BUDGET_SENTENCE.test(cutOff?.summary || ''));
}

// ── X2: reason table ────────────────────────────────────────────────────────
{
  const cov = (over = {}) => ({ completed: 0, pending: 0, blocked: 0, not_applicable: 0, budget_exhausted: 0, uncertain: 0, pending_assets: 0, not_applicable_hosts: 0, ...over });
  eq('X2_CANCELLED_IS_AUTHORITY_LOST', exposureIncompleteReason('cancelled', cov({ pending: 4 }), 4), 'authority_lost');
  eq('X2_BUDGET_EXHAUSTED_STATE', exposureIncompleteReason('budget_exhausted', cov({ completed: 2, pending: 2 }), 4), 'budget_exhausted');
  eq('X2_PENDING_JOB_NOT_FINISHED', exposureIncompleteReason('pending', cov({ pending: 4 }), 4), 'checks_not_finished');
  eq('X2_RUNNING_JOB_NOT_FINISHED', exposureIncompleteReason('running', cov({ completed: 1, pending: 3 }), 4), 'checks_not_finished');
  eq('X2_COMPLETE_ALL_COMPARABLE_IS_NULL', exposureIncompleteReason('complete', cov({ completed: 4 }), 4), null);
  eq('X2_COMPLETE_UNCERTAIN_WINS', exposureIncompleteReason('complete', cov({ completed: 1, uncertain: 2, blocked: 1 }), 4), 'checks_inconclusive');
  eq('X2_COMPLETE_BLOCKED_ONLY', exposureIncompleteReason('complete', cov({ completed: 3, blocked: 1 }), 4), 'checks_blocked');
  eq('X2_COMPLETE_OMITTED_CHECKS', exposureIncompleteReason('complete', cov({ completed: 4, budget_exhausted: 10 }), 4), 'check_budget_exhausted');
  eq('X2_COMPLETE_ASSETS_WAITING', exposureIncompleteReason('complete', cov({ completed: 4, pending_assets: 7 }), 4), 'assets_awaiting_rotation');
  eq('X2_COMPLETE_NOTHING_PLANNED_NO_ADDRESS', exposureIncompleteReason('complete', cov({ not_applicable_hosts: 1 }), 0), 'http_not_applicable_no_address');
  eq('X2_COMPLETE_NOTHING_PLANNED', exposureIncompleteReason('complete', cov(), 0), 'no_checks_planned');
  ok('X2_EVERY_REASON_IS_IN_THE_FIXED_LIST', ['authority_lost', 'budget_exhausted', 'checks_not_finished', 'checks_inconclusive', 'checks_blocked', 'check_budget_exhausted', 'assets_awaiting_rotation', 'http_not_applicable_no_address', 'no_checks_planned'].every(r => EXPOSURE_INCOMPLETE_REASONS.includes(r)));
  // The projection carries only the fixed list; an unknown word fails closed to a
  // generic incomplete marker, never to null (null would read as "not finished").
  const base = { source: 'external_exposure', coverage: cov({ completed: 1, uncertain: 1 }), checks: [], observed_at: iso(NOW), job_state: 'complete' };
  eq('X2_MODULE_UNKNOWN_REASON_FAILS_CLOSED', externalExposureModule({ ...base, incomplete_reason: 'made_up_word' }).incomplete_reason, 'coverage_incomplete');
  eq('X2_MODULE_NULL_REASON_STAYS_NULL', externalExposureModule({ ...base, incomplete_reason: null }).incomplete_reason, null);
  eq('X2_MODULE_UNKNOWN_JOB_STATE_IS_NULL', externalExposureModule({ ...base, job_state: 'exploded' }).job_state, null);
  eq('X2_MODULE_NOT_RECORDED_HAS_NO_REASON', externalExposureModule(null).incomplete_reason, null);
  // Control: a finished, fully comparable job still reaches assessed_healthy on
  // a complete scan — the fix must not make a healthy conclusion impossible.
  const h = harness();
  h.setJob('complete', [check(DOMAIN, 0, 'not_found', null, true), check(DOMAIN, 1, 'not_found', null, true)]);
  const clean = externalExposureModule(await readExposureForScan(h.env, { workspaceId: h.scan.workspace_id, scanId: h.scan.id }));
  eq('X2_CONTROL_CLEAN_JOB_REASON_NULL', clean.incomplete_reason, null);
  eq('X2_CONTROL_CLEAN_JOB_QUALITY_COMPLETE', clean.quality, 'complete');
  eq('X2_CONTROL_CLEAN_JOB_CARD_HEALTHY', card(clean)?.state, 'assessed_healthy');
  // Reader-level terminal states (real rows, not the pure function).
  h.setJob('cancelled', [check(DOMAIN, 0, 'not_found', null, true)], { cursor: 0 });
  eq('X2_READ_CANCELLED_REASON', (await readExposureForScan(h.env, { workspaceId: h.scan.workspace_id, scanId: h.scan.id })).incomplete_reason, 'authority_lost');
  h.setJob('budget_exhausted', [check(DOMAIN, 0, 'not_found', null, true)], { cursor: 0 });
  eq('X2_READ_BUDGET_EXHAUSTED_REASON', (await readExposureForScan(h.env, { workspaceId: h.scan.workspace_id, scanId: h.scan.id })).incomplete_reason, 'budget_exhausted');
}

// ── X3: a mail-only name with CURRENT authoritative no-address evidence ──────
{
  const h = harness();
  const mailOnly = `cm-accept-mail.${DOMAIN}`, gone = `cm-nxdomain.${DOMAIN}`, web = `www.${DOMAIN}`;
  h.asset(mailOnly, { observation: SIGNALS.mailOnly, ip_addresses: '[]' });
  h.asset(gone, { observation: SIGNALS.nxdomain });
  h.asset(web, { observation: SIGNALS.addressed, ip_addresses: '["192.0.2.10"]' });
  // Three more addressed names so the freed slots are measurable (hosts cap 4).
  for (const extra of ['app', 'docs', 'shop']) h.asset(`${extra}.${DOMAIN}`, { observation: SIGNALS.addressed });
  await ensureExposureReady(h.env, h.scan);
  const plan = h.plan();
  const hosts = h.hostsIn(plan.checks);
  ok('X3_MAIL_ONLY_NOT_PLANNED', !hosts.includes(mailOnly), JSON.stringify(hosts));
  ok('X3_NXDOMAIN_NOT_PLANNED', !hosts.includes(gone), JSON.stringify(hosts));
  ok('X3_MAIL_ONLY_NOT_IN_HOST_LIST', !plan.hosts.includes(mailOnly) && !plan.hosts.includes(gone));
  eq('X3_RECORDED_NOT_APPLICABLE', plan.hosts_not_applicable.map(h => [h.hostname, h.reason]).sort(), [[mailOnly, 'authoritative_no_address'], [gone, 'authoritative_no_address']]);
  ok('X3_EVIDENCE_IS_CITED', plan.hosts_not_applicable.length === 2 && plan.hosts_not_applicable.every(h => h.evidence?.scan_id === 'scan_prev' && typeof h.evidence.observed_at === 'string'));
  eq('X3_FREED_SLOTS_GO_TO_ADDRESSED_NAMES', plan.hosts.length, EXPOSURE_JOB_LIMITS.hosts);
  ok('X3_APEX_STILL_FIRST', plan.hosts[0] === DOMAIN);
  // 6 assets total: 3 planned among candidates, 2 not applicable → 1 awaiting.
  eq('X3_PENDING_ASSETS_EXCLUDES_NOT_APPLICABLE', plan.pending_assets, 1);
  // The reader and projection surface the record so a customer can see WHY the
  // name has no HTTP checks, instead of 134 "uncertain" rows.
  const receipt = await readExposureForScan(h.env, { workspaceId: h.scan.workspace_id, scanId: h.scan.id });
  eq('X3_READ_COVERAGE_COUNTS_HOSTS', receipt.coverage.not_applicable_hosts, 2);
  const module = externalExposureModule(receipt);
  eq('X3_MODULE_CARRIES_HOSTS', module.hosts_not_applicable.map(h => h.hostname).sort(), [mailOnly, gone]);
  eq('X3_MODULE_COVERAGE_CARRIES_COUNT', module.coverage.not_applicable_hosts, 2);
  ok('X3_NO_DNS_NO_ADDRESS_CHECK_PLANNED', receipt.checks.every(c => new URL(c.url).hostname !== mailOnly));
  // Pure gate, directly: the production row shape.
  const row = { last_observation_scan_id: 'scan_prev', observation_scan_id: 'scan_prev', observation_at: iso(NOW - 3600_000), dns_state: 'observed', dns_reason: 'dns_name_without_address', http_reason: 'http_not_applicable_no_address' };
  eq('X3_GATE_MAIL_ONLY_NOT_APPLICABLE', exposureHostHttpApplicability(row, NOW).applicable, false);
  eq('X3_GATE_NXDOMAIN_NOT_APPLICABLE', exposureHostHttpApplicability({ ...row, dns_state: 'absent', dns_reason: 'authoritative_a_aaaa_absence' }, NOW).applicable, false);
  eq('X3_GATE_HTTP_PREFLIGHT_PROOF_ALONE_SUFFICES', exposureHostHttpApplicability({ ...row, dns_state: 'observed', dns_reason: null }, NOW).applicable, false);
}

// ── X4: everything that is NOT authoritative current evidence stays planned ──
{
  const h = harness();
  const transient = `flaky.${DOMAIN}`, stale = `stale.${DOMAIN}`, superseded = `superseded.${DOMAIN}`, emptyIp = `empty-ip.${DOMAIN}`, unchecked = `unchecked.${DOMAIN}`;
  h.asset(transient, { observation: SIGNALS.transient, ip_addresses: '[]' });
  h.asset(stale, { observation: SIGNALS.mailOnly, observedAt: NOW - EXPOSURE_JOB_LIMITS.noAddressEvidenceMs - 86400_000 });
  h.asset(superseded, { observation: SIGNALS.mailOnly, observationScanId: 'scan_old', latestScanId: 'scan_newer' });
  h.asset(emptyIp, { ip_addresses: '[]' });
  h.asset(unchecked, { observation: SIGNALS.notChecked, ip_addresses: null });
  await ensureExposureReady(h.env, h.scan);
  const plan = h.plan();
  const planned = new Set(h.hostsIn(plan.checks));
  eq('X4_NOTHING_RECORDED_NOT_APPLICABLE', plan.hosts_not_applicable, []);
  // Only three asset slots exist beside the apex; every candidate must have been
  // eligible, so the three planned names are all drawn from this set and the
  // remainder is honestly "awaiting rotation", never "not applicable".
  eq('X4_ALL_SLOTS_FILLED_FROM_ELIGIBLE_NAMES', plan.hosts.length, EXPOSURE_JOB_LIMITS.hosts);
  ok('X4_PLANNED_NAMES_ARE_ELIGIBLE', plan.hosts.slice(1).every(host => [transient, stale, superseded, emptyIp, unchecked].includes(host)));
  eq('X4_REMAINDER_AWAITS_ROTATION', plan.pending_assets, 5 - (EXPOSURE_JOB_LIMITS.hosts - 1));
  ok('X4_PLANNED_HOSTS_HAVE_CHECKS', plan.hosts.every(host => planned.has(host)));
  const row = { last_observation_scan_id: 'scan_prev', observation_scan_id: 'scan_prev', observation_at: iso(NOW - 3600_000), dns_state: 'observed', dns_reason: 'dns_name_without_address', http_reason: 'http_not_applicable_no_address' };
  eq('X4_GATE_TRANSIENT_DNS_STAYS_PLANNED', exposureHostHttpApplicability({ ...row, dns_state: 'unavailable', dns_reason: 'active_dns_evidence_unavailable', http_reason: 'dns_resolution_unavailable' }, NOW).applicable, true);
  eq('X4_GATE_STALE_OBSERVATION_STAYS_PLANNED', exposureHostHttpApplicability({ ...row, observation_at: iso(NOW - EXPOSURE_JOB_LIMITS.noAddressEvidenceMs - 1) }, NOW).applicable, true);
  eq('X4_GATE_SUPERSEDED_OBSERVATION_STAYS_PLANNED', exposureHostHttpApplicability({ ...row, last_observation_scan_id: 'scan_newer' }, NOW).applicable, true);
  eq('X4_GATE_NO_OBSERVATION_STAYS_PLANNED', exposureHostHttpApplicability({ last_observation_scan_id: null, observation_scan_id: null, ip_addresses: '[]' }, NOW).applicable, true);
  eq('X4_GATE_EMPTY_IP_COLUMN_IS_NOT_EVIDENCE', exposureHostHttpApplicability({ ...row, dns_state: 'observed', dns_reason: 'active_dns_records_observed', http_reason: 'http_response_observed', ip_addresses: '[]' }, NOW).applicable, true);
  eq('X4_GATE_FUTURE_TIMESTAMP_STAYS_PLANNED', exposureHostHttpApplicability({ ...row, observation_at: iso(NOW + 3600_000) }, NOW).applicable, true);
}

// X5: production scan_bc7a4cd9 shape. The job and both selected phases finished;
// content comparability and TLS breadth remain limited. Never call them unrun.
{
  const h = harness();
  const apex = DOMAIN, other = `mail.${DOMAIN}`;
  const results = [
    ...Array.from({ length: 145 }, (_, i) => check(apex, i, 'uncertain', 'soft_404_or_common_response')),
    ...Array.from({ length: 132 }, (_, i) => check(other, i, 'not_found', 'explicit_absence', true)),
    ...Array.from({ length: 99 }, (_, i) => check(other, i, 'uncertain', 'dns_no_address')),
    ...Array.from({ length: 4 }, (_, i) => check(apex, i, 'blocked', 'authentication_rate_limit_or_challenge')),
    check(apex, 381, 'not_found', 'required_content_not_observed', true),
    check(apex, 382, 'uncertain', 'body_limit'),
    check(apex, 383, 'uncertain', 'decoded_limit'),
    check(apex, 384, 'uncertain', 'request_budget_exhausted'),
  ];
  eq('X5_HTTP_RESULT_SHAPE', results.length, 384);
  const tlsCheck = (state, reason, endpoint_index = 0) => ({
    endpoint_index, check: { control: 'protocol', protocol: 'tls1_2' }, state, reason,
    observed_at: iso(NOW), evidence: null,
  });
  const dynamic = [
    ...Array.from({ length: 73 }, () => tlsCheck('accepted', 'handshake_completed')),
    ...Array.from({ length: 79 }, () => tlsCheck('rejected', 'protocol_version_rejected')),
    ...Array.from({ length: 356 }, () => tlsCheck('uncertain', 'handshake_failed')),
    ...Array.from({ length: 4 }, () => tlsCheck('unexecutable', 'heartbeat_unavailable')),
  ];
  const statics = [
    ...Array.from({ length: 208 }, () => tlsCheck('unexecutable', 'requires_credentials')),
    ...Array.from({ length: 88 }, () => tlsCheck('not_applicable', 'control_not_applicable')),
  ];
  const tls = { profile_version: 'fixture', policy_version: 'fixture', cursor: 512,
    selected: dynamic.map(row => ({ endpoint_index: row.endpoint_index, check: row.check })),
    results: dynamic, static_results: statics, omitted_checks: 1216, omitted_services: 0,
    gaps: [], endpoints: [{ endpoint: { hostname: apex }, endpoint_identity: apex, scope: {} }],
  };
  h.setJob('complete', results, { cursor: 380, plannedChecks: 380, pending_assets: 5, omitted: 169, tls });
  const http = externalExposureModule(await readExposureForScan(h.env, { workspaceId: h.scan.workspace_id, scanId: h.scan.id }));
  const deepTls = await readTlsAssessmentForScan(h.env, { workspaceId: h.scan.workspace_id, scanId: h.scan.id });
  eq('X5_HTTP_PHASE_COMPLETE', [http.job_state, http.phase_state, http.coverage.completed, http.checks.length], ['complete', 'complete', 133, 384]);
  eq('X5_HTTP_PARTIAL_COUNTS', [http.coverage.blocked, http.coverage.uncertain, http.coverage.budget_exhausted, http.coverage.pending_assets], [4, 244, 172, 5]);
  eq('X5_TLS_PHASE_COMPLETE_WITH_LIMITS', [deepTls.phase_state, deepTls.coverage.completed, deepTls.coverage.uncertain,
    deepTls.coverage.unexecutable, deepTls.coverage.not_applicable, deepTls.coverage.omitted_checks],
    ['complete', 152, 356, 212, 88, 1216]);
  const modules = { ...baseModules, certificate_intelligence: { source: 'certificate_intelligence' },
    asset_exposure: { checked: 12, incomplete: true, incomplete_reason: 'server_error', not_assessed_count: 1 },
    external_exposure: http, tls_assessment: deepTls };
  const scanQuality = buildScanQuality(modules);
  eq('X5_QUALITY_STILL_PARTIAL', scanQuality.status, 'partial');
  ok('X5_EXECUTED_ASSET_IS_NOT_SKIPPED', !scanQuality.modules_skipped.includes('asset_exposure'));
  ok('X5_ASSET_INCOMPLETE_REASON_RETAINED', scanQuality.modules_incomplete.some(item =>
    item.module === 'asset_exposure' && item.incomplete_reason === 'server_error'));
  const report = { modules, findings: [], scan_quality: scanQuality };
  const domains = resolveSecurityCheckDomainStates(report);
  const website = domains.find(d => d.domain_key === 'website_security');
  const certificates = domains.find(d => d.domain_key === 'certificates_trust');
  eq('X5_WEBSITE_PROVISIONAL_NOT_HEALTHY', website?.state, 'provisional');
  ok('X5_WEBSITE_NAMES_CONCLUSIVE_AND_BLOCKED', /133 of 384/.test(website?.summary || '') && /4 were blocked/.test(website?.summary || ''));
  eq('X5_CERTIFICATES_PROVISIONAL_NOT_HEALTHY', certificates?.state, 'provisional');
  ok('X5_CERTIFICATES_PHASE_FINISHED_WITHOUT_FALSE_BUDGET_WORDING', /selected TLS checks finished/.test(certificates?.summary || '') &&
    !/did not complete within the scan budget/.test(certificates?.summary || ''));
  const unfinished = structuredClone(report);
  unfinished.modules.tls_assessment.phase_state = 'budget_exhausted';
  eq('X5_UNFINISHED_TLS_REMAINS_INSUFFICIENT', resolveSecurityCheckDomainStates(unfinished)
    .find(d => d.domain_key === 'certificates_trust')?.state, 'evidence_insufficient');
  unfinished.modules.external_exposure.phase_state = 'budget_exhausted';
  eq('X5_UNFINISHED_HTTP_REMAINS_INSUFFICIENT', resolveSecurityCheckDomainStates(unfinished)
    .find(d => d.domain_key === 'website_security')?.state, 'evidence_insufficient');

  // Source mutations: an implementation that drops the phase-complete gate or
  // puts attempted modules back into `modules_skipped` must fail this fixture.
  async function mutant(sourcePath, from, to, inspect) {
    const sourceUrl = new URL(sourcePath, import.meta.url);
    const source = readFileSync(sourceUrl, 'utf8');
    if (!source.includes(from)) throw new Error(`Missing mutation anchor: ${from}`);
    const mutantUrl = new URL(`./.exposure-report-mutant-${randomUUID()}.js`, sourceUrl);
    writeFileSync(mutantUrl, source.replace(from, to));
    try { return await inspect(await import(mutantUrl.href)); }
    finally { unlinkSync(mutantUrl); }
  }
  ok('X5_MUTATION_TLS_PHASE_GATE_CAUGHT', await mutant('../workers/scan-api/src/engines/security-check-domains.js',
    'report.modules.tls_assessment?.phase_state === "complete"',
    'report.modules.tls_assessment?.phase_state === "budget_exhausted"',
    m => /did not complete within the scan budget/.test(m.resolveSecurityCheckDomainStates(report)
      .find(d => d.domain_key === 'certificates_trust')?.summary || '')));
  ok('X5_MUTATION_HTTP_PHASE_GATE_CAUGHT', await mutant('../workers/scan-api/src/engines/security-check-domains.js',
    'report.modules.external_exposure?.phase_state === "complete"',
    'report.modules.external_exposure?.phase_state === "budget_exhausted"',
    m => m.resolveSecurityCheckDomainStates(report).find(d => d.domain_key === 'website_security')?.state !== 'provisional'));
  ok('X5_MUTATION_SKIPPED_MERGE_CAUGHT', await mutant('../workers/scan-api/src/engines/scan-engine.js',
    'for (const name of incompleteModules) {\n    warnings.push(`Module incomplete: ${name}`);',
    'for (const name of incompleteModules) {\n    modulesSkipped.push(name);\n    warnings.push(`Module incomplete: ${name}`);',
    m => m.buildScanQuality(modules).modules_skipped.includes('asset_exposure')));
}

console.log(`\nExposure incomplete-reason: ${pass}/${pass + fail} assertions passed`);
if (fail > 0) { console.error('Exposure incomplete-reason validation FAILED'); process.exit(1); }
console.log('Exposure incomplete-reason validation passed');
