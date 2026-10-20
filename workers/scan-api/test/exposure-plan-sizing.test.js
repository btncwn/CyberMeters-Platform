import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { planExposureChecks } from '../../../shared/exposure/discovery.js';
import { EXPOSURE_JOB_LIMITS, budgetedExposurePrefix, estimateExposureJobBudget, readExposureForScan, workspaceExposureWindow } from '../src/engines/exposure-jobs.js';
import { DatabaseSync } from 'node:sqlite';
import { reconcileCurrentDnsHostCoverage } from '../src/engines/exposure-findings.js';
import { resolveCyberMotDomainStates } from '../src/engines/cyber-mot-domains.js';

function representativePlan(hostCount) {
  const hosts = Array.from({length: hostCount}, (_, index) => index ? `h${index}.example.org` : 'example.org');
  const checks = hosts.flatMap(host => planExposureChecks({origin: `https://${host}`,
    observations: {rotationKey: 'scan_fixture'}}).checks.map(check => ({rule_id: check.ruleId, url: check.url})));
  // The latest four-host job added 17 safe content/reference checks after its
  // base 536-check catalog. Preserve that workload in both comparisons.
  checks.push(...Array.from({length: 17}, (_, index) => ({rule_id: 'env-config',
    url: `https://example.org/reference-${index}`})));
  const selected = hosts.flatMap((_, endpoint_index) => Array.from({length: 28}, () => ({
    endpoint_index, check: {control: 'protocol', protocol: 'tls1_2'}})));
  return {hosts, content_state: 'pending', checks, tls: {selected}};
}

test('four selected hosts admit their complete catalog and content references', () => {
  const plan = representativePlan(4);
  assert.equal(plan.checks.length, 553);
  assert.equal(budgetedExposurePrefix(plan, plan.checks), plan.checks.length);
  const estimate = estimateExposureJobBudget(plan);
  assert.ok(estimate.requests < EXPOSURE_JOB_LIMITS.workspaceRequests);
  assert.ok(estimate.bytes < EXPOSURE_JOB_LIMITS.workspaceBytes);
  assert.ok(estimate.attempts < EXPOSURE_JOB_LIMITS.maxPlannedAttempts);
  assert.ok(estimate.durationMs < 30 * 60_000);
  // The old hard cap is a live mutant: it must omit 169 of the base catalog
  // and also the 17 new references, which this assertion rejects.
  assert.equal(budgetedExposurePrefix(plan, plan.checks, 384), 384);
  assert.notEqual(budgetedExposurePrefix(plan, plan.checks, 384), plan.checks.length);
});

test('nine HTTPS hosts exceed the hourly byte ceiling with TLS and retain rotation', () => {
  const plan = representativePlan(9);
  assert.equal(plan.checks.length, 1223);
  const estimate = estimateExposureJobBudget(plan);
  assert.ok(estimate.bytes > EXPOSURE_JOB_LIMITS.workspaceBytes);
  assert.ok(estimate.requests < EXPOSURE_JOB_LIMITS.workspaceRequests);
  assert.ok(estimate.durationMs > 30 * 60_000);
  assert.equal(EXPOSURE_JOB_LIMITS.hosts, 4);
});

test('current DNS absence keeps prior exposure findings deferred in the read receipt', async () => {
  const scanId = 'scan_fixture';
  const row = {domain: 'example.org', state: 'complete', cursor: 1, updated_at: '2026-10-18T10:00:00Z',
    plan_json: JSON.stringify({content_state: 'complete', hosts_total: 2, pending_assets: 0,
      host_coverage: [{hostname: 'example.org'}, {hostname: 'old.example.org'}],
      hosts_not_applicable: [{hostname: 'old.example.org', reason: 'authoritative_no_address',
        evidence: {scan_id: 'scan_previous', observed_at: '2026-10-18T09:00:00Z'}}],
      retest_checks: [{rule_id: 'env-config', url: 'https://old.example.org/.env'}],
      checks: [{rule_id: 'env-config', url: 'https://example.org/.env'}]}),
    results_json: JSON.stringify([{rule_id: 'env-config', url: 'https://example.org/.env',
      state: 'not_found', comparable: true, observed_at: '2026-10-18T10:00:00Z'}])};
  const env = {cybermeters_db: {prepare: () => ({bind: () => ({first: async () => row})})}};
  const receipt = await readExposureForScan(env, {workspaceId: 'ws_fixture', scanId});
  assert.equal(receipt.coverage.hosts_checked, 1);
  assert.equal(receipt.coverage.deferred_prior_findings, 1);
  assert.equal(receipt.host_coverage.find(host => host.hostname === 'old.example.org')?.evidence_state,
    'awaiting_rotation');
  const projected = {coverage: receipt.coverage, host_coverage: receipt.host_coverage};
  const stale = reconcileCurrentDnsHostCoverage(projected, {assets: []}, '2026-10-18T10:00:00Z');
  assert.equal(stale.coverage.hosts_checked, 1);
  const current = reconcileCurrentDnsHostCoverage(projected, {assets: [{host: 'old.example.org',
    probe_status: 'not_applicable', reason: 'authoritative_no_address'}]}, '2026-10-18T10:00:00Z');
  assert.equal(current.coverage.hosts_checked, 2);
  assert.equal(current.host_coverage.find(host => host.hostname === 'old.example.org')?.last_checked_at,
    '2026-10-18T10:00:00Z');
  assert.equal(current.coverage.deferred_prior_findings, 1);
});

function partialReport() {
  return {scan_quality: {status: 'partial', degradations: [], modules_incomplete: [
    {module: 'tls_assessment', incomplete_reason: 'tls_checks_inconclusive'}],
  modules_skipped: ['tls_assessment'], warnings: ['Module incomplete: tls_assessment']},
  modules: {email_security: {dmarc_state: {enforcement_level: 'reject_enforced'}},
    email_security_intelligence: {}, brand_monitoring: {candidates_validated: true,
      validation: {state: 'complete', checked: 1, unchecked: 0}},
    subdomains: {checked: 9}, dns: {resolves: true}, admin_surface_detection: {checked: 4},
    cloud_storage_discovery: {checked: 4},
    asset_exposure: {assets: [{host: 'example.org', status: 200, http_assessed: true}]},
    external_exposure: {quality: 'partial', coverage: {completed: 553, pending: 0,
      blocked: 0, uncertain: 0, budget_exhausted: 0, omitted_checks: 0,
      hosts_checked: 4, hosts_total: 9, pending_assets: 5}}}, findings: [],
  monitoring_states: {version: 'signal-monitoring-state-v3', signals: {
    attack_surface: {state: 'monitoring_healthy'}}}};
}

test('unrelated TLS uncertainty does not demote complete Email and Brand evidence', async () => {
  const rows = resolveCyberMotDomainStates(partialReport());
  assert.equal(rows.find(row => row.domain_key === 'email_protection')?.state, 'assessed_healthy');
  assert.equal(rows.find(row => row.domain_key === 'brand_protection')?.state, 'assessed_healthy');
  const sourceUrl = new URL('../src/engines/cyber-mot-domains.js', import.meta.url);
  const source = readFileSync(sourceUrl, 'utf8');
  const anchor = 'completeDomainDespiteUnrelatedPhase(report, d, skippedSet)';
  assert.ok(source.includes(anchor));
  const mutantUrl = new URL(`../src/engines/.cyber-mot-local-mutant-${randomUUID()}.js`, import.meta.url);
  writeFileSync(mutantUrl, source.replace(anchor, 'false'));
  try {
    const mutant = await import(mutantUrl.href);
    const wrong = mutant.resolveCyberMotDomainStates(partialReport());
    assert.equal(wrong.find(row => row.domain_key === 'email_protection')?.state, 'provisional');
    assert.equal(wrong.find(row => row.domain_key === 'brand_protection')?.state, 'provisional');
  } finally { unlinkSync(mutantUrl); }
});

test('unchecked hosts cannot become a healthy Attack Surface', async () => {
  const report = partialReport();
  // Even if a stale or malformed scan-quality envelope says complete, the
  // host receipt remains authoritative for the five unchecked hosts.
  report.scan_quality = {status: 'complete', degradations: [], modules_incomplete: [],
    modules_skipped: [], warnings: []};
  const normal = resolveCyberMotDomainStates(report).find(row => row.domain_key === 'attack_surface');
  assert.equal(normal?.state, 'provisional');
  assert.match(normal.summary, /4 of 9 hosts checked this scan/);
  const sourceUrl = new URL('../src/engines/cyber-mot-domains.js', import.meta.url);
  const source = readFileSync(sourceUrl, 'utf8');
  const anchor = "exposureCoverage?.hosts_total > exposureCoverage?.hosts_checked";
  assert.ok(source.includes(anchor));
  const mutantUrl = new URL(`../src/engines/.cyber-mot-rotation-mutant-${randomUUID()}.js`, import.meta.url);
  writeFileSync(mutantUrl, source.replace(anchor, 'false'));
  try {
    const mutant = await import(mutantUrl.href);
    const wrong = mutant.resolveCyberMotDomainStates(report).find(row => row.domain_key === 'attack_surface');
    assert.notEqual(wrong?.state, normal?.state, 'mutation must change the verdict');
    assert.equal(wrong?.state, 'assessed_healthy');
    assert.doesNotMatch(wrong.summary, /4 of 9 hosts checked this scan/);
  } finally { unlinkSync(mutantUrl); }
});

test('a DNS-absent name is covered without clearing prior findings or concealing missing web evidence', async () => {
  const report = partialReport();
  report.modules.asset_exposure.assets.push({host: 'old.example.org', probe_status: 'not_applicable',
    reason: 'authoritative_no_address', http_assessed: false});
  report.modules.external_exposure.phase_state = 'complete';
  report.modules.external_exposure.coverage = {completed: 134, pending: 0, blocked: 0,
    budget_exhausted: 0, uncertain: 0, omitted_checks: 0, pending_assets: 0,
    target_unavailable_hosts: 0, non_resolving_hosts: 1, not_applicable_hosts: 1,
    hosts_checked: 2, hosts_total: 2, deferred_prior_findings: 0};
  report.scan_quality.modules_incomplete.push({module: 'external_exposure',
    incomplete_reason: 'host_does_not_resolve'});
  report.scan_quality.warnings.push('Module incomplete: external_exposure');
  const resolved = resolveCyberMotDomainStates(report).find(row => row.domain_key === 'attack_surface');
  assert.equal(resolved?.state, 'assessed_healthy');
  assert.match(resolved.limitations.join(' '), /web service was not assessed/);
  report.modules.external_exposure.coverage.deferred_prior_findings = 1;
  const prior = resolveCyberMotDomainStates(report).find(row => row.domain_key === 'attack_surface');
  assert.equal(prior?.state, 'provisional');
  assert.match(prior.summary, /No finding was cleared/);
  report.modules.external_exposure.coverage.deferred_prior_findings = 0;
  const sourceUrl = new URL('../src/engines/cyber-mot-domains.js', import.meta.url);
  const source = readFileSync(sourceUrl, 'utf8');
  const anchor = "const dnsAbsenceOnly = domain.domain_key === 'attack_surface'";
  assert.ok(source.includes(anchor));
  const mutantUrl = new URL(`../src/engines/.cyber-mot-dns-mutant-${randomUUID()}.js`, import.meta.url);
  writeFileSync(mutantUrl, source.replace(anchor,
    "const dnsAbsenceOnly = false && domain.domain_key === 'attack_surface'"));
  try {
    const mutant = await import(mutantUrl.href);
    const wrong = mutant.resolveCyberMotDomainStates(report).find(row => row.domain_key === 'attack_surface');
    assert.notEqual(wrong?.state, resolved?.state);
  } finally { unlinkSync(mutantUrl); }
});

test('an Email or Brand phase that is itself incomplete stays provisional', async () => {
  const report = partialReport();
  report.scan_quality.modules_incomplete.push({module: 'email_security', incomplete_reason: 'dns_lookup_failed'});
  report.scan_quality.warnings.push('Module incomplete: email_security');
  report.scan_quality.modules_incomplete.push({module: 'brand_monitoring', incomplete_reason: 'validation_incomplete'});
  report.scan_quality.warnings.push('Module incomplete: brand_monitoring');
  const rows = resolveCyberMotDomainStates(report);
  assert.notEqual(rows.find(row => row.domain_key === 'email_protection')?.state, 'assessed_healthy');
  assert.notEqual(rows.find(row => row.domain_key === 'brand_protection')?.state, 'assessed_healthy');
  // Mutant: the domain-local shortcut forgets to exclude the domain's own
  // incomplete modules. It must flip the verdict to healthy, proving the guard.
  const sourceUrl = new URL('../src/engines/cyber-mot-domains.js', import.meta.url);
  const source = readFileSync(sourceUrl, 'utf8');
  const anchor = '[...other].some(name => !name || domain.modules.includes(name))';
  assert.ok(source.includes(anchor));
  const mutantUrl = new URL(`../src/engines/.cyber-mot-own-module-mutant-${randomUUID()}.js`, import.meta.url);
  writeFileSync(mutantUrl, source.replace(anchor, '[...other].some(name => !name)')
    .replace("domain.modules.every(name => report?.modules?.[name] == null || moduleAssessed(report, name, skippedSet))", 'true')
    .replace("return domain.required.every(name => moduleAssessed(report, name, skippedSet)) &&\n    true", 'return true'));
  try {
    const mutant = await import(mutantUrl.href);
    const wrong = mutant.resolveCyberMotDomainStates(report);
    assert.equal(wrong.find(row => row.domain_key === 'email_protection')?.state, 'assessed_healthy',
      'mutation must let the incomplete Email phase read healthy');
  } finally { unlinkSync(mutantUrl); }
});

// 1a: the hourly window is one domain's share per verified domain, up to the
// plan's domain allowance and an absolute ceiling of 25.
test('workspace exposure window scales with verified domains, capped by plan and ceiling', async () => {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`CREATE TABLE workspaces(id TEXT PRIMARY KEY, owner_user_id TEXT, deleted_at TEXT);
    CREATE TABLE workspace_domains(workspace_id TEXT, domain_id TEXT, verification_status TEXT);
    CREATE TABLE subscriptions(id TEXT PRIMARY KEY, workspace_id TEXT, owner_user_id TEXT, plan TEXT, status TEXT,
      subscription_status TEXT, trial_end TEXT, expires_at TEXT, current_period_end TEXT, payment_failed_at TEXT,
      stripe_subscription_id TEXT, created_at TEXT, updated_at TEXT);`);
  const db = { prepare(sql) { const st = sqlite.prepare(sql); return { bind: (...a) => ({
    first: async () => st.get(...a) ?? null, all: async () => ({ results: st.all(...a) }),
    run: async () => ({ meta: { changes: Number(st.run(...a).changes) } }) }) }; } };
  const env = { cybermeters_db: db };
  const seed = (ws, owner, plan, verified, unverified = 0) => {
    sqlite.prepare('INSERT INTO workspaces VALUES (?,?,NULL)').run(ws, owner);
    if (plan) sqlite.prepare(`INSERT INTO subscriptions(id,owner_user_id,plan,status,subscription_status,current_period_end,created_at)
      VALUES (?,?,?,'active','active','2099-01-01','2026-01-01')`).run(`sub_${ws}`, owner, plan);
    for (let i = 0; i < verified; i++) sqlite.prepare("INSERT INTO workspace_domains VALUES (?,?,'verified')").run(ws, `${ws}_d${i}`);
    for (let i = 0; i < unverified; i++) sqlite.prepare("INSERT INTO workspace_domains VALUES (?,?,'pending')").run(ws, `${ws}_u${i}`);
  };
  const share = (n) => ({ domains: n, requests: EXPOSURE_JOB_LIMITS.workspaceRequests * n, bytes: EXPOSURE_JOB_LIMITS.workspaceBytes * n });
  seed('one', 'u_one', 'business', 1, 4);
  seed('biz', 'u_biz', 'business', 12);
  seed('pro', 'u_pro', 'professional', 5);
  seed('pro2', 'u_pro2', 'professional', 2, 3);
  seed('msp', 'u_msp', 'enterprise', 40);
  seed('free', 'u_free', null, 3);
  assert.deepEqual(await workspaceExposureWindow(env, 'one'), share(1), 'unverified domains do not count');
  assert.deepEqual(await workspaceExposureWindow(env, 'biz'), share(10), 'business allows 10 domains');
  assert.deepEqual(await workspaceExposureWindow(env, 'pro'), share(3), 'professional allows 3 domains');
  assert.deepEqual(await workspaceExposureWindow(env, 'pro2'), share(2));
  assert.deepEqual(await workspaceExposureWindow(env, 'msp'), share(25), 'absolute ceiling');
  assert.deepEqual(await workspaceExposureWindow(env, 'free'), share(1), 'no entitled plan: one share');
  assert.deepEqual(await workspaceExposureWindow(env, 'missing'), share(1));
  assert.deepEqual(await workspaceExposureWindow({ cybermeters_db: { prepare() { throw new Error('d1'); } } }, 'biz'), share(1),
    'a lookup failure falls back to one share, never more');
});
