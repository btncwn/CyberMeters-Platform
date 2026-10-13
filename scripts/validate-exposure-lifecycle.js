#!/usr/bin/env node
// Local-only proof: real detector -> canonical finding -> real D1 lifecycle/case.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { evaluateExposure } from '../shared/exposure/evaluate.js';
import { exposureIdentity } from '../shared/exposure/redaction.js';
import { EXPOSURE_RULES } from '../shared/exposure/catalog.js';
import { normalizeFindingSchema } from '../workers/scan-api/src/engines/findings.js';
import { externalExposureModule, evaluateExposureCondition, exposureConditionKey } from '../workers/scan-api/src/engines/exposure-findings.js';
import { resolveRemediation } from '../workers/scan-api/src/engines/remediation-registry.js';
import { checkForFinding } from '../workers/scan-api/src/engines/check-pack.js';
import { evaluateWebsiteSecurityForScan } from '../workers/scan-api/src/engines/website-security-lifecycle.js';
import { resolveCyberMotDomainStates } from '../workers/scan-api/src/engines/cyber-mot-domains.js';
import { pendingPageReferences, PAGE_REFERENCE_ASSET_SOURCES } from '../workers/scan-api/src/engines/page-references.js';
import { canTransitionCase } from '../workers/scan-api/src/engines/managed-case-model.js';

const root = new URL('../', import.meta.url);
const url = 'https://example.test/.env';
const identity = exposureIdentity('env-config', url);
const coverage = { completed: 1, pending: 0, blocked: 0, not_applicable: 0, budget_exhausted: 0, uncertain: 0, pending_assets: 0 };
const quality = { status: 'complete', modules_skipped: [], modules_incomplete: [] };
const baseModules = { ssl: { https_available: true, https_probe_executed: true }, headers: { accessible: true, headers_assessed: true }, dns: { resolves: true } };
const controls = [0, 1].map(i => ({ status: 404, body: `Missing ${i}` }));
function wire(rule_id, target, body, status = 200) {
  const result = evaluateExposure({ rule: rule_id, response: { status, url: target, body }, controls });
  const project = hit => hit ? { rule_id, family: hit.family, severity: hit.severity, indicators: hit.evidence.indicators, identity: hit.identity, safe_url: hit.safeUrl } : null;
  return { rule_id, url: target, identity: exposureIdentity(rule_id, target), state: result.state, comparable: result.comparable, reason: result.reason,
    finding: project(result.finding), observation: project(result.observation) };
}
const positive = wire('env-config', url, 'APP_ENV=production\nDB_PASSWORD=Str0ng_Value_6948\n');
assert.equal(positive.state, 'finding');
const negative = wire('env-config', url, 'Not found', 404);
assert.equal(negative.state, 'not_found');
const receipt = (checks) => externalExposureModule({ source: 'external_exposure', coverage, checks, observed_at: '2026-10-13T10:00:00Z' });
const module = receipt([{ ...positive, observed_at: '2026-10-13T09:59:00Z' }]);
const finding = module.findings[0];
assert.ok(finding);
assert.equal(finding.id, exposureConditionKey(negative));
assert.equal(finding.finding_type, 'finding');
assert.equal(finding.score_impact, 0);
assert.equal(normalizeFindingSchema(finding).confidence, 90);
assert.equal(finding.evidence[0].checked_at, '2026-10-13T09:59:00.000Z');
assert.equal(resolveRemediation({ finding_type: finding.id }).remediation_id, 'web.exposure.env_config');
assert.equal(checkForFinding(finding).check_id, 'public_content.env-config');
assert.equal(evaluateExposureCondition(finding.id, receipt([negative])).state, 'clear');
assert.equal(evaluateExposureCondition(finding.id, receipt([{ ...negative, url: 'https://example.test/config/.env', identity: exposureIdentity('env-config', 'https://example.test/config/.env') }])).state, 'deferred');
for (const state of ['blocked', 'uncertain', 'not_applicable', 'pending', 'budget_exhausted']) {
  assert.equal(evaluateExposureCondition(finding.id, receipt([{ ...negative, state, comparable: false }])).state, 'deferred');
}
assert.equal(evaluateExposureCondition(finding.id, receipt([{ ...negative, comparable: false }])).state, 'deferred');
assert.equal(evaluateExposureCondition(finding.id, receipt([])).state, 'deferred');
assert.ok(!JSON.stringify(module).includes('Str0ng_Value_6948'));
assert.equal(receipt([positive, positive]).findings.length, 1);
for (const rule of EXPOSURE_RULES) assert.equal(resolveRemediation({ finding_type: `external_exposure_${rule.id}` }).status, 'resolved');
const login = receipt([wire('admin-interface', 'https://example.test/admin/', '<html><title>Admin login</title><form><input type="password"></form></html>')]);
assert.equal(login.findings[0]?.finding_type, 'observation');
assert.equal(login.findings[0]?.severity, 'info');
assert.ok(/no authentication bypass/i.test(login.findings[0]?.description));
const map = receipt([wire('source-map', 'https://example.test/main.js.map', JSON.stringify({version:3,sources:['source.js'],mappings:'AAAA'}))]);
assert.equal(map.findings[0]?.finding_type, 'observation');
assert.ok(!/Original source is embedded/i.test(map.findings[0]?.title), 'metadata-only map must not claim original source');
assert.equal(evaluateExposureCondition(map.findings[0].id, map).state, 'clear', 'successful metadata-only map recheck clears original-source exposure');
assert.equal(evaluateExposureCondition(map.findings[0].id, {...map,checks:map.checks.map(row=>({...row,comparable:false}))}).state, 'deferred');

const state = (exposure, findings = []) => resolveCyberMotDomainStates({ modules: { ...baseModules, external_exposure: exposure }, findings, scan_quality: quality }).find(d => d.domain_key === 'website_security');
assert.notEqual(state(externalExposureModule(null)).state, 'assessed_healthy');
const historic = resolveCyberMotDomainStates({modules:baseModules,findings:[],scan_quality:quality}).find(d=>d.domain_key==='website_security');
assert.equal(historic.state, 'assessed_healthy', 'historic/free scan without exposure scope retains existing conclusion');
assert.notEqual(state({ ...module, coverage: { ...coverage, blocked: 1 } }).state, 'assessed_healthy');
assert.notEqual(state({ ...module, coverage: { ...coverage, pending_assets: 1 } }).state, 'assessed_healthy');
assert.equal(state(module, [finding]).state, 'issue_detected');

const db = new DatabaseSync(':memory:');
const apply = (path) => { try { db.exec(fs.readFileSync(path, 'utf8')); } catch (e) { if (!/^(?:duplicate column name|no such table|table \S+ already exists|index \S+ already exists)/.test(e.message)) throw e; } };
apply(new URL('database/schema.sql', root));
for (const name of fs.readdirSync(new URL('database/migrations/', root)).filter(name=>name.endsWith('.sql')).sort()) apply(new URL(`database/migrations/${name}`,root));
db.exec('PRAGMA foreign_keys = OFF');
const wrap = (sql, args = []) => ({ bind: (...values) => wrap(sql, values), first: async () => db.prepare(sql).get(...args) || null,
  all: async () => ({ results: db.prepare(sql).all(...args) }), run: async () => ({ meta: { changes: db.prepare(sql).run(...args).changes } }) });
const env = { cybermeters_db: { prepare: sql => wrap(sql), batch: list => Promise.all(list.map(item=>item.run())) } };
db.exec(`INSERT INTO users (id,email,name,plan) VALUES ('u','owner@example.test','Owner','professional');
 INSERT INTO workspaces (id,owner_user_id,name) VALUES ('ws','u','Example'),('other','u','Other');
 INSERT INTO workspace_members (id,workspace_id,user_id,role) VALUES ('m','ws','u','owner');
 INSERT INTO domains (id,user_id,domain) VALUES ('d','u','example.test');
 INSERT INTO workspace_domains (workspace_id,domain_id,verification_status) VALUES ('ws','d','verified');`);
const run = (scan_id, checks, scanQuality = quality) => {
  const exposure = receipt(checks);
  return evaluateWebsiteSecurityForScan(env, {workspace_id:'ws',domain_id:'d',domain:'example.test',scan_id, findings:exposure.findings, modules:{...baseModules, external_exposure: exposure},scanQuality});
};
const row = () => db.prepare('SELECT * FROM website_security_conditions WHERE workspace_id=? AND condition_key=?').get('ws', finding.id);
const cases = () => db.prepare("SELECT * FROM managed_cases WHERE workspace_id='ws' AND case_type='website_case'").all();
await run('baseline', [negative]);
await run('positive', [positive]);
assert.equal(row().monitoring_status, 'observed');
assert.equal(cases().length, 1);
assert.equal(cases()[0].asset_ref, url);
assert.ok(!cases()[0].title.includes(identity.replace('exposure:', '')));
const firstCaseId = cases()[0].id;
await run('repeat', [positive]);
assert.equal(cases().length, 1);
const eventsBefore = db.prepare('SELECT COUNT(*) AS n FROM website_security_events').get().n;
for (const state of ['blocked', 'uncertain', 'budget_exhausted', 'pending', 'not_applicable']) await run(state, [{ ...negative, state, comparable: false }]);
await run('missing', []);
assert.equal(row().monitoring_status, 'observed');
assert.equal(db.prepare('SELECT COUNT(*) AS n FROM website_security_events').get().n, eventsBefore, 'inconclusive observations must not mint recurrence or recovery events');
assert.equal(db.prepare("SELECT COUNT(*) AS n FROM website_security_conditions WHERE workspace_id='other'").get().n, 0);
let kase = cases()[0];
for (const target of ['triaged','assigned','approved','action_in_progress','awaiting_verification']) {
  const decision = canTransitionCase({case:kase,target_status:target,actor:{actor_type:'customer',actor_id:'u'},owner_ref:'u'});
  assert.equal(decision.ok, true, `${target}: ${decision.reason}`);
  db.prepare('UPDATE managed_cases SET status=? WHERE id=?').run(decision.case.status,kase.id);
  kase=cases()[0];
}
await run('partial', [negative], {...quality,status:'partial'});
assert.equal(cases()[0].status, 'awaiting_verification');
await run('clear', [negative]);
assert.equal(row().monitoring_status, 'no_longer_observed');
assert.equal(cases()[0].status, 'verified');
await run('returned', [positive]);
assert.equal(row().monitoring_status, 'observed');
assert.equal(cases()[0].id, firstCaseId);
assert.equal(cases()[0].status, 'reopened');
assert.equal(cases().length, 1);
assert.ok(!JSON.stringify(db.prepare('SELECT * FROM managed_cases').all()).includes('Str0ng_Value_6948'));
const refs = { candidates: [{hostname:'api.example.test',sources:['exposure_content']},{hostname:'thirdparty.test',sources:['exposure_content']}] };
assert.deepEqual(pendingPageReferences('example.test', refs), [{hostname:'api.example.test',sources:['exposure_content']}]);
assert.equal(PAGE_REFERENCE_ASSET_SOURCES.exposure_content, 'content_reference');
const engine = fs.readFileSync(new URL('workers/scan-api/src/engines/scan-engine.js', root), 'utf8');
assert.ok(engine.includes('if (exposureReceipt || (workspaceId && durableInvocation && env.EXPOSURE_SCAN_MODE === "evidence-v1"))'));
assert.equal((engine.match(/await readExposureForScan\(/g) || []).length, 1);
assert.ok(engine.indexOf('await readExposureForScan(') < engine.indexOf('const pending = pendingPageReferences('));
assert.ok(engine.includes('...(modules.external_exposure?.hostname_references?.candidates || [])'));
db.close();
console.log('Exposure lifecycle: canonical identity, safe presentation, exact retest, case fixed/reopened, unavailable retention and tenant boundaries passed.');
