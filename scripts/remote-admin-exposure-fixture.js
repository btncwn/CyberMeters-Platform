import { assertProbeRequest } from './lib/probe-contract-fixture.mjs';
// S3-0 remote-administration exposure: module, scoring and scan-quality
// fixtures plus mutation proof. Imported by validate-asm-remediation-loop.js,
// which also walks the managed case end to end.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runRemoteAdminExposureModule, REMOTE_ADMIN_PORT_LIST, REMOTE_ADMIN_LIMITS } from '../workers/scan-api/src/engines/remote-admin-exposure.js';
import { validateNetworkProbeRequest } from '../workers/scan-api/src/engines/network-probe.js';
import { computeScore } from '../workers/scan-api/src/engines/scoring.js';
import { buildScanQuality } from '../workers/scan-api/src/engines/scan-engine.js';
import { moduleCompletionGate } from '../workers/scan-api/src/engines/asm-cases.js';
import { isActionableFinding } from '../workers/scan-api/src/engines/findings.js';

const verifiedEnv = (allowed = true) => ({ cybermeters_db: { prepare: () => ({ bind: () => ({ first: async () => allowed ? { allowed: 1 } : null }) }) } });
const scan = { id: 'scan_t', workspace_id: 'ws_t', domain_id: 'dom_t', domain: 'example.com' };
const observe = (owned, lookups_failed = 0) => async () => ({ roots: ['example.com'], owned, shared: new Map(), lookups_failed });
const answer = (states = {}, service = {}) => async (_env, request) => { assertProbeRequest(request); return ({ observations: request.targets.flatMap((target) => request.ports.map((port) => ({
  address: target.address, hostname: null, port, transport: 'tcp', state: states[port] || 'closed', tls: null, reason: null,
  service: states[port] === 'open' ? (service[port] || { name: 'unidentified', basis: 'unsolicited_tcp_banner', banner_sha256: '0'.repeat(64), banner_sample: '' }) : null }))) }); };
const one = new Map([['81.2.69.160', ['example.com', 'www.example.com']]]);

// Unverified or anonymous: never reaches the probe.
let calls = 0;
const counting = async (...args) => { calls++; return answer()(...args); };
assert.equal((await runRemoteAdminExposureModule(verifiedEnv(false), scan, { observe: observe(one), collect: counting })).reason, 'verified_workspace_required');
assert.equal((await runRemoteAdminExposureModule(verifiedEnv(), { ...scan, workspace_id: null }, { observe: observe(one), collect: counting })).reason, 'verified_workspace_required');
assert.equal(calls, 0, 'no probe without a verified workspace domain');

// Scope: only this domain's own addresses, public, stable order; one valid request.
let request = null;
const capture = async (env, r) => { request = r; return answer()(env, r); };
await runRemoteAdminExposureModule(verifiedEnv(), scan, { collect: capture, observe: observe(new Map([
  ['81.2.69.161', ['www.example.com']], ['81.2.69.160', ['example.com']], ['81.2.69.162', ['mail.other.example']], ['203.0.113.9', ['example.com']]])) });
assert.equal(validateNetworkProbeRequest(request).ok, true);
assert.equal(request.profile, 'network_services');
assert.deepEqual(request.targets, [{ address: '81.2.69.160', hostname: null }, { address: '81.2.69.161', hostname: null }]);
assert.deepEqual(request.ports, REMOTE_ADMIN_PORT_LIST);
assert.equal(REMOTE_ADMIN_PORT_LIST.length, 16);

// Findings: RDP high (named by port), FTP medium, SSH an observation named from its banner.
const exposed = await runRemoteAdminExposureModule(verifiedEnv(), scan, { observe: observe(one),
  collect: answer({ 3389: 'open', 21: 'open', 22: 'open' }, { 22: { name: 'ssh', basis: 'unsolicited_tcp_banner', banner_sha256: '0'.repeat(64), banner_sample: 'SSH-2.0-OpenSSH_9.6' } }) });
assert.equal(exposed.incomplete, false);
const scored = computeScore({ dns: { resolves: true, has_mx: true }, remote_admin_exposure: exposed }, 'example.com');
const byId = (id) => scored.findings.find((item) => item.id === id);
assert.equal(byId('remote_admin_service_reachable')?.severity, 'high');
assert.match(byId('remote_admin_service_reachable').description, /Remote Desktop \(RDP\) port 3389 reachable from the internet at 81\.2\.69\.160 .*the service did not identify itself/);
assert.doesNotMatch(byId('remote_admin_service_reachable').description, /vulnerab|compromis|exploit/i, 'reachability is never a vulnerability claim');
assert.equal(byId('ftp_service_reachable')?.severity, 'medium');
assert.equal(byId('ssh_service_observed')?.finding_type, 'observation');
assert.equal(isActionableFinding(byId('ssh_service_observed')), false, 'SSH is an observation, not a case');
assert.match(byId('ssh_service_observed').description, /SSH-2\.0-OpenSSH_9\.6/);
for (const item of scored.findings.filter((f) => f.module === 'remote_admin_exposure')) {
  assert.doesNotMatch(`${item.title} ${item.description}`, /vulnerab|compromis|breach|attacked/i, 'reachable, never vulnerable');
  assert.equal(item.score_impact, 0);
}
assert.equal(computeScore({ dns: { resolves: true }, remote_admin_exposure: await runRemoteAdminExposureModule(verifiedEnv(), scan, { observe: observe(one), collect: answer() }) }, 'example.com')
  .findings.some((f) => f.module === 'remote_admin_exposure'), false, 'all closed: no finding');

// Completeness: every gap is stated, never partial, and never verifies a case.
const many = new Map(Array.from({ length: REMOTE_ADMIN_LIMITS.max_addresses + 1 }, (_, i) => [`81.2.69.${150 + i}`, ['example.com']]));
const capped = await runRemoteAdminExposureModule(verifiedEnv(), scan, { observe: observe(many), collect: answer() });
assert.equal(capped.incomplete_reason, 'address_cap');
// A port that did not answer is a conclusive "no answer" (22 Oct 2026); only a
// measurement error or a pair that never ran leaves the module incomplete.
const noAnswer = await runRemoteAdminExposureModule(verifiedEnv(), scan, { observe: observe(one), collect: answer({ 3389: 'timeout' }) });
assert.equal(noAnswer.incomplete, false, 'a port that did not answer is a checked pair');
const timedOut = await runRemoteAdminExposureModule(verifiedEnv(), scan, { observe: observe(one), collect: answer({ 3389: 'error' }) });
assert.equal(timedOut.incomplete_reason, 'ports_not_all_checked', 'a measurement error is not a checked pair');
// Nothing on the address answered: not conclusive (filtered vs unreachable).
const allTimeout = Object.fromEntries(REMOTE_ADMIN_PORT_LIST.map((port) => [port, 'timeout']));
const silentHost = await runRemoteAdminExposureModule(verifiedEnv(), scan, { observe: observe(one), collect: answer(allTimeout) });
assert.equal(silentHost.incomplete_reason, 'address_unreachable', 'an address where nothing answered is stated unreachable');
const lookupGap = await runRemoteAdminExposureModule(verifiedEnv(), scan, { observe: observe(new Map(), 2), collect: counting });
assert.equal(lookupGap.incomplete_reason, 'address_lookup_failed');
const down = await runRemoteAdminExposureModule(verifiedEnv(), scan, { observe: observe(one), collect: async (_env,input) => { assertProbeRequest(input); throw new Error('collector_unavailable'); } });
assert.equal(down.error, 'probe_unavailable');
for (const gap of [capped, timedOut, lookupGap, down]) {
  const quality = buildScanQuality({ remote_admin_exposure: gap });
  assert.equal(quality.status, 'complete', `stated limit, not partial: ${gap.incomplete_reason}`);
  assert.equal(quality.stated_limits.some((limit) => limit.module === 'remote_admin_exposure'), true);
  assert.equal(moduleCompletionGate({ remote_admin_exposure: gap }, { status: 'complete' }).canVerify('remote_admin_exposure'), false);
}
assert.equal(moduleCompletionGate({ remote_admin_exposure: exposed }, { status: 'complete' }).canVerify('remote_admin_exposure'), true);

// Mutation proof: each guard reintroduces its defect and the fixture catches it.
const source = readFileSync(new URL('../workers/scan-api/src/engines/remote-admin-exposure.js', import.meta.url), 'utf8')
  .replaceAll('from "./dns.js"', `from "${new URL('../workers/scan-api/src/engines/dns.js', import.meta.url)}"`)
  .replaceAll('from "./network-ownership.js"', `from "${new URL('../workers/scan-api/src/engines/network-ownership.js', import.meta.url)}"`)
  .replaceAll('from "./network-probe.js"', `from "${new URL('../workers/scan-api/src/engines/network-probe.js', import.meta.url)}"`)
  .replaceAll('from "../lib/util.js"', `from "${new URL('../workers/scan-api/src/lib/util.js', import.meta.url)}"`);
const MUTANTS = [
  { name: 'address cap no longer stated', from: 'if (owned.length > selected.length) reasons.push("address_cap");', to: '',
    caught: async (m) => (await m.runRemoteAdminExposureModule(verifiedEnv(), scan, { observe: observe(many), collect: answer() })).incomplete === false },
  { name: 'a measurement error counted as checked', from: '(row?.state === "timeout" && answeredAddresses.has(row.address))', to: 'row?.state !== "not_run"',
    caught: async (m) => (await m.runRemoteAdminExposureModule(verifiedEnv(), scan, { observe: observe(one), collect: answer({ 3389: 'error' }) })).incomplete === false },
  { name: 'another domain\'s address probed', from: '.filter((h) => hostUnder(h, root))', to: '',
    caught: async (m) => { let r = null; await m.runRemoteAdminExposureModule(verifiedEnv(), scan, { observe: observe(new Map([['81.2.69.162', ['mail.other.example']]])), collect: async (e, q) => { r = q; return answer()(e, q); } }); return r !== null; } },
];
const directory = mkdtempSync(join(tmpdir(), 'cm-remote-admin-mutation-'));
try {
  let index = 0;
  for (const mutant of MUTANTS) {
    assert.equal(source.split(mutant.from).length, 2, `mutation anchor present once: ${mutant.name}`);
    const target = join(directory, `remote-admin-mutant-${++index}.mjs`);
    writeFileSync(target, source.replace(mutant.from, mutant.to));
    assert.equal(await mutant.caught(await import(`file://${target}`)), true, `mutant caught: ${mutant.name}`);
  }
} finally { rmSync(directory, { recursive: true, force: true }); }
console.log(`remote-admin exposure: scope, request, findings, wording, stated limits, case gate and ${MUTANTS.length} mutants passed`);
