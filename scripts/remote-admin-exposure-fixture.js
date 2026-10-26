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

// ── Dangling DNS on a cloud address (24 Oct 2026) ─────────────────────────────
// Fires only when the owned address is in a provider's published range AND no
// checked port answered (16 admin + 80/443) in this run. Medium with history of
// a live service there; an observation without. Never a takeover claim.
{
  const cloud = { schema: 'cloud-ranges-v1', fetched_at: new Date().toISOString(), providers: { gcp: ['35.224.0.0/16'], aws: ['3.5.140.0/22'] } };
  const owned = new Map([['35.224.199.137', ['probe.example.com']]]);
  const allTimeout = (overrides = {}) => async (_env, request) => { assertProbeRequest(request); return ({ observations: request.targets.flatMap((t) => request.ports.map((port) => ({
    address: t.address, hostname: null, port, transport: 'tcp', state: overrides[port] || 'timeout', service: null, tls: null, reason: null }))) }); };
  const live = { '35.224.199.137': { seen_at: '2026-10-22T17:40:44.503Z', source: 'open_port', port: 22 } };
  const run = (opts) => runRemoteAdminExposureModule(verifiedEnv(), scan, { observe: observe(owned), cloudRanges: async () => cloud, history: async () => ({}), ...opts });
  const requests = [];
  const dark = await run({ collect: async (e, r) => { requests.push(r); return allTimeout()(e, r); }, history: async () => live });
  assert.deepEqual(requests.map((r) => r.ports.length).sort((a, b) => a - b), [2, 16], 'one web-port request beside the 16-port request');
  const web = requests.find((r) => r.ports.length === 2);
  assert.deepEqual(web.ports, [80, 443]); assert.equal(validateNetworkProbeRequest(web).ok, true);
  assert.deepEqual(dark.cloud_hosts.hosts.map((h) => [h.address, h.provider, h.state]), [['35.224.199.137', 'gcp', 'unreachable']]);
  const darkScore = computeScore({ dns: { resolves: true }, remote_admin_exposure: dark }, 'example.com');
  const medium = darkScore.findings.find((f) => f.id === 'dns_cloud_address_unreachable_after_live');
  assert.equal(medium?.severity, 'medium'); assert.equal(isActionableFinding(medium), true);
  assert.match(medium.description, /^probe\.example\.com resolves to 35\.224\.199\.137 in a Google Cloud address range but no service answered\. If that address was released, another tenant could claim it and serve content on your subdomain\. Verify the record still points at infrastructure you control, or remove the DNS record\.$/);
  assert.doesNotMatch(medium.description + medium.title, /taken over|takeover|vulnerab|compromis/i, 'never a takeover claim');
  // No history: an observation only.
  const unseen = computeScore({ dns: { resolves: true }, remote_admin_exposure: await run({ collect: allTimeout() }) }, 'example.com');
  assert.equal(unseen.findings.some((f) => f.id === 'dns_cloud_address_unreachable_after_live'), false);
  const obs = unseen.findings.find((f) => f.id === 'dns_cloud_address_unreachable_observed');
  assert.equal(obs?.severity, 'info'); assert.equal(isActionableFinding(obs), false);
  // Any answer (open, or closed = the host refused, so it is up) is not dark.
  for (const overrides of [{ 443: 'open' }, { 80: 'closed' }, { 22: 'closed' }]) {
    const answered = await run({ collect: allTimeout(overrides), history: async () => live });
    assert.equal(answered.cloud_hosts.hosts[0].state, 'answered', JSON.stringify(overrides));
    assert.equal(computeScore({ dns: { resolves: true }, remote_admin_exposure: answered }, 'example.com').findings.some((f) => /^dns_cloud_address/.test(f.id)), false);
  }
  // Not a cloud address: never assessed for dangling DNS.
  const onPrem = await runRemoteAdminExposureModule(verifiedEnv(), scan, { observe: observe(new Map([['81.2.69.160', ['example.com']]])), cloudRanges: async () => cloud,
    history: async () => live, collect: allTimeout() });
  assert.deepEqual(onPrem.cloud_hosts.hosts, []);
  // The web-port check failed: not assessed, never unreachable.
  const noWeb = await run({ history: async () => live, collect: async (e, r) => { if (r.ports.length === 2) throw new Error('down'); return allTimeout()(e, r); } });
  assert.deepEqual([noWeb.cloud_hosts.hosts[0].state, noWeb.cloud_hosts.hosts[0].reason], ['not_assessed', 'web_ports_not_checked']);
  // A port not checked (not_run) is not a timeout: not assessed.
  const partial = await run({ history: async () => live, collect: allTimeout({ 3389: 'not_run' }) });
  assert.equal(partial.cloud_hosts.hosts[0].state, 'not_assessed');
  // Stale or missing ranges: the whole check is not assessed.
  const stale = await run({ cloudRanges: async () => ({ ...cloud, fetched_at: new Date(Date.now() - 8 * 86400000).toISOString() }), collect: allTimeout() });
  assert.deepEqual([stale.cloud_hosts.state, stale.cloud_hosts.reason], ['not_assessed', 'cloud_ranges_unavailable']);
  assert.equal(computeScore({ dns: { resolves: true }, remote_admin_exposure: stale }, 'example.com').findings.some((f) => /^dns_cloud_address/.test(f.id)), false);
}

// #1001 live test: the probe has TWO scan slots and answers a third concurrent
// request with collector_busy. With mail_transport holding one slot, the web
// check must run after the 16-port request (and retry once on busy).
{
  const { cloudCheckStatedLimit, CLOUD_CHECK_LIMIT_MESSAGE, CLOUD_RANGES_LIMIT_MESSAGE } = await import('../workers/scan-api/src/engines/scan-stated-limits.js');
  const cloud = { schema: 'cloud-ranges-v1', fetched_at: new Date().toISOString(), providers: { gcp: ['35.224.0.0/16'] } };
  const owned = new Map([['35.224.199.137', ['probe.example.com']]]);
  const live = async () => ({ '35.224.199.137': { seen_at: '2026-10-24T17:43:30.791Z', source: 'tls_handshake', port: 443 } });
  const dark = (r) => ({ observations: r.targets.flatMap((t) => r.ports.map((port) => ({ address: t.address, hostname: null, port, transport: 'tcp', state: 'timeout', service: null, tls: null, reason: null }))) });
  const twoSlots = ({ held = 1, busyFirstWeb = 0 } = {}) => {
    let inFlight = 0, webCalls = 0;
    return async (_env, request) => {
      assertProbeRequest(request);
      if (request.ports.length === 2 && webCalls++ < busyFirstWeb) throw new Error('collector_busy');
      if (inFlight + held >= 2) throw new Error('collector_busy');
      inFlight++; try { await new Promise((resolve) => setTimeout(resolve, 20)); return dark(request); } finally { inFlight--; }
    };
  };
  const run = (opts) => runRemoteAdminExposureModule(verifiedEnv(), scan, { observe: observe(owned), cloudRanges: async () => cloud, history: live, ...opts });
  const sequential = await run({ collect: twoSlots() });
  assert.deepEqual([sequential.cloud_hosts.hosts[0].state, sequential.cloud_hosts.hosts[0].reason], ['unreachable', 'no_port_answered'],
    'with one slot held elsewhere, the web check still gets a slot (it runs after the 16-port request)');
  assert.equal(computeScore({ dns: { resolves: true }, remote_admin_exposure: sequential }, 'example.com').findings
    .some((f) => f.id === 'dns_cloud_address_unreachable_after_live'), true, 'the live-test shape now yields the medium');
  const retried = await run({ collect: twoSlots({ busyFirstWeb: 1 }) });
  assert.equal(retried.cloud_hosts.hosts[0].state, 'unreachable', 'one retry after collector_busy');
  const busy = await run({ collect: twoSlots({ busyFirstWeb: 2 }) });
  assert.deepEqual([busy.cloud_hosts.hosts[0].state, busy.cloud_hosts.hosts[0].reason], ['not_assessed', 'collector_busy'], 'busy twice: the reason is recorded');
  // Budget: the accounting refuses the web attempt -> 'budget', no request sent.
  let issued = 0, webSent = 0;
  const accounting = { assertCanIssue: () => { if (issued >= 1) throw new Error('budget'); return true; }, recordAttempt: () => { issued++; } };
  const budget = await run({ accounting, collect: async (e, r) => { if (r.ports.length === 2) webSent++; return dark(r); } });
  assert.deepEqual([budget.cloud_hosts.hosts[0].reason, webSent], ['budget', 0], 'no budget bypass');
  // Deadline: too little time left after the 16-port request -> 'deadline'.
  let clock = Date.now();
  const late = await run({ now: () => clock, collect: async (e, r) => { if (r.ports.length === 16) clock = Date.parse(r.deadline_at) - 500; return dark(r); } });
  assert.equal(late.cloud_hosts.hosts[0].reason, 'deadline');
  // R1 #1003 (1): less than connect timeout + margin left -> 'deadline', never a
  // shortened connect window read as 'timeout' (a false 'unreachable').
  const { CLOUD_WEB_MIN_REMAINING_MS } = await import('../workers/scan-api/src/engines/remote-admin-exposure.js');
  const { PROBE_CONNECT_TIMEOUT_MS } = await import('../workers/scan-api/src/engines/network-probe.js');
  assert.ok(CLOUD_WEB_MIN_REMAINING_MS >= 3000 && CLOUD_WEB_MIN_REMAINING_MS > PROBE_CONNECT_TIMEOUT_MS, 'guard = connect timeout + margin');
  assert.ok(readFileSync(new URL('../workers/network-probe/src/collector.js', import.meta.url), 'utf8').includes(`Math.min(${PROBE_CONNECT_TIMEOUT_MS},deadline-Date.now())`),
    'PROBE_CONNECT_TIMEOUT_MS is the collector\'s connect window');
  let clock2 = Date.now(), lateWeb = 0;
  const shortWindow = await run({ now: () => clock2, collect: async (e, r) => {
    if (r.ports.length === 16) clock2 = Date.parse(r.deadline_at) - 2500; else lateWeb++;
    return dark(r); } });
  assert.deepEqual([shortWindow.cloud_hosts.hosts[0].state, shortWindow.cloud_hosts.hosts[0].reason, lateWeb], ['not_assessed', 'deadline', 0],
    '2.5 s left (>= the old 1.5 s guard): no web request, deadline, never unreachable');
  // R1 #1003 (2): a non-busy error is not retried.
  let webTries = 0;
  const down = await run({ collect: async (e, r) => { if (r.ports.length === 2) { webTries++; throw new Error('collector_unavailable'); } return dark(r); } });
  assert.deepEqual([webTries, down.cloud_hosts.hosts[0].reason], [1, 'web_ports_not_checked'], 'only collector_busy is retried');
  // ... and the retry goes through the accounting: budget exhausted on the retry -> 'budget'.
  let used = 0, webAttempts = 0;
  const retryBudget = { assertCanIssue: () => { if (used >= 2) throw new Error('budget'); return true; }, recordAttempt: () => { used++; } };
  const exhausted = await run({ accounting: retryBudget, collect: async (e, r) => { if (r.ports.length === 2) { webAttempts++; throw new Error('collector_busy'); } return dark(r); } });
  assert.deepEqual([webAttempts, exhausted.cloud_hosts.hosts[0].reason], [1, 'budget'], 'the retry is refused by the budget, not sent');
  // The 16-port request failed: no web request at all.
  let webAfterFail = 0;
  await run({ collect: async (e, r) => { if (r.ports.length === 2) webAfterFail++; throw new Error('collector_unavailable'); } });
  assert.equal(webAfterFail, 0, 'no web request after the 16-port request failed');
  // A failed 16-port request with NO owned address in a cloud range: the cloud
  // check had nothing to check, so no cloud limit; the remote-admin limit stays.
  {
    const { isStatedAccessLimit, statedLimitMessage } = await import('../workers/scan-api/src/engines/scan-stated-limits.js');
    const plain = await runRemoteAdminExposureModule(verifiedEnv(), scan, { observe: observe(new Map([['81.2.69.161', ['www.example.com']]])),
      cloudRanges: async () => cloud, history: live, collect: async () => { throw new Error('collector_unavailable'); } });
    assert.deepEqual([plain.cloud_hosts.state, plain.cloud_hosts.hosts], ['assessed', []], 'no cloud address: nothing to assess');
    assert.equal(cloudCheckStatedLimit({ remote_admin_exposure: plain }), null, 'no cloud-check limit when no address is in a cloud range');
    assert.ok(isStatedAccessLimit('remote_admin_exposure', plain) && /unavailable/.test(statedLimitMessage('remote_admin_exposure', plain)), 'the remote-admin limit stays');
    const stated = buildScanQuality({ remote_admin_exposure: plain }).stated_limits;
    assert.deepEqual(stated.map((l) => l.reason), ['probe_unavailable'], 'exactly the remote-admin limit');
    // With a cloud address the failed request still states the cloud limit.
    const cloudy = await runRemoteAdminExposureModule(verifiedEnv(), scan, { observe: observe(owned), cloudRanges: async () => cloud, history: live,
      collect: async () => { throw new Error('collector_unavailable'); } });
    assert.equal(cloudCheckStatedLimit({ remote_admin_exposure: cloudy })?.reason, 'cloud_check_incomplete', 'a cloud address still states the cloud limit');
  }
  // Stated limits: never silence when the cloud check did not complete.
  assert.deepEqual(cloudCheckStatedLimit({ remote_admin_exposure: busy }), { module: 'remote_admin_exposure', reason: 'cloud_check_incomplete',
    hosts: ['probe.example.com'], message: CLOUD_CHECK_LIMIT_MESSAGE });
  assert.equal(cloudCheckStatedLimit({ remote_admin_exposure: { cloud_hosts: { state: 'not_assessed', reason: 'cloud_ranges_unavailable', hosts: [] } } }).message, CLOUD_RANGES_LIMIT_MESSAGE);
  assert.equal(cloudCheckStatedLimit({ remote_admin_exposure: sequential }), null, 'an assessed check states nothing');
  assert.ok(buildScanQuality({ remote_admin_exposure: busy }).stated_limits.some((l) => l.reason === 'cloud_check_incomplete' && l.message === CLOUD_CHECK_LIMIT_MESSAGE),
    'scan quality carries the cloud-check limit');
}

// #1001 live test #2: the scan's own probe calls (mail transport's batch of two,
// remote admin, live TLS) share the probe's two slots. Through the per-scan gate
// they queue; without it the 16-port call is refused collector_busy.
{
  const { createProbeGate, PROBE_SCAN_SLOTS, PROBE_MIN_REMAINING_MS, probeErrorDetail } = await import('../workers/scan-api/src/engines/network-probe.js');
  const { runMailTransportModule } = await import('../workers/scan-api/src/engines/mail-transport.js');
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  assert.equal(PROBE_SCAN_SLOTS, 2, 'the gate is sized to the probe\'s two scan slots');
  // Gate unit behaviour: FIFO, at most `capacity` at once, released on every path.
  {
    const gate = createProbeGate(2);
    const order = [];
    let running = 0, peak = 0;
    const job = (name, ms, fail = false) => gate.run(async () => { running++; peak = Math.max(peak, running); order.push(name); await sleep(ms); running--; if (fail) throw new Error('collector_unavailable'); return name; });
    const settled = await Promise.allSettled([job('a', 20), job('b', 20, true), job('c', 5), job('d', 5)]);
    assert.deepEqual([order, peak, settled.map((r) => r.status)], [['a', 'b', 'c', 'd'], 2, ['fulfilled', 'rejected', 'fulfilled', 'fulfilled']], 'FIFO, never above capacity, a throw releases');
    assert.deepEqual([gate.active, gate.waiting], [0, 0], 'no permit leaked after a throw');
    // A queued call aborted while waiting leaves the queue and is never sent.
    let sent = 0;
    const controller = new AbortController();
    const hold = gate.run(() => sleep(30));
    const hold2 = gate.run(() => sleep(30));
    const queued = gate.run(async () => { sent++; }, { signal: controller.signal });
    controller.abort();
    await assert.rejects(queued, /collector_aborted/);
    await Promise.all([hold, hold2]);
    assert.deepEqual([sent, gate.active, gate.waiting], [0, 0, 0], 'an aborted queued call is not sent and leaks no permit');
    // An aborted call holding a permit releases it too.
    const inflight = new AbortController();
    const running2 = gate.run(() => new Promise((_, reject) => inflight.signal.addEventListener('abort', () => reject(new Error('collector_aborted')))), { signal: inflight.signal });
    inflight.abort();
    await assert.rejects(running2, /collector_aborted/);
    assert.deepEqual([gate.active, gate.waiting], [0, 0], 'an aborted in-flight call releases its permit');
    // When its turn comes with less than a connect window + margin left, the call is not sent: 'deadline'.
    let clock = Date.now(), late = 0;
    const timed = createProbeGate(1, { now: () => clock });
    const first = timed.run(async () => { await sleep(10); clock += 60_000; });
    const second = timed.run(async () => { late++; }, { deadlineAt: new Date(Date.now() + 30_000).toISOString() });
    await first;
    await assert.rejects(second, /probe_gate_deadline/);
    assert.deepEqual([late, timed.active], [0, 0], 'a call whose deadline passed in the queue is not sent');
    assert.ok(PROBE_MIN_REMAINING_MS >= 3000);
    assert.deepEqual([new Error('collector_busy'), new Error('probe_gate_deadline'), new Error('collector_aborted'), Object.assign(new Error('x'), { name: 'SubrequestBudgetExhaustedError' }), new Error('boom')].map((e) => probeErrorDetail(e)),
      ['collector_busy', 'deadline', 'deadline', 'budget', 'collector_unavailable']);
  }
  // The live-test shape: a 3-MX mail plan (batch of two) and remote admin on
  // probe.cybermeters.com's shape, launched together on a 2-slot probe.
  const gcp = { schema: 'cloud-ranges-v1', fetched_at: new Date().toISOString(), providers: { gcp: ['35.224.0.0/16'] } };
  const probeHost = new Map([['35.224.199.137', ['probe.example.com']]]);
  const wasLive = async () => ({ '35.224.199.137': { seen_at: '2026-10-24T17:43:30.791Z', source: 'tls_handshake', port: 443 } });
  const allDark = (r) => ({ observations: r.targets.flatMap((t) => r.ports.map((port) => ({ address: t.address, hostname: null, port, transport: 'tcp', state: 'timeout', service: null, tls: null, reason: null }))) });
  const mxDns = { mx_records: [{ value: '10 route1.mx.example.com.' }, { value: '20 route2.mx.example.com.' }, { value: '30 route3.mx.example.com.' }] };
  const mailEnv = { cybermeters_db: { prepare: () => ({ bind: () => ({ first: async () => ({ allowed: 1 }) }) }) } };
  const lookup = async (host, type) => ({ Status: 0, Answer: type === 'A' ? [{ type: 1, name: host + '.', data: '162.159.205.12' }] : [] });
  const tlsReceipt = () => ({ results: [{ state: 'accepted', reason: 'handshake_completed', observed_at: new Date().toISOString(),
    evidence: { authenticated_finished: true, negotiated: { version: 'tls1_3', cipher: 'TLS_AES_128_GCM_SHA256' }, certificates: { hostname: true, trust: 'valid', offered_chain: [{ not_after: 1790000000 }] } } }] });
  const together = async (wrap) => {
    let inFlight = 0, peak = 0, refused = 0;
    const take = async (work) => {
      if (inFlight >= 2) { refused++; throw new Error('collector_busy'); }
      inFlight++; peak = Math.max(peak, inFlight);
      try { await sleep(40); return work(); } finally { inFlight--; }
    };
    const [mail, ra] = await Promise.all([
      runMailTransportModule(mailEnv, { id: 'scan_gate', workspace_id: 'ws', domain_id: 'dom', domain: 'example.com' }, mxDns,
        { lookup, collect: wrap(async () => take(tlsReceipt)) }),
      // Remote admin reaches the probe a moment after mail's first batch, as live.
      runRemoteAdminExposureModule(verifiedEnv(), scan, { observe: async (...args) => { await sleep(10); return observe(probeHost)(...args); },
        cloudRanges: async () => gcp, history: wasLive, collect: wrap(async (_env, r) => { assertProbeRequest(r); return take(() => allDark(r)); }) }),
    ]);
    return { mail, ra, peak, refused };
  };
  const ungated = await together((collect) => collect);
  assert.ok(ungated.refused >= 1, 'without the gate the scan\'s own calls collide (the live-test failure)');
  const gate = createProbeGate();
  const gated = await together((collect) => gate.wrap(collect));
  assert.equal(gated.refused, 0, 'through the gate no call is refused');
  assert.ok(gated.peak <= 2, 'never more than two at once');
  assert.deepEqual([gate.active, gate.waiting], [0, 0], 'every permit released');
  assert.equal(gated.ra.state, 'observed', 'the 16-port receipt arrives');
  assert.deepEqual([gated.mail.coverage.tested, gated.mail.coverage.planned], [3, 3], 'all three MX hosts tested');
  assert.equal(gated.ra.cloud_hosts.hosts[0].state, 'unreachable');
  const medium = computeScore({ dns: { resolves: true }, remote_admin_exposure: gated.ra }, 'example.com').findings
    .filter((f) => f.id === 'dns_cloud_address_unreachable_after_live');
  assert.deepEqual(medium.map((f) => f.severity), ['medium'], 'the probe.cybermeters.com shape yields the MEDIUM');
  // The underlying reason is recorded beside the unchanged customer reason.
  const busyAlways = await runRemoteAdminExposureModule(verifiedEnv(), scan, { observe: observe(probeHost), cloudRanges: async () => gcp, history: wasLive,
    collect: async () => { throw new Error('collector_busy'); } });
  assert.deepEqual([busyAlways.incomplete_reason, busyAlways.incomplete_detail], ['probe_unavailable', 'collector_busy'], 'detail recorded, sentence unchanged');
  const mailBusy = await runMailTransportModule(mailEnv, { id: 'scan_gate', workspace_id: 'ws', domain_id: 'dom', domain: 'example.com' }, mxDns,
    { lookup, collect: async () => { throw new Error('collector_busy'); } });
  assert.deepEqual([...new Set(mailBusy.hosts.map((h) => `${h.reason}/${h.detail}`))], ['probe_unavailable/collector_busy'], 'mail records the detail too');
  // The scan engine routes all three of its probe callers through one gate.
  const engineSource = readFileSync(new URL('../workers/scan-api/src/engines/scan-engine.js', import.meta.url), 'utf8');
  assert.equal((engineSource.match(/probeGate\.wrap\(/g) || []).length, 3, 'live TLS, mail transport and remote admin are gated');
  assert.equal((engineSource.match(/createProbeGate\(\)/g) || []).length, 1, 'one gate per scan');
}

// The cloud-range cache is a global public reference list: a fixed key, and only
// provider CIDRs and fetch metadata are stored (tenant-query audit suppression).
{
  const { refreshCloudRanges, CLOUD_RANGES_KEY, CLOUD_RANGE_SOURCES } = await import('../workers/scan-api/src/engines/cloud-ranges.js');
  assert.equal(CLOUD_RANGES_KEY, 'public-feeds/cloud-ranges-v1.json');
  const puts = [];
  const feeds = {
    'https://www.gstatic.com/ipranges/cloud.json': { syncToken: 'x', creationTime: 'x', prefixes: [{ ipv4Prefix: '35.224.0.0/16', service: 'Google Cloud', scope: 'us', secret: 'drop me' }] },
    'https://ip-ranges.amazonaws.com/ip-ranges.json': { prefixes: [{ ip_prefix: '3.5.140.0/22', service: 'EC2' }, { ip_prefix: '13.32.0.0/15', service: 'CLOUDFRONT' }], ipv6_prefixes: [] },
  };
  await refreshCloudRanges({ cybermeters_reports: { put: async (key, value) => { puts.push([key, JSON.parse(value)]); } } }, {
    fetchImpl: async (url, init) => { assert.equal(init.method, 'GET'); assert.equal(init.redirect, 'error');
      return feeds[url] ? new Response(JSON.stringify(feeds[url]), { status: 200 }) : new Response('no', { status: 503 }); } });
  assert.equal(puts.length, 1); assert.equal(puts[0][0], CLOUD_RANGES_KEY);
  assert.deepEqual(Object.keys(puts[0][1]).sort(), ['fetched_at', 'providers', 'schema', 'sources']);
  assert.deepEqual(puts[0][1].providers, { gcp: ['35.224.0.0/16'], aws: ['3.5.140.0/22'] }, 'only CIDRs; CloudFront (CDN) excluded; no other feed field');
  assert.deepEqual(CLOUD_RANGE_SOURCES.map((s) => s.id), ['gcp', 'aws', 'oracle', 'digitalocean']);
}

// ── Stale stored address vs this scan's DNS (26 Oct 2026, mc-b55d622593c6) ─────
// The REAL default scope path (observedNetworkAddresses + confirmObservedScope):
// a stored inventory address is never probed or reported as "resolves to" on
// the strength of the stored row alone. Offline: DNS is a stub, fetch throws.
const realFetch = globalThis.fetch;
globalThis.fetch = async () => { throw new TypeError('offline fixture: no network'); };
const staleScope = {};
try {
  const cloud = { schema: 'cloud-ranges-v1', fetched_at: new Date().toISOString(), providers: { gcp: ['35.224.0.0/16'] } };
  const live = { '35.224.199.137': { seen_at: '2026-10-22T17:40:44.503Z', source: 'open_port', port: 22 } };
  const asset = (hostname, ips) => ({ hostname, ip_addresses: JSON.stringify(ips), cname: null, status: 'active', lifecycle_state: 'not_assessed', wildcard_dns: 0, domain: 'example.com' });
  const storedEnv = (rows) => ({ cybermeters_db: { prepare: (sql) => ({ bind: () => ({
    first: async () => (/AS allowed/.test(sql) ? { allowed: 1 } : null),
    all: async () => ({ results: /SELECT DISTINCT lower\(d\.domain\)/.test(sql) ? [{ domain: 'example.com' }] : /FROM workspace_assets a/.test(sql) ? rows : [] }) }) }) } });
  const rr = (type, data) => ({ name: '', type, TTL: 60, data });
  const empty = { Status: 0, Answer: [] };
  const apex = { 'example.com A': { Status: 0, Answer: [rr(1, '81.2.69.160')] } };
  // The apex host answers (closed ports); every cloud address is dark.
  const collect = (requests) => async (_env, request) => { assertProbeRequest(request); requests.push(request); return ({ observations: request.targets.flatMap((t) => request.ports.map((port) => ({
    address: t.address, hostname: null, port, transport: 'tcp', state: t.address.startsWith('35.224.') ? 'timeout' : 'closed', service: null, tls: null, reason: null }))) }); };
  const scopeRun = async (rows, table = {}) => {
    const requests = [], asked = [];
    const dnsQueryImpl = async (name, type) => {
      asked.push(`${name} ${type}`);
      const value = { ...apex, ...table }[`${name} ${type}`] ?? empty;
      if (value instanceof Error) throw value;
      return value;
    };
    const module = await runRemoteAdminExposureModule(storedEnv(rows), scan, { dnsQueryImpl, cloudRanges: async () => cloud, history: async () => live, collect: collect(requests) });
    const targeted = requests.flatMap((r) => r.targets.map((t) => t.address));
    const score = computeScore({ dns: { resolves: true }, remote_admin_exposure: module }, 'example.com');
    const dangling = score.findings.find((f) => f.id === 'dns_cloud_address_unreachable_after_live') || null;
    const canVerify = moduleCompletionGate({ remote_admin_exposure: module }, { status: 'complete' }).canVerify('remote_admin_exposure');
    return { module, targeted, asked, dangling, canVerify };
  };
  const stale = [asset('probe.example.com', ['35.224.199.137'])];

  // Removed record (NOERROR, no A/AAAA): the stored address is neither probed nor reported.
  for (const [label, table] of [['NOERROR/empty', {}], ['NXDOMAIN', { 'probe.example.com A': { Status: 3 }, 'probe.example.com AAAA': { Status: 3 } }]]) {
    const run = await scopeRun(stale, table);
    assert.ok(run.asked.includes('probe.example.com A') && run.asked.includes('probe.example.com AAAA'), `${label}: fresh A+AAAA evidence is obtained`);
    assert.equal(run.targeted.includes('35.224.199.137'), false, `${label}: the stale stored address is not probed`);
    assert.equal(run.dangling, null, `${label}: no "resolves to" claim for a removed record`);
    assert.deepEqual(run.module.scope_recheck.stale, [{ address: '35.224.199.137', hostname: 'probe.example.com' }]);
    assert.equal(run.module.incomplete, false, `${label}: a definitively removed record is a complete re-check`);
    assert.equal(run.canVerify, true, `${label}: the removed record can verify the case`);
    staleScope[label] = run;
  }
  // Unchanged positive answer: the existing dangling-DNS finding still fires.
  const positive = await scopeRun(stale, { 'probe.example.com A': { Status: 0, Answer: [rr(1, '35.224.199.137')] } });
  assert.equal(positive.targeted.includes('35.224.199.137'), true);
  assert.equal(positive.dangling?.severity, 'medium');
  assert.match(positive.dangling.description, /^probe\.example\.com resolves to 35\.224\.199\.137 in a Google Cloud address range/);
  // A truncated answer that still contains the address keeps it.
  const truncatedSame = await scopeRun(stale, { 'probe.example.com A': { Status: 0, TC: true, Answer: [rr(1, '35.224.199.137')] } });
  assert.equal(truncatedSame.dangling?.severity, 'medium', 'a truncated answer naming the address keeps the claim');
  // CNAME chain ending at the same address: still the same record.
  const cname = await scopeRun(stale, { 'probe.example.com A': { Status: 0, Answer: [rr(5, 'lb.cloud.example.'), rr(1, '35.224.199.137')] } });
  assert.equal(cname.dangling?.severity, 'medium', 'a CNAME chain to the address keeps the claim');
  // Changed address: the old address is not probed, and the re-check cannot verify anything.
  const changed = await scopeRun(stale, { 'probe.example.com A': { Status: 0, Answer: [rr(1, '35.224.199.200')] } });
  assert.equal(changed.targeted.includes('35.224.199.137'), false);
  assert.equal(changed.dangling, null);
  assert.ok(changed.module.incomplete_reasons.includes('address_changed'));
  assert.equal(changed.canVerify, false, 'a changed address cannot cause a false recovery');
  // Unknown DNS (SERVFAIL, or a refused/out-of-budget lookup): no claim, no recovery.
  for (const [label, table] of [['SERVFAIL', { 'probe.example.com A': { Status: 2 } }], ['lookup refused', { 'probe.example.com AAAA': new Error('subrequest_budget_exhausted') }],
    // A truncated answer may be missing records: it proves neither absence nor a move.
    ['truncated empty', { 'probe.example.com A': { Status: 0, TC: true, Answer: [] } }],
    ['truncated elsewhere', { 'probe.example.com A': { Status: 0, TC: true, Answer: [rr(1, '35.224.199.200')] } }]]) {
    const run = await scopeRun(stale, table);
    assert.equal(run.targeted.includes('35.224.199.137'), false, `${label}: not probed on stored evidence alone`);
    assert.equal(run.dangling, null, `${label}: no "resolves to" claim`);
    assert.ok(run.module.incomplete_reasons.includes('address_lookup_failed'), `${label}: stated as a lookup gap`);
    assert.equal(run.canVerify, false, `${label}: unknown DNS cannot verify a case`);
  }
  // Two names on one address: only the name that still points there is named.
  const two = await scopeRun([asset('probe.example.com', ['35.224.199.137']), asset('old.example.com', ['35.224.199.137'])],
    { 'probe.example.com A': { Status: 0, Answer: [rr(1, '35.224.199.137')] } });
  assert.deepEqual(two.dangling?.affected_hosts, ['probe.example.com']);
  assert.doesNotMatch(two.dangling.description, /old\.example\.com/);
  // Bounded: at most max_names names are looked up again; the rest are unknown, never assumed.
  const crowd = Array.from({ length: 10 }, (_, i) => asset(`h${i}.example.com`, ['35.224.199.137']));
  const capped = await scopeRun(crowd, Object.fromEntries(crowd.map((a) => [`${a.hostname} A`, { Status: 0, Answer: [rr(1, '35.224.199.137')] }])));
  const recheckQueries = capped.asked.filter((q) => /^h\d\.example\.com /.test(q)).length;
  assert.ok(recheckQueries <= 2 * 8, `fresh lookups stay bounded (${recheckQueries})`);
  assert.ok(capped.module.incomplete_reasons.includes('address_lookup_failed'), 'names beyond the cap are stated, not assumed');
} finally { globalThis.fetch = realFetch; }

// Mutation proof: each guard reintroduces its defect and the fixture catches it.
const source = readFileSync(new URL('../workers/scan-api/src/engines/remote-admin-exposure.js', import.meta.url), 'utf8')
  .replaceAll('from "./dns.js"', `from "${new URL('../workers/scan-api/src/engines/dns.js', import.meta.url)}"`)
  .replaceAll('from "./network-ownership.js"', `from "${new URL('../workers/scan-api/src/engines/network-ownership.js', import.meta.url)}"`)
  .replaceAll('from "./network-probe.js"', `from "${new URL('../workers/scan-api/src/engines/network-probe.js', import.meta.url)}"`)
  .replaceAll('from "../lib/util.js"', `from "${new URL('../workers/scan-api/src/lib/util.js', import.meta.url)}"`)
  .replaceAll('from "./cloud-ranges.js"', `from "${new URL('../workers/scan-api/src/engines/cloud-ranges.js', import.meta.url)}"`)
  .replaceAll('from "./network-suggestions.js"', `from "${new URL('../workers/scan-api/src/engines/network-suggestions.js', import.meta.url)}"`);
const MUTANTS = [
  { name: 'address cap no longer stated', from: 'if (owned.length > selected.length) reasons.push("address_cap");', to: '',
    caught: async (m) => (await m.runRemoteAdminExposureModule(verifiedEnv(), scan, { observe: observe(many), collect: answer() })).incomplete === false },
  { name: 'a measurement error counted as checked', from: '(row?.state === "timeout" && answeredAddresses.has(row.address))', to: 'row?.state !== "not_run"',
    caught: async (m) => (await m.runRemoteAdminExposureModule(verifiedEnv(), scan, { observe: observe(one), collect: answer({ 3389: 'error' }) })).incomplete === false },
  { name: 'another domain\'s address probed', from: '.filter((h) => hostUnder(h, root))', to: '',
    caught: async (m) => { let r = null; await m.runRemoteAdminExposureModule(verifiedEnv(), scan, { observe: observe(new Map([['81.2.69.162', ['mail.other.example']]])), collect: async (e, q) => { r = q; return answer()(e, q); } }); return r !== null; } },
  { name: 'a host that answered on the web ports read as dark', from: 'if (answered(rows, address) || answered(webRows, address))', to: 'if (answered(rows, address))',
    caught: async (m) => (await m.runRemoteAdminExposureModule(verifiedEnv(), scan, { observe: observe(new Map([['35.224.199.137', ['probe.example.com']]])),
      cloudRanges: async () => ({ schema: 'cloud-ranges-v1', fetched_at: new Date().toISOString(), providers: { gcp: ['35.224.0.0/16'] } }), history: async () => ({}),
      collect: async (_e, r) => ({ observations: r.targets.flatMap((t) => r.ports.map((port) => ({ address: t.address, hostname: null, port, transport: 'tcp',
        state: port === 443 ? 'open' : 'timeout', service: null, tls: null, reason: null }))) }) })).cloud_hosts.hosts[0].state !== 'answered' },
  // Without the guard a failed web check either crashes or reads as assessed: both are caught.
  { name: 'a failed web check read as dark', from: 'if (!webRows) return { ...base, state: "not_assessed", reason: webReason || "web_ports_not_checked" };', to: '',
    caught: async (m) => (await m.runRemoteAdminExposureModule(verifiedEnv(), scan, { observe: observe(new Map([['35.224.199.137', ['probe.example.com']]])),
      cloudRanges: async () => ({ schema: 'cloud-ranges-v1', fetched_at: new Date().toISOString(), providers: { gcp: ['35.224.0.0/16'] } }), history: async () => ({}),
      collect: async (_e, r) => { if (r.ports.length === 2) throw new Error('down'); return ({ observations: r.targets.flatMap((t) => r.ports.map((port) => ({ address: t.address, hostname: null, port, transport: 'tcp',
        state: 'timeout', service: null, tls: null, reason: null }))) }); } }).catch(() => ({ cloud_hosts: { hosts: [{ state: 'crashed' }] } }))).cloud_hosts.hosts[0].state !== 'not_assessed' },
  // Stale stored address (26 Oct 2026): each reintroduces a false "resolves to" or a false recovery.
  { name: 'a stored address kept without fresh DNS', from: 'else if (answer.addresses.includes(canonical)) kept.push(hostname);', to: 'else if (answer) kept.push(hostname);',
    caught: async (m) => (await staleRun(m, {})).targeted.includes('35.224.199.137') },
  { name: 'an unknown lookup treated as still pointing there', from: 'if (!answer || answer.state === "unknown") recheck.unknown.push({ address, hostname });', to: 'if (!answer || answer.state === "unknown") kept.push(hostname);',
    caught: async (m) => (await staleRun(m, { 'probe.example.com A': { Status: 2 } })).targeted.includes('35.224.199.137') },
  { name: 'SERVFAIL read as a definitive answer', from: 'if (status !== 0 && status !== 3) return { state: "unknown", addresses: [] };', to: '',
    caught: async (m) => (await staleRun(m, { 'probe.example.com A': { Status: 2 } })).canVerify === true },
  { name: 'a truncated empty answer read as a removed record', from: 'else if (answer.truncated) recheck.unknown.push({ address, hostname });', to: '',
    caught: async (m) => (await staleRun(m, { 'probe.example.com A': { Status: 0, TC: true, Answer: [] } })).canVerify === true },
  { name: 'a changed address no longer stated', from: 'if (addressesChanged > 0) reasons.push("address_changed");', to: '',
    caught: async (m) => (await staleRun(m, { 'probe.example.com A': { Status: 0, Answer: [{ type: 1, data: '35.224.199.200' }] } })).canVerify === true },
];
// The stale-scope fixture above, against a mutant module.
async function staleRun(m, table) {
  const realFetchInner = globalThis.fetch;
  globalThis.fetch = async () => { throw new TypeError('offline fixture: no network'); };
  try {
    const rows = [{ hostname: 'probe.example.com', ip_addresses: '["35.224.199.137"]', cname: null, status: 'active', lifecycle_state: 'not_assessed', wildcard_dns: 0, domain: 'example.com' }];
    const env = { cybermeters_db: { prepare: (sql) => ({ bind: () => ({
      first: async () => (/AS allowed/.test(sql) ? { allowed: 1 } : null),
      all: async () => ({ results: /SELECT DISTINCT lower\(d\.domain\)/.test(sql) ? [{ domain: 'example.com' }] : /FROM workspace_assets a/.test(sql) ? rows : [] }) }) }) } };
    const answers = { 'example.com A': { Status: 0, Answer: [{ type: 1, data: '81.2.69.160' }] }, ...table };
    const requests = [];
    const module = await m.runRemoteAdminExposureModule(env, scan, {
      dnsQueryImpl: async (name, type) => answers[`${name} ${type}`] ?? { Status: 0, Answer: [] },
      cloudRanges: async () => ({ schema: 'cloud-ranges-v1', fetched_at: new Date().toISOString(), providers: { gcp: ['35.224.0.0/16'] } }), history: async () => ({}),
      collect: async (_e, r) => { requests.push(r); return ({ observations: r.targets.flatMap((t) => r.ports.map((port) => ({ address: t.address, hostname: null, port, transport: 'tcp',
        state: t.address.startsWith('35.224.') ? 'timeout' : 'closed', service: null, tls: null, reason: null }))) }); } });
    return { targeted: requests.flatMap((r) => r.targets.map((t) => t.address)),
      canVerify: moduleCompletionGate({ remote_admin_exposure: module }, { status: 'complete' }).canVerify('remote_admin_exposure') };
  } finally { globalThis.fetch = realFetchInner; }
}
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
