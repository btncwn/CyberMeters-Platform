#!/usr/bin/env node
// Offline contract fixtures and actual in-memory mutation execution.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const moduleUrl = new URL('../workers/scan-api/src/engines/discovery-dns-observation.js', import.meta.url);
const source = fs.readFileSync(fileURLToPath(moduleUrl), 'utf8');
const dependency = new URL('./hostname-candidates.js', moduleUrl).href;
const at = '2026-10-12T00:00:00.000Z';
const rr = (name, type, data, TTL = 300) => ({ name, type, data, TTL });

function fixtures(api) {
  let checks = 0;
  const eq = (actual, expected, label) => { assert.deepEqual(actual, expected, label); checks++; };
  const ok = (actual, label) => { assert.ok(actual, label); checks++; };
  const classify = (response, recordType = 'A', extra = {}) => api.classifyDiscoveryDnsResponse({
    hostname: 'EXAMPLE.com.', recordType, response, observedAt: at, ...extra,
  });
  const merge = (...items) => api.mergeDiscoveryDnsObservations(items);
  const A = rr('example.com.', 1, '192.0.2.1');
  const AAAA = rr('example.com.', 28, '2001:DB8::1');
  const positive = classify({ Status: 0, Question: [{ name: 'example.com', type: 1 }], Answer: [A] });
  eq(positive.hostname, 'example.com', 'canonical query owner');
  eq(positive.outcome, 'answer', 'A answer');
  eq(positive.dns_address_resolved, true, 'A address observed');
  eq(positive.observed_at, at, 'supplied timestamp');
  eq(positive.records, [{ name: 'example.com', type: 'A', data: '192.0.2.1', ttl: 300 }], 'normalised answer');
  eq(classify({ Status: 0 }).observed_at, at, 'empty answers retain provenance');
  eq(api.classifyDiscoveryDnsResponse({ hostname: 'example.com', recordType: 'A', response: { Status: 0 } }).observed_at, null, 'no ambient clock');
  for (const type of [1, '1', 'a', 'A']) eq(classify({ Status: 0, Answer: [A] }, type).record_type, 'A', 'query type variants');
  eq(classify({ Status: 0, Answer: [rr('xn--bcher-kva.example', 1, '192.0.2.2')] }, 'A', { hostname: 'bücher.example' }).outcome, 'answer', 'shared IDNA canonicalisation');
  for (const [Status, outcome] of [[3, 'nxdomain'], [0, 'nodata'], [2, 'servfail'], [5, 'refused'], [1, 'dns_error']]) {
    const value = classify({ Status });
    eq(value.outcome, outcome, `distinct rcode ${Status}`);
    eq(value.dns_address_resolved, [0, 3].includes(Status) ? false : null, 'error not absence');
  }
  for (const error of [{ name: 'TimeoutError' }, { code: 'ETIMEDOUT' }, { outcome: 'timeout' }, 'timeout', new DOMException('timed out', 'TimeoutError')]) {
    eq(classify(undefined, 'A', { error }).outcome, 'timeout', 'timeout preserved');
  }
  for (const error of [new Error('socket failure'), { name: 'AbortError' }, { code: 'redirect_refused' }]) {
    eq(classify(undefined, 'A', { error }).outcome, 'transport_error', 'transport/cancellation not absence');
  }
  const v6 = classify({ Status: 0, Answer: [AAAA] }, 28);
  eq(v6.dns_address_resolved, true, 'AAAA-only resolves');
  eq(v6.records[0].data, '2001:db8::1', 'IPv6 canonicalised');
  eq(classify({ Status: 0, Answer: [AAAA] }, 'A').dns_address_resolved, false, 'unsolicited family cannot answer A');
  const mx = classify({ Status: 0, Answer: [rr('example.com', 15, '10 MAIL.example.com.')] }, 'MX');
  eq(mx.outcome, 'answer', 'MX observation');
  eq(mx.records[0].data, '10 mail.example.com', 'MX normalised');
  eq(mx.dns_address_resolved, null, 'MX does not prove address');
  eq(classify({ Status: 0, Answer: [rr('example.com', 15, '0 .')] }, 'MX').outcome, 'answer', 'null MX observation');
  const txt = classify({ Status: 0, Answer: [rr('example.com', 16, '"v=spf1 -all"')] }, 'TXT');
  eq(txt.outcome, 'answer', 'TXT observation');
  eq(txt.dns_address_resolved, null, 'TXT does not prove address');
  eq(classify({ Status: 0, Answer: [rr('example.com', 16, null)] }, 'TXT').outcome, 'invalid_response', 'null TXT is not an empty text record');
  const alias = rr('example.com', 5, 'edge.example.net.');
  const terminal = rr('edge.example.net', 1, '192.0.2.8');
  const chain = classify({ Status: 0, Answer: [terminal, alias, rr('unrelated.test', 1, '192.0.2.99')] });
  eq(chain.outcome, 'answer', 'unordered reachable CNAME chain');
  eq(chain.records.length, 2, 'unrelated answer excluded');
  eq(chain.cname_chain, [{ name: 'example.com', target: 'edge.example.net' }], 'chain retained');
  eq(classify({ Status: 0, Answer: [terminal] }).outcome, 'nodata', 'unrelated Answer cannot resolve');
  eq(classify({ Status: 0, Additional: [A] }).outcome, 'nodata', 'Additional cannot resolve');
  eq(classify({ Status: 0, Answer: [alias], Additional: [terminal] }).outcome, 'cname_only', 'Additional not terminal answer');
  eq(classify({ Status: 0, Answer: [alias] }).dns_address_resolved, null, 'CNAME-only not absence');
  eq(classify({ Status: 0, Answer: [alias] }, 'CNAME').outcome, 'answer', 'CNAME query succeeds on alias');
  eq(classify({ Status: 3, Answer: [alias] }).outcome, 'nxdomain', 'NXDOMAIN alias terminal negative preserved');
  eq(classify({ Status: 3, Answer: [A] }).outcome, 'invalid_response', 'contradictory positive NXDOMAIN');
  eq(classify({ Status: 0, Answer: [alias, rr('edge.example.net', 5, 'example.com')] }).reason, 'cname_loop', 'alias cycle');
  eq(classify({ Status: 0, Answer: [alias, rr('example.com', 5, 'other.example.net')] }).reason, 'conflicting_cname', 'multiple CNAME targets');
  eq(classify({ Status: 0, Answer: [alias, A] }).reason, 'conflicting_cname', 'CNAME and A cannot coexist');
  const aliases = Array.from({ length: 17 }, (_, i) => rr(i ? `h${i}.example.com` : 'example.com', 5, `h${i + 1}.example.com`));
  eq(classify({ Status: 0, Answer: aliases }).truncation_reasons, ['cname_hops'], 'bounded CNAME traversal');
  eq(classify({ Status: 0, Answer: aliases.slice(0, 16) }).outcome, 'cname_only', 'CNAME hop boundary inclusive');
  eq(classify({ Status: 0, Authority: [rr('example.com', 2, 'ns.example.com')] }).outcome, 'referral', 'referral not NODATA');
  for (const question of [[{ name: 'other.test', type: 1 }], [{ name: 'example.com', type: 28 }], [], null]) {
    eq(classify({ Status: 0, Question: question, Answer: [A] }).outcome, 'invalid_response', 'explicit question mismatch');
  }
  for (const response of [null, {}, [], { Status: '0' }, { Status: -1 }, { Status: 0.5 }, { Status: 4096 }, { Status: 0, Answer: null }, { Status: 0, Answer: {} }, { Status: 0, Answer: [null] }, { Status: 0, Answer: [A, {}] }, { Status: 0, AD: 'true' }, { Status: 0, TC: 1 }]) {
    eq(classify(response).outcome, 'invalid_response', 'partial/malformed response remains unknown');
  }
  for (const [type, data] of [[1, '999.2.3.4'], [1, '127.1'], [1, '01.2.3.4'], [28, 'not-v6'], [28, 'fe80::1%zone'], [5, 'https://target.test'], [15, '65536 mail.test'], [15, '10 .'], [16, 'bad\ntext']]) {
    eq(classify({ Status: 0, Answer: [rr('example.com', type, data)] }).outcome, 'invalid_response', 'malformed RDATA rejected');
  }
  for (const ttl of [-1, '300', 0x1_0000_0000]) eq(classify({ Status: 0, Answer: [rr('example.com', 1, '192.0.2.1', ttl)] }).outcome, 'invalid_response', 'invalid TTL');
  eq(classify({ Status: 0, Answer: [rr('example.com', 1, '192.0.2.1', 0)] }).outcome, 'answer', 'zero TTL allowed');
  for (const Status of [0, 3, 2]) {
    const partial = classify({ Status, TC: true, Answer: Status === 0 ? [A] : [] });
    eq(partial.outcome, 'truncated', 'TC response never conclusive');
    eq(partial.dns_address_resolved, null, 'TC address unknown');
    eq(partial.truncation_reasons, ['dns_tc'], 'TC reason');
  }
  eq(positive.dnssec_authenticated, null, 'missing AD unknown');
  eq(classify({ Status: 0, AD: false }).dnssec_authenticated, false, 'AD false remains authentication observation');
  eq(classify({ Status: 0, AD: true }).dnssec_authenticated, true, 'AD true retained');
  const tooMany = classify({ Status: 0, Answer: Array(257).fill(A) });
  eq(tooMany.outcome, 'truncated', 'record bound');
  eq(tooMany.truncation_reasons, ['record_count'], 'record cap reason');
  eq(classify({ Status: 0, Answer: Array(256).fill(A) }).outcome, 'answer', 'record cap inclusive');
  eq(classify({ Status: 0, Answer: [rr('example.com', 16, 'é'.repeat(2049))] }, 'TXT').truncation_reasons, ['string_bytes'], 'UTF8 string bound');
  eq(classify({ Status: 0, Answer: [rr('example.com', 16, 'é'.repeat(2048))] }, 'TXT').outcome, 'answer', 'UTF8 boundary inclusive');
  eq(classify({ Status: 0, Answer: Array(17).fill(rr('example.com', 16, 'x'.repeat(4000))) }, 'TXT').truncation_reasons, ['input_bytes'], 'aggregate input byte bound');
  eq(classify({ Status: 0 }, 'A', { observedAt: 'é'.repeat(65) }).truncation_reasons, ['string_bytes'], 'timestamp byte bound');
  const inherited = Object.create({ Status: 0, Answer: [A] });
  eq(classify(inherited).outcome, 'invalid_response', 'inherited response fields rejected');
  let accesses = 0;
  const accessor = { Status: 0, get Answer() { accesses++; return [A]; } };
  eq(classify(accessor).outcome, 'invalid_response', 'accessor not evidence');
  eq(accesses, 0, 'does not execute getters');
  const polluted = JSON.parse('{"Status":0,"__proto__":{"polluted":true},"Answer":[]}');
  classify(polluted);
  eq({}.polluted, undefined, 'prototype remains pristine');
  const frozen = Object.freeze({ hostname: 'example.com', recordType: 'A', observedAt: at,
    response: Object.freeze({ Status: 0, Answer: Object.freeze([Object.freeze({ ...A })]) }) });
  const before = JSON.stringify(frozen);
  eq(api.classifyDiscoveryDnsResponse(frozen), api.classifyDiscoveryDnsResponse(frozen), 'deterministic');
  eq(JSON.stringify(frozen), before, 'input remains immutable');
  const changed = api.classifyDiscoveryDnsResponse(frozen);
  changed.records[0].data = 'forged';
  eq(api.classifyDiscoveryDnsResponse(frozen).records[0].data, '192.0.2.1', 'fresh output objects');
  for (const invalid of [null, [], 1, 'x', {}, new Proxy({}, { getOwnPropertyDescriptor() { throw new Error('bad'); } })]) {
    eq(api.classifyDiscoveryDnsResponse(invalid).outcome, 'invalid_response', 'malformed outer input fails closed');
  }
  const emptyA = classify({ Status: 0 });
  const emptyAAAA = classify({ Status: 0 }, 'AAAA');
  eq(merge(v6, emptyA).hosts[0].ipv6_only_observed, true, 'IPv6-only requires explicit A negative');
  eq(merge(v6).hosts[0].ipv6_only_observed, false, 'missing A not IPv6-only');
  eq(merge(v6, classify(undefined, 'A', { error: 'timeout' })).hosts[0].ipv6_only_observed, false, 'A timeout not IPv6-only');
  eq(merge(v6, classify({ Status: 3 })).hosts[0].ipv6_only_observed, false, 'NXDOMAIN contradicts IPv6 positive');
  eq(merge(positive, emptyA).hosts[0].address_observations_conflict, true, 'conflicting family observations explicit');
  eq(merge(emptyA).hosts[0].dns_address_resolved, null, 'one absent family cannot prove all addresses absent');
  eq(merge(emptyA, emptyAAAA).hosts[0].dns_address_resolved, false, 'two absent families');
  eq(merge(mx, txt).hosts[0].dns_address_resolved, null, 'non-address observations not resolution');
  eq(merge(positive, v6).hosts[0].dns_address_resolved, true, 'dual stack merge');
  eq(merge(positive, v6).hosts[0].ipv6_only_observed, false, 'dual stack not IPv6-only');
  eq(merge(positive, v6), merge(v6, positive), 'summary deterministic across input order');
  const other = classify({ Status: 0 }, 'A', { hostname: 'other.test' });
  eq(merge(v6, other).hosts[0].ipv6_only_observed, false, 'no cross-host negative inference');
  eq(merge({ ...emptyA, dns_address_resolved: true }).hosts[0].dns_address_resolved, null, 'forged boolean ignored');
  eq(merge({ ...positive, records: [{ ...positive.records[0], name: 'unrelated.test' }] }).rejected_count, 1, 'inconsistent positive rejected');
  eq(merge({ ...positive, outcome: '__proto__' }).rejected_count, 1, 'unknown outcome cannot pollute map');
  const customMap = [...positive.records];
  Object.defineProperty(customMap, 'map', { get() { accesses++; return Array.prototype.map; } });
  eq(merge({ ...positive, records: customMap }).observation_count, 1, 'custom array map ignored');
  const customIndex = [...positive.records];
  Object.defineProperty(customIndex, '0', { get() { accesses++; return positive.records[0]; } });
  eq(merge({ ...positive, records: customIndex }).rejected_count, 1, 'record index accessor rejected');
  eq(merge({ ...positive, record_type: { toString() { accesses++; return 'A'; } } }).rejected_count, 1, 'record type cannot coerce input');
  eq(accesses, 0, 'merge never invokes array accessors or type coercion');
  eq(merge({ ...positive, hostname: ' '.repeat(4097) + 'example.com' }).rejected_count, 1, 'merge hostname bounded before normalization');
  eq(api.mergeDiscoveryDnsObservations(null).rejected_count, 1, 'invalid merge input');
  eq(api.mergeDiscoveryDnsObservations(Array(257).fill(positive)).truncation_reasons, ['observation_count'], 'observation cap');
  eq(merge(tooMany).truncation_reasons, ['observation_truncated'], 'upstream truncation propagated');
  const incompleteNegative = api.mergeDiscoveryDnsObservations([emptyA, emptyAAAA, ...Array(254).fill(mx), positive]);
  eq(incompleteNegative.hosts[0].dns_address_resolved, null, 'omitted positive cannot become negative summary');
  const incompleteV6 = api.mergeDiscoveryDnsObservations([v6, emptyA, ...Array(254).fill(mx), positive]);
  eq(incompleteV6.hosts[0].dns_address_resolved, true, 'known positive retained in partial summary');
  eq(incompleteV6.hosts[0].ipv6_only_observed, false, 'omitted A observation prevents IPv6-only inference');
  eq(merge(emptyA, emptyAAAA, {}).hosts[0].dns_address_resolved, null, 'rejected observations prevent negative inference');
  eq(merge(v6, emptyA, {}).hosts[0].ipv6_only_observed, false, 'rejected observations prevent IPv6-only inference');
  eq(merge(emptyA, emptyAAAA, tooMany).hosts[0].dns_address_resolved, null, 'truncated observation prevents negative inference');
  eq(merge(Object.freeze(positive)).observation_count, 1, 'frozen observation merge');
  const facts = JSON.stringify(merge(positive, v6, mx, txt));
  ok(!/"(?:healthy|active|service_reachable|owned|dnssec_enabled)":/.test(facts), 'no health/service/ownership claims');
  return checks;
}

try {
  const savedFetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error('network use forbidden in pure fixtures'); };
  const api = await import(moduleUrl.href);
  let checks;
  try { checks = fixtures(api); } finally { globalThis.fetch = savedFetch; }
  assert.ok(!/\b(?:fetch|connect)\s*\(|from\s*['"](?:node:)?(?:net|tls|https?|dns|dgram|fs)['"]/.test(source), 'no network or filesystem I/O in module'); checks++;
  assert.ok(!/Date\.now\s*\(|new Date\s*\(|Math\.random\s*\(/.test(source), 'no ambient clock/randomness'); checks++;
  const mutations = [
    ["if (rcode === 3) {", "if (rcode === 30) {", 'NXDOMAIN distinction'],
    ["rcode === 2 ? 'servfail'", "rcode === 2 ? 'nodata'", 'SERVFAIL not absence'],
    ["? 'timeout' : 'transport_error'", "? 'transport_error' : 'transport_error'", 'timeout distinction'],
    ["const records = byOwner.get(owner) ?? [];", "const records = answers;", 'owner binding'],
    ["if (result.cname_chain.length) return finish('cname_only', 'terminal_answer_missing');", "if (false) return finish('cname_only', 'terminal_answer_missing');", 'CNAME-only uncertainty'],
    ["flag === 'TC' && value === true", "flag === 'TC' && value === false", 'TC incomplete'],
    ["maxRecords: 256,", "maxRecords: 257,", 'record count bound'],
    ["maxObservations: 256,", "maxObservations: 257,", 'observation count bound'],
    ["return value.length > limit ? limit + 1 : encoder.encode(value).length;", "return value.length;", 'UTF8 byte bound'],
    ["result.record_type === 'A' || result.record_type === 'AAAA'", "result.record_type === 'A'", 'IPv6 resolution'],
    ["&& host.nodata.has('A') && !host.unknown.has('A')", "&& true", 'IPv6-only evidence'],
    ["const batchComplete = truncated.size === 0 && result.rejected_count === 0;", "const batchComplete = true;", 'partial batch cannot prove absence'],
    ["if (typeof value !== 'string') throw new Error('invalid_string');", "if (value == null) value = '';", 'malformed data types'],
  ];
  for (const [before, after, label] of mutations) {
    assert.equal(source.split(before).length, 2, `unique mutant anchor: ${label}`);
    const mutantSource = source.replace(before, after).replace("'./hostname-candidates.js'", JSON.stringify(dependency));
    const mutant = await import(`data:text/javascript;base64,${Buffer.from(mutantSource).toString('base64')}`);
    assert.throws(() => fixtures(mutant), assert.AssertionError, `fixtures reject mutant: ${label}`);
    checks++;
  }
  console.log(`PASS: discovery DNS observation — ${checks} checks; ${mutations.length} in-memory mutants killed; no live DNS requests.`);
} catch (error) {
  console.error(error);
  process.exitCode = 1;
}
