#!/usr/bin/env node
// Bounded local fixtures and real-module in-memory mutants; no product writes.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const moduleUrl = new URL('../workers/scan-api/src/engines/discovery-scope-relations.js', import.meta.url);
const helperUrl = new URL('../workers/scan-api/src/engines/hostname-candidates.js', import.meta.url);
const source = await readFile(moduleUrl, 'utf8');
const helperSource = await readFile(helperUrl, 'utf8');
const api = await import(moduleUrl.href);
const time = '2026-10-12T01:02:03.000Z';

function fixtures(lib) {
  let checks = 0;
  const eq = (actual, expected, label) => { assert.deepEqual(actual, expected, label); checks++; };
  const ok = (value, label) => { assert.ok(value, label); checks++; };
  const run = (observations, verifiedDomains = ['example.com'], extra = {}) => lib.routeDiscoveryEvidence({
    tenantId: 'tenant-a', verifiedDomains, observations, observedAt: time, ...extra,
  });
  const observation = (hostname, source = 'dns_cname', extra = {}) => ({
    hostname, source, from_hostname: 'www.example.com', evidence_ref: 'evidence:1', ...extra,
  });
  const names = result => result.candidates.map(candidate => candidate.hostname);
  const basic = run([observation('API.EXAMPLE.COM.'), observation('api.example.com', 'javascript', { evidence_ref: 'evidence:2' })]);
  eq(basic.version, 'discovery-scope-relations-v1', 'contract version');
  eq(basic.tenantId, 'tenant-a', 'caller tenant preserved');
  eq(basic.observed_at, time, 'no ambient timestamp');
  eq(basic.candidates, [{ root: 'example.com', hostname: 'api.example.com',
    sources: ['dns_cname', 'javascript'], provenance: [
      { source: 'dns_cname', from_hostname: 'www.example.com', evidence_ref: 'evidence:1', observed_at: time },
      { source: 'javascript', from_hostname: 'www.example.com', evidence_ref: 'evidence:2', observed_at: time },
    ] }], 'normalized candidate retains independent provenance');
  eq(basic.relationships.map(relation => [relation.kind, relation.relationship]),
    [['within_scope', 'dns_cname'], ['within_scope', 'javascript_reference']], 'relationships keep evidence type');

  const overlapping = run([observation('x.team.example.com'), observation('team.example.com'),
    observation('api.other.test'), observation('other.test')], ['example.com', 'team.example.com', 'other.test']);
  eq(overlapping.candidates.map(item => [item.root, item.hostname]),
    [['other.test', 'api.other.test'], ['team.example.com', 'x.team.example.com']], 'most-specific root and cross-domain routing');
  eq(overlapping.counters.root_observations, 2, 'verified roots are never candidates');
  eq(overlapping.relationships.filter(item => item.to_root === 'other.test').length, 2, 'cross-domain relationships retain destination scope');
  const originSpecific = run([observation('cdn.vendor.test', 'mx', { from_hostname: 'mail.team.example.com' })], ['example.com', 'team.example.com']);
  eq(originSpecific.relationships[0].from_root, 'team.example.com', 'origin uses most-specific scope too');
  const spoofed = run([observation('example.com.evil.test', 'live_tls_san'), observation('evilexample.com', 'live_tls_san')]);
  eq(names(spoofed), [], 'suffix spoof never enters scope');
  eq(spoofed.counters.out_of_scope_observations, 2, 'suffix spoof counts only');
  ok(!JSON.stringify(spoofed).includes('evil'), 'foreign SAN names not retained');
  const idn = run([observation('API.BÜCHER.EXAMPLE.', 'ct', { from_hostname: undefined }),
    observation('api.xn--bcher-kva.example', 'ct', { from_hostname: undefined }),
    observation('www。bücher。example。', 'ct', { from_hostname: undefined })], ['BÜCHER.EXAMPLE.']);
  eq(names(idn), ['api.xn--bcher-kva.example', 'www.xn--bcher-kva.example'], 'shared IDNA and Unicode-dot normalization');
  eq(idn.candidates[0].provenance.length, 1, 'identical canonical provenance deduplicates');
  const wildcard = run([observation('*.example.com', 'live_tls_san'), observation('*.Team.Example.Com.', 'csp'),
    observation('a.*.example.com'), observation('*.vendor.test')]);
  eq(wildcard.candidates, [], 'wildcards cannot become concrete candidates');
  eq(wildcard.wildcard_scopes.map(item => [item.root, item.scope]),
    [['example.com', 'example.com'], ['example.com', 'team.example.com']], 'wildcard scopes remain separate with provenance');
  eq(wildcard.relationships, [], 'wildcards are never concrete relationship targets');
  eq(wildcard.counters.rejected_observations, 1, 'interior wildcard rejected');

  const external = run([observation('edge.vendor.test', 'dns_cname'), observation('edge.vendor.test', 'cname', { evidence_ref: 'evidence:2', observed_at: '2026-10-11T01:00:00Z' })]);
  eq(external.candidates, [], 'dependency evidence grants no candidate ownership');
  eq(external.relationships.length, 1, 'aliases dedupe relationship without losing sources');
  eq(external.relationships[0], { kind: 'external', from_root: 'example.com', from_hostname: 'www.example.com',
    to_root: null, to_hostname: 'edge.vendor.test', relationship: 'dns_cname', sources: ['cname', 'dns_cname'],
    provenance: [
      { source: 'cname', from_hostname: 'www.example.com', evidence_ref: 'evidence:2', observed_at: '2026-10-11T01:00:00Z' },
      { source: 'dns_cname', from_hostname: 'www.example.com', evidence_ref: 'evidence:1', observed_at: time },
    ] }, 'external relation is explicit evidence only');
  for (const [sourceKey, type] of [['mx', 'mx'], ['ns', 'ns'], ['spf', 'spf'], ['dns_mx', 'mx'], ['dns_ns', 'ns'], ['dns_spf', 'spf'],
    ['redirect_chain', 'redirect'], ['http_redirect', 'redirect'], ['javascript', 'javascript_reference'], ['csp', 'csp_reference']]) {
    eq(run([observation('service.vendor.test', sourceKey)]).relationships[0]?.relationship, type, `structured source ${sourceKey}`);
  }
  for (const sourceKey of ['live_tls_san', 'ct', 'linked_hostnames', 'ptr', 'nsec', 'verified', 'unknown', '__proto__']) {
    const result = run([observation('tenant-b.vendor.test', sourceKey)]);
    eq(result.relationships, [], `source ${sourceKey} cannot manufacture relationship`);
    ok(!JSON.stringify(result).includes('tenant-b.vendor.test'), 'unrelated target never retained');
  }
  const foreignSans = run(Array.from({ length: 500 }, (_, i) => observation(`tenant-${i}.shared.test`, 'live_tls_san')));
  eq(foreignSans.counters.foreign_san_observations, 500, 'foreign SAN coverage count retained');
  eq(foreignSans.relationships, [], 'SAN list cannot become bulk external inventory');
  ok(!JSON.stringify(foreignSans).includes('shared.test'), 'SAN hostnames and provenance refs never escape');
  const crossSan = run([observation('api.approved.test', 'live_tls_san')], ['example.com', 'approved.test']);
  eq(crossSan.candidates[0]?.root, 'approved.test', 'explicit approved-domain SAN routes across origin root');
  eq(crossSan.relationships, [], 'approved SAN still not relationship proof');
  for (const extra of [{ from_hostname: undefined }, { from_hostname: 'unverified.test' }, { from_hostname: 'example.com.evil.test' },
    { evidence_ref: undefined }, { evidence_ref: null }]) {
    const result = run([observation('unrelated.test', 'dns_cname', extra)]);
    eq(result.relationships, [], 'in-scope origin and reference both required');
    eq(result.counters.unlinked_external_observations, 1, 'unsupported external record counted only');
    ok(!JSON.stringify(result).includes('unrelated.test'), 'rejected relationship does not leak target');
  }
  const unverifiedOrigin = run([observation('api.example.com', 'dns_cname', { from_hostname: 'unverified.test' })]);
  eq(names(unverifiedOrigin), ['api.example.com'], 'target scope routing independent of origin scope');
  eq(unverifiedOrigin.candidates[0].provenance[0].from_hostname, null, 'unverified origin is not retained');
  eq(unverifiedOrigin.relationships, [], 'unverified origin cannot link an approved target');
  eq(run([observation('www.example.com')]).relationships, [], 'self-reference not a relationship');
  const unknownSource = run([observation('api.example.com', 'unknown')]);
  eq(unknownSource.candidates[0].sources, ['unknown'], 'untrusted source can be preserved as provenance');
  eq(unknownSource.relationships, [], 'provenance label confers no extra authority');
  const missingTime = run([observation('api.example.com', 'ct')], ['example.com'], { observedAt: undefined });
  eq(missingTime.candidates[0].provenance[0].observed_at, null, 'missing timestamp remains unknown');

  const candidateCap = run(Array.from({ length: 201 }, (_, i) => observation(`h${String(i).padStart(3, '0')}.example.com`, 'ct')));
  eq(candidateCap.candidates.length, 200, '200-candidate cap');
  eq(candidateCap.truncated_count, 1, 'candidate omissions counted');
  eq(candidateCap.truncation_reasons, ['candidates_limit'], 'candidate cap reason');
  const externalCap = run(Array.from({ length: 101 }, (_, i) => observation(`h${String(i).padStart(3, '0')}.vendor.test`)));
  eq(externalCap.relationships.length, 100, '100 external-relationship cap');
  eq(externalCap.truncated_count, 1, 'external omissions counted');
  eq(externalCap.truncation_reasons, ['external_relationships_limit'], 'external cap reason');
  const withinCap = run(Array.from({ length: 201 }, (_, i) => observation('api.example.com', 'dns_cname', { from_hostname: `from${i}.example.com` })));
  eq(withinCap.relationships.length, 200, 'within-scope relationship bound');
  eq(withinCap.truncation_reasons, ['within_scope_relationships_limit'], 'within-scope cap reason');
  const wildcardCap = run(Array.from({ length: 201 }, (_, i) => observation(`*.h${i}.example.com`, 'ct')));
  eq(wildcardCap.wildcard_scopes.length, 200, 'wildcard output bound');
  eq(wildcardCap.truncated_count, 1, 'wildcard omissions counted');
  const listCap = run([...Array(500).fill(observation('api.example.com', 'ct')), observation('must-not-process.example.com', 'ct')]);
  eq(names(listCap), ['api.example.com'], 'only first 500 observations processed');
  eq(listCap.counters.processed_observations, 500, 'observation processing bound');
  eq(listCap.truncated_count, 1, 'omitted input count');
  eq(listCap.truncation_reasons, ['observations_limit'], 'input count cap reason');
  const bare = { hostname: 'api.example.com', source: 'ct' };
  const scalarBytes = bare.hostname.length + bare.source.length;
  eq(names(run([{ ...bare, evidence_ref: 'x'.repeat(16_384 - scalarBytes) }])), ['api.example.com'], '16 KiB consumed-field boundary inclusive');
  const oversized = run([{ ...bare, evidence_ref: 'x'.repeat(16_385 - scalarBytes) }, { ...bare, evidence_ref: 'é'.repeat(8192) }]);
  eq(oversized.candidates, [], 'oversized entries wholly rejected');
  eq(oversized.truncated_count, 2, 'UTF-8 and combined field bytes bounded');
  eq(oversized.truncation_reasons, ['entry_bytes_limit'], 'entry size reason');
  const oversizedName = run([observation('a'.repeat(16_385), 'ct')]);
  eq(oversizedName.truncated_count, 1, 'plain oversized string bounded before encoding');
  const thousandScopes = Array.from({ length: 1000 }, (_, i) => `d${i}.customer.test`);
  const thousandRoute = run([observation('api.d999.customer.test', 'dns_cname', { from_hostname: 'www.d0.customer.test' }),
    observation('api.team.d999.customer.test', 'ct', { from_hostname: undefined })], [...thousandScopes, 'team.d999.customer.test']);
  eq(thousandRoute.candidates.map(item => [item.root, item.hostname]),
    [['d999.customer.test', 'api.d999.customer.test'], ['team.d999.customer.test', 'api.team.d999.customer.test']], 'thousand-domain scope routes most-specific cross-domain candidates');
  eq(thousandRoute.relationships[0].from_root, 'd0.customer.test', 'thousand-domain relationship retains originating scope');
  eq(thousandRoute.relationships[0].to_root, 'd999.customer.test', 'thousand-domain relationship retains destination scope');
  eq(thousandRoute.truncated, false, 'ordinary thousand-domain scope does not truncate');
  const boundaryScopes = ['example.com'.padEnd(262_144, ' ')];
  eq(names(run([observation('api.example.com')], boundaryScopes)), ['api.example.com'], 'aggregate scope byte boundary inclusive');
  const byteOverflow = run([observation('api.example.com')], ['example.com'.padEnd(262_144, ' '), 'another.test']);
  eq(byteOverflow.candidates, [], 'scope byte overflow never uses partial scope');
  eq(byteOverflow.truncation_reasons, ['verified_domains_bytes_limit'], 'scope byte overflow reason');
  eq(byteOverflow.truncated_count, 2, 'all unused domains counted on byte overflow');
  const unicodeScopeOverflow = run([observation('api.example.com')], ['example.com'.padEnd(131_080, '\u3000')]);
  eq(unicodeScopeOverflow.candidates, [], 'scope UTF-8 bytes counted before whitespace normalization');
  eq(unicodeScopeOverflow.truncation_reasons, ['verified_domains_bytes_limit'], 'multibyte scope overflow reason');
  eq(run([observation('api.example.com')], Array(10_000).fill('example.com')).truncated, false, 'scope entry boundary inclusive');
  const tooManyScopes = run([observation('api.example.com')], Array(10_001).fill('example.com'));
  eq(tooManyScopes.candidates, [], 'partial scope never used');
  eq(tooManyScopes.truncation_reasons, ['verified_domains_limit'], 'scope cap reason');
  for (const scopes of [[], null, 'example.com', ['example.com', '*.example.com'], ['example.com', 'https://other.test'], ['localhost'], [{ hostname: 'example.com', tenantId: 'tenant-a' }]]) {
    eq(run([observation('api.example.com')], scopes).candidates, [], 'invalid prevalidated scope rejected entirely');
  }

  const malformed = [null, false, 42, [], {}, observation('https://api.example.com'), observation('api.example.com:443'),
    observation('127.0.0.1'), observation('api.example.com', '__proto__'), observation('api.example.com', 'ct', { evidence_ref: {} }),
    observation('api.example.com', 'ct', { evidence_ref: '' }), observation('api.example.com', 'ct', { observed_at: 42 }),
    observation('api.example.com', 'ct', { from_hostname: '*.example.com' })];
  const mixed = run([...malformed, observation('good.example.com', 'ct')]);
  eq(names(mixed), ['good.example.com'], 'malformed entries do not erase good evidence');
  eq(mixed.counters.rejected_observations, malformed.length, 'all malformed entries counted');
  for (const input of [null, undefined, false, 12, [], 'bad', Object.create({ tenantId: 'tenant-a', verifiedDomains: ['example.com'], observations: [] }),
    new Proxy({}, { getPrototypeOf() { throw Error('trap'); } })]) {
    eq(lib.routeDiscoveryEvidence(input).candidates, [], 'invalid outer input cannot produce evidence');
  }
  for (const tenantId of [null, undefined, 42, '', 'tenant\na', '__proto__', 'x'.repeat(129)]) {
    const result = run([observation('api.example.com')], ['example.com'], { tenantId });
    eq(result.candidates, [], 'invalid tenant fails closed'); eq(result.tenantId, null, 'invalid tenant not echoed');
  }
  eq(run([observation('api.example.com')], ['example.com'], { observedAt: 'x'.repeat(129) }).candidates, [], 'bad caller timestamp rejects input');
  eq(run(null).rejected_reasons, ['invalid_observations'], 'observations must be array');
  const tenantB = run([observation('api.example.com', 'ct'), observation('api.other.test', 'ct')], ['other.test'], { tenantId: 'tenant-b' });
  eq(names(tenantB), ['api.other.test'], 'separate invocation cannot reuse another tenant scope');
  eq(tenantB.tenantId, 'tenant-b', 'tenant routing remains explicit');
  const forged = run([observation('api.other.test', 'verified', { verifiedDomains: ['other.test'], tenantId: 'tenant-b' })]);
  eq(forged.candidates, [], 'observation cannot append verified scope or change tenant');
  eq(forged.relationships, [], 'claimed verification source never authorizes destination');

  let accessorCalls = 0;
  const getter = { source: 'ct', get hostname() { accessorCalls++; return 'bad.example.com'; } };
  const getterResult = run([getter, observation('good.example.com', 'ct')]);
  eq(names(getterResult), ['good.example.com'], 'accessors cannot provide evidence');
  eq(accessorCalls, 0, 'input getters never execute');
  const inherited = Object.create({ hostname: 'bad.example.com', source: 'ct' });
  eq(run([inherited]).candidates, [], 'inherited observation not evidence');
  const inheritedList = new Array(1);
  const inheritedArrayPrototype = Object.create(Array.prototype, { 0: { value: observation('bad.example.com', 'ct') } });
  Object.setPrototypeOf(inheritedList, inheritedArrayPrototype);
  eq(run(inheritedList).candidates, [], 'inherited array index not evidence');
  const accessorList = [observation('bad.example.com', 'ct')];
  Object.defineProperty(accessorList, '0', { get() { accessorCalls++; return observation('bad.example.com', 'ct'); } });
  eq(run(accessorList).candidates, [], 'array accessor not evidence');
  eq(accessorCalls, 0, 'array accessor never invoked');
  const nullPrototype = Object.assign(Object.create(null), { hostname: 'safe.example.com', source: 'ct' });
  eq(names(run([nullPrototype])), ['safe.example.com'], 'null-prototype data records accepted');
  const unknownGetter = { hostname: 'safe.example.com', source: 'ct', get ignored() { throw Error('unread field'); }, toJSON() { throw Error('not serialization input'); } };
  eq(names(run([unknownGetter])), ['safe.example.com'], 'unknown fields and custom serializers never run');
  const pollution = JSON.parse('{"hostname":"safe.example.com","source":"ct","__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}}}');
  eq(names(run([pollution])), ['safe.example.com'], 'prototype keys ignored');
  eq(Object.prototype.polluted, undefined, 'prototype not mutated');
  const frozen = Object.freeze({ tenantId: 'tenant-a', verifiedDomains: Object.freeze(['other.test', 'example.com']),
    observedAt: time, observations: Object.freeze([
      Object.freeze(observation('api.other.test', 'ct')), Object.freeze(observation('z.example.com', 'ct')),
      Object.freeze(observation('a.example.com', 'ct')), Object.freeze(observation('a.example.com', 'dns_cname')),
    ]) });
  const before = JSON.stringify(frozen), first = lib.routeDiscoveryEvidence(frozen);
  eq(first, lib.routeDiscoveryEvidence(frozen), 'same input yields same result');
  eq(JSON.stringify(frozen), before, 'caller input remains untouched');
  eq(first, lib.routeDiscoveryEvidence({ ...frozen, verifiedDomains: [...frozen.verifiedDomains].reverse(), observations: [...frozen.observations].reverse() }), 'sub-limit output independent of input ordering');
  first.candidates[0].sources.push('forged'); first.candidates[0].provenance[0].evidence_ref = 'forged';
  ok(!JSON.stringify(lib.routeDiscoveryEvidence(frozen)).includes('forged'), 'results share no mutable state across calls');
  const forbiddenKeys = new Set(['observed', 'active', 'resolved', 'owned', 'verified', 'scan_authorized', 'service']);
  const checkNoClaims = value => {
    if (!value || typeof value !== 'object') return;
    for (const [key, child] of Object.entries(value)) { assert.ok(!forbiddenKeys.has(key), `unsupported state assertion ${key}`); checkNoClaims(child); }
  };
  checkNoClaims(basic); checkNoClaims(external); checks++;
  return checks;
}

try {
  let checks = fixtures(api);
  const noIo = /\b(?:fetch|connect|setTimeout|setInterval)\s*\(|\b(?:import|require)\s*\(|from\s*["'](?!\.{1,2}\/)|\b(?:Date\.now|Math\.random)\s*\(/;
  assert.ok(!noIo.test(source), 'routing module has no I/O or ambient time/randomness'); checks++;
  assert.ok(!noIo.test(helperSource), 'shared normalizer dependency has no I/O or ambient state'); checks++;
  assert.deepEqual([...source.matchAll(/from\s*['"]([^'"]+)['"]/g)].map(match => match[1]), ['./hostname-candidates.js'], 'only shared pure helper imported'); checks++;
  const originalFetch = globalThis.fetch, originalNow = Date.now, originalRandom = Math.random;
  try {
    globalThis.fetch = () => { throw Error('network call forbidden'); };
    Date.now = () => { throw Error('ambient time forbidden'); };
    Math.random = () => { throw Error('randomness forbidden'); };
    fixtures(api); checks++;
  } finally { globalThis.fetch = originalFetch; Date.now = originalNow; Math.random = originalRandom; }
  const mutations = [
    ['if (roots.has(suffix)) return suffix;', 'if (roots.has(suffix) || [...roots].some(root => suffix.endsWith(root))) return suffix;', 'suffix scope weakened'],
    ['if (roots.has(suffix)) return suffix;', 'if (roots.has(suffix)) { const broader = [...roots].find(root => suffix.endsWith("." + root)); return broader ?? suffix; }', 'most-specific root removed'],
    ["const wildcard = raw.startsWith('*.');", 'const wildcard = false;', 'wildcard separation lost'],
    ['if (hostname === root) result.counters.root_observations++;', 'if (false) result.counters.root_observations++;', 'root admitted as candidate'],
    ["['dns_cname', 'dns_cname'], ['cname', 'dns_cname'],", "['dns_cname', 'dns_cname'], ['cname', 'dns_cname'], ['live_tls_san', 'dns_cname'],", 'SAN becomes dependency evidence'],
    ['!wildcard && fromRoot && ref !== null && relationship && from !== hostname', '!wildcard && ref !== null && relationship && from !== hostname', 'origin scope bypassed'],
    ['!wildcard && fromRoot && ref !== null && relationship && from !== hostname', '!wildcard && fromRoot && relationship && from !== hostname', 'evidence reference bypassed'],
    ['const relationship = RELATIONSHIPS.get(entry.source);', "const relationship = RELATIONSHIPS.get(entry.source) ?? 'dns_cname';", 'arbitrary source becomes relationship'],
    ['item.provenance.set(JSON.stringify(provenance), provenance);', 'item.provenance = new Map([[JSON.stringify(provenance), provenance]]);', 'provenance overwritten'],
    ['maxCandidates: 200,', 'maxCandidates: 201,', 'candidate cap raised'],
    ['maxExternalRelationships: 100,', 'maxExternalRelationships: 101,', 'external cap raised'],
    ['maxObservations: 500,', 'maxObservations: 501,', 'observation cap raised'],
    ['bytes += encoder.encode(value).length;', 'bytes += value.length;', 'UTF-8 cap removed'],
    ['maxScopeBytes: 262_144,', 'maxScopeBytes: 524_288,', 'scope byte cap raised'],
    ["const descriptor = Object.getOwnPropertyDescriptor(value, key);", 'const descriptor = { value: value[key] };', 'input accessor executed'],
  ];
  for (const [before, after, label] of mutations) {
    assert.equal(source.split(before).length, 2, `unique mutation anchor: ${label}`);
    const mutated = source.replace(before, after).replace("'./hostname-candidates.js'", JSON.stringify(helperUrl.href));
    const mutant = await import(`data:text/javascript;base64,${Buffer.from(mutated).toString('base64')}`);
    assert.throws(() => fixtures(mutant), assert.AssertionError, `fixture suite must kill ${label}`);
    checks++;
  }
  console.log(`${checks} checks passed (discovery scope relations; ${mutations.length} real-module in-memory mutants killed)`);
} catch (error) {
  console.error('FAIL discovery scope relations:', error);
  process.exitCode = 1;
}
