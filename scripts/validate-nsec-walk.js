#!/usr/bin/env node
// Local deterministic fixtures plus real, in-memory source mutants. No queries,
// disk mutation, external data or production state are used by this contract.
import assert from 'node:assert/strict';
import fs from 'node:fs';

const moduleUrl = new URL('../workers/scan-api/src/engines/nsec-walk.js', import.meta.url);
const helperUrl = new URL('../workers/scan-api/src/engines/hostname-candidates.js', import.meta.url);
const source = fs.readFileSync(moduleUrl, 'utf8');
const api = await import(moduleUrl.href);
const root = 'example.com';
const nsec = (owner, next, bitmap = 'A RRSIG NSEC') => ({ name: `${owner}.`, type: 47, data: `${next}. ${bitmap}` });
const response = (name, records, section = 'Answer') => ({ Status: 0, Question: [{ name: `${name}.`, type: 47 }], [section]: records });
const deepFreeze = value => {
  if (value && typeof value === 'object') { Object.values(value).forEach(deepFreeze); Object.freeze(value); }
  return value;
};
const names = ['a', 'b', 'c', 'd', 'e'].map(label => `${label}.${root}`);
const chain = [root, ...names];
function classic(api, initial = api.createNsecWalkState({ domain: root })) {
  let state = initial;
  for (let guard = 0; guard < 20 && api.nextNsecQuery(state); guard++) {
    const query = api.nextNsecQuery(state);
    const position = chain.indexOf(query);
    assert.notEqual(position, -1, 'query stays on fixture chain');
    const record = nsec(query, chain[(position + 1) % chain.length], query === root ? 'NS SOA RRSIG NSEC DNSKEY' : undefined);
    state = api.applyNsecAnswer(state, response(query, [record], position % 2 ? 'Authority' : 'Answer'));
  }
  return state;
}

function contract(api) {
  const results = [];
  const test = (id, check) => {
    try { check(); results.push({ id, passed: true }); }
    catch (error) { results.push({ id, passed: false, message: error.message }); }
  };
  const initial = () => api.createNsecWalkState({ domain: root });
  const first = () => api.applyNsecAnswer(initial(), response(root, [nsec(root, names[0], 'NS SOA RRSIG NSEC')]));
  test('classic-five-names', () => {
    const state = classic(api);
    assert.equal(state.outcome, 'complete');
    assert.deepEqual(state.candidates, names.map(hostname => ({ hostname, sources: ['nsec'] })));
    assert.equal(state.queriesUsed, 6);
    assert.equal(state.totalQueries, 6);
    assert.equal(state.chain.length, 6);
    assert.equal(api.nextNsecQuery(state), null);
  });
  test('initial-state', () => {
    const state = api.createNsecWalkState({ domain: 'EXAMPLE.COM.' });
    assert.equal(api.nextNsecQuery(state), root);
    assert.equal(state.maxQueries, 64);
    assert.deepEqual(state.candidates, []);
  });
  test('invalid-initial-state', () => {
    for (const domain of [null, '', '*.example.com', 'https://example.com', 'example.com.evil/']) {
      assert.throws(() => api.createNsecWalkState({ domain }), TypeError);
    }
    for (const maxQueries of [-1, 1.5, Infinity, '2']) assert.throws(() => api.createNsecWalkState({ domain: root, maxQueries }), TypeError);
  });
  test('cursor-cannot-bypass-chain', () => {
    for (const query of ['outside.test', 'b.example.com', null]) {
      const forged = { ...initial(), query };
      assert.equal(api.nextNsecQuery(forged), null);
      assert.throws(() => api.applyNsecAnswer(forged, response(query, [nsec(query, root)])), TypeError);
    }
    const forged = { ...first(), query: names[1] };
    assert.equal(api.nextNsecQuery(forged), null);
    assert.throws(() => api.applyNsecAnswer(forged, response(names[1], [nsec(names[1], root)])), TypeError);
  });
  test('resume-position-cannot-bypass-chain', () => {
    const state = classic(api, api.createNsecWalkState({ domain: root, maxQueries: 2 }));
    assert.throws(() => api.resumeNsecWalk({ ...state, resume_after: 'outside.test' }), TypeError);
    assert.throws(() => api.resumeNsecWalk({ ...state, visited: [] }), TypeError);
  });
  test('nsec3-answer', () => {
    const state = api.applyNsecAnswer(initial(), response(root, [{ name: `HASH.${root}.`, type: 50, data: '1 0 0 - HASH A' }]));
    assert.equal(state.outcome, 'nsec3_not_walkable');
    assert.deepEqual(state.candidates, []);
  });
  test('nsec3-authority', () => {
    const state = api.applyNsecAnswer(initial(), response(root, [{ name: `${root}.`, type: 'NSEC3PARAM', data: '1 0 0 -' }], 'Authority'));
    assert.equal(state.outcome, 'nsec3_not_walkable');
  });
  test('synthetic-null', () => {
    const state = api.applyNsecAnswer(initial(), response(root, [nsec(root, `\\000.${root}`, 'NS SOA RRSIG NSEC')]));
    assert.equal(state.outcome, 'synthetic_nsec_not_walkable');
    assert.deepEqual(state.candidates, []);
  });
  test('synthetic-bitmap', () => {
    for (const bitmap of ['NSEC RRSIG', 'NSEC RRSIG TYPE65281']) {
      const state = api.applyNsecAnswer(first(), response(names[0], [nsec(names[0], names[1], bitmap)]));
      assert.equal(state.outcome, 'synthetic_nsec_not_walkable');
      assert.deepEqual(state.candidates, []);
    }
  });
  test('synthetic-label-inflation', () => {
    const state = api.applyNsecAnswer(first(), response(names[0], [nsec(names[0], `a.${names[0]}`)]));
    assert.equal(state.outcome, 'synthetic_nsec_not_walkable');
  });
  test('budget-resume', () => {
    const state = classic(api, api.createNsecWalkState({ domain: root, maxQueries: 2 }));
    assert.equal(state.outcome, 'budget_exhausted');
    assert.equal(state.resume_after, names[1]);
    assert.equal(api.nextNsecQuery(state), null);
    assert.deepEqual(state.visited, [root, names[0]]);
    const resumed = api.resumeNsecWalk(deepFreeze(state), { maxQueries: 4 });
    assert.equal(resumed.queriesUsed, 0);
    assert.equal(resumed.totalQueries, 2);
    assert.deepEqual(resumed.visited, state.visited);
    assert.deepEqual(resumed.chain, state.chain);
    assert.deepEqual(resumed.candidates, state.candidates);
    const completed = classic(api, resumed);
    assert.equal(completed.outcome, 'complete');
    assert.equal(completed.totalQueries, 6);
    assert.deepEqual(completed.candidates.map(item => item.hostname), names);
  });
  test('zero-budget', () => {
    const state = api.createNsecWalkState({ domain: root, maxQueries: 0 });
    assert.equal(api.nextNsecQuery(state), null);
    assert.equal(state.outcome, 'budget_exhausted');
    assert.equal(state.resume_after, root);
    assert.equal(api.nextNsecQuery(api.resumeNsecWalk(state, { maxQueries: 1 })), root);
  });
  test('explicit-resume-only', () => {
    assert.throws(() => api.resumeNsecWalk(initial()), TypeError);
    assert.throws(() => api.resumeNsecWalk(classic(api)), TypeError);
    assert.throws(() => api.resumeNsecWalk(api.createNsecWalkState({ domain: root, maxQueries: 0 }), { maxQueries: 0 }), TypeError);
  });
  test('delegation-parent-chain', () => {
    const state = api.applyNsecAnswer(initial(), response(root, [
      nsec(root, 'child.example.com', 'NS SOA RRSIG NSEC'),
      nsec('child.example.com', 'www.example.com', 'NS DS RRSIG NSEC'),
    ]));
    assert.equal(api.nextNsecQuery(state), 'www.example.com');
    assert.deepEqual(state.delegated_zones, ['child.example.com']);
    assert.deepEqual(state.candidates.map(item => item.hostname), ['child.example.com']);
    const closed = api.applyNsecAnswer(state, response('www.example.com', [nsec('www.example.com', root)]));
    assert.equal(closed.outcome, 'complete');
  });
  test('delegation-no-descendant', () => {
    const state = api.applyNsecAnswer(initial(), response(root, [
      nsec(root, 'child.example.com', 'NS SOA RRSIG NSEC'),
      nsec('child.example.com', 'api.child.example.com', 'NS DS RRSIG NSEC'),
    ]));
    assert.equal(state.outcome, 'delegation_boundary');
    assert.equal(api.nextNsecQuery(state), null);
    assert.deepEqual(state.candidates, []);
  });
  test('delegation-child-apex', () => {
    const state = api.applyNsecAnswer(first(), response(names[0], [nsec(names[0], `www.${names[0]}`, 'NS SOA RRSIG NSEC')]));
    assert.equal(state.outcome, 'delegation_boundary');
    assert.deepEqual(state.candidates, []);
  });
  test('delegation-child-soa', () => {
    const state = api.applyNsecAnswer(first(), response(names[0], [{ name: names[0], type: 6, data: 'ns.example.com. hostmaster.example.com. 1 2 3 4 5' }], 'Authority'));
    assert.equal(state.outcome, 'delegation_boundary');
  });
  test('out-of-zone', () => {
    for (const outside of ['elsewhere.test', 'example.com.evil.test']) {
      const state = api.applyNsecAnswer(initial(), response(root, [nsec(root, outside, 'NS SOA RRSIG NSEC')]));
      assert.equal(state.outcome, 'out_of_zone');
      assert.deepEqual(state.candidates, []);
    }
  });
  test('no-pointer-evidence', () => {
    assert.deepEqual(first().candidates, []);
    assert.equal(first().query, names[0]);
  });
  test('root-anchor-required', () => {
    const state = api.applyNsecAnswer(initial(), response(root, [nsec(root, names[0])]));
    assert.equal(state.outcome, 'incoherent_chain');
  });
  test('incidental-cycle', () => {
    const state = api.applyNsecAnswer(first(), response(names[0], [nsec('other.example.com', root)]));
    assert.equal(state.outcome, 'incoherent_chain');
    assert.notEqual(state.outcome, 'complete');
  });
  test('non-root-cycle', () => {
    const second = api.applyNsecAnswer(first(), response(names[0], [nsec(names[0], names[1])]));
    const state = api.applyNsecAnswer(second, response(names[1], [nsec(names[1], names[0])]));
    assert.equal(state.outcome, 'incoherent_chain');
  });
  test('self-cycle', () => {
    const state = api.applyNsecAnswer(first(), response(names[0], [nsec(names[0], names[0])]));
    assert.equal(state.outcome, 'incoherent_chain');
  });
  test('conflicting-chain-records', () => {
    const state = api.applyNsecAnswer(first(), response(names[0], [nsec(names[0], names[1]), nsec(names[0], root)]));
    assert.equal(state.outcome, 'incoherent_chain');
  });
  test('dns-error-is-not-absence', () => {
    for (const Status of [1, 2, 4, 5]) assert.equal(api.applyNsecAnswer(initial(), { Status }).outcome, 'dns_error');
  });
  test('nxdomain-is-not-owner-evidence', () => {
    const answer = response(root, [nsec(root, root, 'SOA NS NSEC RRSIG')]);
    answer.Status = 3;
    const state = api.applyNsecAnswer(initial(), answer);
    assert.equal(state.outcome, 'incoherent_chain');
    assert.deepEqual(state.candidates, []);
  });
  test('timeout-is-not-absence', () => {
    for (const value of [null, undefined, {}, { error: 'timeout' }, { Status: '0' }]) {
      assert.equal(api.applyNsecAnswer(initial(), value).outcome, 'invalid_response');
    }
  });
  test('no-observed-dnssec', () => {
    assert.equal(api.applyNsecAnswer(initial(), { Status: 0, Answer: [] }).outcome, 'no_dnssec');
  });
  test('dnssec-without-nsec', () => {
    for (const value of [ { Status: 0, AD: true }, response(root, [{ name: root, type: 48, data: '256 3 8 ABCD' }]) ]) {
      assert.equal(api.applyNsecAnswer(initial(), value).outcome, 'nsec_unavailable');
    }
    assert.equal(api.applyNsecAnswer(first(), { Status: 0 }).outcome, 'nsec_unavailable');
  });
  test('truncated-response', () => {
    assert.equal(api.applyNsecAnswer(initial(), { Status: 0, TC: true }).outcome, 'truncated_response');
    assert.equal(api.applyNsecAnswer(initial(), { Status: 0, Answer: Array(501).fill({ type: 1, name: root, data: '192.0.2.1' }) }).outcome, 'truncated_response');
  });
  test('question-mismatch', () => {
    assert.equal(api.applyNsecAnswer(initial(), response('wrong.example.com', [nsec(root, names[0], 'SOA NSEC RRSIG')])).outcome, 'invalid_response');
    assert.equal(api.applyNsecAnswer(initial(), { Status: 0, Question: [{ name: root, type: 1 }] }).outcome, 'invalid_response');
  });
  test('malformed-records', () => {
    for (const value of [ { Status: 0, Answer: {} }, response(root, [{ name: root, type: 47, data: null }]),
      response(root, [{ name: root, type: 47, data: 'a'.repeat(16385) }]), response(root, [nsec(root, 'invalid/name', 'SOA NSEC RRSIG')]) ]) {
      assert.equal(api.applyNsecAnswer(initial(), value).outcome, 'invalid_response');
    }
  });
  test('service-owner-not-hostname', () => {
    const state = api.applyNsecAnswer(initial(), response(root, [nsec(root, '_dmarc.example.com', 'SOA NSEC RRSIG'), nsec('_dmarc.example.com', root, 'TXT NSEC RRSIG')]));
    assert.equal(state.outcome, 'complete');
    assert.deepEqual(state.candidates, []);
  });
  test('wildcard-not-concrete-host', () => {
    const state = api.applyNsecAnswer(initial(), response(root, [nsec(root, '*.example.com', 'SOA NSEC RRSIG'), nsec('*.example.com', root)]));
    assert.equal(state.outcome, 'complete');
    assert.deepEqual(state.candidates, []);
    assert.deepEqual(state.wildcard_scopes, ['example.com']);
  });
  test('input-immutability', () => {
    const state = deepFreeze(initial());
    const answer = deepFreeze(response(root, [nsec(root, names[0], 'SOA NSEC RRSIG')]));
    const beforeState = JSON.stringify(state), beforeAnswer = JSON.stringify(answer);
    const result = api.applyNsecAnswer(state, answer);
    assert.notEqual(result, state);
    assert.notEqual(result.visited, state.visited);
    assert.equal(JSON.stringify(state), beforeState);
    assert.equal(JSON.stringify(answer), beforeAnswer);
  });
  test('terminal-no-query', () => {
    const state = deepFreeze(classic(api));
    const repeated = api.applyNsecAnswer(state, { Status: 2 });
    assert.deepEqual(repeated, state);
    assert.notEqual(repeated, state);
  });
  return results;
}

const results = contract(api);
results.push({ id: 'pure-source', passed: !/\b(?:fetch|XMLHttpRequest|WebSocket|eval|Function)\s*\(|\bDate\.now\s*\(|\bMath\.random\s*\(|from\s+['"]node:/.test(source) });
const mutants = [
  { id: 'M01-nsec3-ignored', from: 'if (zoneRecords.some(isNsec3))', to: 'if (false)', catches: 'nsec3-answer' },
  { id: 'M02-premature-complete', from: "return stop(next, 'budget_exhausted');", to: "return stop(next, 'complete');", catches: 'budget-resume' },
  { id: 'M03-dns-error-as-no-dnssec', from: "return stop(next, 'dns_error');", to: "return stop(next, 'no_dnssec');", catches: 'dns-error-is-not-absence' },
  { id: 'M04-synthetic-ignored', from: "if (item.synthetic) return stop(next, 'synthetic_nsec_not_walkable');", to: 'if (false) return next;', catches: 'synthetic-bitmap' },
  { id: 'M05-lost-resume-history', from: "return { ...next, queriesUsed: 0, maxQueries, query: state.resume_after, outcome: 'walking', resume_after: null };", to: "return { ...next, visited: [], chain: [], candidates: [], queriesUsed: 0, maxQueries, query: state.resume_after, outcome: 'walking', resume_after: null };", catches: 'budget-resume' },
  { id: 'M06-delegation-descended', from: "if (next.delegated_zones.some(zone => under(record.next, zone))) return stop(next, 'delegation_boundary');", to: 'if (false) return next;', catches: 'delegation-no-descendant' },
  { id: 'M07-incidental-record-trusted', from: 'const matches = parsed.filter(record => record.owner === next.query);', to: 'const matches = parsed;', catches: 'incidental-cycle' },
  { id: 'M08-unchecked-cursor', from: "if (!validState(state) || state.outcome !== 'walking' || state.queriesUsed >= state.maxQueries) return null;", to: "if (!state || state.outcome !== 'walking' || state.queriesUsed >= state.maxQueries) return null;", catches: 'cursor-cannot-bypass-chain' },
  { id: 'M09-nxdomain-owner-trusted', from: "if (dohJson.Status === 3) return stop(next, 'incoherent_chain');", to: 'if (false) return next;', catches: 'nxdomain-is-not-owner-evidence' },
];
for (const mutant of mutants) {
  try {
    assert.equal(source.split(mutant.from).length - 1, 1, 'unique mutation anchor');
    const code = source.replace(mutant.from, mutant.to).replace("'./hostname-candidates.js'", JSON.stringify(helperUrl.href));
    const mutatedApi = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
    const mutantResults = contract(mutatedApi);
    assert.equal(mutantResults.find(item => item.id === mutant.catches)?.passed, false, `fixture ${mutant.catches} must reject mutant`);
    results.push({ id: mutant.id, passed: true });
  } catch (error) { results.push({ id: mutant.id, passed: false, message: error.message }); }
}
assert.equal(fs.readFileSync(moduleUrl, 'utf8'), source, 'mutations never modify source on disk');
for (const result of results.filter(item => !item.passed)) console.error(`FAIL ${result.id}: ${result.message || 'contract violated'}`);
console.log(`NSEC walk: ${results.filter(item => item.passed).length}/${results.length} checks passed`);
if (results.some(item => !item.passed)) process.exitCode = 1;
