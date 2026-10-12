#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const modulePath = path.join(root, 'workers/scan-api/src/engines/discovery-dns-extractors.js');
const source = await readFile(modulePath, 'utf8');
const helperUrl = pathToFileURL(path.join(path.dirname(modulePath), 'hostname-candidates.js')).href;
const api = await import(pathToFileURL(modulePath).href);
let checks = 0, mutants = 0;
const check = (name, body) => { try { body(); checks++; } catch (error) { error.message = `${name}: ${error.message}`; throw error; } };
const options = Object.freeze({ domain: 'example.com', observedAt: '2026-10-12T00:00:00.000Z' });
const hosts = result => result.candidates.map(item => item.hostname);
const same = (actual, expected) => assert.deepEqual(actual, expected);
const one = (result, name, sourceKey) => { same(hosts(result), [name]); same(result.candidates[0].sources, [sourceKey]); };
const spf = (lib, text) => lib.extractFromSpfRecords(text, options);
const txt = (lib, text) => lib.extractFromTxtRecords(text, options);
const cname = (lib, rows) => lib.extractFromCnameRecords(rows, options);
const byteRecords = prefix => [`${prefix}a.example.com`.padEnd(131072, ' '), `${prefix}b.example.com`.padEnd(131072, ' '), `${prefix}tail.example.com`];

function fixtures(lib) {
  check('SPF all supported operands and qualifiers', () => {
    const result = spf(lib, 'v=spf1 +include:a.example.com -a:b.example.com/24 ?mx:c.example.com//64 ~include:d.example.com redirect=e.example.com a:f.example.com/32//128');
    same(hosts(result), ['a.example.com', 'b.example.com', 'c.example.com', 'd.example.com', 'e.example.com', 'f.example.com']);
    assert.ok(result.candidates.every(item => JSON.stringify(item.sources) === '["spf"]'));
  });
  check('SPF normalizes case, root dot and duplicate inputs', () => one(spf(lib, ['V=SPF1 INCLUDE:API.EXAMPLE.COM.', 'v=spf1 mx:api.example.com']), 'api.example.com', 'spf'));
  check('SPF requires exact version at record start', () => same(hosts(spf(lib, ['prefix v=spf1 include:a.example.com', 'v=spf10 include:b.example.com', 'include:c.example.com', 'v=spf1include:d.example.com'])), []));
  check('SPF ignores implicit and unsupported mechanisms', () => same(hosts(spf(lib, 'v=spf1 a mx a/24 mx//64 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all ptr:ptr.example.com exists:exists.example.com exp=exp.example.com unknown=other.example.com')), []));
  check('SPF never expands macros or emits their host-shaped suffix', () => same(hosts(spf(lib, 'v=spf1 include:%{d}.example.com a:api.example.com/%{i} mx:%{ir}.example.com redirect=%{d} include:%%.example.com')), []));
  check('SPF root exclusion and suffix scope protection', () => {
    const result = spf(lib, 'v=spf1 include:example.com include:example.com.evil.test include:notexample.com');
    same(hosts(result), []); assert.equal(result.out_of_scope_count, 2);
  });
  check('SPF malformed CIDRs are not stripped into hosts', () => same(hosts(spf(lib, 'v=spf1 a:a.example.com/33 mx:b.example.com//129 a:c.example.com/24/64 a:d.example.com/01 mx:e.example.com/24//064 a:f.example.com/ a:g.example.com///64')), []));
  check('SPF valid CIDR boundaries', () => same(hosts(spf(lib, 'v=spf1 a:a.example.com/0 mx:b.example.com//0 mx:c.example.com/32//128')), ['a.example.com', 'b.example.com', 'c.example.com']));
  check('SPF redirect cannot have a qualifier', () => same(hosts(spf(lib, 'v=spf1 +redirect=a.example.com -redirect=b.example.com ?redirect=c.example.com ~redirect=d.example.com')), []));
  check('SPF invalid operands never become host evidence', () => {
    const result = spf(lib, 'v=spf1 include:https://api.example.com include:*.example.com include:_spf.example.com include:192.0.2.4 include:api.example.com/path');
    same(hosts(result), []); same(result.wildcard_scopes, []); assert.equal(result.rejected_count, 5);
  });
  check('SPF does not concatenate separate records', () => same(hosts(spf(lib, ['v=spf1 include:', 'api.example.com'])), []));
  check('SPF controls cannot split malformed operands', () => same(hosts(spf(lib, 'v=spf1 include:api.example.com\tinclude:auth.example.com')), []));
  check('SPF is evidence extraction even after all', () => one(spf(lib, 'v=spf1 -all include:api.example.com'), 'api.example.com', 'spf'));
  check('SPF total UTF-8 budget spans all records', () => {
    const result = spf(lib, byteRecords('v=spf1 include:'));
    same(hosts(result), ['a.example.com', 'b.example.com']); assert.equal(result.truncated_count, 1);
  });
  check('SPF oversized record is atomic', () => {
    const result = spf(lib, `v=spf1 include:api.example.com ${' '.repeat(262144)}`);
    same(hosts(result), []); assert.equal(result.truncated, true);
  });

  check('CNAME accepts both observed record shapes and retains chain owners', () => {
    const result = cname(lib, [{ name: 'A.EXAMPLE.COM.', value: 'b.example.com' }, { name: 'b.example.com', target: 'c.example.com' }]);
    same(hosts(result), ['a.example.com', 'b.example.com', 'c.example.com']); assert.equal(result.cname_loop_count, 0);
    assert.ok(result.candidates.every(item => JSON.stringify(item.sources) === '["cname"]'));
  });
  check('CNAME external owner cannot inject in-scope target', () => {
    const result = cname(lib, [{ name: 'example.com.evil.test', target: 'injected.example.com' }]);
    same(hosts(result), []); assert.equal(result.out_of_scope_count, 1);
  });
  check('CNAME malformed or wildcard owners cannot inject targets', () => {
    const result = cname(lib, [{ name: 'https://example.com', target: 'injected.example.com' }, { name: '*.example.com', target: 'injected.example.com' }]);
    same(hosts(result), []); same(result.wildcard_scopes, []); assert.equal(result.rejected_count, 2);
  });
  check('CNAME external target is counted and owner retained', () => {
    const result = cname(lib, [{ name: 'a.example.com', target: 'cloud.vendor.test' }]);
    one(result, 'a.example.com', 'cname'); assert.equal(result.out_of_scope_count, 1);
  });
  check('CNAME root owner and target use shared root exclusion', () => {
    const result = cname(lib, [{ name: 'example.com', target: 'a.example.com' }, { name: 'a.example.com', value: 'example.com' }]);
    one(result, 'a.example.com', 'cname'); assert.equal(result.cname_loop_count, 1);
  });
  check('CNAME URL and wildcard targets are rejected', () => {
    const result = cname(lib, [{ name: 'a.example.com', value: 'https://b.example.com' }, { name: 'b.example.com', value: '*.example.com' }]);
    same(hosts(result), []); same(result.wildcard_scopes, []); assert.equal(result.rejected_count, 2);
  });
  check('CNAME record is not a target string or array pair', () => {
    const result = cname(lib, ['a.example.com', ['a.example.com', 'b.example.com'], {}]);
    same(hosts(result), []); assert.equal(result.rejected_count, 3);
  });
  check('CNAME conflicting value and target is rejected', () => same(hosts(cname(lib, [{ name: 'a.example.com', value: 'b.example.com', target: 'c.example.com' }])), []));
  check('CNAME equivalent value and target accepted', () => same(hosts(cname(lib, [{ name: 'a.example.com', value: 'B.EXAMPLE.COM.', target: 'b.example.com' }])), ['a.example.com', 'b.example.com']));
  check('CNAME two-node loop and duplicate rows counted once', () => {
    const result = cname(lib, [{ name: 'a.example.com', target: 'b.example.com' }, { name: 'b.example.com', target: 'a.example.com' }, { name: 'a.example.com', target: 'b.example.com' }]);
    same(hosts(result), ['a.example.com', 'b.example.com']); assert.equal(result.cname_loop_count, 1);
  });
  check('CNAME self-loop is visible', () => assert.equal(cname(lib, [{ name: 'a.example.com', value: 'a.example.com' }]).cname_loop_count, 1));
  check('CNAME disjoint cyclic components and incoming chain', () => {
    const result = cname(lib, [{ name: 'start.example.com', target: 'a.example.com' }, { name: 'a.example.com', target: 'b.example.com' }, { name: 'b.example.com', target: 'a.example.com' }, { name: 'c.example.com', target: 'c.example.com' }]);
    assert.equal(result.cname_loop_count, 2);
  });
  check('CNAME branching observations count one strongly connected component', () => {
    const rows = [['a', 'b'], ['a', 'c'], ['b', 'a'], ['c', 'a']].map(([a, b]) => ({ name: `${a}.example.com`, target: `${b}.example.com` }));
    assert.equal(cname(lib, rows).cname_loop_count, 1);
  });
  check('CNAME maximum-length observed chain terminates', () => {
    const rows = Array.from({ length: 500 }, (_, i) => ({ name: `a${i}.example.com`, target: `a${i + 1}.example.com` }));
    const result = cname(lib, rows); assert.equal(result.cname_loop_count, 0); assert.equal(result.candidates.length, 200); assert.equal(result.truncated_count, 301);
  });
  check('CNAME byte budget includes all parsed fields atomically', () => {
    const result = cname(lib, [{ name: 'a.example.com', target: 'b.example.com'.padEnd(262144, ' ') }, { name: 'later.example.com', value: 'tail.example.com' }]);
    same(hosts(result), []); assert.equal(result.truncated_count, 2);
  });
  check('CNAME loops cannot be inferred through external owners', () => {
    const result = cname(lib, [{ name: 'a.example.com', target: 'outside.test' }, { name: 'outside.test', target: 'a.example.com' }]);
    assert.equal(result.cname_loop_count, 0); assert.equal(result.out_of_scope_count, 2);
  });

  check('TXT explicit supported URL schemes and keys', () => {
    const result = txt(lib, ['https://a.example.com/path', 'http://b.example.com/', 'wss://c.example.com/socket', 'ws://d.example.com/', 'URL=https://e.example.com/x; uri="https://f.example.com/"']);
    same(hosts(result), ['a.example.com', 'b.example.com', 'c.example.com', 'd.example.com', 'e.example.com', 'f.example.com']);
    assert.ok(result.candidates.every(item => JSON.stringify(item.sources) === '["txt"]'));
  });
  check('TXT structured domains including quoted values', () => same(hosts(txt(lib, 'DOMAIN = A.EXAMPLE.COM.; hostname="b.example.com"\nhostname=\'c.example.com\'')), ['a.example.com', 'b.example.com', 'c.example.com']));
  check('TXT arbitrary text and bare dotted tokens are not evidence', () => same(hosts(txt(lib, ['api.example.com', 'a long token api.example.com here', 'token=api.example.com', 'google-site-verification=api.example.com', 'MS=ms123456', 'v=DKIM1; p=api.example.com', 'include:api.example.com'])), []));
  check('TXT skips URLs embedded in unknown values and prose', () => same(hosts(txt(lib, ['google-site-verification=https://api.example.com/', 'visit https://api.example.com/', '{"hostname":"api.example.com"}', 'redirect=https://api.example.com/'])), []));
  check('TXT quoted verification content cannot smuggle explicit fields', () => same(hosts(txt(lib, 'token="opaque; hostname=api.example.com; uri=https://auth.example.com/"')), []));
  check('TXT unterminated quotes do not expose trailing keys', () => same(hosts(txt(lib, 'token="opaque; hostname=api.example.com')), []));
  check('TXT quotes preserve URL path separators', () => one(txt(lib, 'url="https://api.example.com/path;part"'), 'api.example.com', 'txt'));
  check('TXT URL authority repair is rejected', () => {
    const result = txt(lib, ['https:///api.example.com/', 'https://user@api.example.com/', 'https://api.example.com\\@evil.test/', 'https://api%2eexample.com/', 'https://*.example.com/', 'https://api.example.com:99999/', '//api.example.com/', 'ftp://api.example.com/']);
    same(hosts(result), []); same(result.wildcard_scopes, []);
  });
  check('TXT malformed domain values never use URL or wildcard semantics', () => same(hosts(txt(lib, 'domain=https://api.example.com; hostname=*.example.com; hostname=_service.example.com; domain=192.0.2.1')), []));
  check('TXT URL scopes and root exclusion', () => {
    const result = txt(lib, 'url=https://example.com/; domain=example.com.evil.test; url=https://external.test/');
    same(hosts(result), []); assert.equal(result.out_of_scope_count, 2);
  });
  check('TXT normalizes Unicode through shared host helper', () => one(txt(lib, 'domain=bücher.example.com'), 'xn--bcher-kva.example.com', 'txt'));
  check('TXT byte budget is shared across records', () => {
    const result = txt(lib, byteRecords('domain=')); same(hosts(result), ['a.example.com', 'b.example.com']); assert.equal(result.truncated_count, 1);
  });
  check('TXT byte budget counts UTF-8 bytes', () => {
    const result = txt(lib, [`token=${'é'.repeat(131070)}`, 'domain=tail.example.com']);
    same(hosts(result), []); assert.equal(result.truncated, true);
  });
  check('TXT cannot recover a hostname from a truncated external URL', () => {
    const prefix = 'https://api.example.com';
    const record = ' '.repeat(262144 - prefix.length) + prefix + '.evil.test/';
    const result = txt(lib, record); same(hosts(result), []); assert.equal(result.truncated, true);
  });

  for (const [name, operation, row] of [
    ['SPF', lib.extractFromSpfRecords, 'v=spf1 include:a.example.com'],
    ['CNAME', lib.extractFromCnameRecords, { name: 'a.example.com', target: 'example.com' }],
    ['TXT', lib.extractFromTxtRecords, 'hostname=a.example.com'],
  ]) {
    check(`${name} record cap and precise omitted-record count`, () => {
      const result = operation(Array(503).fill(row), options); assert.equal(result.truncated, true); assert.equal(result.truncated_count, 3);
      const exact = operation(Array(500).fill(row), options); assert.equal(exact.truncated, false);
    });
    check(`${name} collector metadata preserved`, () => {
      const result = operation([row], options); assert.equal(result.version, 'hostname-candidates-v1'); assert.equal(result.root, 'example.com'); assert.equal(result.observed_at, options.observedAt);
    });
    check(`${name} ordinary malformed input remains bounded`, () => {
      for (const value of [null, undefined, true, 42, {}]) { const result = operation(value, null); same(hosts(result), []); assert.equal(typeof result.truncated, 'boolean'); }
    });
    check(`${name} invalid root grants no candidate scope`, () => same(hosts(operation([row], { domain: 'https://example.com/' })), []));
    check(`${name} frozen inputs stay unchanged`, () => {
      const rows = Object.freeze([typeof row === 'object' ? Object.freeze({ ...row }) : row]);
      const before = JSON.stringify(rows); operation(rows, options); assert.equal(JSON.stringify(rows), before);
    });
  }
  check('candidate cap is deterministic with full deduplication', () => {
    const rows = Array.from({ length: 205 }, (_, i) => `domain=a${String(i).padStart(3, '0')}.example.com`);
    const forward = txt(lib, rows), backward = txt(lib, [...rows].reverse());
    same(forward, backward); assert.equal(forward.candidates.length, 200); assert.equal(forward.truncated_count, 5);
  });
  check('candidate results are detached from later output mutation', () => {
    const first = txt(lib, 'hostname=api.example.com'); first.candidates[0].sources.push('fake');
    one(txt(lib, 'hostname=api.example.com'), 'api.example.com', 'txt');
  });
}

const originalFetch = globalThis.fetch;
globalThis.fetch = () => { throw new Error('network forbidden in DNS extractor fixtures'); };
try { fixtures(api); } finally { globalThis.fetch = originalFetch; }
check('production module has no I/O or execution primitive', () => {
  assert.doesNotMatch(source, /\b(?:eval|Function|vm)\b/);
  assert.doesNotMatch(source, /\b(?:fetch|XMLHttpRequest|WebSocket)\s*\(|node:|require\s*\(/);
});
check('scope normalization and collector are shared imports', () => {
  assert.match(source, /import\s*\{\s*normalizeHostname, classifyHostname, createCandidateCollector\s*\} from '\.\/hostname-candidates\.js'/);
  assert.doesNotMatch(source, /function\s+(?:normalizeHostname|classifyHostname|createCandidateCollector)\b/);
});
check('fixed source keys and immutable bounds', () => {
  same(api.DISCOVERY_DNS_SOURCES, { spf: 'spf', cname: 'cname', txt: 'txt' });
  same(api.DISCOVERY_DNS_LIMITS, { maxInputBytes: 262144, maxRecords: 500, maxCandidates: 200 });
  assert.ok(Object.isFrozen(api.DISCOVERY_DNS_LIMITS)); assert.ok(Object.isFrozen(api.DISCOVERY_DNS_SOURCES));
});

async function killedMutation(name, anchor, replacement, proof) {
  check(`${name} mutation target unique`, () => assert.equal(source.split(anchor).length - 1, 1));
  // Execute changed production source in memory, importing the real shared
  // hostname helper. Mutation evidence is a failed behavioural assertion.
  const changed = source.replace(anchor, replacement).replace("'./hostname-candidates.js'", JSON.stringify(helperUrl));
  const mutant = await import(`data:text/javascript;base64,${Buffer.from(`${changed}\n// ${name}`).toString('base64')}`);
  check(`${name} source mutant detected`, () => assert.throws(() => proof(mutant), assert.AssertionError));
  mutants++;
}
await killedMutation('SPF version gate', "if (!/^v=spf1(?: |$)/i.test(text)) continue;", 'if (false) continue;', lib => same(hosts(spf(lib, 'v=spf10 include:a.example.com')), []));
await killedMutation('SPF macro expansion prohibition', "if (token.includes('%')) return null;", "token = token.replace('%{d}', 'a');", lib => same(hosts(spf(lib, 'v=spf1 include:%{d}.example.com')), []));
await killedMutation('SPF CIDR range', 'Number(cidrs[1]) > 32', 'Number(cidrs[1]) > 99', lib => same(hosts(spf(lib, 'v=spf1 a:a.example.com/33')), []));
await killedMutation('CNAME owner scope', 'if (!inScope(owner)) {', 'if (false) {', lib => same(hosts(cname(lib, [{ name: 'evil.test', target: 'injected.example.com' }])), []));
await killedMutation('CNAME loop detection', 'const cname_loop_count = countLoops(graph);', 'const cname_loop_count = 0;', lib => assert.equal(cname(lib, [{ name: 'a.example.com', target: 'a.example.com' }]).cname_loop_count, 1));
await killedMutation('CNAME self-loop handling', "if (size > 1 || graph.get(node)?.has(node)) loops++;", 'if (size > 1) loops++;', lib => assert.equal(cname(lib, [{ name: 'a.example.com', target: 'a.example.com' }]).cname_loop_count, 1));
await killedMutation('TXT structured keys', '(domain|hostname|url|uri)', '(domain|hostname|url|uri|token)', lib => same(hosts(txt(lib, 'token=https://api.example.com/')), []));
await killedMutation('TXT quoted field boundaries', 'for (const field of txtFields(record)) {', 'for (const field of record.split(/[;\\r\\n]/)) {', lib => same(hosts(txt(lib, 'token="x; hostname=api.example.com; x"')), []));
await killedMutation('TXT authority rejects wildcard hosts', 'if (!authority || !normalizeHostname(authority[1]))', 'if (false)', lib => { const result = txt(lib, 'https://*.example.com/'); same(hosts(result), []); same(result.wildcard_scopes, []); });
await killedMutation('total byte accounting', 'ctx.remaining -= size;', 'ctx.remaining -= 0;', lib => { const result = txt(lib, byteRecords('domain=')); same(hosts(result), ['a.example.com', 'b.example.com']); assert.equal(result.truncated_count, 1); });
await killedMutation('UTF-8 byte bound', 'const bytes = encoder.encode(value).length;', 'const bytes = value.length;', lib => { const result = txt(lib, [`token=${'é'.repeat(131070)}`, 'domain=tail.example.com']); same(hosts(result), []); assert.equal(result.truncated, true); });
await killedMutation('record count bound', 'maxRecords: 500', 'maxRecords: 1000', lib => assert.equal(txt(lib, Array(503).fill('domain=a.example.com')).truncated_count, 3));
await killedMutation('candidate bound preserved', 'maxCandidates: 200', 'maxCandidates: 1', lib => same(hosts(txt(lib, 'domain=a.example.com; hostname=b.example.com')), ['a.example.com', 'b.example.com']));
console.log(`${checks} checks passed; ${mutants} in-memory source mutants detected; no network requests.`);
