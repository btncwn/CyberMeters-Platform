#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';

const moduleUrl = new URL('../workers/scan-api/src/engines/discovery-inventory-import.js', import.meta.url);
const helperUrl = new URL('../workers/scan-api/src/engines/hostname-candidates.js', import.meta.url);
const source = fs.readFileSync(moduleUrl, 'utf8');

function fixtures(api) {
  let checks = 0;
  const eq = (got, want, name) => { assert.deepEqual(got, want, name); checks++; };
  const ok = (value, name) => { assert.ok(value, name); checks++; };
  const run = (text, format = 'list', domain = 'example.com') => api.importDiscoveryInventory(text, { domain, format, observedAt: '2026-10-12T00:00:00Z' });
  const names = value => value.candidates.map(item => item.hostname);
  const listed = run('API.EXAMPLE.COM.\nauth.example.com\napi.example.com\n# user note\nexample.com\n');
  eq(names(listed), ['api.example.com', 'auth.example.com'], 'list normalization, root exclusion and dedup');
  eq(listed.candidates[0].sources, ['customer_import'], 'customer provenance');
  eq(listed.entries_examined, 4, 'input entries counted independently of unique candidates');
  eq(listed.observed_at, '2026-10-12T00:00:00Z', 'caller timestamp preserved');
  eq(names(run('api.bücher.example\napi.xn--bcher-kva.example', 'list', 'BÜCHER.EXAMPLE')), ['api.xn--bcher-kva.example'], 'IDN variants merge');
  const outside = run('example.com.evil.test\nevilexample.com\napi.example.com');
  eq(names(outside), ['api.example.com'], 'strict root boundary');
  eq(outside.out_of_scope_count, 2, 'out of scope counted only');
  ok(!JSON.stringify(outside).includes('evil'), 'external input not leaked');
  const wildcard = run('*.example.com\n*.cdn.example.com\na.*.example.com');
  eq(names(wildcard), [], 'wildcard not a concrete host');
  eq(wildcard.wildcard_scopes, ['cdn.example.com', 'example.com'], 'wildcard scope separate');
  eq(wildcard.rejected_count, 1, 'interior wildcard rejected');
  for (const bad of ['https://api.example.com', 'api.example.com:443', '127.0.0.1', 'api.example.com value', 'api-.example.com']) {
    eq(names(run(bad)), [], 'list only contains hostnames');
  }
  const csv = run('\uFEFFhostname,note\r\n"API.EXAMPLE.COM.","a, b"\r\nauth.example.com,"a ""quoted"" note"\r\n', 'csv');
  eq(names(csv), ['api.example.com', 'auth.example.com'], 'CSV BOM, CRLF and quotes');
  eq(names(run('name\napi.example.com', 'csv')), ['api.example.com'], 'CSV name column supported');
  eq(names(run('description,domain\n"multi\nline",api.example.com', 'csv')), ['api.example.com'], 'quoted multiline metadata does not create hosts');
  const malformed = run('hostname,note\napi.example.com,"unterminated', 'csv');
  eq(names(malformed), [], 'malformed CSV never partially imported');
  eq(malformed.rejected_reasons, ['malformed_csv'], 'CSV syntax reason');
  eq(run('hostname\n"api.example.com"suffix', 'csv').rejected_reasons, ['malformed_csv'], 'closed CSV quote cannot take suffix');
  eq(run('hostname,domain\napi.example.com,auth.example.com', 'csv').rejected_reasons, ['ambiguous_csv_header'], 'ambiguous hostname fields rejected');
  eq(run('url\nhttps://api.example.com', 'csv').rejected_reasons, ['ambiguous_csv_header'], 'unknown CSV schema rejected');
  const badRow = run('hostname,note\napi.example.com\nauth.example.com,ok', 'csv');
  eq(names(badRow), ['auth.example.com'], 'malformed row cannot shift column meaning');
  eq(badRow.rejected_reasons, ['invalid_csv_row'], 'row shape reported');
  const zone = run('$ORIGIN example.com.\n$TTL 1h\n@ IN SOA ns.example.com. hostmaster.example.com. (\n  1 1h 1h 1d 1h\n)\napi 300 IN A 192.0.2.1\n  IN AAAA 2001:db8::1\nauth IN 300 CNAME api.example.com.\n*.cdn IN A 192.0.2.2\n', 'zone');
  eq(names(zone), ['api.example.com', 'auth.example.com'], 'zone owners, inherited names, TTL order and multiline RDATA');
  eq(zone.wildcard_scopes, ['cdn.example.com'], 'zone wildcard scope');
  const apexWildcard = run('$ORIGIN example.com.\n* IN A 192.0.2.1', 'zone');
  eq(apexWildcard.wildcard_scopes, ['example.com'], 'relative apex wildcard remains scope');
  eq(apexWildcard.candidates, [], 'relative apex wildcard never becomes host');
  eq(zone.rejected_count, 0, 'supported zone subset parses');
  const nested = run('$ORIGIN example.com.\n$ORIGIN dev\napi IN A 192.0.2.1\nabsolute.example.com. IN A 192.0.2.2', 'zone');
  eq(names(nested), ['absolute.example.com', 'api.dev.example.com'], 'relative origin and absolute owner');
  const zoneOutside = run('$ORIGIN evil.test.\napi IN A 192.0.2.1', 'zone');
  eq(names(zoneOutside), [], 'external origin cannot grant new scope');
  eq(zoneOutside.out_of_scope_count, 1, 'external zone owner counted only');
  const directives = run('$INCLUDE secrets.example.com\n$GENERATE 1-10 host$ A 192.0.2.$\napi A 192.0.2.1', 'zone');
  eq(names(directives), ['api.example.com'], 'include and generation never interpreted');
  eq(directives.rejected_count, 2, 'unsupported directives reported');
  eq(directives.rejected_reasons, ['unsupported_zone_directive'], 'directive reason');
  eq(names(run('notes TXT "quoted; value (no grouping)" ; comment\napi A 192.0.2.1', 'zone')), ['api.example.com', 'notes.example.com'], 'quoted TXT punctuation cannot change zone syntax');
  eq(names(run('notes TXT "fake.example.com"', 'zone')), ['notes.example.com'], 'TXT content is not an imported owner');
  eq(run(' IN A 192.0.2.1', 'zone').rejected_reasons, ['invalid_zone_owner'], 'missing inherited owner refused');
  for (const bad of ['api TXT "unfinished', 'api SOA ns.example.com. (', 'api A 192.0.2.1 )']) {
    eq(run(bad, 'zone').rejected_reasons, ['malformed_zone'], 'unbalanced zone document rejected');
  }
  eq(run('$ORIGIN bad/root\napi A 192.0.2.1', 'zone').candidates, [], 'invalid origin cannot reuse old scope');
  eq(names(run('api IN AXFR ns.example.com.', 'zone')), [], 'unsupported record not guessed');
  const cap = run(Array.from({ length: 205 }, (_, i) => `host${i}.example.com`).join('\n'));
  eq(cap.candidates.length, 200, 'candidate cap');
  eq(cap.truncated_count, 5, 'candidate omissions visible');
  const entryCap = run(Array(5002).fill('api.example.com').join('\n'));
  eq(entryCap.entries_examined, 5000, 'entry cap');
  eq(entryCap.truncated_count, 2, 'entry omissions visible');
  const oversized = run('api.example.com\n' + ' '.repeat(262144));
  eq(names(oversized), [], 'oversized document refused whole');
  eq(oversized.truncated, true, 'byte bound visible');
  eq(oversized.rejected_reasons, ['input_byte_limit'], 'byte bound reason');
  eq(run('é'.repeat(131073)).truncated, true, 'UTF8 byte count');
  for (const bad of [null, undefined, 42, {}, []]) eq(api.importDiscoveryInventory(bad, { domain: 'example.com' }).candidates, [], 'bad text type safe');
  for (const bad of [null, undefined, {}, { domain: 'bad/root' }]) eq(api.importDiscoveryInventory('api.example.com', bad).candidates, [], 'bad domain safe');
  eq(run('api.example.com', 'xml').rejected_reasons, ['unsupported_format'], 'unknown format refused');
  const options = Object.freeze({ domain: 'example.com', format: 'csv' });
  const text = 'hostname\napi.example.com\nauth.example.com';
  eq(api.importDiscoveryInventory(text, options), api.importDiscoveryInventory(text, options), 'deterministic immutable input');
  ok(!JSON.stringify(listed).match(/"(?:active|resolved|authorized|scan_allowed)"/), 'no activity or authorization claim');
  return checks;
}

try {
  let checks = fixtures(await import(moduleUrl.href));
  assert.doesNotMatch(source, /\b(?:fetch|connect|eval|Function)\s*\(|from\s*['"]node:|\b(?:Date\.now|Math\.random)\s*\(/); checks++;
  const mutants = [
    ['if (exceedsUtf8Bytes(text, DISCOVERY_IMPORT_LIMITS.maxInputBytes)) {', 'if (false) {', 'input bound removed'],
    ['if (examined >= DISCOVERY_IMPORT_LIMITS.maxEntries)', 'if (false)', 'entry bound removed'],
    ['if (columns.length !== 1)', 'if (columns.length === 0)', 'ambiguous CSV column admitted'],
    ['if (row.length !== header.length)', 'if (false)', 'bad row shape admitted'],
    ["collector.add(hostname, DISCOVERY_IMPORT_SOURCE);", "collector.add(String(hostname).replace(/^\\*\\./, ''), DISCOVERY_IMPORT_SOURCE);", 'wildcard promoted'],
    ['if (closed) return null;', 'if (false) return null;', 'CSV suffix repaired'],
    ["if (value === '*') return `*.${origin}`;", "if (false) return `*.${origin}`;", 'apex wildcard lost'],
  ];
  for (const [from, to, name] of mutants) {
    assert.equal(source.split(from).length, 2, `unique mutation anchor: ${name}`);
    const code = source.replace(from, to).replace("'./hostname-candidates.js'", JSON.stringify(helperUrl.href));
    const mutant = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
    assert.throws(() => fixtures(mutant), assert.AssertionError, `fixtures detect ${name}`); checks++;
  }
  console.log(`${checks} checks passed (discovery inventory import; ${mutants.length} in-memory mutants killed)`);
} catch (error) { console.error('FAIL discovery inventory import:', error); process.exitCode = 1; }
