// S3-C DANE/TLSA: classification, module, scoring and scan-quality fixtures
// plus mutation proof. Imported by validate-deep-tls-contract.js.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseTlsaRecord, classifyTlsaAnswer, runDaneModule } from '../workers/scan-api/src/engines/dane.js';
import { computeScore } from '../workers/scan-api/src/engines/scoring.js';
import { buildScanQuality } from '../workers/scan-api/src/engines/scan-engine.js';
import { isActionableFinding } from '../workers/scan-api/src/engines/findings.js';

const tlsa = (data) => ({ type: 52, data });
const packet = ({ status = 0, ad = true, records = [], tc = false } = {}) => ({ Status: status, TC: tc, AD: ad, Answer: records.map(tlsa) });

assert.deepEqual(parseTlsaRecord('3 1 1 ( 38A88126A15AE8E6 43CE9447 )'), { usage: 3, selector: 1, matching_type: 1 });
assert.equal(parseTlsaRecord('not a record'), null);

const smtp = { service: 'smtp' }, https = { service: 'https' };
assert.equal(classifyTlsaAnswer(packet({ records: ['3 1 1 AB'] }), smtp).state, 'active');
assert.equal(classifyTlsaAnswer(packet({ records: ['2 0 1 AB'] }), smtp).state, 'active');
assert.equal(classifyTlsaAnswer(packet({ ad: false, records: ['3 1 1 AB'] }), smtp).state, 'not_validated', 'TLSA without DNSSEC is ignored');
assert.equal(classifyTlsaAnswer(packet({ records: ['1 0 1 AB'] }), smtp).state, 'unusable', 'PKIX-EE is ignored for SMTP (RFC 7672 3.1.3)');
assert.equal(classifyTlsaAnswer(packet({ records: ['1 0 1 AB'] }), https).state, 'active', 'any usage counts for HTTPS');
assert.equal(classifyTlsaAnswer(packet(), smtp).state, 'not_published');
assert.equal(classifyTlsaAnswer(packet({ ad: false }), smtp).state, 'not_assessable', 'unsigned zone: not assessable, never missing');
assert.equal(classifyTlsaAnswer(packet({ status: 3, ad: false }), smtp).state, 'not_assessable');
for (const broken of [null, packet({ status: 2 }), packet({ tc: true })]) assert.equal(classifyTlsaAnswer(broken, smtp).state, 'unavailable');

// Module: queries _25._tcp per MX and _443._tcp for the domain; a failed lookup is stated, never partial.
const asked = [];
const dns = { mx_records: [{ value: '10 mx1.example.com.' }, { value: '20 mx2.provider.example.net.' }] };
const answers = { '_25._tcp.mx1.example.com': packet({ ad: false, records: ['3 1 1 AB'] }), '_25._tcp.mx2.provider.example.net': packet({ records: ['3 1 1 AB'] }), '_443._tcp.example.com': packet() };
const module = await runDaneModule('example.com', dns, { lookup: async (name) => { asked.push(name); return answers[name]; } });
assert.deepEqual(asked.sort(), ['_25._tcp.mx1.example.com', '_25._tcp.mx2.provider.example.net', '_443._tcp.example.com']);
assert.equal(module.incomplete, false);
const failed = await runDaneModule('example.com', dns, { lookup: async () => { throw new Error('timeout'); } });
assert.equal(failed.incomplete_reason, 'tlsa_lookup_failed');
const quality = buildScanQuality({ dane: failed });
assert.equal(quality.status, 'complete');
assert.equal(quality.stated_limits.some((limit) => limit.module === 'dane'), true);

// Scoring: published-but-ineffective is a finding; everything else an observation.
const scored = computeScore({ dns: { resolves: true, has_mx: true }, dane: module }, 'example.com');
const ineffective = scored.findings.find((item) => item.id === 'email_dane_tlsa_ineffective');
assert.equal(ineffective?.severity, 'medium');
assert.match(ineffective.description, /mx1\.example\.com: TLSA published but not DNSSEC-validated/);
assert.deepEqual(ineffective.affected_hosts, ['mx1.example.com'], 'a provider host is never a case target');
const observed = scored.findings.find((item) => item.id === 'dane_status_observed');
assert.equal(isActionableFinding(observed), false);
assert.match(observed.description, /does not yet check that the TLSA matches the certificate/);
const unsigned = computeScore({ dns: { resolves: true }, dane: await runDaneModule('example.com', dns, { lookup: async () => packet({ ad: false }) }) }, 'example.com');
assert.equal(unsigned.findings.some((item) => item.module === 'dane' && item.finding_type !== 'observation'), false, 'no DNSSEC: no finding');
assert.match(unsigned.findings.find((item) => item.id === 'dane_status_observed').description, /not assessable/);
for (const item of scored.findings.filter((f) => f.module === 'dane')) assert.equal(item.score_impact, 0);

// Mutation proof.
const source = readFileSync(new URL('../workers/scan-api/src/engines/dane.js', import.meta.url), 'utf8')
  .replaceAll('from "./dns.js"', `from "${new URL('../workers/scan-api/src/engines/dns.js', import.meta.url)}"`)
  .replaceAll('from "./mail-transport.js"', `from "${new URL('../workers/scan-api/src/engines/mail-transport.js', import.meta.url)}"`);
const MUTANTS = [
  { name: 'AD flag ignored (unvalidated TLSA read as active)', from: 'const validated = answer.AD === true;', to: 'const validated = true;',
    caught: (m) => m.classifyTlsaAnswer(packet({ ad: false, records: ['3 1 1 AB'] }), smtp).state === 'active' },
  { name: 'SMTP usage rule dropped (PKIX-only read as active)', from: 'service === "smtp" ? records.filter((row) => row.usage === 2 || row.usage === 3) : records', to: 'records',
    caught: (m) => m.classifyTlsaAnswer(packet({ records: ['1 0 1 AB'] }), smtp).state === 'active' },
  { name: 'unsigned zone read as not published', from: ': { state: "not_assessable", reason: "dnssec_not_validated", records, dnssec_validated: false };', to: ': { state: "not_published", reason: null, records, dnssec_validated: false };',
    caught: (m) => m.classifyTlsaAnswer(packet({ ad: false }), smtp).state === 'not_published' },
];
const directory = mkdtempSync(join(tmpdir(), 'cm-dane-mutation-'));
try {
  let index = 0;
  for (const mutant of MUTANTS) {
    assert.equal(source.split(mutant.from).length, 2, `mutation anchor present once: ${mutant.name}`);
    const target = join(directory, `dane-mutant-${++index}.mjs`);
    writeFileSync(target, source.replace(mutant.from, mutant.to));
    assert.equal(mutant.caught(await import(`file://${target}`)), true, `mutant caught: ${mutant.name}`);
  }
} finally { rmSync(directory, { recursive: true, force: true }); }
console.log(`dane: parsing, classification, module, stated limit, findings and ${MUTANTS.length} mutants passed`);
