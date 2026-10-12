import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  DISCOVERY_WORDLIST,
  DISCOVERY_WORDLIST_LIMITS,
  wordlistSlice,
  deriveNameVariants,
} from '../workers/scan-api/src/engines/discovery-wordlist.js';

let checks = 0;
const eq = (message, actual, expected) => { assert.deepEqual(actual, expected, message); checks++; };
const ok = (message, value) => { assert.ok(value, message); checks++; };
const list = DISCOVERY_WORDLIST;
const domain = 'example.com';
const variantNames = (names, options = {}) => deriveNameVariants(names, { domain, ...options }).map(item => item.hostname);

ok('locally generated list has at least 1500 labels', list.length >= 1500);
eq('labels are unique', new Set(list).size, list.length);
eq('labels are deterministically sorted', list, [...list].sort());
ok('every label is a valid DNS label', list.every(label => /^(?:[a-z0-9]|[a-z0-9][a-z0-9-]{0,61}[a-z0-9])$/.test(label)));
ok('wordlist is immutable between requests', Object.isFrozen(list));
for (const label of [
  'api', 'auth', 'sso', 'vpn', 'mail', 'smtp', 'webmail', 'autodiscover',
  'dev', 'staging', 'test', 'uat', 'qa', 'beta', 'admin', 'portal', 'cdn',
  'static', 'assets', 'git', 'gitlab', 'jenkins', 'ci', 'grafana', 'kibana',
  'status', 'docs', 'help', 'support', 'shop', 'pay', 'billing', 'm', 'mobile',
  'app', 'apps', 'eu', 'us', 'uk', 'de', 'fr', 'internal', 'intranet', 'extranet',
  'remote', 'citrix', 'owa', 'exchange', 'sharepoint', 's3', 'backup', 'db',
  'sql', 'mysql', 'redis', 'elastic', 'monitor', 'api-staging', 'mail-eu', 'app1',
]) ok(`common authored label ${label} is included`, list.includes(label));

const slices = [];
let cursor = 0;
let wraps = 0;
for (let iteration = 0; iteration < list.length; iteration++) {
  const result = wordlistSlice({ cursor, size: 73 });
  assert.ok(result.labels.length <= 73 && result.labels.length > 0, 'bounded nonempty slice');
  slices.push(...result.labels);
  cursor = result.next_cursor;
  if (result.wrapped) { wraps++; break; }
}
eq('consecutive slices cover one complete cycle in order', slices, list);
eq('cycle wraps exactly once to zero', [wraps, cursor], [1, 0]);
eq('next cycle begins at the start', wordlistSlice({ cursor, size: 2 }).labels, list.slice(0, 2));
eq('end slice truncates rather than duplicating next-cycle labels', wordlistSlice({ cursor: list.length - 2, size: 50 }), {
  labels: list.slice(-2), next_cursor: 0, wrapped: true,
});
eq('zero-size slice does not advance', wordlistSlice({ cursor: 7, size: 0 }), { labels: [], next_cursor: 7, wrapped: false });
eq('slice without options uses bounded defaults', wordlistSlice(), { labels: list.slice(0, 50), next_cursor: 50, wrapped: false });
eq('null options are safe', wordlistSlice(null), wordlistSlice());
eq('oversized slice returns only one cycle', wordlistSlice({ cursor: 0, size: Number.MAX_SAFE_INTEGER }), {
  labels: [...list], next_cursor: 0, wrapped: true,
});
for (const invalid of [-1, 1.5, NaN, Infinity, '20', null, {}, list.length, list.length + 1]) {
  eq('invalid cursor restarts safely: ' + String(invalid), wordlistSlice({ cursor: invalid, size: 3 }), {
    labels: list.slice(0, 3), next_cursor: 3, wrapped: false,
  });
}
for (const invalid of [-1, 1.5, NaN, Infinity, '20', null, {}]) {
  eq('invalid size stays bounded: ' + String(invalid), wordlistSlice({ cursor: 3, size: invalid }), {
    labels: list.slice(3, 53), next_cursor: 53, wrapped: false,
  });
}
const mutableSlice = wordlistSlice({ size: 1 });
mutableSlice.labels[0] = 'changed';
eq('caller cannot modify shared wordlist via slice', wordlistSlice({ size: 1 }).labels, [list[0]]);

const seeds = ['app1.example.com', 'api-eu.example.com', 'portal.example.com', 'api.us.example.com'];
const variants = deriveNameVariants(seeds, { domain, max: 1000 });
const names = variants.map(item => item.hostname);
ok('numeric next siblings app2 and app3 are generated', ['app2.example.com', 'app3.example.com'].every(name => names.includes(name)));
ok('environment suffixes and prefixes are generated', [
  'portal-dev.example.com', 'portal-staging.example.com', 'portal-test.example.com',
  'portal-uat.example.com', 'portal-qa.example.com', 'portal-prod.example.com',
  'portal-old.example.com', 'portal-new.example.com', 'portal-v2.example.com',
  'dev-portal.example.com', 'staging-portal.example.com',
].every(name => names.includes(name)));
ok('region substitutions preserve hostname paths', ['api-us.example.com', 'api-de.example.com', 'api.eu.example.com'].every(name => names.includes(name)));
ok('numeric width is preserved', variantNames(['app01.example.com']).includes('app02.example.com'));
ok('compound region substitution uses full matched region', variantNames(['api-us-east-1.example.com'], { max: 1000 }).includes('api-us-west-2.example.com'));
ok('prefix region substitution is supported', variantNames(['eu-api.example.com']).includes('us-api.example.com'));
eq('variants are sorted and unique', names, [...new Set(names)].sort());
ok('variants remain strictly below the provided root', names.every(name => name !== domain && name.endsWith('.' + domain)));
ok('observed names are not proposed again', names.every(name => !seeds.includes(name)));
ok('only guess and parent are returned, without observation claims', variants.every(item => Object.keys(item).sort().join(',') === 'derived_from,hostname'));
ok('all parent references come from normalized input evidence', variants.every(item => seeds.includes(item.derived_from)));
eq('reordered inputs and duplicates produce identical results', deriveNameVariants([...seeds].reverse().concat(seeds[0]), { domain, max: 1000 }), variants);
eq('repeated calls are deterministic', deriveNameVariants(seeds, { domain, max: 1000 }), variants);
eq('max is enforced after deterministic sorting', deriveNameVariants(seeds, { domain, max: 3 }), variants.slice(0, 3));
eq('max zero disables generation', deriveNameVariants(seeds, { domain, max: 0 }), []);
eq('invalid input arrays do not generate guesses', deriveNameVariants('api.example.com', { domain }), []);
eq('invalid domain cannot expand scope', deriveNameVariants(seeds, { domain: 'https://example.com/' }), []);
eq('null options safely produce no result', deriveNameVariants(seeds, null), []);
eq('missing options safely produce no result', deriveNameVariants(seeds), []);
eq('root, wildcard, external and malformed inputs do not generate guesses', deriveNameVariants([
  domain, '*.example.com', 'badexample.com', 'example.com.evil.test',
  'evil.test', 'bad_name.example.com', '127.0.0.1', null, {},
], { domain }), []);
eq('normalization is shared for case and trailing dots', deriveNameVariants(['APP1.EXAMPLE.COM.'], { domain: 'EXAMPLE.COM.' }), deriveNameVariants(['app1.example.com'], { domain }));
const collisions = deriveNameVariants(['api-us.example.com', 'api-eu.example.com'], { domain, max: 1000 });
eq('multiple parents choose a deterministic lexical parent', collisions.find(item => item.hostname === 'api-de.example.com')?.derived_from, 'api-eu.example.com');
const existingSibling = deriveNameVariants(['app1.example.com', 'app2.example.com'], { domain, max: 1000 });
ok('a guess observed in another seed is excluded', !existingSibling.some(item => item.hostname === 'app2.example.com'));
const longLabel = 'a'.repeat(62);
ok('derived labels beyond the DNS label maximum are rejected', variantNames([`${longLabel}.example.com`], { max: 1000 }).every(name => name.split('.')[0].length <= 63));
const many = Array.from({ length: 1200 }, (_, index) => `service${index}.example.com`);
eq('input inspection is explicitly bounded', deriveNameVariants(many, { domain, max: 1000 }), deriveNameVariants(many.slice(0, 1000), { domain, max: 1000 }));
eq('positive max above hard ceiling remains bounded', deriveNameVariants(many, { domain, max: Number.MAX_SAFE_INTEGER }).length, DISCOVERY_WORDLIST_LIMITS.maxVariants);
for (const invalid of [-1, 1.5, NaN, Infinity, '20', null]) {
  eq('invalid max uses bounded default: ' + String(invalid), deriveNameVariants(many, { domain, max: invalid }).length, 100);
}

// Actually import changed in-memory source and run assertions against its behavior.
// No tracked file, filesystem fixture, network connection or production state changes.
const moduleUrl = new URL('../workers/scan-api/src/engines/discovery-wordlist.js', import.meta.url);
const helperUrl = new URL('../workers/scan-api/src/engines/hostname-candidates.js', import.meta.url).href;
const source = await readFile(moduleUrl, 'utf8');
ok('runtime module has no network, Node, dynamic evaluation or state side effects',
  !/\b(?:fetch|eval|Function|setTimeout|setInterval)\s*\(|\b(?:node:|require\s*\(|process\.|Date\.now|Math\.random)/.test(source));
const mutationProofs = [
  {
    name: 'deduplication removal',
    before: 'return Object.freeze([...labels].sort());',
    after: 'return Object.freeze([...labels, "api"].sort());',
    test(module) { assert.equal(new Set(module.DISCOVERY_WORDLIST).size, module.DISCOVERY_WORDLIST.length); },
  },
  {
    name: 'wrap signal disabled',
    before: 'wrapped: end === length,',
    after: 'wrapped: false,',
    test(module) { assert.equal(module.wordlistSlice({ cursor: list.length - 1, size: 1 }).wrapped, true); },
  },
  {
    name: 'output budget removed',
    before: '.sort().slice(0, limit)',
    after: '.sort()',
    test(module) { assert.equal(module.deriveNameVariants(seeds, { domain, max: 2 }).length, 2); },
  },
  {
    name: 'observed-name exclusion removed',
    before: "result.kind !== 'candidate' || observed.has(result.hostname)",
    after: "result.kind !== 'candidate'",
    test(module) { assert.equal(module.deriveNameVariants(['app1.example.com', 'app2.example.com'], { domain }).some(item => item.hostname === 'app2.example.com'), false); },
  },
  {
    name: 'numeric sibling generation disabled',
    before: 'for (const increment of [1, 2])',
    after: 'for (const increment of [])',
    test(module) { assert.ok(module.deriveNameVariants(['app1.example.com'], { domain }).some(item => item.hostname === 'app2.example.com')); },
  },
];
let killed = 0;
for (const mutation of mutationProofs) {
  assert.equal(source.split(mutation.before).length - 1, 1, `unique mutation target: ${mutation.name}`);
  const changed = source.replace(mutation.before, mutation.after)
    .replace("'./hostname-candidates.js'", JSON.stringify(helperUrl));
  const mutant = await import(`data:text/javascript;base64,${Buffer.from(changed).toString('base64')}`);
  let detected = false;
  try { mutation.test(mutant); }
  catch (error) {
    if (error.code !== 'ERR_ASSERTION') throw error;
    detected = true;
  }
  eq(`in-memory mutant detected: ${mutation.name}`, detected, true);
  killed++;
}
console.log(`${checks} checks passed; ${killed} in-memory mutants detected; ${list.length} authored labels; no network requests.`);
