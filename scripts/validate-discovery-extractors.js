#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const modulePath = path.join(root, 'workers/scan-api/src/engines/discovery-extractors.js');
const source = await readFile(modulePath, 'utf8');
const moduleUrl = pathToFileURL(modulePath).href;
const helperUrl = pathToFileURL(path.join(path.dirname(modulePath), 'hostname-candidates.js')).href;
const nsecUrl = pathToFileURL(path.join(path.dirname(modulePath), 'nsec-walk.js')).href;
const api = await import(moduleUrl);
let checks = 0;
const check = (name, body) => { try { body(); checks++; } catch (error) { error.message = `${name}: ${error.message}`; throw error; } };
const domain = 'example.com';
const options = { domain, baseUrl: 'https://www.example.com/app/index.html' };
const hosts = result => result.candidates.map(candidate => candidate.hostname);
const same = (actual, expected) => assert.deepEqual(actual, expected);
const one = (result, hostname, sourceKey) => {
  same(hosts(result), [hostname]);
  same(result.candidates[0].sources, [sourceKey]);
};

function fixtureSuite(lib) {
  check('robots ignores relative paths', () => same(hosts(lib.extractFromRobotsTxt('Allow: /api\nDisallow: /admin\nSitemap: /map.xml', options)), []));
  check('robots reads explicit URL sources', () => same(hosts(lib.extractFromRobotsTxt('Sitemap: https://maps.example.com/sitemap.xml\nAllow: https://api.example.com/a\nDisallow: https://private.example.com/x', options)), ['api.example.com', 'maps.example.com', 'private.example.com']));
  check('robots URL list has scope and limit', () => {
    const input = Array.from({ length: 7 }, (_, i) => `Sitemap: https://map${i}.example.com/map.xml`).join('\n') + '\nSitemap: https://outside.test/map.xml';
    const result = lib.extractFromRobotsTxt(input, options);
    assert.equal(result.sitemap_urls.length, 5); assert.equal(result.out_of_scope_count, 1); assert.equal(result.truncated, true);
  });
  check('robots deduplicates URL list', () => assert.equal(lib.extractFromRobotsTxt('Sitemap: https://example.com/a.xml\nSitemap: https://example.com/a.xml', options).sitemap_urls.length, 1));
  check('sitemap reads loc and alternate href', () => same(hosts(lib.extractFromSitemapXml('<urlset><url><loc>https://www.example.com/?a=1&amp;b=2</loc><xhtml:link href="https://fr.example.com/" /></url></urlset>', options)), ['fr.example.com', 'www.example.com']));
  check('sitemap index exposes bounded child URLs', () => {
    const result = lib.extractFromSitemapXml(`<sitemapindex>${Array.from({ length: 8 }, (_, i) => `<sitemap><loc>https://example.com/map${i}.xml</loc></sitemap>`).join('')}</sitemapindex>`, options);
    assert.equal(result.sitemap_urls.length, 5); assert.equal(result.truncated, true); same(hosts(result), []);
  });
  check('ordinary sitemap pages are not fetchable sitemap list', () => same(lib.extractFromSitemapXml('<urlset><loc>https://www.example.com/page</loc></urlset>', options).sitemap_urls, []));
  check('DOCTYPE fails closed', () => {
    const result = lib.extractFromSitemapXml('<!DOCTYPE urlset [<!ENTITY x SYSTEM "https://outside.test/">]><loc>https://api.example.com/</loc>', options);
    same(hosts(result), []); assert.equal(result.rejected_reason, 'xml_doctype'); assert.ok(result.rejected_count > 0);
  });
  check('ENTITY without DOCTYPE fails closed', () => assert.equal(lib.extractFromSitemapXml('<!ENTITY ext "x"><loc>https://api.example.com/</loc>', options).rejected_reason, 'xml_doctype'));
  check('XML comments supply no evidence', () => same(hosts(lib.extractFromSitemapXml('<!-- <loc>https://fake.example.com/</loc> --><loc>https://api.example.com/</loc>', options)), ['api.example.com']));
  check('JS exact hostname and supported URL schemes', () => same(hosts(lib.extractFromJavaScript('const a = "api.example.com"; const b = \'https://auth.example.com/x\'; const c = "wss://rt.example.com"; const d = "ws://socket.example.com";', options)), ['api.example.com', 'auth.example.com', 'rt.example.com', 'socket.example.com']));
  check('JS source text and comments are not evidence', () => same(hosts(lib.extractFromJavaScript('unquoted.example.com; // "line.example.com"\n/* \'https://block.example.com/\' */ const x = "real.example.com";', options)), ['real.example.com']));
  check('JS cannot admit suffix spoof', () => {
    const result = lib.extractFromJavaScript('"example.com.evil.test"; "https://user:pass@api.example.com/";', options);
    same(hosts(result), []); assert.equal(result.out_of_scope_count, 1); assert.ok(result.rejected_count > 0);
  });
  check('JS URLs do not start comments inside literals', () => one(lib.extractFromJavaScript('"https://api.example.com/a//b"', options), 'api.example.com', 'javascript'));
  check('JS escaped literals decoded without execution', () => same(hosts(lib.extractFromJavaScript(String.raw`"https:\/\/api.example.com/x"; "auth\u002eexample.com"; "rt\x2eexample.com"`, options)), ['api.example.com', 'auth.example.com', 'rt.example.com']));
  check('JS ignores regexp string lookalikes', () => same(hosts(lib.extractFromJavaScript('const pattern = /"fake.example.com"/; const real = "real.example.com";', options)), ['real.example.com']));
  check('JS ignores regexp after control condition', () => same(hosts(lib.extractFromJavaScript('if (ready && nested(x)) /"fake.example.com"/.test(x); "real.example.com";', options)), ['real.example.com']));
  check('JS ignores templates and unterminated strings', () => same(hosts(lib.extractFromJavaScript('const template = `"fake.example.com"`; const broken = "broken.example.com', options)), []));
  check('JS nested template text never becomes a quoted literal', () => same(hosts(lib.extractFromJavaScript('const nested = `${`"fake.example.com"`}`; const real="real.example.com";', options)), ['real.example.com']));
  check('JS template interpolation braces and comments stay inside template', () => same(hosts(lib.extractFromJavaScript('const template = `${({x: "fake.example.com", y: /[}]/}).x /* } */}`; "real.example.com";', options)), ['real.example.com']));
  check('JS does not run supplied code', () => {
    const marker = '__discovery_extractor_must_not_run'; delete globalThis[marker];
    lib.extractFromJavaScript(`globalThis.${marker} = true; "api.example.com"`, options);
    assert.equal(globalThis[marker], undefined);
  });
  check('scriptSrcs resolves relative scripts and ignores inline strings', () => {
    const result = lib.scriptSrcs('<script src="./app.js"></script><script>"<script src=\'https://fake.example.com/x.js\'>"</script><script src="https://cdn.example.com/app.js"></script>', options.baseUrl, domain);
    same(result.script_urls, ['https://www.example.com/app/app.js', 'https://cdn.example.com/app.js']); same(hosts(result), ['cdn.example.com', 'www.example.com']);
  });
  check('scriptSrcs filters scope and schemes', () => {
    const result = lib.scriptSrcs('<script src="https://outside.test/x.js"></script><script src="javascript:alert(1)"></script><!-- <script src="https://fake.example.com/x.js"></script> -->', options.baseUrl, domain);
    same(result.script_urls, []); assert.equal(result.out_of_scope_count, 1);
  });
  check('script-looking HTML attribute text is not markup', () => {
    const html = `<div data-template="<script src='https://fake.example.com/app.js'></script>"></div><script src="https://real.example.com/app.js"></script>`;
    const result = lib.scriptSrcs(html, options.baseUrl, domain);
    same(hosts(result), ['real.example.com']); same(result.script_urls, ['https://real.example.com/app.js']);
  });
  check('raw-text HTML elements cannot supply script tags', () => {
    for (const tag of ['style', 'textarea', 'title']) same(hosts(lib.scriptSrcs(`<${tag}><script src="https://fake.example.com/a.js"></script></${tag}><script src="https://real.example.com/a.js"></script>`, options.baseUrl, domain)), ['real.example.com']);
  });
  check('scriptSrcs URL list bounded', () => {
    const result = lib.scriptSrcs(Array.from({ length: 8 }, (_, i) => `<script src="/bundle${i}.js"></script>`).join(''), options.baseUrl, domain);
    assert.equal(result.script_urls.length, 5); assert.equal(result.truncated, true);
  });
  check('Link relative URL resolves with base', () => one(lib.extractFromLinkHeader('</assets/app.js>; rel=preload', options), 'www.example.com', 'link_header'));
  check('Link multiple references', () => same(hosts(lib.extractFromLinkHeader('<https://api.example.com/x>; rel="preload", <//cdn.example.com/y>; rel=preload', options)), ['api.example.com', 'cdn.example.com']));
  check('Link ignores targets embedded in quoted parameters', () => same(hosts(lib.extractFromLinkHeader('</app.js>; title="x, <https://fake.example.com/>"; rel=preload', options)), ['www.example.com']));
  check('Link malformed target cannot produce candidate', () => same(hosts(lib.extractFromLinkHeader('<https://api.example.com', options)), []));
  check('CORS star and null are not hosts', () => { same(hosts(lib.extractFromCorsHeader('*', options)), []); same(hosts(lib.extractFromCorsHeader('null', options)), []); });
  check('CORS static origin contributes host', () => one(lib.extractFromCorsHeader('https://auth.example.com:8443', options), 'auth.example.com', 'cors_header'));
  check('CORS rejects paths and origin lists', () => {
    for (const value of ['https://api.example.com/x', 'https://api.example.com https://auth.example.com', 'https://api.example.com,https://auth.example.com', 'https://api.example.com/']) same(hosts(lib.extractFromCorsHeader(value, options)), []);
  });
  check('MTA-STS wildcard is scope only', () => {
    const result = lib.extractFromMtaStsPolicy('version: STSv1\nmx: *.example.com\nmx: mail.example.com\nmx: external.test', options);
    one(result, 'mail.example.com', 'mta_sts'); same(result.wildcard_scopes, ['example.com']); assert.equal(result.out_of_scope_count, 1);
  });
  check('BIMI l and a hosts only', () => same(hosts(lib.extractFromBimiRecord('v=BIMI1; l=https://logo.example.com/logo.svg; a=https://cert.example.com/vmc.pem; x=https://fake.example.com/', options)), ['cert.example.com', 'logo.example.com']));
  check('DMARC reporting host and URL host', () => {
    const result = lib.extractFromDmarcRecord('v=DMARC1; rua=mailto:dmarc@reports.example.com!10m,mailto:other@outside.test; ruf=https://ruf.example.com/upload', options);
    same(hosts(result), ['reports.example.com', 'ruf.example.com']); assert.equal(result.out_of_scope_count, 1);
  });
  check('DMARC rejects malformed addresses', () => same(hosts(lib.extractFromDmarcRecord('rua=mailto:a@@reports.example.com,mailto:a@reports.example.com@evil.test', options)), []));
  check('redirect chain from and to are extracted', () => same(hosts(lib.extractFromRedirectChain([{ from: 'https://www.example.com/a', to: 'https://login.example.com/a' }, { from: 'https://login.example.com/a', to: 'https://outside.test/' }], options)), ['login.example.com', 'www.example.com']));
  check('redirect relative destinations are not guessed', () => {
    const result = lib.extractFromRedirectChain([{ from: 'https://www.example.com/', to: '/login' }], options);
    same(hosts(result), ['www.example.com']); assert.ok(result.rejected_count > 0);
  });
  check('security.txt recognized fields only', () => same(hosts(lib.extractFromSecurityTxt('Contact: mailto:security@reports.example.com\nPolicy: https://policy.example.com/\nHiring: https://jobs.example.com/\nCanonical: https://security.example.com/.well-known/security.txt\nEncryption: https://keys.example.com/key\nUnknown: https://fake.example.com/', options)), ['jobs.example.com', 'keys.example.com', 'policy.example.com', 'reports.example.com', 'security.example.com']));
  check('PTR normalizes and rejects IP/outside/suffix spoof', () => {
    const result = lib.extractFromPtrNames(['PTR.Example.COM.', 'api.example.com', 'example.com.evil.test', '203.0.113.2', 'outside.test'], options);
    same(hosts(result), ['api.example.com', 'ptr.example.com']); assert.equal(result.out_of_scope_count, 2); assert.ok(result.rejected_count > 0);
  });
  check('IDN uses shared normalization', () => one(lib.extractFromPtrNames(['API.BÜCHER.EXAMPLE.'], { domain: 'bücher.example' }), 'api.xn--bcher-kva.example', 'ptr'));
  check('three sources merge deterministically', () => {
    const result = lib.mergeCandidateSets(lib.extractFromJavaScript('"api.example.com"', options), lib.extractFromLinkHeader('<https://api.example.com/x>', options), lib.extractFromCorsHeader('https://api.example.com', options));
    same(hosts(result), ['api.example.com']); same(result.candidates[0].sources, ['cors_header', 'javascript', 'link_header']);
  });
  check('merge preserves coverage counters and wildcard scopes', () => {
    const first = lib.extractFromMtaStsPolicy('mx: *.example.com\nmx: outside.test\nmx: invalid host', options);
    const result = lib.mergeCandidateSets(first, first);
    same(result.wildcard_scopes, ['example.com']); assert.equal(result.out_of_scope_count, 2); assert.equal(result.rejected_count, 2);
  });
  check('merge also retains shared primary sources', () => {
    const result = lib.mergeCandidateSets({ candidates: [{ hostname: 'api.example.com', sources: ['csp', 'live_tls_san'] }], wildcard_scopes: ['example.com'] }, lib.extractFromPtrNames(['api.example.com'], options));
    same(result.candidates[0].sources, ['csp', 'live_tls_san', 'ptr']); same(result.wildcard_scopes, ['example.com']);
  });
  check('merge preserves NSEC source', () => {
    const result = lib.mergeCandidateSets({ candidates: [{ hostname: 'api.example.com', sources: ['nsec'] }] }, lib.extractFromPtrNames(['api.example.com'], options));
    same(result.candidates[0].sources, ['nsec', 'ptr']);
  });
  check('merge validates malformed candidates', () => {
    const result = lib.mergeCandidateSets(null, { candidates: [{ hostname: 'https://api.example.com', sources: ['ptr'] }, { hostname: 'api.example.com', sources: ['invented'] }] });
    same(hosts(result), []); assert.equal(result.rejected_count, 3);
  });
  check('200-candidate hard bound is visible', () => {
    const result = lib.extractFromPtrNames(Array.from({ length: 220 }, (_, i) => `host${i}.example.com`), options);
    assert.equal(result.candidates.length, 200); assert.equal(result.truncated, true);
  });
  check('merge has same hard candidate bound', () => {
    const left = lib.extractFromPtrNames(Array.from({ length: 150 }, (_, i) => `a${i}.example.com`), options);
    const right = lib.extractFromPtrNames(Array.from({ length: 150 }, (_, i) => `b${i}.example.com`), options);
    const result = lib.mergeCandidateSets(left, right); assert.equal(result.candidates.length, 200); assert.equal(result.truncated, true);
  });
  check('byte limit marks truncation without parsing tail', () => {
    const text = ' '.repeat(lib.DISCOVERY_EXTRACTOR_LIMITS.maxInputBytes) + '"tail.example.com"';
    const result = lib.extractFromJavaScript(text, options); same(hosts(result), []); assert.equal(result.truncated, true);
  });
  check('truncation cannot turn an outside URL into an in-scope host', () => {
    const prefix = 'Sitemap: https://api.example.com';
    const input = ' '.repeat(lib.DISCOVERY_EXTRACTOR_LIMITS.maxInputBytes - prefix.length) + prefix + '.evil.test/map.xml';
    const result = lib.extractFromRobotsTxt(input, options);
    same(hosts(result), []); same(result.sitemap_urls, []); assert.equal(result.truncated, true);
  });
  check('all text formats discard oversized documents rather than partial tokens', () => {
    const documents = [
      ['extractFromRobotsTxt', 'Sitemap: https://api.example.com/map.xml\n'],
      ['extractFromSitemapXml', '<loc>https://api.example.com/</loc>'],
      ['extractFromJavaScript', '"api.example.com";'],
      ['extractFromLinkHeader', '<https://api.example.com/>; rel=preload'],
      ['extractFromCorsHeader', 'https://api.example.com'],
      ['extractFromMtaStsPolicy', 'mx: api.example.com\n'],
      ['extractFromBimiRecord', 'l=https://api.example.com/a.svg;'],
      ['extractFromDmarcRecord', 'rua=mailto:x@api.example.com;'],
      ['extractFromSecurityTxt', 'Policy: https://api.example.com/\n'],
    ];
    for (const [name, valid] of documents) {
      const result = lib[name](valid + ' '.repeat(lib.DISCOVERY_EXTRACTOR_LIMITS.maxInputBytes), options);
      same(hosts(result), []); assert.equal(result.truncated, true);
    }
    const scripts = lib.scriptSrcs('<script src="https://api.example.com/a.js"></script>' + ' '.repeat(lib.DISCOVERY_EXTRACTOR_LIMITS.maxInputBytes), options.baseUrl, domain);
    same(hosts(scripts), []); same(scripts.script_urls, []); assert.equal(scripts.truncated, true);
  });
  check('UTF-8 bound is byte-based', () => {
    const text = 'é'.repeat(lib.DISCOVERY_EXTRACTOR_LIMITS.maxInputBytes / 2) + '\nSitemap: https://tail.example.com/x';
    const result = lib.extractFromRobotsTxt(text, options); same(hosts(result), []); assert.equal(result.truncated, true);
  });
  check('oversized XML cannot hide a declaration beyond the bound', () => {
    const input = '<loc>https://api.example.com/</loc>' + ' '.repeat(lib.DISCOVERY_EXTRACTOR_LIMITS.maxInputBytes) + '<!DOCTYPE x>';
    const result = lib.extractFromSitemapXml(input, options); same(hosts(result), []); assert.equal(result.truncated, true);
  });
  check('oversized XML still reports a visible prohibited declaration', () => {
    const result = lib.extractFromSitemapXml('<!DOCTYPE urlset>' + ' '.repeat(lib.DISCOVERY_EXTRACTOR_LIMITS.maxInputBytes), options);
    same(hosts(result), []); assert.equal(result.truncated, true); assert.equal(result.rejected_reason, 'xml_doctype');
  });
  check('list input bound visible', () => {
    const result = lib.extractFromPtrNames(Array.from({ length: 510 }, () => 'api.example.com'), options);
    assert.equal(result.truncated, true); assert.ok(result.truncated_count >= 10);
  });
  check('redirect total byte bound visible', () => {
    const result = lib.extractFromRedirectChain([{ from: 'https://www.example.com/' + 'x'.repeat(lib.DISCOVERY_EXTRACTOR_LIMITS.maxInputBytes), to: 'https://tail.example.com/' }], options);
    same(hosts(result), []); assert.equal(result.truncated, true);
  });
  check('all extractors handle malformed ordinary inputs', () => {
    for (const [name, operation] of Object.entries(lib)) {
      if (!name.startsWith('extractFrom')) continue;
      for (const value of [null, undefined, 42, {}, true]) {
        const result = operation(value, null); assert.ok(Array.isArray(result.candidates)); assert.equal(typeof result.truncated, 'boolean');
      }
    }
    assert.ok(Array.isArray(lib.scriptSrcs(null, null, null).script_urls));
  });
  check('extractors do not mutate supplied objects', () => {
    const chain = Object.freeze([Object.freeze({ from: 'https://api.example.com/', to: 'https://auth.example.com/' })]);
    same(hosts(lib.extractFromRedirectChain(chain, Object.freeze(options))), ['api.example.com', 'auth.example.com']);
  });
}

const originalFetch = globalThis.fetch;
globalThis.fetch = () => { throw new Error('network forbidden in extractor fixtures'); };
try { fixtureSuite(api); } finally { globalThis.fetch = originalFetch; }
check('production module contains no execution primitive or I/O', () => {
  assert.doesNotMatch(source, /\b(?:eval|Function|vm)\b/);
  assert.doesNotMatch(source, /\b(?:fetch|XMLHttpRequest|WebSocket)\s*\(|node:|require\s*\(/);
});
check('normalization and scope are imported from the shared helper', () => {
  assert.match(source, /import\s*\{[^}]*normalizeHostname[^}]*classifyHostname[^}]*createCandidateCollector[^}]*\}\s*from '\.\/hostname-candidates\.js'/);
  assert.doesNotMatch(source, /function\s+(?:normalizeHostname|classifyHostname)\b/);
});
check('exported source keys fixed and limits frozen', () => {
  same(Object.keys(api.DISCOVERY_EXTRACTOR_SOURCES), ['robots_txt', 'sitemap', 'javascript', 'link_header', 'cors_header', 'mta_sts', 'bimi', 'dmarc', 'redirect_chain', 'security_txt', 'ptr']);
  assert.equal(api.DISCOVERY_EXTRACTOR_LIMITS.maxInputBytes, 262144); assert.equal(api.DISCOVERY_EXTRACTOR_LIMITS.maxCandidates, 200); assert.equal(api.DISCOVERY_EXTRACTOR_LIMITS.maxUrls, 5);
  assert.ok(Object.isFrozen(api.DISCOVERY_EXTRACTOR_LIMITS)); assert.ok(Object.isFrozen(api.DISCOVERY_EXTRACTOR_SOURCES));
});

async function killedMutation(name, anchor, replacement, proof) {
  check(`${name} mutation anchor unique`, () => assert.equal(source.split(anchor).length - 1, 1));
  const mutant = source.replace(anchor, replacement)
    .replace("'./hostname-candidates.js'", JSON.stringify(helperUrl))
    .replace("'./nsec-walk.js'", JSON.stringify(nsecUrl));
  const imported = await import(`data:text/javascript;base64,${Buffer.from(mutant + `\n// ${name}`).toString('base64')}`);
  check(`${name} mutant rejected by fixture`, () => assert.throws(() => proof(imported), assert.AssertionError));
}

await killedMutation('XML declaration guard', "if (/<!\\s*(?:DOCTYPE|ENTITY)\\b/i.test(xml)) {", 'if (false) {', mutant => {
  assert.equal(mutant.extractFromSitemapXml('<!DOCTYPE urlset><loc>https://api.example.com/</loc>', options).rejected_reason, 'xml_doctype');
});
await killedMutation('relative Link resolution', 'new URL(value, baseUrl)', 'new URL(value)', mutant => {
  one(mutant.extractFromLinkHeader('</app.js>; rel=preload', options), 'www.example.com', 'link_header');
});
await killedMutation('JS line comment exclusion', "if (n === '/' && c === '/')", 'if (false)', mutant => {
  same(hosts(mutant.extractFromJavaScript('const x = 1; // "fake.example.com"\n"real.example.com";', options)), ['real.example.com']);
});
await killedMutation('CORS static-origin restriction', 'url.origin !== text', 'false', mutant => {
  same(hosts(mutant.extractFromCorsHeader('https://api.example.com/path', options)), []);
});
await killedMutation('sitemap list cap', 'list.length >= DISCOVERY_EXTRACTOR_LIMITS.maxUrls', 'false', mutant => {
  assert.equal(mutant.extractFromRobotsTxt(Array.from({ length: 8 }, (_, i) => `Sitemap: https://example.com/map${i}.xml`).join('\n'), options).sitemap_urls.length, 5);
});
await killedMutation('source union', 'for (const source of sources) merged.get(hostname).add(source);', 'for (const source of sources) { merged.set(hostname, new Set([source])); }', mutant => {
  const result = mutant.mergeCandidateSets(api.extractFromPtrNames(['api.example.com'], options), api.extractFromCorsHeader('https://api.example.com', options));
  same(result.candidates[0].sources, ['cors_header', 'ptr']);
});
await killedMutation('oversized whole-document rejection', "if (!retainPrefix) return '';", 'if (false) return "";', mutant => {
  const prefix = 'Sitemap: https://api.example.com';
  const result = mutant.extractFromRobotsTxt(' '.repeat(api.DISCOVERY_EXTRACTOR_LIMITS.maxInputBytes - prefix.length) + prefix + '.evil.test/map.xml', options);
  same(hosts(result), []); same(result.sitemap_urls, []);
});
await killedMutation('nested template skipping', "if (c === '`') { stack.push({ kind: 'template' }); frame.expressionStart = false; i++; continue; }", "if (c === '`') return i + 1;", mutant => {
  same(hosts(mutant.extractFromJavaScript('const nested = `${`"fake.example.com"`}`; const real="real.example.com";', options)), ['real.example.com']);
});
await killedMutation('HTML outer attribute quotes', "else if (text[end] === '\"' || text[end] === \"'\") quote = text[end];", 'else if (false) quote = text[end];', mutant => {
  const html = `<div data-template="prefix > <script src='https://fake.example.com/app.js'></script>"></div><script src="https://real.example.com/app.js"></script>`;
  same(hosts(mutant.scriptSrcs(html, options.baseUrl, domain)), ['real.example.com']);
});
console.log(`${checks} checks passed`);
