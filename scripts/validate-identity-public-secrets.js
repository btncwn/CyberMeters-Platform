import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { buildDb, makeEnv, makeCaller } from './security/lib/worker-harness.js';
import { inspectPublicSecrets, linkedSameOriginScripts, checkPublicSecretSources, validateSecretCheckUrl } from '../workers/scan-api/src/engines/identity-public-secrets.js';

// Generated fixture strings have provider syntax but were never provider keys.
const candidate = ['sk', 'live', randomBytes(28).toString('hex')].join('_');
const publicKey = candidate.replace(/^sk_/, 'pk_');
let checks = 0;
const eq = (name, actual, expected) => { assert.deepEqual(actual, expected, name); checks++; };
const page = 'https://example.test/';
const found = await inspectPublicSecrets('const key="' + candidate + '";\nconst again="' + candidate + '";', page);
eq('secret pattern produces one deduplicated candidate', found.findings.length, 1);
eq('candidate does not claim confirmed compromise', [found.findings[0].status, found.findings[0].compromise], ['candidate', 'not_assessed']);
eq('raw key never leaves parser', JSON.stringify(found).includes(candidate), false);
eq('publishable and repetitive placeholder keys excluded', (await inspectPublicSecrets(publicKey + ' ' + ['sk', 'live', 'a'.repeat(36)].join('_'), page)).findings.length, 0);
eq('line number preserves source location', (await inspectPublicSecrets('\n\n' + candidate, page)).findings[0].line, 3);
eq('query and token path are redacted', (await inspectPublicSecrets(candidate, page + candidate + '?auth=private')).findings[0].source_url, page + '[redacted]');
for (const url of ['http://127.0.0.1/', 'https://example.test.evil.test/', 'https://attacker.test/', 'https://user:pass@example.test/', 'https://example.test/?token=x', 'https://example.test:8443/']) {
  assert.throws(() => validateSecretCheckUrl(url, 'example.test')); checks++;
}
eq('script discovery excludes external hosts, comments, inline-string markup and deceptive attributes', linkedSameOriginScripts('<script>var text="<script src=\'/fake.js\'>";</script><!-- <script src="/comment.js"></script> --><script data-src="/fake2.js" src="/one.js"></script><script title="src=\'/fake3.js\'" src="/two.js"></script><script src="https://external.test/x.js"></script><script src="/one.js"></script>', page), [page + 'one.js', page + 'two.js']);
const calls = [];
const fixtureFetch = async url => {
  calls.push(url);
  return new Response(url === page ? '<script src="/main.js"></script><script src="https://external.test/leak.js"></script>' : candidate, { headers: { 'content-type': url === page ? 'text/html' : 'application/javascript' } });
};
const measured = await checkPublicSecretSources(page, 'example.test', { fetcher: fixtureFetch });
eq('only explicit page and linked same-origin script fetched', calls, [page, page + 'main.js']);
eq('candidate source retained', measured.findings[0].source_url, page + 'main.js');
eq('redirects are not followed', (await checkPublicSecretSources(page, 'example.test', { fetcher: async () => new Response(null, { status: 302, headers: { location: 'https://external.test' } }) })).state, 'unavailable');
eq('an unreadable body cannot become a clean result', (await checkPublicSecretSources(page, 'example.test', { fetcher: async () => new Response(new ReadableStream({ start(c) { c.error(new Error('fixture')); } }), { headers: { 'content-type': 'text/html' } }) })).state, 'unavailable');
let cancelled = false;
const large = await checkPublicSecretSources(page, 'example.test', { fetcher: async () => new Response(new ReadableStream({ pull(c) { c.enqueue(new Uint8Array(65536).fill(65)); }, cancel() { cancelled = true; } }), { headers: { 'content-type': 'text/html' } }) });
eq('large streaming body is cancelled with partial coverage', [large.coverage, cancelled], ['partial', true]);

// Production routing, real schema, real roles and SSRF DNS guard. No live target.
let networkMode = 'normal', outbound = [], revokeAfterFetch = null;
globalThis.fetch = async (url, opts) => {
  const target = new URL(url); outbound.push(target.origin + target.pathname);
  assert.equal(opts.redirect, 'manual');
  if (target.hostname === 'cloudflare-dns.com') {
    const name = target.searchParams.get('name'), type = target.searchParams.get('type');
    return Response.json({ Status: 0, TC: false, Question: [{ name: name + '.', type: type === 'A' ? 1 : 28 }], Answer: type === 'A' ? [{ name, type: 1, data: networkMode === 'private' ? '127.0.0.1' : '1.1.1.1', TTL: 30 }] : [] });
  }
  assert.equal(target.origin, 'https://example.test');
  assert.equal(opts.method, 'GET');
  assert.equal(new Headers(opts.headers).has('authorization'), false);
  if (revokeAfterFetch) { const action = revokeAfterFetch; revokeAfterFetch = null; action(); }
  return fixtureFetch(target.href);
};
const { default: worker, hashToken, WORKSPACE_PURGE_TABLES } = await import('../workers/scan-api/src/index.js');
const db = buildDb(), env = makeEnv(db);
db.exec('PRAGMA foreign_keys=ON');
env.cybermeters_db.batch = async stmts => {
  db.exec('BEGIN');
  try { const values = stmts.map(s => ({ meta: { changes: db.prepare(s.__sql).run(...s.__args).changes } })); db.exec('COMMIT'); return values; }
  catch (e) { db.exec('ROLLBACK'); throw e; }
};
for (const u of ['owner', 'other', 'viewer']) {
  db.prepare('INSERT INTO users(id,email,email_verified) VALUES(?,?,1)').run(u, u + '@example.test');
  db.prepare("INSERT INTO user_sessions(id,user_id,token_hash,expires_at) VALUES(?,?,?,datetime('now','+1 day'))").run('s-' + u, u, await hashToken(u));
}
for (const [ws, owner] of [['wa', 'owner'], ['wb', 'other']]) {
  db.prepare('INSERT INTO workspaces(id,name,owner_user_id) VALUES(?,?,?)').run(ws, ws, owner);
  db.prepare("INSERT INTO workspace_members(workspace_id,user_id,role) VALUES(?,?,'owner')").run(ws, owner);
}
db.prepare("INSERT INTO workspace_members(workspace_id,user_id,role) VALUES('wa','viewer','viewer')").run();
for (const [id, domain, ws, verified] of [['da','example.test','wa',true],['db','other.test','wb',true],['du','pending.test','wa',false]]) {
  db.prepare('INSERT INTO domains(id,user_id,domain) VALUES(?,?,?)').run(id, ws === 'wa' ? 'owner' : 'other', domain);
  db.prepare('INSERT INTO workspace_domains(workspace_id,domain_id,verification_status,verified_at) VALUES(?,?,?,?)').run(ws, id, verified ? 'verified' : 'pending', verified ? new Date().toISOString() : null);
}
db.prepare("INSERT INTO subscriptions(id,owner_user_id,workspace_id,plan,status,subscription_status,current_period_end,trial_end) VALUES('trial','owner','wa','professional','active','trialing',?,?)").run(new Date(Date.now()+86400000).toISOString(), new Date(Date.now()+86400000).toISOString());
const call = makeCaller(worker, env);
const path = '/api/workspaces/wa/identity-public-sources', body = { domain_id: 'da', source_url: page };
for (const [name, token, payload, expected] of [
  ['anonymous',null,body,401], ['other tenant','other',body,403], ['viewer','viewer',body,403],
  ['foreign domain','owner',{ ...body,domain_id:'db' },403], ['unverified domain','owner',{ ...body,domain_id:'du' },403],
  ['off-domain URL','owner',{ ...body,source_url:'https://example.test.evil.test/' },400],
]) eq(name + ' denied', (await call('POST', path, token, payload)).status, expected);
eq('authorization and input negatives make zero outgoing calls', outbound.length, 0);
const positive = await call('POST', path, 'owner', body);
eq('production check accepted', positive.status, 201);
eq('real route saves masked evidence', positive.data.check.result.findings.length, 1);
eq('no secret in API or database', JSON.stringify(positive.data).includes(candidate) || JSON.stringify(db.prepare('SELECT * FROM identity_public_source_checks').all()).includes(candidate), false);
eq('other workspace cannot read the check', (await call('GET', path, 'other')).status, 403);
eq('workspace member can read masked evidence', (await call('GET', path, 'viewer')).data.checks.length, 1);
eq('new evidence table participates in workspace purge', WORKSPACE_PURGE_TABLES.includes('identity_public_source_checks'), true);
networkMode = 'private'; outbound = [];
const blocked = await call('POST', path, 'owner', body);
eq('private DNS never fetched', outbound.some(v => v.startsWith('https://example.test')), false);
eq('private DNS does not produce clean evidence', blocked.data.check.result.state, 'unavailable');
networkMode = 'normal'; const before = db.prepare('SELECT COUNT(*) AS n FROM identity_public_source_checks').get().n;
revokeAfterFetch = () => db.prepare("UPDATE workspace_members SET role='viewer' WHERE workspace_id='wa' AND user_id='owner'").run();
eq('revoked permission after fetch blocks saving', (await call('POST', path, 'owner', body)).status, 403);
eq('revoked permission leaves no evidence row', db.prepare('SELECT COUNT(*) AS n FROM identity_public_source_checks').get().n, before);
db.prepare("UPDATE workspace_members SET role='owner' WHERE workspace_id='wa' AND user_id='owner'").run();
const clearRates = () => db.prepare('DELETE FROM api_rate_limits').run();
clearRates(); outbound = [];
db.prepare("UPDATE subscriptions SET trial_end=datetime('now','-1 day'), current_period_end=datetime('now','-1 day') WHERE id='trial'").run();
eq('expired trial cannot run a check', (await call('POST', path, 'owner', body)).status, 403);
eq('expired trial makes no outgoing call', outbound.length, 0);
db.prepare("UPDATE subscriptions SET trial_end=datetime('now','+1 day'),current_period_end=datetime('now','+1 day') WHERE id='trial'").run();
db.prepare("INSERT INTO api_tokens(id,user_id,workspace_id,name,token_hash,scope,status) VALUES('api','owner','wa','fixture',?,'write','active')").run(await hashToken('cm_synthetic'));
eq('API token cannot trigger checks', (await call('POST', path, 'cm_synthetic', body)).status, 403);
db.prepare("UPDATE workspaces SET deleted_at=datetime('now') WHERE id='wa'").run();
eq('deleted workspace cannot run a check', [403,404].includes((await call('POST', path, 'owner', body)).status), true);
db.prepare("UPDATE workspaces SET deleted_at=NULL WHERE id='wa'").run();
eq('all preflight denials made no outgoing call', outbound.length, 0);
const normalBatch = env.cybermeters_db.batch;
env.cybermeters_db.batch = async stmts => { if (stmts[0].__sql.includes('INSERT INTO identity_public_source_checks')) throw new Error('storage fixture'); return normalBatch(stmts); };
const savedBeforeFailure = db.prepare('SELECT COUNT(*) n FROM identity_public_source_checks').get().n;
eq('failed persistence is unavailable', (await call('POST', path, 'owner', body)).status, 503);
eq('failed persistence has no partial evidence', db.prepare('SELECT COUNT(*) n FROM identity_public_source_checks').get().n, savedBeforeFailure);
env.cybermeters_db.batch = async stmts => { if (stmts[0].__sql.includes('INSERT INTO identity_public_source_checks')) db.prepare("UPDATE workspace_members SET role='viewer' WHERE workspace_id='wa' AND user_id='owner'").run(); return normalBatch(stmts); };
eq('permission change at the commit boundary is denied', (await call('POST', path, 'owner', body)).status, 403);
eq('atomic permission guard writes nothing', db.prepare('SELECT COUNT(*) n FROM identity_public_source_checks').get().n, savedBeforeFailure);
env.cybermeters_db.batch = normalBatch;
db.prepare("UPDATE workspace_members SET role='owner' WHERE workspace_id='wa' AND user_id='owner'").run();
clearRates();
for(let i=0;i<6;i++) eq('quota positive '+i, (await call('POST', path, 'owner', body)).status, 201);
outbound=[];
eq('seventh hourly check is rate limited', (await call('POST', path, 'owner', body)).status,429);
eq('quota denial makes no outgoing call',outbound.length,0);
clearRates();
for(let i=0;i<24;i++) db.prepare("INSERT INTO identity_public_source_checks(id,workspace_id,domain_id,requested_by,result_json,created_at) VALUES(?,'wa','da','owner',?,?)").run('history-'+i,JSON.stringify(measured),new Date(Date.now()-86400000-i*1000).toISOString());
eq('retention check succeeds',(await call('POST',path,'owner',body)).status,201);
eq('per-domain evidence history remains bounded',db.prepare("SELECT COUNT(*) n FROM identity_public_source_checks WHERE workspace_id='wa' AND domain_id='da'").get().n,20);
const stalled = await checkPublicSecretSources(page,'example.test',{fetcher:async()=>new Response(new ReadableStream({pull(){return new Promise(()=>{});}}),{headers:{'content-type':'text/html'}})});
eq('stalled source never produces clean evidence',stalled.state,'unavailable');
db.close();
console.log('Identity public sources: ' + checks + '/' + checks + ' passed (synthetic fixtures; no live checks).');
