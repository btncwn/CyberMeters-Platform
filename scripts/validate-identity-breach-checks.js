#!/usr/bin/env node
// Actual production entry, local Miniflare D1 + SQLite Durable Object. All
// outbound requests terminate in a synthetic provider; never a real identity.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { splitStatements, isToleratedStatement } from './lib/migration-apply-tolerated.js';
import { parseLeakCheckResult, queryLeakCheck, subjectHashes, cleanupIdentityBreachChecks } from '../workers/scan-api/src/engines/identity-breach-checks.js';
import { identityBreachCheckRoutes } from '../workers/scan-api/src/routes/identity-breach-checks.js';
import { requireWorkspaceRole, purgeWorkspaceData, WORKSPACE_PURGE_TABLES } from '../workers/scan-api/src/index.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const require = createRequire(path.join(root, 'workers/scan-api/package.json'));
const { build } = require('esbuild');
const { Miniflare, convertV4MiniflareOptions } = require('miniflare');
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'cm-breach-validation-'));
let mf, db, checks = 0;
const pass = (name, fn) => { fn(); checks++; console.log('PASS ' + name); };
const equal = (name, actual, expected) => pass(name, () => assert.deepEqual(actual, expected));
const providerCalls = [];
let mode = 'positive', duringProvider = null;
const positive = { success: true, found: 5, fields: ['email','password'], sources: [{ name: 'Synthetic source <img src=x onerror=alert(1)>', date: '2020-01' }], password: 'DISCARD-NOT-REAL' };
const zero = { success: true, found: 0, fields: [], sources: [] };
// Exact response observed from the Public API on 2026-10-09.
const notFound = { success: false, error: 'Not found' };
const outbound = async request => {
  const url = new URL(request.url);
  assert.equal(url.origin + url.pathname, 'https://leakcheck.io/api/public');
  assert.match(url.searchParams.get('check'), /^[a-f0-9]{24}$/);
  assert.deepEqual([...url.searchParams.keys()], ['check']);
  assert.equal(request.method, 'GET');
  providerCalls.push({ at: Date.now(), hash: url.searchParams.get('check') });
  if (duringProvider) await duringProvider();
  if (mode === 'positive') return Response.json(positive);
  if (mode === 'zero') return Response.json(zero);
  if (mode === 'not_found') return Response.json(notFound);
  if (mode === '429') return new Response('', { status: 429 });
  if (mode === '500') return new Response('', { status: 500 });
  if (mode === 'redirect') return new Response('', { status: 302, headers: { Location: 'https://forbidden.invalid/' } });
  if (mode === 'oversized') return new Response('x'.repeat(131073));
  return Response.json({ success: false, found: 0 });
};
const opts = () => convertV4MiniflareOptions({ cf: false, modules: true,
  resourcePersistencePath: path.join(scratch, 'state'),
  script: fs.readFileSync(path.join(scratch, 'worker.mjs'), 'utf8'), compatibilityDate: '2026-06-18', compatibilityFlags: ['global_fetch_strictly_public'],
  bindings: { ALLOWED_ORIGIN: 'https://app.cybermeters.test', MAINTENANCE_MODE: 'off' },
  d1Databases: { cybermeters_db: 'synthetic-breach' },
  durableObjects: { LEAKCHECK_PUBLIC: { className: 'LeakCheckPublic', useSQLite: true } },
  outboundService: outbound,
});
async function call({ user = 'owner', ws = 'wa', method = 'GET', id = '', body, raw } = {}) {
  const response = await mf.dispatchFetch(`https://local.invalid/api/workspaces/${ws}/identity-breach-checks${id ? '/' + id : ''}`, {
    method, headers: { ...(user ? { Authorization: `Bearer ${user === 'token' ? 'cm_synthetic' : 'test-' + user}` } : {}), Origin: 'https://app.cybermeters.test', 'Content-Type': 'application/json' },
    ...(method === 'POST' ? { body: raw ?? JSON.stringify(body ?? input()) } : {}),
  });
  return { status: response.status, body: await response.json() };
}
const input = extra => ({ domain_id: 'da', email: 'Person@Example.Test', consent: true, consent_version: '2026-10-09', request_id: randomUUID(), ...extra });
const waitCooldown = async () => new Promise(resolve => setTimeout(resolve, 1100));
async function clearRates() { await db.prepare('DELETE FROM api_rate_limits').run(); }
async function snapshot() { return JSON.stringify((await db.prepare('SELECT * FROM identity_breach_checks ORDER BY id').all()).results); }
try {
  const built = await build({ entryPoints: [path.join(root, 'workers/scan-api/src/worker.js')], outfile: path.join(scratch, 'worker.mjs'), bundle: true, format: 'esm', platform: 'browser', target: 'es2022', external: ['cloudflare:*'], logLevel: 'silent' });
  assert.equal(built.errors.length, 0);
  mf = new Miniflare(opts()); db = await mf.getD1Database('cybermeters_db');
  // Build the actual migration-composed schema first; deploy only its schema to
  // disposable local D1. No production backup or customer records are loaded.
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(fs.readFileSync(path.join(root, 'database/schema.sql'), 'utf8'));
  for (const name of fs.readdirSync(path.join(root,'database/migrations')).filter(n => n.endsWith('.sql')).sort()) {
    const source = fs.readFileSync(path.join(root,'database/migrations',name),'utf8');
    const hash = createHash('sha256').update(source).digest('hex');
    for (const sql of splitStatements(source)) { try { sqlite.exec(sql); } catch (e) { if (!isToleratedStatement(name, hash, sql, e.message)) throw e; } }
  }
  const schema = sqlite.prepare("SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY CASE type WHEN 'table' THEN 0 ELSE 1 END").all(); sqlite.close();
  await db.batch(schema.map(row => db.prepare(row.sql)));
  await db.prepare('INSERT INTO identity_breach_cleanup_state(id) VALUES(1)').run();
  for (const user of ['owner','admin','analyst','viewer','other','actor']) {
    await db.prepare('INSERT INTO users(id,email,email_verified) VALUES(?,?,1)').bind(user, `${user}@example.test`).run();
    await db.prepare("INSERT INTO user_sessions(id,user_id,token_hash,expires_at) VALUES(?,?,?,datetime('now','+1 day'))").bind('s_'+user,user,createHash('sha256').update('test-'+user).digest('hex')).run();
  }
  for (const [ws, owner] of [['wa','owner'],['wb','other']]) {
    await db.prepare('INSERT INTO workspaces(id,name,owner_user_id) VALUES(?,?,?)').bind(ws,ws,owner).run();
    await db.prepare("INSERT INTO workspace_members(workspace_id,user_id,role) VALUES(?,?,'owner')").bind(ws,owner).run();
    await db.prepare('INSERT INTO workspace_retention_settings(workspace_id,retention_days,auto_cleanup) VALUES(?,30,1)').bind(ws).run();
  }
  for (const role of ['admin','analyst','viewer']) await db.prepare('INSERT INTO workspace_members(workspace_id,user_id,role) VALUES(?,?,?)').bind('wa',role,role).run();
  for (const [id,domain,ws] of [['da','example.test','wa'],['db','other.test','wb'],['unverified','pending.test','wa']]) {
    await db.prepare('INSERT INTO domains(id,user_id,domain) VALUES(?,?,?)').bind(id,ws==='wa'?'owner':'other',domain).run();
    await db.prepare('INSERT INTO workspace_domains(workspace_id,domain_id,verification_status,verified_at) VALUES(?,?,?,?)').bind(ws,id,id==='unverified'?'pending':'verified',id==='unverified'?null:new Date().toISOString()).run();
  }
  await db.prepare("INSERT INTO api_tokens(id,user_id,workspace_id,name,token_hash,scope,status) VALUES('tok','owner','wa','synthetic',?,'write','active')").bind(createHash('sha256').update('cm_synthetic').digest('hex')).run();
  equal('production entry routes owner metadata', (await call()).body.can_check, true);
  equal('only verified exact workspace domain listed', (await call()).body.domains.map(d=>d.id), ['da']);
  for (const role of ['analyst','viewer','token']) {
    const result = await call({user:role}); equal(`${role} no sensitive observations`, [result.body.can_check,result.body.items,result.body.domains], [false,[],[]]);
  }
  const beforeDenied = await snapshot();
  for (const [name,args,status] of [
    ['anonymous',{user:null},401], ['foreign member',{user:'other'},403], ['viewer',{user:'viewer'},403], ['analyst',{user:'analyst'},403], ['API token',{user:'token'},403],
    ['foreign domain',{body:input({domain_id:'db',email:'person@other.test'})},403], ['pending domain',{body:input({domain_id:'unverified',email:'person@pending.test'})},403],
    ['domain suffix',{body:input({email:'person@example.test.attacker.test'})},400], ['missing consent',{body:input({consent:false})},400], ['old consent',{body:input({consent_version:'old'})},400],
    ['client hash',{body:input({hash:'a'.repeat(24)})},400], ['injected email',{body:input({email:"x' OR 1=1--@example.test"})},400],
    ['list addresses',{body:input({email:'one@example.test,two@example.test'})},400], ['oversized input',{raw:'x'.repeat(2049)},400], ['broken JSON',{raw:'{'},400],
  ]) equal(name+' rejected before provider', (await call({method:'POST',...args})).status,status);
  await db.prepare("UPDATE workspace_domains SET verified_at=NULL WHERE domain_id='da'").run();
  equal('verified label without timestamp refused',(await call({method:'POST'})).status,403);
  await db.prepare("UPDATE workspace_domains SET verified_at=datetime('now') WHERE domain_id='da'").run();
  await db.prepare("UPDATE workspaces SET deleted_at=datetime('now') WHERE id='wa'").run();
  equal('deleted workspace refused by canonical access check',(await call({method:'POST'})).status,403);
  await db.prepare("UPDATE workspaces SET deleted_at=NULL WHERE id='wa'").run();
  equal('all negative paths zero provider calls',providerCalls.length,0);
  equal('all negative paths preserve every observation byte',await snapshot(),beforeDenied);

  const same = input();
  const race = await Promise.all([call({method:'POST',body:same}),call({method:'POST',body:same})]);
  equal('concurrent same request admitted once',race.map(r=>r.status).sort(),[200,201]);
  equal('idempotent concurrency one physical query',providerCalls.length,1);
  const saved = (await call()).body.items[0], id = saved.id;
  equal('positive provider is records not source-count equality',[saved.status,saved.found_count,saved.sources.length],['sources_found',5,1]);
  equal('query exactly normalized hash',providerCalls[0].hash,createHash('sha256').update('person@example.test').digest('hex').slice(0,24));
  equal('masked address only',saved.masked_address,'p•••@example.test');
  equal('retention expiry30days',Date.parse(saved.expires_at)-Date.parse(saved.checked_at),30*86400000);
  await db.prepare("UPDATE workspace_retention_settings SET retention_days=90 WHERE workspace_id='wa'").run();
  const changedExpiry=(await call()).body.items[0];
  equal('GET expiry reflects current retention policy',Date.parse(changedExpiry.expires_at)-Date.parse(changedExpiry.checked_at),90*86400000);
  await db.prepare("UPDATE workspace_retention_settings SET retention_days=30 WHERE workspace_id='wa'").run();
  pass('no raw email/provider hash/values in saved row or response',()=>{const text=JSON.stringify(saved); assert(!text.includes('person@')&&!text.includes('DISCARD-NOT-REAL')&&!text.includes(providerCalls[0].hash));});
  const stored = await snapshot(); pass('D1 contains no raw input or provider query hash',()=>{assert(!stored.toLowerCase().includes('person@')&&!stored.includes(providerCalls[0].hash));});
  equal('idempotent replay no provider',(await call({method:'POST',body:same})).body.item.id,id);
  equal('idempotency key bound to subject',(await call({method:'POST',body:{...same,email:'different@example.test'}})).status,409);
  equal('foreign delete indistinguishable missing',(await call({user:'other',ws:'wb',method:'DELETE',id})).status,404);
  equal('viewer cannot delete',(await call({user:'viewer',method:'DELETE',id})).status,403);
  equal('admin reads protected result',(await call({user:'admin'})).body.items[0].id,id);
  const otherHash = await subjectHashes('wb','person@example.test');
  pass('stored subject hash scoped to workspace',()=>assert.notEqual(JSON.parse(stored)[0].subject_hash,otherHash.subjectHash));

  // The object itself is shared across workspaces. Restart the runtime while
  // cooldown persists; a new instance must not forget the provider reservation.
  const namespace = await mf.getDurableObjectNamespace('LEAKCHECK_PUBLIC');
  const stub = namespace.get(namespace.idFromName('public-api-global'));
  equal('immediate second call limited',(await stub.lookup('a'.repeat(24))).status,'rate_limited');
  await mf.dispose(); mf = new Miniflare(opts()); db = await mf.getD1Database('cybermeters_db');
  const ns2 = await mf.getDurableObjectNamespace('LEAKCHECK_PUBLIC'), stub2=ns2.get(ns2.idFromName('public-api-global'));
  // Startup may exceed one second; force a slow response and restart only after
  // its reservation is persisted in the subsequent focused object test below.
  await waitCooldown();
  const callsBefore=providerCalls.length;
  const pair=await Promise.all([stub2.lookup('b'.repeat(24)),stub2.lookup('c'.repeat(24))]);
  equal('global concurrency one success/one limiter',pair.map(r=>r.status).sort(),['rate_limited','sources_found']);
  equal('global concurrency one outbound',providerCalls.length,callsBefore+1);
  for(let i=1;i<providerCalls.length;i++) pass('no fixed-window boundary burst '+i,()=>assert(providerCalls[i].at-providerCalls[i-1].at>=1000));
  equal('invalid direct hash no query',(await stub2.lookup('person@example.test')).status,'unavailable');

  for (const [selected,status] of [['zero','no_matches'],['not_found','no_matches'],['429','rate_limited'],['500','unavailable'],['redirect','unavailable'],['malformed','unavailable'],['oversized','unavailable']]) {
    await waitCooldown(); await clearRates(); mode=selected;
    const result=await call({user:'admin',method:'POST'});
    equal(selected+' honest saved result',result.body.item?.status,status);
    if(status!=='no_matches') equal(selected+' never numeric zero',result.body.item.found_count,null);
    else equal(selected+' saved absence has no leaked fields or sources',[result.body.item.found_count,result.body.item.fields,result.body.item.sources],[0,[],[]]);
  }
  for(const body of [{}, {success:false,found:0,fields:[],sources:[]}, {...zero,found:-1}, {...zero,found:'0'}, {...zero,sources:positive.sources}, {...zero,fields:['password']}, {...positive,sources:[]}, {...positive,sources:[{name:'x',date:4}]}, {...positive,fields:Array(101).fill('x')}]) equal('malformed response never clean',parseLeakCheckResult(body).status,'unavailable');
  equal('exact Public API not-found response is a scoped no-match',parseLeakCheckResult(notFound),{status:'no_matches',reason:null,found_count:0,fields:[],sources:[]});
  for (const [name,body] of [
    ['provider failure',{success:false,error:'Internal server error'}],
    ['rate limit',{success:false,error:'Rate limit exceeded'}],
    ['invalid query',{success:false,error:'Invalid email'}],
    ['missing success',{error:'Not found'}],
    ['string success',{success:'false',error:'Not found'}],
    ['contradictory count',{...notFound,found:1}],
    ['contradictory sources',{...notFound,sources:positive.sources}],
    ['unexpected fields',{...notFound,fields:[]}],
    ['extra error details',{...notFound,details:'upstream unavailable'}],
    ['changed error wording',{success:false,error:'not found'}],
  ]) equal(name+' is not the exact no-match envelope',parseLeakCheckResult(body).status,'unavailable');
  for (const status of [302,404,429,500]) {
    const result=await queryLeakCheck('a'.repeat(24),async()=>Response.json(notFound,{status}));
    pass('HTTP '+status+' with not-found body never becomes no-match',()=>assert.notEqual(result.status,'no_matches'));
    equal('HTTP '+status+' preserves unknown count',result.found_count,null);
  }
  let requested=null;
  await queryLeakCheck('a'.repeat(24),async(url,options)=>{requested={url,options};return Response.json(zero);});
  equal('adapter never follows redirects',requested.options.redirect,'manual');
  pass('adapter uses abort deadline',()=>assert(requested.options.signal instanceof AbortSignal));
  equal('transport error not clean',(await queryLeakCheck('a'.repeat(24),async()=>{throw Error('private details');})).reason,'provider_unavailable');

  await waitCooldown();await clearRates();mode='positive';
  duringProvider=async()=>{await db.prepare("UPDATE workspace_members SET role='viewer' WHERE workspace_id='wa' AND user_id='admin'").run();};
  equal('membership revoked during query no result disclosure',(await call({user:'admin',method:'POST'})).status,403);
  duringProvider=null;await db.prepare("UPDATE workspace_members SET role='admin' WHERE workspace_id='wa' AND user_id='admin'").run();
  await waitCooldown();await clearRates();
  duringProvider=async()=>{await db.prepare("DELETE FROM identity_breach_checks WHERE workspace_id='wa'").run();};
  equal('concurrent delete never resurrects check',(await call({method:'POST'})).status,409);
  duringProvider=null;equal('no resurrected rows',JSON.parse(await snapshot()).length,0);

  // Real D1 retention, anonymisation and canonical workspace purge.
  const seed=async(id,ws,date,actor='actor')=>db.prepare("INSERT INTO identity_breach_checks(id,workspace_id,domain_id,requested_by,request_id,subject_hash,masked_address,consent_version,consented_at,checked_at) VALUES(?,?,?,?,?,?,?,?,?,?)").bind(id,ws,ws==='wa'?'da':'db',actor,id,'a'.repeat(64),'•••@example.test','2026-10-09',date,date).run();
  const old=new Date(Date.now()-40*86400000).toISOString(),fresh=new Date().toISOString();
  await seed('old','wa',old);await seed('fresh','wa',fresh);await seed('other','wb',old);
  await db.prepare("UPDATE workspace_retention_settings SET auto_cleanup=0 WHERE workspace_id='wb'").run();
  equal('existing retention removes expired only',(await cleanupIdentityBreachChecks(fresh,{cybermeters_db:db})).deleted,1);
  equal('disabled cleanup preserves old observation',(await db.prepare("SELECT id FROM identity_breach_checks ORDER BY id").all()).results.map(r=>r.id),['fresh','other']);
  // More than one bounded cleanup page, with permanent records at the front.
  // The second page must be reached instead of selecting the same first100.
  const bulk=[];
  for(let i=0;i<101;i++) {
    const ws=`rotation_${String(i).padStart(3,'0')}`;
    bulk.push(db.prepare('INSERT INTO workspaces(id,name,owner_user_id) VALUES(?,?,?)').bind(ws,ws,'owner'));
    bulk.push(db.prepare('INSERT INTO workspace_retention_settings(workspace_id,retention_days,auto_cleanup) VALUES(?,30,0)').bind(ws));
    bulk.push(db.prepare("INSERT INTO identity_breach_checks(id,workspace_id,domain_id,request_id,subject_hash,masked_address,consent_version,consented_at,checked_at) VALUES(?,?,'da',?,'hash','mask','2026-10-09',?,?)").bind(ws,ws,ws,old,old));
  }
  bulk.push(db.prepare("INSERT INTO workspaces(id,name,owner_user_id) VALUES('zzz','last','owner')"));
  bulk.push(db.prepare("INSERT INTO workspace_retention_settings(workspace_id,retention_days,auto_cleanup) VALUES('zzz',30,1)"));
  await db.batch(bulk); await seed('last_expired','zzz',old);
  await cleanupIdentityBreachChecks(fresh,{cybermeters_db:db});
  equal('first retention page preserves later row',(await db.prepare("SELECT id FROM identity_breach_checks WHERE id='last_expired'").first()).id,'last_expired');
  await cleanupIdentityBreachChecks(fresh,{cybermeters_db:db});
  equal('persisted rotation reaches later expired workspace',await db.prepare("SELECT id FROM identity_breach_checks WHERE id='last_expired'").first(),null);
  await db.prepare("DELETE FROM identity_breach_checks WHERE workspace_id LIKE 'rotation_%'").run();
  await db.prepare("DELETE FROM user_sessions WHERE user_id='actor'").run();
  await db.prepare("DELETE FROM users WHERE id='actor'").run();
  equal('account actor reference anonymized on deletion',(await db.prepare('SELECT requested_by FROM identity_breach_checks').all()).results.map(r=>r.requested_by),[null,null]);
  pass('new table included in canonical purge',()=>assert(WORKSPACE_PURGE_TABLES.includes('identity_breach_checks')));
  const r2={get:async()=>null,head:async()=>null,delete:async()=>{},list:async()=>({objects:[]})};
  await purgeWorkspaceData({cybermeters_db:db,cybermeters_reports:r2},'wa');
  equal('canonical purge removes selected workspace only',(await db.prepare('SELECT id FROM identity_breach_checks').all()).results.map(r=>r.id),['other']);

  // Denied limiter and storage fail before external disclosure (real D1 reads).
  let fakeCalls=0;
  const routeEnv={cybermeters_db:db,LEAKCHECK_PUBLIC:{getByName:()=>({lookup:async()=>{fakeCalls++;return parseLeakCheckResult(zero);}})}};
  const request=new Request('https://local.invalid/api/workspaces/wb/identity-breach-checks',{method:'POST',body:JSON.stringify(input({domain_id:'db',email:'x@other.test'}))});
  const denied=await identityBreachCheckRoutes({request,url:new URL(request.url),env:routeEnv,requireAuth:async()=>({id:'other'}),requireWorkspaceRole,consumeApiRateLimit:async()=>({status:503,body:{error:'rate_limit_unavailable'}}),json:(b,s=200)=>Response.json(b,{status:s})});
  equal('workspace limiter failure closed',denied.status,503);equal('limiter failure no provider calls',fakeCalls,0);

  // Isolated test-only subclass exposes storage to establish deterministic
  // restart/corrupt-state fixtures. Production has no storage-control endpoint.
  await mf.dispose();
  const doFixture=await build({stdin:{contents:`import {LeakCheckPublic as Base} from './workers/scan-api/src/durable-objects/leakcheck-public.js'; export class InspectQuota extends Base { async putState(value){await this.ctx.storage.put('next_allowed_at',value);} async state(){return this.ctx.storage.get('next_allowed_at');} } export default{fetch(){return new Response('fixture')}}`,resolveDir:root},bundle:true,write:false,format:'esm',platform:'browser',external:['cloudflare:*'],logLevel:'silent'});
  const quotaOptions=()=>convertV4MiniflareOptions({cf:false,modules:true,script:doFixture.outputFiles[0].text,compatibilityDate:'2026-06-18',resourcePersistencePath:path.join(scratch,'quota-state'),durableObjects:{QUOTA:{className:'InspectQuota',useSQLite:true}},outboundService:outbound});
  mf=new Miniflare(quotaOptions()); mode='positive';
  let quotaNamespace=await mf.getDurableObjectNamespace('QUOTA');
  let quota=quotaNamespace.get(quotaNamespace.idFromName('global'));
  const beforeQuota=providerCalls.length;
  const quotaResult=await quota.lookup('d'.repeat(24));
  equal('real object successful query',quotaResult.status,'sources_found');
  const savedCooldown=await quota.state();
  pass('successful query persists future cooldown',()=>assert(savedCooldown>Date.now()));
  await quota.putState(Date.now()+60000);
  await mf.dispose(); mf=new Miniflare(quotaOptions());
  quotaNamespace=await mf.getDurableObjectNamespace('QUOTA');quota=quotaNamespace.get(quotaNamespace.idFromName('global'));
  equal('fresh runtime honors persisted in-flight lease',(await quota.lookup('e'.repeat(24))).status,'rate_limited');
  await quota.putState(NaN);
  equal('corrupt persistent quota fails closed',(await quota.lookup('e'.repeat(24))).reason,'limiter_unavailable');
  equal('restart/corruption caused no outbound',providerCalls.length,beforeQuota+1);
  equal('actual deadline failure never clean',(await queryLeakCheck('f'.repeat(24),async(url,{signal})=>new Promise((resolve,reject)=>signal.addEventListener('abort',()=>reject(new Error('aborted')),{once:true})))).reason,'provider_timeout');
  console.log(`Identity breach checks: ${checks}/${checks} passed (local fixtures; no real lookups).`);
} finally { await mf?.dispose(); fs.rmSync(scratch,{recursive:true,force:true}); }
