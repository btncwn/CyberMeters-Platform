#!/usr/bin/env node
// Real application entry and local Miniflare/D1; every external request is a
// synthetic Cloudflare/DNS fixture. No credential or customer DNS is contacted.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { createHash, randomUUID, randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { splitStatements, isToleratedStatement } from './lib/migration-apply-tolerated.js';
import { encryptProviderToken, decryptProviderToken, providerKeyAvailable } from '../workers/scan-api/src/lib/provider-secrets.js';
import { buildExplicitSpf, observeDnsTxt } from '../workers/scan-api/src/engines/dns-remediation.js';
import { createCloudflareDns, stableJson } from '../workers/scan-api/src/engines/cloudflare-dns.js';
import { purgeWorkspaceData, WORKSPACE_PURGE_TABLES } from '../workers/scan-api/src/index.js';
const root=fileURLToPath(new URL('../',import.meta.url));
const require=createRequire(path.join(root,'workers/scan-api/package.json'));
const {build}=require('esbuild'); const {Miniflare,convertV4MiniflareOptions}=require('miniflare');
const scratch=fs.mkdtempSync(path.join(os.tmpdir(),'cm-dns-remediation-'));
const token='synthetic_cloudflare_token_not_a_real_secret',zone='a'.repeat(32),zoneB='b'.repeat(32);
const key=JSON.stringify({v:1,active:'test1',keys:{test1:randomBytes(32).toString('base64')}});
let mf,db,checks=0,serial=1,mode='normal',hook=null,dnsMode='matching',dnsOverrides=new Map();
const records=new Map(),calls=[],writes=[];
function equal(name,actual,expected){assert.deepEqual(actual,expected,name);checks++;console.log('PASS '+name);}
async function rejected(name,fn,code){await assert.rejects(fn,e=>e.code===code,name);checks++;console.log('PASS '+name);}
const response=(result,extra={})=>Response.json({success:true,result,...extra});
function record(name,content,extra={}){return {id:(serial++).toString(16).padStart(32,'0'),name,type:'TXT',content,ttl:300,proxied:false,comment:'',tags:[],settings:{},modified_on:'2026-01-01T00:00:00Z',...extra};}
function setRecords(name,items){records.set(name,items);}
const current=name=>records.get(name)||[];
async function outbound(request){
  const url=new URL(request.url),method=request.method;
  calls.push({origin:url.origin,path:url.pathname,method});
  if(url.origin==='https://cloudflare-dns.com'){
    assert.equal(url.pathname,'/dns-query');assert.equal(method,'GET');
    const name=url.searchParams.get('name');assert.equal(url.searchParams.get('type'),'TXT');
    if(dnsMode==='unavailable')return new Response('',{status:503});
    if(dnsMode==='redirect')return new Response('',{status:302,headers:{Location:'https://forbidden.invalid'}});
    const values=dnsOverrides.has(name)?dnsOverrides.get(name):dnsMode==='pending'?[]:current(name).filter(r=>r.type==='TXT').map(r=>r.content);
    return Response.json({Status:0,TC:false,Question:[{name:name+'.',type:16}],Answer:values.map(value=>({name,type:16,data:JSON.stringify(value)}))});
  }
  assert.equal(url.origin,'https://api.cloudflare.com');assert.equal(request.headers.get('authorization'),'Bearer '+token);
  if(hook){const action=hook;hook=null;await action({url,method});}
  if(mode==='denied')return new Response('',{status:403});
  if(mode==='redirect')return new Response('',{status:302,headers:{Location:'https://forbidden.invalid'}});
  if(mode==='malformed')return Response.json({success:true,result:[],result_info:{page:1,total_count:999,total_pages:1}});
  if(url.pathname==='/client/v4/user/tokens/verify')return response({status:'active'});
  if(url.pathname===`/client/v4/zones/${zone}`)return response({id:zone,name:'example.test',status:'active'});
  if(url.pathname===`/client/v4/zones/${zoneB}`)return response({id:zoneB,name:'evil-example.test',status:'active'});
  assert.ok(url.pathname.startsWith(`/client/v4/zones/${zone}/dns_records`));
  if(method==='GET'){
    assert.deepEqual([...url.searchParams.keys()],['name.exact','per_page','page']);
    const name=url.searchParams.get('name.exact'),items=structuredClone(current(name));
    if(mode==='drift-after-read') { mode='normal';setRecords(name,[...items,record(name,'outside-change=keep')]); }
    return response(items,{result_info:{page:1,total_count:items.length,total_pages:1}});
  }
  const input=method==='DELETE'?null:await request.json();
  writes.push({method,path:url.pathname,input});
  if(mode==='write-denied')return new Response('',{status:403});
  let changed;
  if(method==='POST') {changed=record(input.name,input.content,{...input,modified_on:new Date().toISOString()});setRecords(input.name,[...current(input.name),changed]);}
  else {
    const id=url.pathname.split('/').at(-1),entry=[...records].find(([,items])=>items.some(r=>r.id===id));assert.ok(entry);
    const [name,items]=entry; changed=items.find(r=>r.id===id);
    if(method==='DELETE')setRecords(name,items.filter(r=>r.id!==id));
    else {assert.equal(method,'PATCH');changed={...changed,...input,modified_on:new Date().toISOString()};setRecords(name,items.map(r=>r.id===id?changed:r));}
  }
  if(mode==='write-then-timeout'){mode='normal';throw new Error('Synthetic committed transport interruption');}
  return response(changed||{});
}
async function call({user='owner',ws='wa',domain='example.test',tail='dns-connection',method='GET',body,raw,origin='https://app.cybermeters.test'}={}){
  const suffix=tail==='metadata'?'dns-connections':`domains/${encodeURIComponent(domain)}/${tail}`;
  const result=await mf.dispatchFetch(`https://local.invalid/api/workspaces/${ws}/${suffix}`,{method,headers:{...(user?{Authorization:`Bearer ${user==='token'?'cm_synthetic':'test-'+user}`} :{}),Origin:origin,'Content-Type':'application/json'},...(['PUT','POST'].includes(method)?{body:raw??JSON.stringify(body??{})}:{})});
  return {status:result.status,body:await result.json()};
}
const preview=extra=>({action_id:'spf_publish',request_id:randomUUID(),inputs:{mail_mode:'no_mail',no_mail_confirmed:true},...extra});
const action=extra=>({request_id:randomUUID(),confirm:true,...extra});
const clearRates=()=>db.prepare('DELETE FROM api_rate_limits').run();
async function makePreview(extra){await clearRates();const result=await call({method:'POST',tail:'dns-changes/preview',body:preview(extra)});assert.equal(result.status,200,JSON.stringify(result));return result.body.change;}
async function act(change,verb,body=action()){await clearRates();return call({method:'POST',tail:`dns-changes/${change.id}/${verb}`,body});}
async function connect(){await clearRates();return call({method:'PUT',body:{zone_id:zone,token}});}
try{
  await build({entryPoints:[path.join(root,'workers/scan-api/src/worker.js')],outfile:path.join(scratch,'worker.mjs'),bundle:true,format:'esm',platform:'browser',target:'es2022',external:['cloudflare:*'],logLevel:'silent'});
  mf=new Miniflare(convertV4MiniflareOptions({cf:false,modules:true,resourcePersistencePath:path.join(scratch,'state'),script:fs.readFileSync(path.join(scratch,'worker.mjs'),'utf8'),compatibilityDate:'2026-06-18',compatibilityFlags:['global_fetch_strictly_public'],bindings:{ALLOWED_ORIGIN:'https://app.cybermeters.test',MAINTENANCE_MODE:'off',DNS_PROVIDER_KEY:key,RUA_INBOUND_DOMAIN:'reports.cybermeters.test'},d1Databases:{cybermeters_db:'synthetic-dns'},r2Buckets:{cybermeters_reports:'synthetic-reports'},durableObjects:{LEAKCHECK_PUBLIC:{className:'LeakCheckPublic',useSQLite:true}},outboundService:outbound}));
  db=await mf.getD1Database('cybermeters_db');
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
  await db.prepare("INSERT INTO subscriptions(id,owner_user_id,workspace_id,plan,status,subscription_status,current_period_end,trial_end) VALUES('paid','owner','wa','starter','active','trialing',?,?)").bind(new Date(Date.now()+86400000).toISOString(),new Date(Date.now()+86400000).toISOString()).run();
  await db.prepare("INSERT INTO dmarc_ingest_endpoints(id,workspace_id,domain_id,domain,token_hash,address_local,status,created_at) VALUES('endpoint','wa','da','example.test','synthetic-hash','cmrua_abcdefgh','active',datetime('now'))").run();
  await db.prepare("INSERT INTO managed_cases(id,workspace_id,case_type,domain,domain_key,remediation_id,status) VALUES('case','wa','email_control','example.test','email_protection','email.spf.publish','awaiting_verification')").run();
  equal('production entry lists only current verified domains',(await call({tail:'metadata'})).body.domains.map(d=>d.id),['da']);
  equal('effective paid trial can apply',(await call({tail:'metadata'})).body.can_apply,true);
  for(const role of ['analyst','viewer','token']){
    const meta=await call({user:role,tail:'metadata'});equal(`${role} cannot see sensitive connection metadata`,[meta.body.can_manage,meta.body.domains],[false,[]]);
  }
  const beforeDenied=calls.length;
  for(const [name,args,status] of [
    ['anonymous',{user:null},401],['other tenant',{user:'other'},403],['viewer',{user:'viewer'},403],['analyst',{user:'analyst'},403],['API token',{user:'token'},403],
    ['foreign domain',{domain:'other.test'},403],['unverified domain',{domain:'pending.test'},403],['domain suffix',{domain:'example.test.attacker.test'},403],
    ['cross-origin without session Bearer',{origin:'https://attacker.invalid',user:null},401],['invalid JSON',{raw:'{'},400],['oversized body',{raw:'x'.repeat(8193)},400],
  ])equal(name+' refused before provider',(await call({method:'PUT',body:{zone_id:zone,token},...args})).status,status);
  equal('all access/input negatives zero provider calls',calls.length,beforeDenied);
  await clearRates();
  equal('zone suffix never proves ownership',(await call({method:'PUT',body:{zone_id:zoneB,token}})).body.code,'zone_mismatch');
  const connection=await connect();equal('connection succeeds',connection.status,200);
  equal('metadata never returns token',JSON.stringify(connection.body).includes(token),false);
  const stored=await db.prepare('SELECT * FROM dns_provider_connections').first();
  equal('token encrypted at rest',stored.token_ciphertext.includes(token),false);
  const scope={workspace_id:'wa',domain_id:'da',zone_id:zone,connection_id:stored.id};
  equal('scoped decrypt restores synthetic token',await decryptProviderToken(stored.token_ciphertext,scope,key),token);
  const second=await encryptProviderToken(token,scope,key);equal('fresh AES-GCM nonce',second===stored.token_ciphertext,false);
  for(const field of Object.keys(scope))await rejected('ciphertext cannot move across '+field,()=>decryptProviderToken(second,{...scope,[field]:'different'},key),'key_unavailable');
  const corrupted=JSON.parse(second);corrupted.ct=corrupted.ct.slice(0,-4)+'AAAA';
  await rejected('ciphertext tamper fails closed',()=>decryptProviderToken(JSON.stringify(corrupted),scope,key),'key_unavailable');
  equal('missing encryption binding unavailable',providerKeyAvailable(undefined),false);
  const simultaneous=await Promise.all([connect(),connect()]);equal('concurrent rotation returns only valid state',simultaneous.every(r=>[200,409].includes(r.status)),true);
  const rotated=await db.prepare('SELECT * FROM dns_provider_connections').first();equal('concurrent rotation preserves AAD',await decryptProviderToken(rotated.token_ciphertext,{...scope,connection_id:rotated.id},key),token);

  for(const [name,inputs] of [
    ['missing explicit choice',{}],['unconfirmed no mail',{mail_mode:'no_mail'}],['no-mail mixed senders',{mail_mode:'no_mail',no_mail_confirmed:true,includes:['spf.example.test']}],
    ['unconfirmed senders',{mail_mode:'senders',ip4:['192.0.2.1'],all:'~all'}],['permissive all',{mail_mode:'senders',senders_confirmed:true,ip4:['192.0.2.1'],all:'+all'}],
    ['injected SPF',{mail_mode:'senders',senders_confirmed:true,includes:['safe.test ~all'],all:'-all'}],['guessed empty senders',{mail_mode:'senders',senders_confirmed:true,all:'-all'}],
    ['invalid IP',{mail_mode:'senders',senders_confirmed:true,ip4:['999.0.2.1'],all:'~all'}],['broad all IPv4',{mail_mode:'senders',senders_confirmed:true,ip4:['0.0.0.0/0'],all:'~all'}],
  ]){assert.throws(()=>buildExplicitSpf(inputs));checks++;console.log('PASS '+name+' refused');}
  equal('explicit structured sender policy',buildExplicitSpf({mail_mode:'senders',senders_confirmed:true,ip4:['192.0.2.1'],ip6:['2001:db8::/32'],all:'~all'}),'v=spf1 ip4:192.0.2.1 ip6:2001:db8::/32 ~all');
  const first=await makePreview({case_id:'case'});
  equal('exact create-only preview',[first.status,first.before,first.after.content,first.can_apply],['preview',[],'v=spf1 -all',true]);
  equal('preview TTL ten minutes',Date.parse(first.expires_at)-Date.parse(first.created_at),600000);
  equal('preview makes zero writes',writes.length,0);
  const originalInput=preview();const initial=await call({method:'POST',tail:'dns-changes/preview',body:originalInput});
  const repeated=await call({method:'POST',tail:'dns-changes/preview',body:originalInput});equal('preview request idempotency',repeated.body.change.id,initial.body.change.id);
  equal('idempotency rejects changed intent',(await call({method:'POST',tail:'dns-changes/preview',body:{...originalInput,inputs:{mail_mode:'senders',senders_confirmed:true,ip4:['192.0.2.1'],all:'~all'}}})).status,409);
  equal('foreign tenant cannot read change',(await call({user:'other',ws:'wb',domain:'other.test',tail:`dns-changes/${first.id}`})).status,404);
  await db.prepare("UPDATE dns_provider_changes SET expires_at='2000-01-01T00:00:00Z' WHERE id=?").bind(initial.body.change.id).run();
  equal('expired preview cannot apply',(await act(initial.body.change,'apply')).body.code,'preview_expired');
  const applyId=action();const applied=await act(first,'apply',applyId);equal('provider acceptance separate from DNS',[applied.body.change.status,applied.body.change.verification.state],['provider_accepted','not_checked']);
  equal('one exact provider create',writes.length,1);
  equal('same apply request no duplicate write',(await act(first,'apply',applyId)).body.change.status,'provider_accepted');equal('still one create',writes.length,1);
  equal('different apply request refused',(await act(first,'apply')).body.code,'request_conflict');
  equal('confirmed provider write does not close case',(await db.prepare("SELECT status FROM managed_cases WHERE id='case'").first()).status,'awaiting_verification');
  dnsMode='pending';equal('propagation pending is honest',(await act(first,'verify',{})).body.change.verification.state,'pending');
  dnsMode='unavailable';equal('DNS failure is not success',(await act(first,'verify',{})).body.change.verification.state,'unavailable');
  dnsMode='matching';const verified=await act(first,'verify',{});equal('actual DNS value observed',[verified.body.change.status,verified.body.change.verification.state],['dns_verified','observed']);
  equal('DNS observed does not fake canonical case closure',(await db.prepare("SELECT status FROM managed_cases WHERE id='case'").first()).status,'awaiting_verification');
  equal('case history preserves observation',(await db.prepare("SELECT COUNT(*) n FROM managed_case_events WHERE case_id='case' AND action='dns_observed'").first()).n,1);
  equal('existing SPF never overwritten',(await call({method:'POST',tail:'dns-changes/preview',body:preview()})).body.code,'existing_record_conflict');
  await db.prepare("UPDATE subscriptions SET subscription_status='canceled',status='canceled' WHERE id='paid'").run();
  equal('downgrade removes apply capability',(await call()).body.can_apply,false);
  equal('downgrade retains verify',(await act(first,'verify',{})).status,200);
  const undoId=action();const undo=await act(first,'rollback',undoId);equal('downgrade retains undo',[undo.body.change.status,undo.body.change.verification.state],['rolled_back','not_checked']);
  equal('undo deletes only own created record',current('example.test').length,0);
  const writeCount=writes.length;equal('undo idempotency',(await act(first,'rollback',undoId)).body.change.status,'rolled_back');equal('undo once',writes.length,writeCount);
  const freePreview=await makePreview();equal('free plan can preview',freePreview.can_apply,false);equal('free cannot apply',(await act(freePreview,'apply')).body.code,'plan_required');
  await db.prepare("UPDATE subscriptions SET subscription_status='trialing',status='active' WHERE id='paid'").run();

  const drift=await makePreview();setRecords('example.test',[record('example.test','other-verification=value')]);
  equal('new outside record invalidates preview',(await act(drift,'apply')).body.change.status,'conflict');equal('drift sends no write',writes.length,writeCount);
  setRecords('example.test',[]);
  const lateDrift=await makePreview();mode='drift-after-read';const lateWrites=writes.length;
  equal('drift after initial read refused inside claim',(await act(lateDrift,'apply')).body.change.status,'conflict');
  equal('claim recheck prevents stale write',writes.length,lateWrites);
  setRecords('example.test',[]);
  const rotatedPreview=await makePreview();await connect();equal('credential rotation invalidates preview',(await act(rotatedPreview,'apply')).body.code,'connection_changed');
  const concurrency=await makePreview(),sameAction=action();await clearRates();
  const concurrent=await Promise.all([act(concurrency,'apply',sameAction),act(concurrency,'apply',sameAction)]);
  equal('concurrent same operation both resolve without duplicate',concurrent.every(r=>r.status===200),true);equal('concurrent operation one write',writes.length,writeCount+1);
  await act(concurrency,'rollback');
  const undoDrift=await makePreview();await act(undoDrift,'apply');mode='drift-after-read';const undoWrites=writes.length;
  equal('late rollback drift refused inside claim',(await act(undoDrift,'rollback')).body.change.status,'conflict');
  equal('late rollback drift zero destructive write',writes.length,undoWrites);setRecords('example.test',[]);
  const ambiguous=await makePreview();mode='write-then-timeout';const unclear=await act(ambiguous,'apply');equal('committed write interruption remains uncertain',unclear.body.change.status,'uncertain');
  const pendingWrites=writes.length;equal('uncertain apply never repeats provider request',(await act(ambiguous,'apply',{request_id:(await db.prepare('SELECT apply_request_id FROM dns_provider_changes WHERE id=?').bind(ambiguous.id).first()).apply_request_id,confirm:true})).body.change.status,'uncertain');equal('ambiguous write count unchanged',writes.length,pendingWrites);
  const reconciled=await act(ambiguous,'verify',{});equal('own marked postimage reconciled',reconciled.body.change.status,'dns_verified');
  current('example.test')[0].content='v=spf1 ip4:192.0.2.99 -all';const beforeUndo=writes.length;
  equal('external modification prevents rollback',(await act(ambiguous,'rollback')).body.change.status,'conflict');equal('rollback drift never overwrites external value',writes.length,beforeUndo);
  setRecords('example.test',[]);
  const denied=await makePreview();mode='write-denied';equal('provider access denial not accepted',(await act(denied,'apply')).body.change.status,'unavailable');mode='normal';

  const dmarcName='_dmarc.example.test';const originalDmarc=record(dmarcName,'v=DMARC1; p=reject; sp=quarantine; pct=75; adkim=s; rua=mailto:existing@example.test',{comment:'Customer note',tags:['team:mail']});setRecords(dmarcName,[originalDmarc]);
  const dm=await makePreview({action_id:'dmarc_reporting',inputs:{}});
  equal('DMARC preserves enforcement and existing recipient',dm.after.content,'v=DMARC1; p=reject; sp=quarantine; pct=75; adkim=s; rua=mailto:existing@example.test,mailto:cmrua_abcdefgh@reports.cybermeters.test');
  equal('DMARC targets exact prior record',dm.after.id,originalDmarc.id);
  equal('DMARC append accepted',(await act(dm,'apply')).body.change.status,'provider_accepted');equal('DMARC preserves tags',current(dmarcName)[0].tags,['team:mail']);
  equal('DMARC undo succeeds',(await act(dm,'rollback')).body.change.status,'rolled_back');equal('DMARC original content and comment restored',[current(dmarcName)[0].content,current(dmarcName)[0].comment],[originalDmarc.content,originalDmarc.comment]);
  for(const bad of ['v=DMARC1; p=reject; p=none','v=DMARC1; p=unexpected']){setRecords(dmarcName,[record(dmarcName,bad)]);equal('malformed DMARC refused '+bad,(await call({method:'POST',tail:'dns-changes/preview',body:preview({action_id:'dmarc_reporting',inputs:{}})})).body.code,'existing_record_conflict');}
  setRecords(dmarcName,[originalDmarc,record(dmarcName,'v=DMARC1; p=none')]);equal('multiple DMARC policies refused',(await call({method:'POST',tail:'dns-changes/preview',body:preview({action_id:'dmarc_reporting',inputs:{}})})).body.code,'existing_record_conflict');
  const tls=await makePreview({action_id:'tls_rpt',inputs:{}});equal('TLS reporting uses active real endpoint',tls.after.content,'v=TLSRPTv1; rua=mailto:cmrua_abcdefgh@reports.cybermeters.test');
  await db.prepare("UPDATE dmarc_ingest_endpoints SET revoked_at=datetime('now') WHERE id='endpoint'").run();
  equal('endpoint revocation blocks saved apply',(await act(tls,'apply')).body.code,'reporting_endpoint_required');
  equal('missing endpoint blocks new reporting preview',(await call({method:'POST',tail:'dns-changes/preview',body:preview({action_id:'tls_rpt',inputs:{}})})).body.code,'reporting_endpoint_required');
  await db.prepare("UPDATE dmarc_ingest_endpoints SET revoked_at=NULL WHERE id='endpoint'").run();
  equal('TLS reporting apply',(await act(tls,'apply')).body.change.status,'provider_accepted');await act(tls,'rollback');

  dnsOverrides.set('spf.provider.test',['v=spf1 ip4:192.0.2.1 -all']);
  equal('structured include policy verified without flattening',(await makePreview({inputs:{mail_mode:'senders',senders_confirmed:true,includes:['spf.provider.test'],all:'~all'}})).after.content,'v=spf1 include:spf.provider.test ~all');
  dnsOverrides.set('spf.provider.test',['v=spf1 include:spf.provider.test -all']);
  equal('SPF include loop refused',(await call({method:'POST',tail:'dns-changes/preview',body:preview({inputs:{mail_mode:'senders',senders_confirmed:true,includes:['spf.provider.test'],all:'~all'}})})).body.code,'spf_include_loop');
  dnsOverrides.set('spf.provider.test',['v=spf1 exists:%{i}.provider.test -all']);
  equal('unvalidated SPF mechanisms not executable',(await call({method:'POST',tail:'dns-changes/preview',body:preview({inputs:{mail_mode:'senders',senders_confirmed:true,includes:['spf.provider.test'],all:'~all'}})})).body.code,'unsupported_spf_chain');
  dnsMode='unavailable';equal('include DNS outage refuses preview',(await call({method:'POST',tail:'dns-changes/preview',body:preview({inputs:{mail_mode:'senders',senders_confirmed:true,includes:['spf.provider.test'],all:'~all'}})})).body.code,'dns_unavailable');dnsMode='matching';dnsOverrides.clear();
  mode='malformed';equal('partial provider listing refuses preview',(await call({method:'POST',tail:'dns-changes/preview',body:preview()})).body.code,'incomplete_record_set');mode='normal';
  for(const reason of ['session','role','verification','workspace']){
    const pending=await makePreview();
    hook=async()=>{if(reason==='session')await db.prepare("UPDATE user_sessions SET expires_at='2000-01-01' WHERE user_id='owner'").run();if(reason==='role')await db.prepare("UPDATE workspace_members SET role='viewer' WHERE workspace_id='wa' AND user_id='owner'").run();if(reason==='verification')await db.prepare("UPDATE workspace_domains SET verified_at=NULL WHERE domain_id='da'").run();if(reason==='workspace')await db.prepare("UPDATE workspaces SET deleted_at=datetime('now') WHERE id='wa'").run();};
    const n=writes.length;equal(reason+' revoked while checking refuses apply',(await act(pending,'apply')).status,403);equal(reason+' revoked zero write',writes.length,n);
    await db.prepare("UPDATE user_sessions SET expires_at=datetime('now','+1 day') WHERE user_id='owner'").run();await db.prepare("UPDATE workspace_members SET role='owner' WHERE workspace_id='wa' AND user_id='owner'").run();await db.prepare("UPDATE workspace_domains SET verified_at=datetime('now') WHERE domain_id='da'").run();await db.prepare("UPDATE workspaces SET deleted_at=NULL WHERE id='wa'").run();
  }
  const adapter=createCloudflareDns(token,{timeoutMs:10,fetchImpl:async(_url,options)=>new Promise((_,reject)=>options.signal.addEventListener('abort',()=>reject(new Error('timeout'))))});
  await rejected('provider deadline is bounded',()=>adapter.list(zone,'example.test'),'provider_unavailable');
  const redirected=createCloudflareDns(token,{fetchImpl:async()=>new Response('',{status:302})});await rejected('provider redirect never followed',()=>redirected.list(zone,'example.test'),'provider_unavailable');
  const oversized=createCloudflareDns(token,{fetchImpl:async()=>new Response('x'.repeat(524289))});await rejected('provider response memory bound',()=>oversized.list(zone,'example.test'),'invalid_response');
  const truncatedDns=await observeDnsTxt('example.test',{fetchImpl:async()=>Response.json({Status:0,TC:true,Question:[{name:'example.test',type:16}],Answer:[]})});equal('truncated DNS never observed',truncatedDns.state,'unavailable');
  const badDns=await observeDnsTxt('example.test',{fetchImpl:async()=>Response.json({Status:0,TC:false,Question:[{name:'other.test',type:16}],Answer:[]})});equal('wrong DNS question never observed',badDns.state,'unavailable');
  equal('disconnect allowed',(await call({method:'DELETE'})).status,200);equal('disconnect removes ciphertext',(await db.prepare('SELECT COUNT(*) n FROM dns_provider_connections').first()).n,0);
  equal('history retained after disconnect',(await db.prepare('SELECT COUNT(*) n FROM dns_provider_changes').first()).n>0,true);
  await connect();
  equal('purge inventory includes child before credential',WORKSPACE_PURGE_TABLES.indexOf('dns_provider_changes')>=0&&WORKSPACE_PURGE_TABLES.indexOf('dns_provider_changes')<WORKSPACE_PURGE_TABLES.indexOf('dns_provider_connections'),true);
  await purgeWorkspaceData({cybermeters_db:db,cybermeters_reports:await mf.getR2Bucket('cybermeters_reports')},'wa');
  equal('workspace purge removes encrypted credentials',(await db.prepare("SELECT COUNT(*) n FROM dns_provider_connections WHERE workspace_id='wa'").first()).n,0);
  equal('workspace purge removes change snapshots',(await db.prepare("SELECT COUNT(*) n FROM dns_provider_changes WHERE workspace_id='wa'").first()).n,0);
  console.log(`DNS remediation validation: ${checks}/${checks} PASS; actual production entry, synthetic provider only.`);
} finally { await mf?.dispose(); fs.rmSync(scratch,{recursive:true,force:true}); }
