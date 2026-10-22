#!/usr/bin/env node
import { assertProbeFetch } from './lib/probe-contract-fixture.mjs';
// Real route/RBAC, D1 transaction and queue-consumer controls, no external I/O.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { splitStatements, isToleratedStatement } from './lib/migration-apply-tolerated.js';
import { networkAssetRoutes } from '../workers/scan-api/src/routes/network-assets.js';
import { normalizeNetworkTarget, normalizeNetworkPorts } from '../workers/scan-api/src/engines/network-targets.js';
import { processNetworkScanMessage, networkObservationChanges, recoverNetworkScans, networkReceiptCoverage } from '../workers/scan-api/src/engines/network-scan-dispatch.js';
import { requireWorkspaceRole } from '../workers/scan-api/src/index.js';
import { getPlanLimits, countScansThisMonth, checkScanLimit } from '../workers/scan-api/src/engines/plan-usage.js';
import { collectNetworkProbe, validateNetworkProbeReceipt } from '../workers/scan-api/src/engines/network-probe.js';

globalThis.fetch=async()=>{throw new Error('external network disabled');};
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
let passed=0,failed=0;
function ok(name,value){if(value){passed++;console.log(`PASS ${name}`);}else{failed++;console.error(`FAIL ${name}`);}}
function eq(name,a,b){ok(name,JSON.stringify(a)===JSON.stringify(b));}
async function rejects(name,fn){let denied=false;try{await fn();}catch{denied=true;}ok(name,denied);}
const db=new DatabaseSync(':memory:');
db.exec(fs.readFileSync(path.join(root,'database/schema.sql'),'utf8'));
for(const name of fs.readdirSync(path.join(root,'database/migrations')).filter(n=>n.endsWith('.sql')).sort()) {
  const sql=fs.readFileSync(path.join(root,'database/migrations',name),'utf8');
  const hash=createHash('sha256').update(sql).digest('hex');
  for(const statement of splitStatements(sql)) {
    try{db.exec(statement);}catch(error){if(!isToleratedStatement(name,hash,statement,error.message))throw error;}
  }
}
db.exec('PRAGMA foreign_keys=ON');
let batchFailure=false,readFailure=false,rateFailure=false,r2Failure=false;
function stmt(sql,args=[]){const obj={sql,args,bind:(...a)=>stmt(sql,a),first:async()=>{if(readFailure)throw new Error('storage');return db.prepare(sql).get(...args)||null;},all:async()=>{if(readFailure)throw new Error('storage');return {results:db.prepare(sql).all(...args)};},run:async()=>({meta:{changes:db.prepare(sql).run(...args).changes}})};return obj;}
const d1={prepare:sql=>stmt(sql),batch:async statements=>{db.exec('BEGIN');try{const out=[];for(let i=0;i<statements.length;i++){if(batchFailure&&i===2)throw new Error('injected transaction failure');out.push(await statements[i].run());}db.exec('COMMIT');return out;}catch(e){db.exec('ROLLBACK');throw e;}}};
for(const id of ['owner','other','admin','analyst','viewer'])db.prepare('INSERT INTO users(id,email,email_verified) VALUES(?,?,1)').run(id,`${id}@example.test`);
for(const [id,owner] of [['wa','owner'],['wb','other']]){
  db.prepare('INSERT INTO workspaces(id,name,owner_user_id) VALUES(?,?,?)').run(id,id,owner);
  db.prepare('INSERT INTO workspace_members(workspace_id,user_id,role) VALUES(?,?,?)').run(id,owner,'owner');
  db.prepare("INSERT INTO subscriptions(id,owner_user_id,workspace_id,plan,status,subscription_status,created_at,updated_at) VALUES(?,?,?,'professional','active','active',datetime('now'),datetime('now'))").run(`sub_${id}`,owner,id);
}
for(const role of ['admin','analyst','viewer'])db.prepare('INSERT INTO workspace_members(workspace_id,user_id,role) VALUES(?,?,?)').run('wa',role,role);
const objects=new Map(),queued=[];let probeCalls=0,puts=0,rateCalls=0;
const env={cybermeters_db:d1,NETWORK_PROBE:{fetch:async()=>{throw new Error('test adapter only');}},SCAN_QUEUE:{send:async b=>{queued.push(b);}},cybermeters_reports:{put:async(key,text,opts)=>{puts++;if(r2Failure)throw new Error('storage');if(opts.onlyIf.get('If-None-Match')!=='*')throw new Error('not immutable');if(objects.has(key))return null;objects.set(key,text);return {etag:'test'};},get:async key=>objects.has(key)?{text:async()=>objects.get(key)}:null}};
async function call(resource,{user='owner',workspace='wa',method='GET',body,token={}}={}){
 const url=new URL(`https://unit.test/api/workspaces/${workspace}/${resource}`);
 const request=new Request(url,{method,...(method!=='GET'?{body:JSON.stringify(body??{}),headers:{'Content-Type':'application/json'}}:{})});
 const response=await networkAssetRoutes({request,url,env,requireAuth:async()=>user?{id:user,...token}:null,requireWorkspaceRole,consumeApiRateLimit:async()=>{rateCalls++;return rateFailure?{status:503,body:{error:'rate_limit_unavailable'}}:null;},json:(b,s=200)=>Response.json(b,{status:s}),serverError:()=>Response.json({error:'server_error'},{status:500})});
 return {status:response.status,body:await response.json()};
}
const snapshot=()=>JSON.stringify(['network_targets','network_scans','network_assets','audit_events'].map(t=>db.prepare(`SELECT * FROM ${t} ORDER BY rowid`).all()));
// The declared address is observed in this workspace's verified-domain DNS
// (network-ownership.js): an attestation alone no longer authorises it.
{
  const seen=new Date().toISOString();
  db.prepare("INSERT INTO domains(id,user_id,domain) VALUES('d_seed','owner','seed.example')").run();
  db.prepare("INSERT INTO workspace_domains(workspace_id,domain_id,verification_status) VALUES('wa','d_seed','verified')").run();
  db.prepare("INSERT INTO workspace_assets(id,workspace_id,domain_id,hostname,first_seen,last_seen,created_at,updated_at,ip_addresses,wildcard_dns,lifecycle_state,status) VALUES('seed1','wa','d_seed','mail.seed.example',?,?,?,?,'[\"8.8.8.8\"]',0,'observed','active')").run(seen,seen,seen,seen);
}
const declaration={target:'8.8.8.8',authorization_confirmed:true};
const priorEmpty=snapshot();
for(const [name,args,status] of [
 ['unauthenticated',{user:null},401],['foreign',{user:'other'},403],['viewer',{user:'viewer'},403],['analyst declaration',{user:'analyst'},403],
 ['read token',{token:{token_scope:'read',token_workspace_id:'wa'}},403],['token other workspace',{token:{token_scope:'write',token_workspace_id:'wb'}},403],
 ['no declaration',{body:{target:'8.8.8.8'}},400],['false declaration',{body:{...declaration,authorization_confirmed:false}},400],['no provider input',{body:{...declaration,url:'http://internal'}},400]
 ]){eq(name,(await call('network-targets',{method:'POST',body:declaration,...args})).status,status);}
eq('all rejected declarations preserve full records',snapshot(),priorEmpty);
for(const target of ['127.0.0.1','10.0.0.1','169.254.169.254','192.0.2.1','198.51.100.1','203.0.113.1','::1','fd00::1','fe80::1','::ffff:7f00:1','8.8.8.0/26','8.8.8.1/27','2001:4860::/122','cybermeters.com','2130706433','010.0.0.1','8.8.8.8:443'])await rejects(`reject ${target}`,()=>normalizeNetworkTarget(target));
const range=await normalizeNetworkTarget('8.8.8.0/27');eq('32 literal range',range.address_count,32);eq('scope exact first/last',[range.addresses[0],range.addresses.at(-1)],['8.8.8.0','8.8.8.31']);
eq('IPv6 canonical public',(await normalizeNetworkTarget('2001:4860:4860::8888')).target,'2001:4860:4860::8888');
await rejects('more than256pairs',()=>normalizeNetworkPorts([21,22,25,53,80,110,143,443,445],32));
await rejects('duplicate ports',()=>normalizeNetworkPorts([443,443],1));await rejects('arbitrary port',()=>normalizeNetworkPorts([65535],1));
const created=await call('network-targets',{method:'POST',user:'admin',body:declaration});eq('admin declaration succeeds',created.status,201);
const targetId=created.body.target.id;eq('attestation honest',created.body.target.authorization_status,'attested');eq('actor retained',created.body.target.authorized_by,'admin');
const audit=db.prepare("SELECT metadata_json FROM audit_events WHERE event_type='network_target_authorized'").get();eq('no independent ownership claim',JSON.parse(audit.metadata_json).independently_verified,false);
eq('duplicate declaration', (await call('network-targets',{method:'POST',body:declaration})).status,409);
const noMutation=snapshot();
eq('foreign cannot get target', (await call('network-targets',{user:'other'})).status,403);
eq('foreign target cannot scan', (await call(`network-targets/${targetId}/scans`,{user:'other',workspace:'wb',method:'POST',body:{ports:[22]}})).status,404);
eq('viewer cannot scan', (await call(`network-targets/${targetId}/scans`,{user:'viewer',method:'POST',body:{ports:[22]}})).status,403);
const collector=env.NETWORK_PROBE;delete env.NETWORK_PROBE;
eq('missing collector503', (await call(`network-targets/${targetId}/scans`,{method:'POST',body:{ports:[22]}})).status,503);env.NETWORK_PROBE=collector;
eq('no side effects on refusals',snapshot(),noMutation);eq('no queued refused jobs',queued.length,0);
db.prepare("UPDATE subscriptions SET status='canceled',subscription_status='canceled' WHERE id='sub_wa'").run();
eq('free has no silent allowance',(await call(`network-targets/${targetId}/scans`,{method:'POST',body:{ports:[22]}})).status,403);
db.prepare("UPDATE subscriptions SET status='active',subscription_status='active' WHERE id='sub_wa'").run();
rateFailure=true;eq('rate failure503',(await call(`network-targets/${targetId}/scans`,{method:'POST',body:{ports:[22]}})).status,503);rateFailure=false;
eq('denied rates no queue',queued.length,0);
const admitted=await call(`network-targets/${targetId}/scans`,{user:'analyst',method:'POST',body:{ports:[22,443]}});eq('analyst scans declared target',admitted.status,202);
const scanId=admitted.body.scan.id;eq('queued has no quality',admitted.body.scan.quality,null);
eq('one active workspace scan',(await call(`network-targets/${targetId}/scans`,{method:'POST',body:{ports:[22]}})).status,409);
let state='open',invalid=false;
const adapter={collectNetworkProbe,validateNetworkProbeReceipt};
env.NETWORK_PROBE.fetch=async(url,options)=>{
  if(url!=='https://network-probe.internal/collect'||options.method!=='POST')throw new Error('unexpected service request');
  probeCalls++;const request=assertProbeFetch(options),now=new Date().toISOString();
  return Response.json({schema_version:'network-probe-receipt-v1',request_id:request.request_id,workspace_id:invalid?'foreign':request.workspace_id,scan_id:request.scan_id,profile:request.profile,started_at:now,finished_at:now,
    collector:{name:'cybermeters-cloudflare-network-probe',version:'1',node_version:'v26.10.0',openssl_version:'synthetic-test',trust_store:{name:'Node.js bundled Mozilla CA roots',sha256:'a'.repeat(64)}},
    limitations:['Synthetic local transport fixture; not a provider receipt.'],quality:state==='timeout'?'partial':'complete',coverage:{planned:2,attempted:2,completed:state==='timeout'?0:2,not_run:0},observations:request.targets.flatMap(t=>request.ports.map(port=>({address:t.address,hostname:null,port,transport:'tcp',state,service:state==='open'?{name:'ssh',basis:'unsolicited_tcp_banner',banner_sha256:'b'.repeat(64),banner_sample:'SSH-2.0-SyntheticFixture'}:null,tls:null,reason:state==='timeout'?'timeout':null})))});
};
const beforeConsumer=snapshot();eq('forged workspace rejected',(await processNetworkScanMessage({...queued[0],workspace_id:'wb'},env,{adapter})).outcome,'identity_mismatch');eq('forged unchanged',snapshot(),beforeConsumer);eq('forged no probe',probeCalls,0);
eq('durable completed',(await processNetworkScanMessage(queued[0],env,{adapter})).outcome,'completed');
eq('2actual tuples persisted',db.prepare('SELECT COUNT(*) n FROM network_assets').get().n,2);
eq('new actual services discovered',JSON.parse(db.prepare('SELECT changes_json FROM network_scans WHERE id=?').get(scanId).changes_json).map(c=>c.type),['discovered','discovered']);
const completed=snapshot(),savedObjects=[...objects];eq('duplicate no execution',(await processNetworkScanMessage(queued[0],env,{adapter})).outcome,'already_claimed');eq('duplicate preserves rows',snapshot(),completed);eq('duplicate preserves receipt',[...objects],savedObjects);eq('one physical collector invocation',probeCalls,1);
const read=await call(`network-scans/${scanId}`);eq('receipt exact authenticated read',read.status,200);eq('receipt linked hash',read.body.scan.receipt_sha256.length,64);
eq('foreign receipt inaccessible',(await call(`network-scans/${scanId}`,{workspace:'wb',user:'other'})).status,404);
const key=db.prepare('SELECT receipt_key FROM network_scans WHERE id=?').get(scanId).receipt_key,original=objects.get(key);objects.set(key,original+' ');eq('receipt drift rejected',(await call(`network-scans/${scanId}`)).status,503);objects.set(key,original);
let retest=await call(`network-scans/${scanId}/retest`,{method:'POST'});eq('retest uses original scope',retest.status,202);eq('retest linkage',retest.body.scan.retest_of,scanId);state='timeout';
eq('timeout run completes partial',(await processNetworkScanMessage(queued.at(-1),env,{adapter})).outcome,'completed');
const timeoutRow=db.prepare('SELECT * FROM network_scans WHERE id=?').get(retest.body.scan.id);
eq('unknown attempt preserves last actual seen',db.prepare('SELECT last_seen_at FROM network_assets ORDER BY port').all().map(r=>r.last_seen_at),JSON.parse(completed)[2].map(r=>r.last_seen_at));/* 22 Oct 2026 (Executive R1): nothing on the address answered, so the no-answers are not conclusive (filtered vs unreachable): partial; no 'closed' change recorded below. */eq('timeout grade honest',timeoutRow.quality,'partial');eq('timeout no closed change',JSON.parse(timeoutRow.changes_json),[]);eq('previous open retained',db.prepare('SELECT last_observed_state FROM network_assets ORDER BY port').all().map(r=>r.last_observed_state),['open','open']);eq('latest timeout visible',db.prepare('SELECT state FROM network_assets ORDER BY port').all().map(r=>r.state),['timeout','timeout']);
retest=await call(`network-scans/${scanId}/retest`,{method:'POST'});state='closed';await processNetworkScanMessage(queued.at(-1),env,{adapter});eq('actual closed observation produces change',JSON.parse(db.prepare('SELECT changes_json FROM network_scans WHERE id=?').get(retest.body.scan.id).changes_json).map(c=>c.type),['closed','closed']);
const inventory=JSON.stringify(db.prepare('SELECT * FROM network_assets ORDER BY port').all());
retest=await call(`network-scans/${scanId}/retest`,{method:'POST'});invalid=true;eq('invalid receipt fails',(await processNetworkScanMessage(queued.at(-1),env,{adapter})).outcome,'failed');invalid=false;eq('invalid receipt no inventory rewrite',JSON.stringify(db.prepare('SELECT * FROM network_assets ORDER BY port').all()),inventory);
retest=await call(`network-scans/${scanId}/retest`,{method:'POST'});r2Failure=true;eq('R2 fault fails',(await processNetworkScanMessage(queued.at(-1),env,{adapter})).outcome,'failed');r2Failure=false;eq('R2 fault inventory unchanged',JSON.stringify(db.prepare('SELECT * FROM network_assets ORDER BY port').all()),inventory);
retest=await call(`network-scans/${scanId}/retest`,{method:'POST'});state='open';batchFailure=true;eq('atomic D1 fault fails',(await processNetworkScanMessage(queued.at(-1),env,{adapter})).outcome,'failed');batchFailure=false;eq('atomic fault rolls back first tuple',JSON.stringify(db.prepare('SELECT * FROM network_assets ORDER BY port').all()),inventory);eq('failed finalization never quality complete',db.prepare('SELECT quality FROM network_scans WHERE id=?').get(retest.body.scan.id).quality,null);
const old={address:'8.8.8.8',port:443,transport:'tcp',last_observed_state:'open',service_json:'null',tls_json:JSON.stringify({leaf_certificate:{certificate_identity:'sha256:same'},observed_at:'old'})};
eq('timestamp change not a service change',networkObservationChanges([old],[{...old,state:'open',service:null,tls:{leaf_certificate:{certificate_identity:'sha256:same'},observed_at:'new'}}]),[]);
retest=await call(`network-scans/${scanId}/retest`,{method:'POST'});db.prepare("UPDATE network_scans SET created_at=datetime('now','-16 minutes') WHERE id=?").run(retest.body.scan.id);await recoverNetworkScans(env);eq('abandoned queue recovered honestly',db.prepare('SELECT status,quality,reason FROM network_scans WHERE id=?').get(retest.body.scan.id),{status:'failed',quality:null,reason:'network_execution_interrupted'});
eq('network runs share monthly count',await countScansThisMonth('owner',env),db.prepare("SELECT COUNT(*) n FROM network_scans WHERE workspace_id='wa'").get().n);
const legacy=new DatabaseSync(':memory:');legacy.exec("CREATE TABLE workspaces(id TEXT,owner_user_id TEXT);CREATE TABLE scans(id TEXT,workspace_id TEXT,created_at TEXT);INSERT INTO workspaces VALUES('w','u');INSERT INTO scans VALUES('s','w','2999-01-01');");
const legacyEnv={cybermeters_db:{prepare:sql=>({bind:(...args)=>({first:async()=>legacy.prepare(sql).get(...args)})})}};
eq('pre109 counts domain usage',await countScansThisMonth('u',legacyEnv),1);
const faultEnv={...env,cybermeters_db:{prepare:sql=>sql.includes('FROM network_scans n')?{bind:()=>({first:async()=>{throw new Error('provider capacity failure');}})}:d1.prepare(sql)}};
await rejects('network quota fault not silently zero',()=>countScansThisMonth('owner',faultEnv));
eq('domain scan quota fails closed on missing measurement',(await checkScanLimit({id:'owner'},'wa',faultEnv)).status,503);
const list=await call('network-assets');eq('inventory list actual count',list.body.total,2);eq('inventory no implicit extra page',list.body.next_cursor,null);
eq('normal domain scans untouched',db.prepare('SELECT COUNT(*) n FROM scans').get().n,0);eq('normal domain inventory untouched',db.prepare("SELECT COUNT(*) n FROM domains WHERE id<>'d_seed'").get().n,0);

// A concurrent workspace deletion must roll back the whole completion transaction.
retest=await call(`network-scans/${scanId}/retest`,{method:'POST'});
const originalFetch=env.NETWORK_PROBE.fetch;
env.NETWORK_PROBE.fetch=async(...args)=>{const response=await originalFetch(...args);db.prepare("UPDATE workspaces SET deleted_at=datetime('now') WHERE id='wa'").run();return response;};
const beforeDeleteInventory=JSON.stringify(db.prepare('SELECT * FROM network_assets ORDER BY port').all()),beforeDeleteObjects=[...objects];
eq('deletion race refuses finalization',(await processNetworkScanMessage(queued.at(-1),env,{adapter})).outcome,'failed');
eq('deletion race preserves inventory',JSON.stringify(db.prepare('SELECT * FROM network_assets ORDER BY port').all()),beforeDeleteInventory);
eq('deleted scope receives no new receipt',[...objects],beforeDeleteObjects);
eq('deleted workspace cannot read',(await call('network-assets')).status,403);
db.prepare("UPDATE workspaces SET deleted_at=NULL WHERE id='wa'").run();env.NETWORK_PROBE.fetch=originalFetch;
// Quota is shared with every admitted network run, including failed attempts.
db.prepare("UPDATE subscriptions SET plan='starter' WHERE id='sub_wa'").run();
const limit=getPlanLimits('starter').scans_per_month,used=await countScansThisMonth('owner',env),timestamp=new Date().toISOString();
for(let n=used;n<limit;n++)db.prepare("INSERT INTO network_scans(id,workspace_id,target_id,requested_by,ports_json,status,receipt_key,created_at) VALUES(?,'wa',?,'owner','[22]','failed',?,?)").run(`quota_${n}`,targetId,`quota/${n}`,timestamp);
const preQuota={rows:snapshot(),queue:queued.length,probes:probeCalls};
const quota=await call(`network-targets/${targetId}/scans`,{method:'POST',body:{ports:[22]}});
eq('shared quota exhausted refuses admission',quota.status,403);eq('quota reports exact used',quota.body.usage,limit);
eq('quota refusal preserves every row',snapshot(),preQuota.rows);eq('quota refusal no queue',queued.length,preQuota.queue);eq('quota refusal no probe',probeCalls,preQuota.probes);

// ── Suggested targets from discovery: read-only, verified-domain, tenant-scoped ──
{
  const ns=await import('../workers/scan-api/src/engines/network-suggestions.js');
  eq('edge range v4 is Cloudflare',ns.publishedEdgeProvider('104.18.1.1'),'Cloudflare');
  eq('edge range v6 is Cloudflare',ns.publishedEdgeProvider('2606:4700::1111'),'Cloudflare');
  eq('ordinary address is not edge',ns.publishedEdgeProvider('93.184.216.40'),null);
  eq('range boundary excluded',ns.publishedEdgeProvider('104.15.255.255'),null);
  eq('IPv6 canonical form',ns.canonicalAddress('2001:4860:4860:0:0:0:0:8888'),'2001:4860:4860::8888');
  const resolved=await ns.resolveHostAddresses(['a.example.com'],{dnsQueryImpl:async(h,t)=>t==='A'?{Answer:[{type:1,data:'93.184.216.50'},{type:5,data:'cname.example.net.'}]}:{Answer:[{type:28,data:'2001:4860:4860::8844'}]}});
  eq('DoH resolution keeps only A/AAAA',resolved.get('a.example.com'),['93.184.216.50','2001:4860:4860::8844']);
  const failedLookup=await ns.resolveHostAddresses(['b.example.com'],{dnsQueryImpl:async()=>{throw new Error('dns down');}});
  eq('failed lookup fabricates no address',failedLookup.get('b.example.com'),[]);
  const many=Array.from({length:30},(_,i)=>({hostname:`h${i}.example.com`,domain:'example.com',status:'active',lifecycle_state:'observed',wildcard_dns:0,ip_addresses:null}));
  many.push({hostname:'vpn.example.com',domain:'example.com',status:'active',lifecycle_state:'observed',wildcard_dns:0,ip_addresses:null});
  const toResolve=ns.hostsNeedingResolution(many);
  eq('resolution budget bounded',toResolve.length,ns.NETWORK_SUGGESTION_LIMITS.resolve_hosts);
  eq('high-value host resolved first',toResolve[0],'vpn.example.com');

  const now=new Date().toISOString();
  db.prepare("INSERT INTO domains(id,user_id,domain) VALUES('d_ok','owner','example.com'),('d_unv','owner','unverified.example'),('d_b','other','other.example')").run();
  db.prepare("INSERT INTO workspace_domains(workspace_id,domain_id,verification_status) VALUES('wa','d_ok','verified'),('wa','d_unv','unverified'),('wb','d_b','verified')").run();
  const asset=db.prepare('INSERT INTO workspace_assets(id,workspace_id,domain_id,hostname,first_seen,last_seen,created_at,updated_at,ip_addresses,cname,wildcard_dns,lifecycle_state,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)');
  for(const [id,ws,dom,host,ips,cname,wild,life,status] of [
    ['a1','wa','d_ok','admin.example.com','["93.184.216.40"]',null,0,'observed','active'],
    ['a2','wa','d_ok','vpn.example.com','["93.184.216.40"]',null,0,'observed','active'],
    ['a3','wa','d_ok','cdn.example.com','["104.18.1.1"]',null,0,'observed','active'],
    ['a4','wa','d_ok','store.example.com','["93.184.216.60"]','shops.myshopify.com',0,'observed','active'],
    ['a5','wa','d_ok','www.example.com','["8.8.8.8"]',null,0,'observed','active'],
    ['a6','wa','d_ok','old.example.com','["93.184.216.70"]',null,0,'confirmed_removed','active'],
    ['a7','wa','d_ok','wild.example.com','["93.184.216.80"]',null,1,'observed','active'],
    ['a8','wa','d_ok','internal.example.com','["10.0.0.5"]',null,0,'observed','active'],
    ['a9','wa','d_ok','ct-only.example.com',null,null,0,'observed','active'],
    ['a10','wa','d_unv','admin.unverified.example','["93.184.216.90"]',null,0,'observed','active'],
    ['a11','wb','d_b','admin.other.example','["93.184.216.99"]',null,0,'observed','active'],
  ])asset.run(id,ws,dom,host,now,now,now,now,ips,cname,wild,life,status);

  const before={rows:snapshot(),queue:queued.length,probes:probeCalls},ratesBefore=rateCalls;
  eq('suggestions unauthenticated',(await call('network-suggestions',{user:null})).status,401);
  eq('suggestions foreign workspace',(await call('network-suggestions',{user:'other'})).status,403);
  const viewer=await call('network-suggestions',{user:'viewer'});eq('viewer may read suggestions',viewer.status,200);
  const got=await call('network-suggestions');eq('suggestions ok',got.status,200);
  const rows=got.body.suggestions||[];
  eq('suggestion addresses and order',rows.map(r=>[r.address,r.recommendation]),[
    ['93.184.216.40','candidate'],['8.8.8.8','covered'],['104.18.1.1','provider_infrastructure'],['93.184.216.60','provider_infrastructure']]);
  eq('one IP groups its hostnames',rows[0].hostnames,['admin.example.com','vpn.example.com']);
  eq('sensitive names flagged',[rows[0].priority,rows[0].high_value_labels],['high',['admin','vpn']]);
  eq('edge evidence named',[rows[2].provider,rows[2].provider_evidence],['Cloudflare','published_edge_range']);
  eq('CNAME evidence named',[rows[3].provider,rows[3].provider_evidence],['Shopify','dns_cname']);
  eq('coverage counts',got.body.coverage,{likely_own_servers:2,covered:1,shared_infrastructure:2});
  const listed=new Set(rows.flatMap(r=>r.hostnames));
  ok('removed, wildcard, private, unresolved, unverified and foreign hosts excluded',
    ['old.example.com','wild.example.com','internal.example.com','ct-only.example.com','admin.unverified.example','admin.other.example'].every(h=>!listed.has(h)));
  eq('suggestions create no target, scan, queue job or probe',{rows:snapshot(),queue:queued.length,probes:probeCalls},before);
  ok('suggestions are rate limited',rateCalls>ratesBefore);
  rateFailure=true;eq('rate limit refusal',(await call('network-suggestions')).status,503);rateFailure=false;
  const routeSrc=fs.readFileSync(path.join(root,'workers/scan-api/src/routes/network-assets.js'),'utf8');
  const slice=routeSrc.slice(routeSrc.indexOf("resource==='network-suggestions'"),routeSrc.indexOf("if(request.method==='POST'&&resource==='network-targets'&&!id)"));
  ok('suggestion route never writes',slice.length>200&&!/\b(INSERT|UPDATE|DELETE)\b/.test(slice)&&!/SCAN_QUEUE|NETWORK_PROBE/.test(slice));
}

// ── Ownership: only addresses observed in this workspace's verified DNS ──────
{
  // The quota test above exhausted the starter plan; restore headroom.
  db.prepare("UPDATE subscriptions SET plan='professional' WHERE id='sub_wa'").run();
  db.prepare("DELETE FROM network_scans WHERE id LIKE 'quota_%'").run();
  const declare=(target,args={})=>call('network-targets',{method:'POST',user:'admin',body:{target,authorization_confirmed:true},...args});
  // An address no verified domain of this workspace points at: attestation alone is refused.
  const unverified=await declare('9.9.9.9');
  eq('unobserved address refused despite the attestation',[unverified.status,unverified.body.error,unverified.body.scope?.reason],[422,'network_target_not_observed','address_not_observed_in_verified_dns']);
  ok('the refusal says what to do',/verified/.test(unverified.body.scope?.message||'')&&unverified.body.scope.unobserved.includes('9.9.9.9'));
  // Another workspace's verified domain points at 93.184.216.99; it authorises nothing here.
  eq('a foreign workspace\'s verified domain does not authorise an address',(await declare('93.184.216.99')).status,422);
  // An unverified domain of this workspace points at 93.184.216.90.
  eq('this workspace\'s unverified domain does not authorise an address',(await declare('93.184.216.90')).status,422);
  // ...even when another workspace has verified that same domain.
  db.prepare("INSERT INTO workspace_domains(workspace_id,domain_id,verification_status) VALUES('wb','d_unv','verified')").run();
  eq('another workspace verifying the same domain authorises nothing here',(await declare('93.184.216.90')).status,422);
  // A CDN edge address is observed but belongs to the provider.
  const edge=await declare('104.18.1.1');
  eq('shared provider infrastructure refused',[edge.status,edge.body.scope?.reason],[422,'address_is_shared_provider_infrastructure']);
  // A host discovered under the verified domain: allowed.
  const own=await declare('93.184.216.40');
  eq('an address of a host under a verified domain is accepted',[own.status,own.body.target?.scope?.state],[201,'in_scope']);
  ok('the stored evidence names the observing hosts',JSON.parse(db.prepare("SELECT scope_evidence_json j FROM network_targets WHERE id=?").get(own.body.target.id).j).evidence['93.184.216.40'].includes('admin.example.com'));
  // A range is in scope only if every address in it is observed.
  eq('a range with unobserved addresses refused',(await declare('93.184.216.40/31')).status,422);

  // DNS moved: the scan request checks again and stops; history is kept.
  const ownId=own.body.target.id;
  db.prepare("UPDATE workspace_assets SET status='inactive' WHERE id IN ('a1','a2')").run();
  const scansBefore=db.prepare('SELECT COUNT(*) n FROM network_scans').get().n,queuedBefore=queued.length;
  const moved=await call(`network-targets/${ownId}/scans`,{user:'analyst',method:'POST',body:{ports:[443]}});
  eq('a target whose address left verified DNS is not scanned',[moved.status,moved.body.error],[409,'network_target_out_of_scope']);
  eq('...nothing is queued or admitted',[db.prepare('SELECT COUNT(*) n FROM network_scans').get().n,queued.length],[scansBefore,queuedBefore]);
  ok('...the target and its history stay',!!db.prepare('SELECT 1 FROM network_targets WHERE id=?').get(ownId));
  const listed=(await call('network-targets')).body.targets.find(t=>t.id===ownId);
  eq('...and the customer sees why',[listed.scope.state,listed.scope.reason],['out_of_scope','address_not_observed_in_verified_dns']);
  ok('...in plain words',/Not scanned/.test(listed.scope.message||''));
  // A retest of an earlier scan of that target is refused the same way.
  const earlier=db.prepare("SELECT id FROM network_scans WHERE target_id=? LIMIT 1").get(targetId);
  db.prepare("UPDATE workspace_assets SET status='inactive' WHERE id='seed1'").run();db.prepare("UPDATE workspace_assets SET ip_addresses='[]' WHERE id='a5'").run();
  if(earlier)eq('a retest after DNS moved is refused',(await call(`network-scans/${earlier.id}/retest`,{method:'POST'})).status,409);
  db.prepare("UPDATE workspace_assets SET status='active' WHERE id IN ('a1','a2','seed1')").run();db.prepare("UPDATE workspace_assets SET ip_addresses='[\"8.8.8.8\"]' WHERE id='a5'").run();
  // A target from before this rule (never checked) is checked when listed.
  db.prepare("UPDATE network_targets SET scope_state=NULL,scope_reason=NULL,scope_checked_at=NULL WHERE id=?").run(targetId);
  eq('an unchecked older target is checked when listed',(await call('network-targets')).body.targets.find(t=>t.id===targetId).scope.state,'in_scope');

  // The queue consumer refuses a scan whose stored decision is out of scope or stale.
  const {processNetworkScanMessage}=await import('../workers/scan-api/src/engines/network-scan-dispatch.js');
  db.prepare("UPDATE network_scans SET status='completed' WHERE status IN ('queued','running')").run();
  const fresh=await call(`network-targets/${ownId}/scans`,{user:'analyst',method:'POST',body:{ports:[443]}});
  eq('back in verified DNS, the target scans again',[fresh.status,fresh.body.error],[202,undefined]);
  db.prepare("UPDATE network_targets SET scope_state='out_of_scope' WHERE id=?").run(ownId);
  const probesBefore=probeCalls;
  const refused=await processNetworkScanMessage(queued.at(-1),env,{adapter:{collectNetworkProbe:async()=>{probeCalls++;throw new Error('must not probe');},validateNetworkProbeReceipt:()=>({ok:true})}});
  eq('dispatch refuses an out-of-scope target without probing',[refused.outcome,probeCalls-probesBefore,db.prepare('SELECT status,reason FROM network_scans WHERE id=?').get(fresh.body.scan.id)],['out_of_scope',0,{status:'failed',reason:'network_target_out_of_scope'}]);
  db.prepare("UPDATE network_targets SET scope_state='in_scope',scope_checked_at='2026-01-01T00:00:00.000Z' WHERE id=?").run(ownId);
  db.prepare("UPDATE network_scans SET status='queued',reason=NULL,completed_at=NULL WHERE id=?").run(fresh.body.scan.id);
  eq('dispatch refuses a stale decision',(await processNetworkScanMessage(queued.at(-1),env,{adapter:{collectNetworkProbe:async()=>{probeCalls++;throw new Error('must not probe');},validateNetworkProbeReceipt:()=>({ok:true})}})).outcome,'out_of_scope');
}

// ── Active Checks consent (mig 135): append-only grants, the isAuthorised gate ──
{
  const {activeCheckConsentRoutes}=await import('../workers/scan-api/src/routes/active-check-consents.js');
  const {isAuthorised,ACTIVE_CHECK_AUTHORITY_VERSION,ACTIVE_CHECK_AUTHORITY_TEXT}=await import('../workers/scan-api/src/engines/active-check-consent.js');
  async function consent(path='',{user='owner',workspace='wa',method='GET',body,token={}}={}){
    const url=new URL(`https://unit.test/api/workspaces/${workspace}/active-check-consents${path}`);
    const request=new Request(url,{method,...(method!=='GET'?{body:JSON.stringify(body??{}),headers:{'Content-Type':'application/json','CF-Connecting-IP':'203.0.113.9'}}:{})});
    const response=await activeCheckConsentRoutes({request,url,env,requireAuth:async()=>user?{id:user,email:`${user}@example.test`,...token}:null,requireWorkspaceRole,json:(b,s=200)=>Response.json(b,{status:s}),serverError:e=>Response.json({error:'server',detail:String(e?.message||e)},{status:500})});
    return {status:response.status,body:await response.json()};
  }
  db.prepare("INSERT INTO domains(id,user_id,domain) VALUES('d_other','other','other.example')").run();
  db.prepare("INSERT INTO workspace_domains(workspace_id,domain_id,verification_status) VALUES('wb','d_other','verified')").run();
  const grant={domain_id:'d_seed',hosts:[],checks:['takeover_active_confirm','mail_spoof_resistance'],signer_name:'Pat Owner',signer_title:'IT Manager',authority_confirmed:true,authority_version:ACTIVE_CHECK_AUTHORITY_VERSION};
  const rows=()=>db.prepare('SELECT * FROM active_check_consents ORDER BY rowid').all();
  const ask=(q)=>isAuthorised(env,{workspaceId:'wa',domain:'seed.example',...q});

  eq('consent: nothing granted → no_grant',(await ask({check:'takeover_active_confirm'})).reason,'no_grant');
  for(const [name,args,status] of [
    ['unauthenticated',{user:null},401],['foreign workspace user',{user:'other'},403],['viewer',{user:'viewer'},403],['analyst',{user:'analyst'},403],
    ['read token',{token:{token_scope:'read',token_workspace_id:'wa'}},403],
    ['no authority confirmation',{body:{...grant,authority_confirmed:false}},400],['stale authority version',{body:{...grant,authority_version:'old'}},400],
    ['unknown check',{body:{...grant,checks:['port_scan']}},400],['empty checks',{body:{...grant,checks:[]}},400],
    ['host outside the domain',{body:{...grant,hosts:['evil.example']}},400],['wildcard host',{body:{...grant,hosts:['*.seed.example']}},400],
    ['another workspace domain is not found',{body:{...grant,domain_id:'d_other'}},404],['unknown field',{body:{...grant,schedule:'daily'}},400],
    ['no signer',{body:{...grant,signer_name:' '}},400],
  ])eq(`consent POST refused: ${name}`,(await consent('',{method:'POST',body:grant,...args})).status,status);
  eq('consent: refused requests wrote nothing',rows().length,0);
  eq('consent: a viewer can read',(await consent('',{user:'viewer'})).status,200);

  const created=await consent('',{method:'POST',body:grant,user:'admin'});
  eq('consent: an admin grants',created.status,201);
  const g=rows()[0];
  eq('consent: the grant records who, when, where, what and the words agreed',
    [g.kind,g.actor_user_id,g.actor_workspace_role,g.signer_name,g.signer_title,g.ip_address,g.domain,JSON.parse(g.hosts_json),JSON.parse(g.checks_json),g.authority_version,g.authority_text===ACTIVE_CHECK_AUTHORITY_TEXT,Boolean(Date.parse(g.created_at))],
    ['grant','admin','admin','Pat Owner','IT Manager','203.0.113.9','seed.example',[],['takeover_active_confirm','mail_spoof_resistance'],ACTIVE_CHECK_AUTHORITY_VERSION,true,true]);
  eq('consent: the grant is audited',db.prepare("SELECT COUNT(*) n FROM audit_events WHERE event_type='active_check_consent_granted' AND entity_id=?").get(g.id).n,1);
  eq('consent: listed with its status',(await consent()).body.consents.map(c=>[c.id,c.status]),[[g.id,'active']]);
  const ownerView=(await consent()).body.consents[0],viewerView=(await consent('',{user:'viewer'})).body.consents[0];
  ok('consent: the receipt carries the exact statement agreed',ownerView.authority_text===ACTIVE_CHECK_AUTHORITY_TEXT&&viewerView.authority_text===ACTIVE_CHECK_AUTHORITY_TEXT);
  eq('consent: the signer IP is shown to those who manage the workspace',ownerView.signer.ip_address,'203.0.113.9');
  ok('consent: ...and never to a viewer',!('ip_address' in viewerView.signer)&&!JSON.stringify((await consent('',{user:'viewer'})).body).includes('203.0.113.9'));
  eq('consent: the other workspace sees none of it',(await consent('',{user:'other',workspace:'wb'})).body.consents.length,0);

  const yes=await ask({check:'takeover_active_confirm'});
  eq('isAuthorised: a granted check on the apex',[yes.authorised,yes.reason,yes.consent_id],[true,'authorised',g.id]);
  eq('isAuthorised: returns the exact scope that was authorised',[yes.scope.checks,yes.scope.hosts,yes.scope.granted_at,yes.scope.signer.name,yes.scope.signer.workspace_role],
    [['takeover_active_confirm','mail_spoof_resistance'],[],g.created_at,'Pat Owner','admin']);
  eq('isAuthorised: a check not in the grant',(await ask({check:'dns_open_resolver',address:'8.8.8.8'})).reason,'check_not_in_grant');
  eq('isAuthorised: an unknown check is never authorised',(await ask({check:'anything'})).reason,'check_not_in_grant');
  eq('isAuthorised: an empty host list is the apex only',(await ask({host:'mail.seed.example',check:'takeover_active_confirm'})).reason,'host_not_in_grant');
  eq('isAuthorised: a host outside the domain',(await ask({host:'seed.example.evil.test',check:'takeover_active_confirm'})).reason,'host_not_in_grant');
  eq('isAuthorised: another workspace cannot use this grant',(await isAuthorised(env,{workspaceId:'wb',domain:'seed.example',check:'takeover_active_confirm'})).reason,'domain_not_verified');

  // A per-address check: the #765 rule decides the address.
  const relay=await consent('',{method:'POST',body:{...grant,hosts:['mail.seed.example'],checks:['mail_open_relay']}});
  eq('consent: a host-scoped grant',relay.status,201);
  eq('isAuthorised: per-address check on an address seen in verified DNS',(await ask({host:'mail.seed.example',check:'mail_open_relay',address:'8.8.8.8'})).authorised,true);
  eq('isAuthorised: an address not seen in verified DNS',(await ask({host:'mail.seed.example',check:'mail_open_relay',address:'9.9.9.9'})).reason,'address_out_of_scope');
  eq('isAuthorised: a per-address check without an address',(await ask({host:'mail.seed.example',check:'mail_open_relay'})).reason,'address_out_of_scope');

  // Revocation appends; the grant row is never touched.
  const before=JSON.stringify(rows()[0]);
  eq('consent: another workspace cannot revoke it (same 404 as unknown)',(await consent(`/${g.id}/revoke`,{method:'POST',user:'other',workspace:'wb'})).status,404);
  eq('consent: an unknown id is the same 404',(await consent('/acc_nope/revoke',{method:'POST'})).status,404);
  eq('consent: an analyst cannot revoke',(await consent(`/${g.id}/revoke`,{method:'POST',user:'analyst'})).status,403);
  eq('consent: a reason longer than 240 characters is refused',(await consent(`/${g.id}/revoke`,{method:'POST',body:{reason:'x'.repeat(241)}})).status,400);
  eq('consent: an unknown revoke field is refused',(await consent(`/${g.id}/revoke`,{method:'POST',body:{reason:'ok',when:'now'}})).status,400);
  const revoked=await consent(`/${g.id}/revoke`,{method:'POST',body:{reason:'  Contract with the hosting company ended  '}});
  eq('consent: the owner revokes, with a reason',[revoked.status,revoked.body.consent?.status,revoked.body.consent?.revocation_reason],[200,'revoked','Contract with the hosting company ended']);
  eq('consent: the reason is written once, on the revocation row',db.prepare("SELECT revocation_reason r FROM active_check_consents WHERE kind='revocation' AND grant_id=?").get(g.id).r,'Contract with the hosting company ended');
  eq('consent: a second revocation is refused',(await consent(`/${g.id}/revoke`,{method:'POST'})).status,409);
  eq('consent: revoking added one row and left the grant unchanged',[rows().length,JSON.stringify(rows()[0]),rows().at(-1).kind,rows().at(-1).grant_id],[3,before,'revocation',g.id]);
  eq('isAuthorised: a revoked grant',(await ask({check:'takeover_active_confirm'})).reason,'grant_revoked');
  eq('isAuthorised: the other live grant is unaffected',(await ask({host:'mail.seed.example',check:'mail_open_relay',address:'8.8.8.8'})).authorised,true);
  eq('consent: listed as revoked',(await consent()).body.consents.find(c=>c.id===g.id).status,'revoked');
  eq('consent: the list returns the revocation reason',(await consent()).body.consents.find(c=>c.id===g.id).revocation_reason,'Contract with the hosting company ended');
  const projected=(await consent()).body.consents.find(c=>c.id===g.id);
  ok('consent: the customer API carries no raw internal user id',projected.signer.user_id===undefined&&projected.revoked_by===undefined&&!JSON.stringify((await consent()).body).includes('"user_id"'));

  // Storage is bounded: at most 100 grants per workspace per 24 h, enforced in the insert itself.
  const fill=db.prepare(`INSERT INTO active_check_consents(id,workspace_id,kind,domain_id,domain,hosts_json,checks_json,actor_user_id,actor_workspace_role,
    signer_name,signer_title,authority_text,authority_version,created_at) VALUES(?,'wa','grant','d_seed','seed.example','[]','["takeover_active_confirm"]','owner','owner','P','T','t','v',?)`);
  const already=db.prepare("SELECT COUNT(*) n FROM active_check_consents WHERE workspace_id='wa' AND kind='grant'").get().n;
  for(let i=already;i<100;i++)fill.run(`acc_fill_${i}`,new Date().toISOString());
  const capped=await consent('',{method:'POST',body:grant});
  eq('consent: the 101st grant in 24 h is refused',[capped.status,capped.body.error],[429,'active_check_consent_limit']);
  eq('consent: ...and writes nothing',db.prepare("SELECT COUNT(*) n FROM active_check_consents WHERE workspace_id='wa' AND kind='grant'").get().n,100);
  db.prepare("DROP TRIGGER trg_active_check_consents_no_update").run();
  db.prepare("UPDATE active_check_consents SET created_at='2026-01-01T00:00:00.000Z' WHERE id LIKE 'acc_fill_%'").run();
  db.exec(fs.readFileSync(path.join(root,'database/migrations/135-active-check-consents.sql'),'utf8'));
  eq('consent: older grants do not count against the day',(await consent('',{method:'POST',body:grant})).status,201);
  db.prepare("DROP TRIGGER trg_active_check_consents_no_update").run();
  db.prepare("DELETE FROM active_check_consents WHERE id LIKE 'acc_fill_%' OR id=(SELECT id FROM active_check_consents WHERE kind='grant' ORDER BY rowid DESC LIMIT 1)").run();
  db.exec(fs.readFileSync(path.join(root,'database/migrations/135-active-check-consents.sql'),'utf8'));

  // Immutable in the database itself, not only in the route.
  await rejects('consent rows cannot be updated',async()=>db.prepare("UPDATE active_check_consents SET checks_json='[\"tls_robot\"]' WHERE id=?").run(g.id));
  await rejects('a revocation cannot name another workspace grant',async()=>db.prepare("INSERT INTO active_check_consents(id,workspace_id,kind,grant_id,actor_user_id,actor_workspace_role,created_at) VALUES('acc_x','wb','revocation',?,'other','owner','2026-10-22')").run(rows()[1].id));

  // Fail closed.
  readFailure=true;
  eq('isAuthorised: a read error is consent_read_failed, never a pass',(await ask({host:'mail.seed.example',check:'mail_open_relay',address:'8.8.8.8'})),{authorised:false,reason:'consent_read_failed',consent_id:null,scope:null});
  readFailure=false;
  db.prepare("UPDATE workspaces SET deleted_at='2026-10-22' WHERE id='wa'").run();
  eq('isAuthorised: a soft-deleted workspace',(await ask({host:'mail.seed.example',check:'mail_open_relay',address:'8.8.8.8'})).reason,'workspace_deleted');
  const deletedRows=rows().length;
  const deletedPost=await consent('',{method:'POST',body:grant});
  ok('consent: a soft-deleted workspace takes no new grant',deletedPost.status>=400&&rows().length===deletedRows);
  db.prepare("UPDATE workspaces SET deleted_at=NULL WHERE id='wa'").run();
  db.prepare("UPDATE workspace_domains SET verification_status='pending' WHERE workspace_id='wa' AND domain_id='d_seed'").run();
  eq('isAuthorised: a domain no longer verified',(await ask({host:'mail.seed.example',check:'mail_open_relay',address:'8.8.8.8'})).reason,'domain_not_verified');
  db.prepare("UPDATE workspace_domains SET verification_status='verified' WHERE workspace_id='wa' AND domain_id='d_seed'").run();
}

// A port that did not answer is an observation, not an unfinished check
// (22 Oct 2026, S3-0 live proof on the probe VM: 22 open + 80/443/3389 no
// answer read "Partial coverage"). Only error / not_run leave coverage partial.
{
  const o=(port,state)=>({address:'35.224.199.137',port,state});
  const proof=networkReceiptCoverage({coverage:{planned:4,attempted:4,completed:1},observations:[o(22,'open'),o(80,'timeout'),o(443,'timeout'),o(3389,'timeout')]});
  ok('one open + three no-answer ports is complete coverage',proof.quality==='complete'&&proof.coverage.concluded===4&&proof.coverage.no_answer===3);
  ok('the receipt\'s own counts are kept beside the projection',proof.coverage.completed===1&&proof.coverage.planned===4);
  ok('a measurement error leaves coverage partial',networkReceiptCoverage({coverage:{planned:2},observations:[o(22,'open'),o(80,'error')]}).quality==='partial');
  ok('a pair that never ran leaves coverage partial',networkReceiptCoverage({coverage:{planned:2},observations:[o(22,'open'),o(80,'not_run')]}).quality==='partial');
  // Nothing on the address answered: filtered vs unreachable cannot be told.
  const silent=networkReceiptCoverage({coverage:{planned:2},observations:[o(22,'timeout'),o(443,'timeout')]});
  ok('nothing on an address answered: partial, address_unreachable, no conclusive no-answer',
    silent.quality==='partial'&&silent.coverage.reason==='address_unreachable'&&silent.coverage.unreachable_addresses?.[0]==='35.224.199.137'&&silent.coverage.no_answer===0);
  const mixed=networkReceiptCoverage({coverage:{planned:3},observations:[o(22,'open'),o(80,'timeout'),{address:'35.224.199.138',port:22,state:'timeout'}]});
  ok('one answering address and one silent address: partial, only the silent one listed',
    mixed.quality==='partial'&&JSON.stringify(mixed.coverage.unreachable_addresses)==='["35.224.199.138"]'&&mixed.coverage.no_answer===1);
  // Mutant: no-answer no longer concluded -> the false "partial" returns.
  const file=new URL('../workers/scan-api/src/engines/network-scan-dispatch.js',import.meta.url);
  const source=fs.readFileSync(file,'utf8');
  const anchor="o?.state==='timeout'&&answered.has(o.address)";
  ok('no-answer mutant anchor present once',source.split(anchor).length===2);
  const dir=fs.mkdtempSync(path.join((await import('node:os')).tmpdir(),'cm-no-answer-'));
  try{
    const target=path.join(dir,'network-scan-dispatch-mutant.mjs');
    fs.writeFileSync(target,source.replace(anchor,"false").replace(/from '(\.{1,2}\/[^']+)'/g,(_m,spec)=>`from '${new URL(spec,file)}'`));
    const mutant=await import(`file://${target}`);
    ok('mutant (no-answer not concluded) is caught: the proof reads partial again',
      mutant.networkReceiptCoverage({coverage:{planned:4},observations:[o(22,'open'),o(80,'timeout'),o(443,'timeout'),o(3389,'timeout')]}).quality==='partial');
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
}

// ── Declared network range consent (mig 138): an unobserved address only under a scoped grant ──
{
  const {NETWORK_RANGE_AUTHORITY_VERSION,NETWORK_RANGE_AUTHORITY_TEXT,liveRangeGrant}=await import('../workers/scan-api/src/engines/network-range-consent.js');
  db.prepare("UPDATE network_scans SET status='completed' WHERE status IN ('queued','running')").run();
  const consentBody={ports:[22,443],signer_name:'Pat Owner',signer_title:'IT Manager',authority_confirmed:true,authority_version:NETWORK_RANGE_AUTHORITY_VERSION};
  const declare=(extra={},args={})=>call('network-targets',{method:'POST',user:'admin',body:{target:'9.9.9.9',authorization_confirmed:true,...extra},...args});
  const grants=()=>db.prepare('SELECT * FROM network_range_consents ORDER BY rowid').all();
  const targetFor=t=>db.prepare('SELECT * FROM network_targets WHERE workspace_id=? AND target=?').get('wa',t);

  const plain=await declare();
  eq('range: an unobserved address without consent is refused and asks for one',[plain.status,plain.body.range_consent],[422,'required']);
  for(const [name,extra,args,status] of [
    ['analyst',{range_consent:consentBody},{user:'analyst'},403],
    ['authority not confirmed',{range_consent:{...consentBody,authority_confirmed:false}},{},400],
    ['stale authority version',{range_consent:{...consentBody,authority_version:'old'}},{},400],
    ['no signer',{range_consent:{...consentBody,signer_name:' '}},{},400],
    ['unknown consent field',{range_consent:{...consentBody,checks:['dns_open_resolver']}},{},400],
    ['a port outside the catalogue',{range_consent:{...consentBody,ports:[65535]}},{},400],
    ['no ports',{range_consent:{...consentBody,ports:[]}},{},400],
  ])eq(`range: refused — ${name}`,(await declare(extra,args)).status,status);
  eq('range: refused requests wrote no grant and no target',[grants().length,!!targetFor('9.9.9.9')],[0,false]);
  const edge=await declare({target:'104.18.1.1',range_consent:consentBody});
  eq('range: shared provider infrastructure is never grantable',[edge.status,edge.body.range_consent,grants().length],[422,'not_grantable_shared',0]);

  const made=await declare({range_consent:consentBody});
  eq('range: a declared address with consent is accepted',made.status,201);
  const t=made.body.target;
  eq('range: the scope stays what DNS says',t.scope.state,'out_of_scope');
  eq('range: the grant is exact and honest',[t.range_consent?.status,t.range_consent?.addresses,t.range_consent?.ports,t.range_consent?.independently_verified],['active',['9.9.9.9'],[22,443],false]);
  ok('range: the customer wording says it is not independently verified',/not independently verified/.test(t.range_consent?.declaration||''));
  const row=grants()[0];
  eq('range: the stored record names signer, role, account and the verbatim text',[row.signer_name,row.signer_title,row.actor_user_id,row.actor_workspace_role,row.authority_text,row.authority_version],['Pat Owner','IT Manager','admin','admin',NETWORK_RANGE_AUTHORITY_TEXT,NETWORK_RANGE_AUTHORITY_VERSION]);
  ok('range: the grant is audited',!!db.prepare("SELECT 1 FROM audit_events WHERE event_type='network_range_consent_granted' AND entity_id=?").get(row.id));
  await rejects('range: grant rows are immutable (SQL trigger)',async()=>db.prepare("UPDATE network_range_consents SET ports_json='[1]' WHERE id=?").run(row.id));
  const viewerList=(await call('network-targets',{user:'viewer'})).body.targets.find(x=>x.id===t.id);
  ok('range: a viewer sees the grant but not the signer IP',viewerList.range_consent?.status==='active'&&!('ip_address' in viewerList.range_consent.signer));

  // Scan admission under the grant.
  const scan=await call(`network-targets/${t.id}/scans`,{user:'analyst',method:'POST',body:{ports:[443]}});
  eq('range: a scan within the granted ports is admitted under the grant',[scan.status,scan.body.scan?.authorised_by,scan.body.scan?.range_consent_id],[202,'declared_range_consent',row.id]);
  db.prepare("UPDATE network_scans SET status='completed' WHERE id=?").run(scan.body.scan.id);
  const extraPort=await call(`network-targets/${t.id}/scans`,{user:'analyst',method:'POST',body:{ports:[80]}});
  eq('range: a port the grant does not name is refused',[extraPort.status,extraPort.body.range_consent],[409,'ports_not_covered']);

  // Dispatch: the claim passes on a live grant and stops on a revoked one.
  const probing={collectNetworkProbe:async()=>{probeCalls++;throw new Error('probe reached');},validateNetworkProbeReceipt:()=>({ok:true})};
  const live=await call(`network-targets/${t.id}/scans`,{user:'analyst',method:'POST',body:{ports:[22]}});
  const before=probeCalls;
  await processNetworkScanMessage(queued.at(-1),env,{adapter:probing});
  eq('range: dispatch claims and probes under a live grant',probeCalls-before,1);
  db.prepare("UPDATE network_scans SET status='completed' WHERE id=?").run(live.body.scan.id);
  const pending=await call(`network-targets/${t.id}/scans`,{user:'analyst',method:'POST',body:{ports:[22]}});
  eq('range: queued before the revocation',pending.status,202);

  // Revocation.
  eq('range: a foreign workspace cannot revoke (same 404)',(await call(`network-range-consents/${row.id}/revoke`,{user:'other',workspace:'wb',method:'POST'})).status,404);
  eq('range: a viewer cannot revoke',(await call(`network-range-consents/${row.id}/revoke`,{user:'viewer',method:'POST'})).status,403);
  eq('range: an unknown id is the same 404',(await call('network-range-consents/nrc_missing/revoke',{user:'admin',method:'POST'})).status,404);
  const revoked=await call(`network-range-consents/${row.id}/revoke`,{user:'admin',method:'POST',body:{reason:'contract ended'}});
  eq('range: an admin revokes with a reason',[revoked.status,revoked.body.consent?.status,revoked.body.consent?.revocation_reason],[200,'revoked','contract ended']);
  eq('range: a second revocation is refused',(await call(`network-range-consents/${row.id}/revoke`,{user:'admin',method:'POST'})).status,409);
  const stopped=probeCalls;
  const outcome=await processNetworkScanMessage(queued.at(-1),env,{adapter:probing});
  eq('range: a scan queued before the revocation is failed at dispatch, never probed',[outcome.outcome,probeCalls-stopped,db.prepare('SELECT status,reason FROM network_scans WHERE id=?').get(pending.body.scan.id)],['range_consent_revoked',0,{status:'failed',reason:'network_range_consent_revoked'}]);
  const after=await call(`network-targets/${t.id}/scans`,{user:'analyst',method:'POST',body:{ports:[443]}});
  eq('range: after revocation no new scan is admitted',[after.status,after.body.range_consent],[409,'required']);
  const history=(await call('network-range-consents',{user:'viewer'})).body.consents;
  eq('range: the revoked grant stays in the history',history.map(c=>[c.id,c.status]),[[row.id,'revoked']]);

  // A fresh grant for the existing target restores scanning; tenants stay apart.
  eq('range: another workspace cannot grant on this target (same 404)',(await call(`network-targets/${t.id}/range-consents`,{user:'other',workspace:'wb',method:'POST',body:consentBody})).status,404);
  eq('range: an analyst cannot grant',(await call(`network-targets/${t.id}/range-consents`,{user:'analyst',method:'POST',body:consentBody})).status,403);
  const regrant=await call(`network-targets/${t.id}/range-consents`,{user:'admin',method:'POST',body:{...consentBody,ports:[443]}});
  eq('range: a new grant on the existing target',[regrant.status,regrant.body.consent?.ports],[201,[443]]);
  eq('range: scanning resumes within the new grant',(await call(`network-targets/${t.id}/scans`,{user:'analyst',method:'POST',body:{ports:[443]}})).status,202);
  db.prepare("UPDATE network_scans SET status='completed' WHERE status IN ('queued','running')").run();
  // A grant covers the addresses it was signed for, never a changed list.
  eq('range: a grant does not cover a different address list',await liveRangeGrant(env.cybermeters_db,'wa',{...targetFor('9.9.9.9'),addresses_json:'["9.9.9.10"]'}),null);
  // A soft-deleted workspace takes no new grant.
  db.prepare("UPDATE workspaces SET deleted_at=datetime('now') WHERE id='wa'").run();
  const count=grants().length;
  const deleted=await call(`network-targets/${t.id}/range-consents`,{user:'admin',method:'POST',body:consentBody});
  ok('range: a soft-deleted workspace takes no new grant',deleted.status>=400&&grants().length===count);
  db.prepare("UPDATE workspaces SET deleted_at=NULL WHERE id='wa'").run();
  // The recorded role is the signer's real one, never a default (Executive 21:40).
  const lastGrant=()=>db.prepare("SELECT actor_workspace_role r FROM network_range_consents WHERE kind='grant' ORDER BY rowid DESC LIMIT 1").get().r;
  eq('range: an owner grant records owner',[(await call(`network-targets/${t.id}/range-consents`,{user:'owner',method:'POST',body:consentBody})).status,lastGrant()],[201,'owner']);
  db.prepare("DELETE FROM workspace_members WHERE workspace_id='wa' AND user_id='owner'").run();
  eq('range: the workspace owner with no membership row records owner',[(await call(`network-targets/${t.id}/range-consents`,{user:'owner',method:'POST',body:consentBody})).status,lastGrant()],[201,'owner']);
  db.prepare("INSERT INTO workspace_members(workspace_id,user_id,role) VALUES('wa','owner','owner')").run();
  // A caller the role check lets through but who holds no membership and is not
  // the owner: refused, nothing written (never recorded as 'admin').
  {
    const url=new URL(`https://unit.test/api/workspaces/wa/network-targets/${t.id}/range-consents`);
    const request=new Request(url,{method:'POST',body:JSON.stringify(consentBody),headers:{'Content-Type':'application/json'}});
    const before=grants().length;
    const response=await networkAssetRoutes({request,url,env,requireAuth:async()=>({id:'other'}),requireWorkspaceRole:async()=>true,consumeApiRateLimit:async()=>null,json:(b,s=200)=>Response.json(b,{status:s}),serverError:()=>Response.json({error:'server_error'},{status:500})});
    eq('range: no membership and not the owner is refused, nothing written',[response.status,grants().length],[403,before]);
  }
  ok('range: the workspace purge erases the consent table',/"network_range_consents",\s*\n?\s*"network_assets"/.test(fs.readFileSync(path.join(root,'workers/scan-api/src/index.js'),'utf8').replace(/\/\/[^\n]*\n/g,'')));
}

console.log(`\nNetwork assets: ${passed} passed, ${failed} failed`);if(failed)process.exit(1);
