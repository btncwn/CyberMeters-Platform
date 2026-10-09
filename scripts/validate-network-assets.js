#!/usr/bin/env node
// Real route/RBAC, D1 transaction and queue-consumer controls, no external I/O.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { networkAssetRoutes } from '../workers/scan-api/src/routes/network-assets.js';
import { normalizeNetworkTarget, normalizeNetworkPorts } from '../workers/scan-api/src/engines/network-targets.js';
import { processNetworkScanMessage, networkObservationChanges, recoverNetworkScans } from '../workers/scan-api/src/engines/network-scan-dispatch.js';
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
  if(name==='109-network-assets.sql')continue;
  try{db.exec(fs.readFileSync(path.join(root,'database/migrations',name),'utf8'));}catch{/* Existing additive migration harness, already-added columns tolerated. */}
}
db.exec(fs.readFileSync(path.join(root,'database/migrations/109-network-assets.sql'),'utf8'));
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
  probeCalls++;const request=JSON.parse(options.body),now=new Date().toISOString();
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
eq('unknown attempt preserves last actual seen',db.prepare('SELECT last_seen_at FROM network_assets ORDER BY port').all().map(r=>r.last_seen_at),JSON.parse(completed)[2].map(r=>r.last_seen_at));eq('timeout grade honest',timeoutRow.quality,'partial');eq('timeout no closed change',JSON.parse(timeoutRow.changes_json),[]);eq('previous open retained',db.prepare('SELECT last_observed_state FROM network_assets ORDER BY port').all().map(r=>r.last_observed_state),['open','open']);eq('latest timeout visible',db.prepare('SELECT state FROM network_assets ORDER BY port').all().map(r=>r.state),['timeout','timeout']);
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
eq('normal domain scans untouched',db.prepare('SELECT COUNT(*) n FROM scans').get().n,0);eq('normal domain inventory untouched',db.prepare('SELECT COUNT(*) n FROM domains').get().n,0);

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

console.log(`\nNetwork assets: ${passed} passed, ${failed} failed`);if(failed)process.exit(1);
