#!/usr/bin/env node
// Actual production queue/cron/purge entry points, real schema and enforced FKs.
// All targets and receipts below are synthetic; external transport is disabled.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { splitStatements, isToleratedStatement } from './lib/migration-apply-tolerated.js';

let externalCalls=0;
globalThis.fetch=async()=>{externalCalls++;throw new Error('external transport disabled');};
const {default:worker,purgeWorkspaceData,processDeletionRequests,requireWorkspaceRole}=await import('../workers/scan-api/src/index.js');
const {attackSurfaceRoutes}=await import('../workers/scan-api/src/routes/attack-surface.js');
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
let passed=0,failed=0;
function ok(name,value){if(value){passed++;console.log(`PASS ${name}`);}else{failed++;console.error(`FAIL ${name}`);}}
function eq(name,actual,expected){ok(name,JSON.stringify(actual)===JSON.stringify(expected));}
async function rejects(name,fn){let threw=false;try{await fn();}catch{threw=true;}ok(name,threw);}
function fixture(){
 const db=new DatabaseSync(':memory:');
 db.exec(fs.readFileSync(path.join(root,'database/schema.sql'),'utf8'));
 for(const name of fs.readdirSync(path.join(root,'database/migrations')).filter(n=>n.endsWith('.sql')).sort()){
  const sql=fs.readFileSync(path.join(root,'database/migrations',name),'utf8');
  const hash=createHash('sha256').update(sql).digest('hex');
  for(const statement of splitStatements(sql)){
   try{db.exec(statement);}catch(error){if(!isToleratedStatement(name,hash,statement,error.message))throw error;}
  }
 }
 db.exec('PRAGMA foreign_keys=ON');
 const queries=[],objects=new Map();let failure=null,probeCalls=0,deleteFailure=false,keepDeleted=false;
 const statement=(sql,args=[])=>({sql,args,bind:(...values)=>statement(sql,values),
  first:async(column)=>{queries.push(sql);if(failure?.(sql))throw Error('injected D1 failure');const row=db.prepare(sql).get(...args)||null;return column&&row?row[column]:row;},
  all:async()=>{queries.push(sql);if(failure?.(sql))throw Error('injected D1 failure');return {results:db.prepare(sql).all(...args)};},
  run:async()=>{queries.push(sql);if(failure?.(sql))throw Error('injected D1 failure');return {meta:{changes:db.prepare(sql).run(...args).changes}};},
 });
 const d1={prepare:sql=>statement(sql),batch:async statements=>{db.exec('BEGIN');try{const result=[];for(const s of statements)result.push(await s.run());db.exec('COMMIT');return result;}catch(error){db.exec('ROLLBACK');throw error;}}};
 const env={cybermeters_db:d1,cybermeters_reports:{
  list:async({prefix,limit})=>({objects:[...objects.keys()].filter(key=>key.startsWith(prefix)).slice(0,limit).map(key=>({key}))}),
  delete:async key=>{if(deleteFailure)throw Error('injected R2 delete failure');if(!keepDeleted)objects.delete(key);},
  head:async key=>objects.has(key)?{key}:null,
  get:async key=>objects.has(key)?{text:async()=>objects.get(key),json:async()=>JSON.parse(objects.get(key))}:null,
  put:async(key,text,options)=>{if(options.onlyIf.get('If-None-Match')!=='*'||objects.has(key))return null;objects.set(key,text);return {etag:'fixture'};},
 },NETWORK_PROBE:{fetch:async(_url,options)=>{
  probeCalls++;const req=JSON.parse(options.body),now=new Date().toISOString();
  return Response.json({schema_version:'network-probe-receipt-v1',request_id:req.request_id,workspace_id:req.workspace_id,scan_id:req.scan_id,profile:req.profile,started_at:now,finished_at:now,
   collector:{name:'cybermeters-cloudflare-network-probe',version:'1',node_version:'v26.10.0',openssl_version:'synthetic',trust_store:{name:'Node.js bundled Mozilla CA roots',sha256:'a'.repeat(64)}},
   limitations:['Synthetic local integration fixture; no provider observation.'],quality:'complete',coverage:{planned:1,attempted:1,completed:1,not_run:0},
   observations:[{address:'8.8.8.8',hostname:null,port:22,transport:'tcp',state:'closed',service:null,tls:null,reason:'connection_refused'}]});
 }}};
 for(const id of ['owner','foreign','actor'])db.prepare('INSERT INTO users(id,email,email_verified) VALUES(?,?,1)').run(id,`${id}@example.test`);
 for(const [id,owner] of [['wa','owner'],['wb','foreign']])db.prepare('INSERT INTO workspaces(id,name,owner_user_id) VALUES(?,?,?)').run(id,id,owner);
 const target=(id,workspace='wa',actor='owner')=>db.prepare("INSERT INTO network_targets(id,workspace_id,target,target_type,addresses_json,address_count,authorization_status,authorized_by,authorized_at,created_at) VALUES(?,?,'8.8.8.8','ip','[\"8.8.8.8\"]',1,'attested',?,datetime('now'),datetime('now'))").run(id,workspace,actor);
 const scan=(id,targetId,workspace='wa',status='queued',retest=null,actor='owner')=>db.prepare("INSERT INTO network_scans(id,workspace_id,target_id,requested_by,retest_of,ports_json,status,receipt_key,created_at) VALUES(?,?,?,?,?,'[22]',?,?,datetime('now'))").run(id,workspace,targetId,actor,retest,status,`network-reports/${workspace}/${id}.json`);
 const snapshot=()=>JSON.stringify(['network_targets','network_scans','network_assets'].map(table=>db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all()));
 return {db,env,queries,objects,target,scan,snapshot,get probeCalls(){return probeCalls;},set failure(value){failure=value;},set deleteFailure(value){deleteFailure=value;},set keepDeleted(value){keepDeleted=value;}};
}
function message(body){return {id:`msg_${body.scan_id}`,body,attempts:1,acks:0,retries:0,ack(){this.acks++;},retry(){this.retries++;}};}

// Drive the default Worker queue export; testing the two lower-level handlers
// separately would miss a missing/wrong production dispatcher integration.
{
 const f=fixture();f.target('t');f.scan('network_1','t');
 f.db.prepare("INSERT INTO domains(id,user_id,domain) VALUES('domain_ref','owner','example.test')").run();
 f.db.prepare("INSERT INTO scans(id,domain_id,workspace_id,domain,status) VALUES('domain_1','domain_ref','wa','example.test','completed')").run();
 const domainBefore=JSON.stringify(f.db.prepare("SELECT * FROM scans WHERE id='domain_1'").get());
 const network=message({kind:'network_probe',v:1,scan_id:'network_1',workspace_id:'wa'}),domain=message({v:1,scan_id:'domain_1',workspace_id:'wa'});
 await worker.queue({queue:'cybermeters-scan-dispatch',messages:[domain,network]},f.env,{});
 eq('default queue completes admitted network work',f.db.prepare("SELECT status FROM network_scans WHERE id='network_1'").get().status,'completed');
 eq('default queue uses exactly one private collector call',f.probeCalls,1);
 eq('default queue acknowledges both message families',[network.acks,domain.acks,network.retries,domain.retries],[1,1,0,0]);
 ok('domain work still reaches existing domain D1 authority',f.queries.some(sql=>/SELECT id, workspace_id, domain_id, domain, status FROM scans/.test(sql)));
 eq('terminal domain work remains byte-identical',JSON.stringify(f.db.prepare("SELECT * FROM scans WHERE id='domain_1'").get()),domainBefore);
 f.scan('network_dlq','t');const before=f.snapshot(),objects=[...f.objects];
 const dlq=message({kind:'network_probe',v:1,scan_id:'network_dlq',workspace_id:'wa'});
 await worker.queue({queue:'cybermeters-scan-dlq',messages:[dlq]},f.env,{});
 eq('network DLQ never starts a collector',f.probeCalls,1);eq('network DLQ preserves all network rows',f.snapshot(),before);eq('network DLQ preserves every receipt',[...f.objects],objects);
 eq('DLQ durable event precedes acknowledgement',[f.db.prepare("SELECT COUNT(*) n FROM operational_events WHERE correlation_id='network_dlq' AND event_type='scan_dlq_observed'").get().n,dlq.acks],[1,1]);
 const failed=message({kind:'network_probe',v:1,scan_id:'network_dlq_fault'});f.failure=sql=>sql.includes('INSERT OR IGNORE INTO operational_events');
 await worker.queue({queue:'cybermeters-scan-dlq',messages:[failed]},f.env,{});
 eq('failed DLQ persistence retries without acknowledgement',[failed.acks,failed.retries],[0,1]);eq('failed DLQ persistence still never probes',f.probeCalls,1);
 f.db.close();
}

// Run the actual hourly entry; empty unrelated tables/configurations prevent
// unrelated work. A stale network run must become failed, never complete.
{
 const f=fixture();f.target('t');f.scan('abandoned','t');f.db.prepare("UPDATE network_scans SET created_at=datetime('now','-16 minutes') WHERE id='abandoned'").run();
 const waits=[];await worker.scheduled({cron:'0 * * * *'},f.env,{waitUntil:promise=>waits.push(promise)});await Promise.allSettled(waits);
 eq('hourly production hook recovers abandoned network work',f.db.prepare("SELECT status,quality,reason FROM network_scans WHERE id='abandoned'").get(),{status:'failed',quality:null,reason:'network_execution_interrupted'});
 eq('recovery performs no measurement',f.probeCalls,0);eq('recovery creates no receipt',f.objects.size,0);
 ok('existing domain recovery still runs',f.queries.some(sql=>sql.includes('last_heartbeat_at')&&sql.includes('FROM scans')&&sql.includes('ORDER BY created_at ASC')));
 f.db.close();
}

// Network receipts are removed before their D1 pointers. Full real FKs include
// asset->scan, scan->target, scan->prior-retest and actor->user edges.
{
 const f=fixture();f.target('ta');f.target('tb','wb','foreign');f.scan('a1','ta','wa','completed');f.scan('a2','ta','wa','completed','a1');f.scan('b1','tb','wb','completed',null,'foreign');
 for(const [ws,scan] of [['wa','a2'],['wb','b1']])f.db.prepare("INSERT INTO network_assets(workspace_id,address,port,transport,state,last_observed_state,last_checked_at,last_scan_id) VALUES(?,'8.8.8.8',22,'tcp','closed','closed',datetime('now'),?)").run(ws,scan);
 for(const id of ['a1','a2'])f.objects.set(`network-reports/wa/${id}.json`,'synthetic receipt');
 f.objects.set('network-reports/wa/orphan-after-r2-put.json','synthetic orphan');f.objects.set('network-reports/wb/b1.json','foreign receipt');
 const foreign=JSON.stringify(['network_targets','network_scans','network_assets'].map(table=>f.db.prepare(`SELECT * FROM ${table} WHERE workspace_id='wb'`).all()));
 ok('network migration is actually enforced by SQLite FKs',f.db.prepare('PRAGMA foreign_keys').get().foreign_keys===1);
 const before=f.snapshot();f.deleteFailure=true;await rejects('R2 delete failure aborts actual purge',()=>purgeWorkspaceData(f.env,'wa'));eq('delete failure preserves every network pointer and asset',f.snapshot(),before);f.deleteFailure=false;
 f.keepDeleted=true;await rejects('R2 successful delete with surviving object aborts purge',()=>purgeWorkspaceData(f.env,'wa'));eq('unproven absence preserves every pointer',f.snapshot(),before);f.keepDeleted=false;
 const list=f.env.cybermeters_reports.list;f.env.cybermeters_reports.list=async()=>({});await rejects('malformed R2 list cannot erase pointers',()=>purgeWorkspaceData(f.env,'wa'));eq('unavailable listing preserves all rows',f.snapshot(),before);f.env.cybermeters_reports.list=list;
 const drained=await purgeWorkspaceData(f.env,'wa');eq('receipt drain keeps row deletion for following bounded pass',drained,{done:false});eq('all requested receipts including orphan drained',[...f.objects.keys()],['network-reports/wb/b1.json']);eq('receipt-first pass retains full pointers',f.snapshot(),before);
 const done=await purgeWorkspaceData(f.env,'wa');eq('network purge completes with retest self-FK present',done,{done:true});
 eq('all three requested network tables emptied',['network_targets','network_scans','network_assets'].map(table=>f.db.prepare(`SELECT COUNT(*) n FROM ${table} WHERE workspace_id='wa'`).get().n),[0,0,0]);
 eq('foreign workspace full network rows unchanged',JSON.stringify(['network_targets','network_scans','network_assets'].map(table=>f.db.prepare(`SELECT * FROM ${table} WHERE workspace_id='wb'`).all())),foreign);
 eq('foreign receipt remains unchanged',f.objects.get('network-reports/wb/b1.json'),'foreign receipt');eq('purge leaves zero FK violations',f.db.prepare('PRAGMA foreign_key_check').all(),[]);f.db.close();
}

// An actor can leave a workspace they do not own. Account deletion must name
// these retained foreign records, not erase them or falsely claim completion.
{
 const f=fixture();f.target('foreign_attestation','wb','actor');f.scan('foreign_request','foreign_attestation','wb','completed',null,'actor');
 f.db.prepare("INSERT INTO deletion_requests(id,request_type,user_id,requested_by,status,created_at) VALUES('dr','account','actor','actor','pending',datetime('now','-60 days'))").run();
 const before=f.snapshot();await processDeletionRequests(f.env);
 eq('account purge honestly blocks on retained network actor records',f.db.prepare("SELECT status FROM deletion_requests WHERE id='dr'").get().status,'blocked_residual_data');
 const event=f.db.prepare("SELECT metadata_json FROM audit_events WHERE event_type='account_purge_blocked_residual_data'").get();const edges=JSON.parse(event?.metadata_json||'{}').residual_edges||[];
 ok('account residual proof names authorized_by FK',edges.some(edge=>edge.table==='network_targets'&&edge.column==='authorized_by'&&edge.rows===1));
 ok('account residual proof names requested_by FK',edges.some(edge=>edge.table==='network_scans'&&edge.column==='requested_by'&&edge.rows===1));
 eq('account purge preserves foreign network history exactly',f.snapshot(),before);ok('retained actor is not silently deleted',!!f.db.prepare("SELECT id FROM users WHERE id='actor'").get());
 eq('account residual path leaves zero FK violations',f.db.prepare('PRAGMA foreign_key_check').all(),[]);f.db.close();
}
// Exercise the real certificate route allowlist and its customer projection.
// Component mocks alone cannot show that persisted live evidence reaches it.
{
 const f=fixture();
 f.db.prepare("INSERT INTO workspace_members(workspace_id,user_id,role) VALUES('wa','owner','owner')").run();
 for(const id of ['live','historic']){
  f.db.prepare('INSERT INTO domains(id,user_id,domain) VALUES(?,?,?)').run(id,'owner',`${id}.example.test`);
  f.db.prepare("INSERT INTO workspace_domains(workspace_id,domain_id) VALUES('wa',?)").run(id);
  f.db.prepare("INSERT INTO scans(id,domain_id,workspace_id,domain,status) VALUES(?,?,'wa',?,'completed')").run(`scan_${id}`,id,`${id}.example.test`);
 }
 const live={leaf_collected:true,leaf_certificate:{collection_performed:true,collection_complete:true,certificate_identity:`sha256:${'a'.repeat(64)}`,subject:'CN=live.example.test'},all_planned_endpoints_observed:false};
 const raw={domain:'live.example.test',modules:{ssl:{error:'HTTP measurement unavailable'},certificate_intelligence:{certificate_status:'valid',certificate_risk_level:'unknown',live_tls:live,evidence_source:'live_tls',live_certificate_verified:true}}};
 f.objects.set('reports/scan_live.json',JSON.stringify(raw));
 f.objects.set('reports/scan_historic.json',JSON.stringify({domain:'historic.example.test',modules:{ssl:{error:'Historical HTTP evidence unavailable'},certificate_intelligence:{issuer:'Historical CT issuer',evidence_source:'certificate_transparency'}}}));
 const before=[...f.objects];
 async function certificates(user){
  const url=new URL('https://fixture.test/api/workspaces/wa/certificates');
  return attackSurfaceRoutes({request:new Request(url),url,env:f.env,requireAuth:async()=>({id:user}),requireWorkspaceRole,json:(body,status=200)=>Response.json(body,{status})});
 }
 const response=await certificates('owner');eq('real certificate route succeeds for workspace owner',response.status,200);
 const output=await response.json(),current=output.certificates?.find(row=>row.domain==='live.example.test'),historic=output.certificates?.find(row=>row.domain==='historic.example.test');
 eq('real certificate route carries exact observed live leaf',current?.live_tls,live);
 eq('live evidence provenance survives actual allowlist',[current?.evidence_source,current?.live_certificate_verified],['live_tls',true]);
 eq('separate unavailable HTTP projection remains unknown',current?.certificate_status,'unknown');
 eq('historical CT has no invented live certificate',[historic?.live_tls,historic?.live_certificate_verified],[null,false]);
 eq('certificate read preserves both immutable raw reports',[...f.objects],before);
 eq('foreign user cannot read new live certificate fields',(await certificates('foreign')).status,403);
 f.db.close();
}
eq('no external transport used by any integration control',externalCalls,0);
console.log(`\nNetwork integration: ${passed} passed, ${failed} failed`);if(failed)process.exit(1);
