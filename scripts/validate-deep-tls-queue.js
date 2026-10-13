import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import { TLS_POLICY_VERSION, TLS_PROFILE_VERSION, tlsEndpointIdentity } from '../shared/tls/catalog.js';
import { projectTlsCollectorReceipt } from '../workers/network-probe/src/tls-contract.js';
import { processExposureMessage, readTlsAssessmentForScan } from '../workers/scan-api/src/engines/exposure-jobs.js';

const sql=new DatabaseSync(':memory:');
sql.exec(`CREATE TABLE workspaces(id TEXT PRIMARY KEY,deleted_at TEXT);
  CREATE TABLE scans(id TEXT PRIMARY KEY,workspace_id TEXT,domain_id TEXT,domain TEXT,status TEXT);
  CREATE TABLE workspace_domains(workspace_id TEXT,domain_id TEXT,verification_status TEXT);
  CREATE TABLE network_targets(id TEXT PRIMARY KEY,workspace_id TEXT,authorization_status TEXT,addresses_json TEXT);`);
sql.exec(readFileSync(new URL('../database/migrations/119-external-exposure-jobs.sql',import.meta.url),'utf8'));
sql.exec(readFileSync(new URL('../database/migrations/120-tls-authorization.sql',import.meta.url),'utf8'));
const prepare=(query,args=[])=>({bind:(...values)=>prepare(query,values),first:async()=>sql.prepare(query).get(...args)||null,
  all:async()=>({results:sql.prepare(query).all(...args)}),run:async()=>({meta:{changes:sql.prepare(query).run(...args).changes}})});
const sent=[];
const env={cybermeters_db:{prepare},SCAN_QUEUE:{send:async message=>sent.push(message)}};
const check={control:'protocol',protocol:'tls1_2',cipher_id:null};
const lookupTlsDns=async(_host,type)=>type==='A'?{Status:0,Answer:[{type:1,name:_host+'.',data:'8.8.8.8'}]}:{Status:0,Answer:[]};
let collectorCalls=0;
const collectTlsAssessment=async(_env,input)=>{
  collectorCalls++;
  const timestamp=new Date().toISOString();
  const engine={schema:'tls-engine-result-v1',engine:{family:'modern',version:'3.5.9',build_id:'a'.repeat(64),sandboxed:true},
    control:'handshake',protocol:'tls1_2',state:'accepted',reason:'handshake_completed',authenticated_finished:true,vulnerability:null,
    negotiated:{version:'tls1_2',cipher:'ECDHE-RSA-AES256-GCM-SHA384',cipher_bits:256,group:'X25519',group_bits:255,pfs:true,alpn:null,sni_sent:true},
    certificates:null,ocsp:null,extensions:null,telemetry:{connections:1,bytes_sent:100,bytes_received:250,duration_ms:10},limitations:[],catalog:null};
  const raw={schema_version:'tls-collector-raw-v1',request_id:input.request_id,started_at:timestamp,finished_at:timestamp,
    results:[{check,engine_result:engine,reason:null,observed_at:timestamp,
      physical_telemetry:{connections:1,bytes_sent:130,bytes_received:300,duration_ms:10}}],
    telemetry:{connections:1,bytes_sent:130,bytes_received:300,duration_ms:0}};
  return projectTlsCollectorReceipt(input,raw);
};
const started=performance.now();
for(let i=0;i<1000;i++){
  const workspace=`w_${i%10}`,scanId=`s_${i}`,domainId=`d_${i}`,domain=`asset${i}.example.org`,now=Date.now();
  sql.prepare('INSERT OR IGNORE INTO workspaces VALUES(?,NULL)').run(workspace);
  sql.prepare('INSERT INTO scans VALUES(?,?,?,?,?)').run(scanId,workspace,domainId,domain,'queued');
  sql.prepare("INSERT INTO workspace_domains VALUES(?,?,'verified')").run(workspace,domainId);
  const endpoint={hostname:domain,sni:domain,address:'8.8.8.8',port:443,transport:'tcp',application_protocol:'https',
    dns_addresses:['8.8.8.8'],dns_observed_at:new Date(now).toISOString()};
  const plan={content_state:'not_requested',checks:[],tls:{profile_version:TLS_PROFILE_VERSION,policy_version:TLS_POLICY_VERSION,
    endpoints:[{endpoint,endpoint_identity:tlsEndpointIdentity(endpoint),scope:{kind:'standard_https',service_authorization_id:null,
      generation:0,special_consent:false,consent_version:null}}],selected:[{endpoint_index:0,check}],static_results:[],results:[],
    cursor:0,gaps:[],omitted_checks:0,omitted_services:0,state:'pending'}};
  sql.prepare('INSERT INTO external_exposure_jobs(scan_id,workspace_id,domain_id,domain,plan_json,created_ms,deadline_ms,updated_at) VALUES(?,?,?,?,?,?,?,?)')
    .run(scanId,workspace,domainId,domain,JSON.stringify(plan),now,now+30*60_000,new Date(now).toISOString());
  const message={kind:'external_exposure',v:1,scan_id:scanId,workspace_id:workspace};
  assert.equal((await processExposureMessage(message,env,{lookupTlsDns,collectTlsAssessment})).outcome,'complete');
  assert.equal((await processExposureMessage(message,env,{lookupTlsDns,collectTlsAssessment})).outcome,'terminal');
  if(i===0){
    const report=await readTlsAssessmentForScan(env,{workspaceId:workspace,scanId});
    assert.equal(report.endpoints[0].checks[0].state,'accepted');
    assert.equal(report.costs.connections,1);
    assert.equal(await readTlsAssessmentForScan(env,{workspaceId:'foreign',scanId}),null);
  }
}
const rows=sql.prepare('SELECT state,charged_requests,charged_bytes FROM external_exposure_jobs').all();
assert.equal(rows.filter(row=>row.state==='complete').length,1000);
assert.equal(rows.reduce((sum,row)=>sum+row.charged_requests,0),1000);
assert.equal(rows.reduce((sum,row)=>sum+row.charged_bytes,0),430000);
assert.equal(collectorCalls,1000);
// Revocation during DNS must prevent dispatch; revocation after collection
// must prevent the accepted evidence from crossing the atomic write fence.
const scopeWorkspace='w_scope',scopeDomain='mail.example.org',scopeDomainId='d_scope';
sql.prepare('INSERT INTO workspaces VALUES(?,NULL)').run(scopeWorkspace);
sql.prepare("INSERT INTO workspace_domains VALUES(?,?,'verified')").run(scopeWorkspace,scopeDomainId);
sql.prepare("INSERT INTO network_targets VALUES(? ,?,'attested',?)").run('target_scope',scopeWorkspace,'["8.8.8.8"]');
sql.prepare('INSERT INTO workspace_tls_authorizations(workspace_id,enabled,generation,updated_at) VALUES(?,?,?,?)')
  .run(scopeWorkspace,0,1,new Date().toISOString());
sql.prepare(`INSERT INTO workspace_tls_service_authorizations
  (id,workspace_id,domain_id,hostname,sni,port,application_protocol,network_target_id,authorization_status,generation,authorized_by,authorized_at,updated_at)
  VALUES(?,?,?,?,?,?,?,?,'active',1,'admin',?,?)`).run('service_scope',scopeWorkspace,scopeDomainId,scopeDomain,scopeDomain,587,'smtp','target_scope',new Date().toISOString(),new Date().toISOString());
function scopedJob(scanId,generation){
  const now=Date.now(),endpoint={hostname:scopeDomain,sni:scopeDomain,address:'8.8.8.8',port:587,transport:'tcp',
    application_protocol:'smtp',dns_addresses:['8.8.8.8'],dns_observed_at:new Date(now).toISOString()};
  const plan={content_state:'not_requested',checks:[],tls:{profile_version:TLS_PROFILE_VERSION,policy_version:TLS_POLICY_VERSION,
    endpoints:[{endpoint,endpoint_identity:tlsEndpointIdentity(endpoint),scope:{kind:'authorized_service',service_authorization_id:'service_scope',
      generation,special_consent:false,consent_version:null}}],selected:[{endpoint_index:0,check}],static_results:[],results:[],
    cursor:0,gaps:[],omitted_checks:0,omitted_services:0,state:'pending'}};
  sql.prepare('INSERT INTO scans VALUES(?,?,?,?,?)').run(scanId,scopeWorkspace,scopeDomainId,scopeDomain,'queued');
  sql.prepare('INSERT INTO external_exposure_jobs(scan_id,workspace_id,domain_id,domain,plan_json,created_ms,deadline_ms,updated_at) VALUES(?,?,?,?,?,?,?,?)')
    .run(scanId,scopeWorkspace,scopeDomainId,scopeDomain,JSON.stringify(plan),now,now+30*60_000,new Date(now).toISOString());
  return {message:{kind:'external_exposure',v:1,scan_id:scanId,workspace_id:scopeWorkspace},now};
}
const first=scopedJob('scope_dns',1);
const revokeDuringDns=async(host,type)=>{
  if(type==='A'){
    sql.prepare("UPDATE workspace_tls_service_authorizations SET authorization_status='revoked' WHERE id='service_scope'").run();
    sql.prepare("UPDATE workspace_tls_authorizations SET generation=generation+1 WHERE workspace_id=?").run(scopeWorkspace);
  }
  return lookupTlsDns(host,type);
};
assert.equal((await processExposureMessage(first.message,env,{lookupTlsDns:revokeDuringDns,collectTlsAssessment})).outcome,'scope_changed');
assert.equal(JSON.parse(sql.prepare('SELECT plan_json FROM external_exposure_jobs WHERE scan_id=?').get('scope_dns').plan_json).tls.results[0].state,'not_authorized');
assert.equal(collectorCalls,1000);
sql.prepare("UPDATE workspace_tls_service_authorizations SET authorization_status='active' WHERE id='service_scope'").run();
const second=scopedJob('scope_receipt',2);
const revokeBeforeReceipt=async(...args)=>{
  const receipt=await collectTlsAssessment(...args);
  sql.prepare("UPDATE workspace_tls_authorizations SET generation=generation+1 WHERE workspace_id=?").run(scopeWorkspace);
  return receipt;
};
assert.equal((await processExposureMessage(second.message,env,{lookupTlsDns,collectTlsAssessment:revokeBeforeReceipt})).outcome,'tls_fence_lost');
let fenced=JSON.parse(sql.prepare('SELECT plan_json FROM external_exposure_jobs WHERE scan_id=?').get('scope_receipt').plan_json);
assert.equal(fenced.tls.results.length,0);
assert.equal((await processExposureMessage(second.message,env,{lookupTlsDns,collectTlsAssessment,now:()=>second.now+31000})).outcome,'scope_changed');
fenced=JSON.parse(sql.prepare('SELECT plan_json FROM external_exposure_jobs WHERE scan_id=?').get('scope_receipt').plan_json);
assert.equal(fenced.tls.results[0].state,'not_authorized');
console.log(JSON.stringify({synthetic_tls_jobs:1000,live_customer_domains:0,deliveries:2000,collector_calls:collectorCalls,
  completed:1000,charged_connections:1000,charged_bytes:430000,scope_revocation_races:2,
  elapsed_ms:Math.round(performance.now()-started)}));
sql.close();
