import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import { TLS_POLICY_VERSION, TLS_PROFILE_VERSION, TLS_SLICE_LIMITS, tlsEndpointIdentity } from '../shared/tls/catalog.js';
import { projectTlsCollectorReceipt } from '../workers/network-probe/src/tls-contract.js';
import { processExposureMessage, readTlsAssessmentForScan } from '../workers/scan-api/src/engines/exposure-jobs.js';
import { loadTlsAssessmentModuleForScan } from '../workers/scan-api/src/engines/scan-engine.js';
import { resolveSecurityCheckDomainStates } from '../workers/scan-api/src/engines/security-check-domains.js';

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
const env={cybermeters_db:{prepare},SCAN_QUEUE:{send:async message=>sent.push(message)},TLS_ASSESSMENT_MODE:'evidence-v1'};
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
// A collector interruption consumes its reserved network budget. A later Queue
// delivery resumes the same cursor and can charge only the remaining allowance.
function interruptedJob(scanId) {
  const workspace='w_interrupt',domain=`${scanId}.example.org`,domainId=`d_${scanId}`,now=Date.now();
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
  return {kind:'external_exposure',v:1,scan_id:scanId,workspace_id:workspace};
}
const retryMessage=interruptedJob('tls_retry');
const interruptedCollector=async()=>{throw new Error('simulated collector interruption');};
assert.equal((await processExposureMessage(retryMessage,env,{lookupTlsDns,collectTlsAssessment:interruptedCollector})).outcome,
  'tls_uncertain_attempt_charged');
let interrupted=sql.prepare('SELECT charged_requests,charged_bytes,unknown_attempts,plan_json FROM external_exposure_jobs WHERE scan_id=?').get('tls_retry');
assert.equal(interrupted.charged_requests,TLS_SLICE_LIMITS.connections);
assert.equal(interrupted.charged_bytes,TLS_SLICE_LIMITS.bytes+TLS_SLICE_LIMITS.overreadBytes);
assert.equal(interrupted.unknown_attempts,1);
assert.equal(JSON.parse(interrupted.plan_json).tls.cursor,0);
assert.equal((await processExposureMessage(retryMessage,env,{lookupTlsDns,collectTlsAssessment})).outcome,'complete');
interrupted=sql.prepare('SELECT charged_requests,unknown_attempts,plan_json FROM external_exposure_jobs WHERE scan_id=?').get('tls_retry');
assert.equal(interrupted.charged_requests,TLS_SLICE_LIMITS.connections+1);
assert.equal(interrupted.unknown_attempts,1);
assert.equal(JSON.parse(interrupted.plan_json).tls.results.length,1);
assert.equal((await processExposureMessage(retryMessage,env,{lookupTlsDns,collectTlsAssessment})).outcome,'terminal');
const cancelMessage=interruptedJob('tls_cancel');
assert.equal((await processExposureMessage(cancelMessage,env,{lookupTlsDns,collectTlsAssessment:interruptedCollector})).outcome,
  'tls_uncertain_attempt_charged');
sql.prepare("UPDATE scans SET status='cancelled' WHERE id=?").run('tls_cancel');
assert.equal((await processExposureMessage(cancelMessage,env,{lookupTlsDns,collectTlsAssessment})).outcome,'authority_lost');
interrupted=sql.prepare('SELECT state,charged_requests,plan_json FROM external_exposure_jobs WHERE scan_id=?').get('tls_cancel');
assert.equal(interrupted.state,'cancelled');
assert.equal(interrupted.charged_requests,TLS_SLICE_LIMITS.connections);
assert.equal(JSON.parse(interrupted.plan_json).tls.results.length,0);
// Turning off the rollout must drain an already-planned TLS job without
// dispatching a connection or misreporting the skipped control as clean.
const rollbackMessage=interruptedJob('tls_flag_off');
const rollbackPlan=JSON.parse(sql.prepare('SELECT plan_json FROM external_exposure_jobs WHERE scan_id=?').get('tls_flag_off').plan_json);
rollbackPlan.tls.selected=Array.from({length:TLS_SLICE_LIMITS.checks+1},(_,i)=>({endpoint_index:0,
  check:{control:'protocol',protocol:i%2?'tls1_2':'tls1_3',cipher_id:null}}));
sql.prepare('UPDATE external_exposure_jobs SET plan_json=? WHERE scan_id=?').run(JSON.stringify(rollbackPlan),'tls_flag_off');
const callsBeforeRollback=collectorCalls;
env.TLS_ASSESSMENT_MODE='disabled';
assert.equal((await processExposureMessage(rollbackMessage,env,{lookupTlsDns,collectTlsAssessment})).outcome,'feature_disabled');
const rollbackRow=sql.prepare('SELECT state,charged_requests,charged_bytes,plan_json FROM external_exposure_jobs WHERE scan_id=?').get('tls_flag_off');
assert.equal(rollbackRow.state,'complete');
assert.equal(rollbackRow.charged_requests,0);
assert.equal(rollbackRow.charged_bytes,0);
assert.equal(JSON.parse(rollbackRow.plan_json).tls.results.length,TLS_SLICE_LIMITS.checks+1);
assert(JSON.parse(rollbackRow.plan_json).tls.results.every(result=>result.state==='unexecutable'&&result.reason==='feature_disabled'));
const rollbackAssessment=await readTlsAssessmentForScan(env,{workspaceId:'w_interrupt',scanId:'tls_flag_off'});
assert.equal(rollbackAssessment.quality,'partial');
assert.equal(rollbackAssessment.coverage.unexecutable,TLS_SLICE_LIMITS.checks+1);
const resumedTlsModule=await loadTlsAssessmentModuleForScan(env,{workspaceId:'w_interrupt',scanId:'tls_flag_off',durableInvocation:true});
assert.deepEqual(resumedTlsModule,rollbackAssessment);
const resumedReport={scan_quality:{status:'complete',modules_skipped:[]},
  modules:{certificate_intelligence:{},tls_assessment:resumedTlsModule},findings:[]};
const certificateState=resolveSecurityCheckDomainStates(resumedReport).find(row=>row.domain_key==='certificates_trust');
assert.equal(certificateState.state,'evidence_insufficient');
assert.equal(await loadTlsAssessmentModuleForScan(env,{workspaceId:'w_interrupt',scanId:'not_planned',durableInvocation:true}),null);
assert.equal(await loadTlsAssessmentModuleForScan(env,{workspaceId:'w_interrupt',scanId:'tls_flag_off',durableInvocation:false}),null);
assert.equal(collectorCalls,callsBeforeRollback);
env.TLS_ASSESSMENT_MODE='evidence-v1';
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
assert.equal(collectorCalls,1001);
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
// A normal check and each active check get separate reservations. In
// particular ROBOT's 21 connections cannot spill into the next control.
{
  const workspace='w_special',scanId='tls_special_slices',domainId='d_special',domain='special.example.org',now=Date.now();
  sql.prepare('INSERT INTO workspaces VALUES(?,NULL)').run(workspace);
  sql.prepare('INSERT INTO scans VALUES(?,?,?,?,?)').run(scanId,workspace,domainId,domain,'queued');
  sql.prepare("INSERT INTO workspace_domains VALUES(?,?,'verified')").run(workspace,domainId);
  sql.prepare('INSERT INTO workspace_tls_authorizations(workspace_id,enabled,generation,consent_version,updated_at) VALUES(?,1,1,?,?)')
    .run(workspace,'tls-special-2026-10-13',new Date(now).toISOString());
  const endpoint={hostname:domain,sni:domain,address:'8.8.8.8',port:443,transport:'tcp',application_protocol:'https',
    dns_addresses:['8.8.8.8'],dns_observed_at:new Date(now).toISOString()};
  const controls=['protocol','robot','ccs'];
  const selected=controls.map(control=>({endpoint_index:0,check:{control,protocol:'tls1_2',cipher_id:null}}));
  const plan={content_state:'not_requested',checks:[],tls:{profile_version:TLS_PROFILE_VERSION,policy_version:TLS_POLICY_VERSION,
    endpoints:[{endpoint,endpoint_identity:tlsEndpointIdentity(endpoint),scope:{kind:'standard_https',service_authorization_id:null,
      generation:1,special_consent:true,consent_version:'tls-special-2026-10-13'}}],selected,static_results:[],results:[],
    cursor:0,gaps:[],omitted_checks:0,omitted_services:0,state:'pending'}};
  sql.prepare('INSERT INTO external_exposure_jobs(scan_id,workspace_id,domain_id,domain,plan_json,created_ms,deadline_ms,updated_at) VALUES(?,?,?,?,?,?,?,?)')
    .run(scanId,workspace,domainId,domain,JSON.stringify(plan),now,now+30*60_000,new Date(now).toISOString());
  const reservations=[];
  const specialCollector=async(_env,input)=>{
    const control=input.checks[0].control;
    assert.equal(input.checks.length,1);
    reservations.push([control,input.max_connections]);
    const physical={connections:control==='robot'?21:control==='ccs'?5:1,bytes_sent:1000,bytes_received:2000,duration_ms:10};
    const special=control!=='protocol';
    const engine={schema:'tls-engine-result-v1',engine:{family:special?'active_legacy':'modern',
      version:special?'1.0.2u':'3.5.9',build_id:'a'.repeat(64),sandboxed:true},
      control:special?control:'handshake',protocol:'tls1_2',state:special?'rejected':'accepted',
      reason:special?'active_not_observed':'handshake_completed',authenticated_finished:true,
      vulnerability:special?{status:'not_observed',profile:control==='robot'?'robot-finite-v1':'ccs-early-record-v1',
        completed_vectors:control==='robot'?20:4,planned_vectors:control==='robot'?20:4}:null,
      negotiated:{version:'tls1_2',cipher:'AES128-GCM-SHA256',cipher_bits:128,group:null,group_bits:null,pfs:false,alpn:null,sni_sent:true},
      certificates:null,ocsp:null,extensions:null,telemetry:physical,limitations:[],catalog:null};
    const timestamp=new Date().toISOString();
    const raw={schema_version:'tls-collector-raw-v1',request_id:input.request_id,started_at:timestamp,finished_at:timestamp,
      results:[{check:input.checks[0],engine_result:engine,reason:null,observed_at:timestamp,physical_telemetry:physical}],
      telemetry:physical};
    return projectTlsCollectorReceipt(input,raw);
  };
  const message={kind:'external_exposure',v:1,scan_id:scanId,workspace_id:workspace};
  assert.equal((await processExposureMessage(message,env,{lookupTlsDns,collectTlsAssessment:specialCollector})).outcome,'pending');
  assert.equal((await processExposureMessage(message,env,{lookupTlsDns,collectTlsAssessment:specialCollector})).outcome,'pending');
  assert.equal((await processExposureMessage(message,env,{lookupTlsDns,collectTlsAssessment:specialCollector})).outcome,'complete');
  assert.deepEqual(reservations,[['protocol',16],['robot',21],['ccs',5]]);
  const finished=sql.prepare('SELECT charged_requests,plan_json FROM external_exposure_jobs WHERE scan_id=?').get(scanId);
  assert.equal(finished.charged_requests,27);
  assert.equal(JSON.parse(finished.plan_json).tls.results.length,3);
}
// A run that completed its checks apart from a capability-limited control (the
// server offers no heartbeat extension, so the heartbleed vector cannot run)
// is a complete TLS module; a check CyberMeters itself did not run is not.
for (const [scanId, unexecutableReason, expected] of [
  ['tls_capability_unexecutable', 'heartbeat_unavailable', 'complete'],
  ['tls_feature_disabled_unexecutable', 'feature_disabled', 'partial'],
]) {
  const workspace = 'w_capability', domain = `${scanId.replaceAll('_', '-')}.example.org`, domainId = `d_${scanId}`, now = Date.now();
  sql.prepare('INSERT OR IGNORE INTO workspaces VALUES(?,NULL)').run(workspace);
  sql.prepare('INSERT INTO scans VALUES(?,?,?,?,?)').run(scanId, workspace, domainId, domain, 'completed');
  const endpoint = { hostname: domain, sni: domain, address: '8.8.8.8', port: 443, transport: 'tcp', application_protocol: 'https',
    dns_addresses: ['8.8.8.8'], dns_observed_at: new Date(now).toISOString() };
  const result = (control, protocol, state, reason) => ({ endpoint_index: 0, control, protocol, cipher_id: null, state, reason,
    observed_at: new Date(now).toISOString(), engine: null, evidence: null,
    physical_telemetry: { connections: 1, bytes_sent: 1, bytes_received: 1, duration_ms: 1 } });
  const plan = { content_state: 'not_requested', checks: [], tls: { profile_version: TLS_PROFILE_VERSION, policy_version: TLS_POLICY_VERSION,
    endpoints: [{ endpoint, endpoint_identity: tlsEndpointIdentity(endpoint), scope: { kind: 'standard_https', service_authorization_id: null,
      generation: 0, special_consent: false, consent_version: null } }],
    selected: [{ endpoint_index: 0, check: { control: 'protocol', protocol: 'tls1_2', cipher_id: null } }],
    static_results: [result('heartbleed', 'tls1_2', 'unexecutable', unexecutableReason)],
    results: [result('protocol', 'tls1_2', 'accepted', 'handshake_completed')],
    cursor: 1, gaps: [], omitted_checks: 0, omitted_services: 0, state: 'complete' } };
  sql.prepare("INSERT INTO external_exposure_jobs(scan_id,workspace_id,domain_id,domain,plan_json,created_ms,deadline_ms,updated_at,state) VALUES(?,?,?,?,?,?,?,?,'complete')")
    .run(scanId, workspace, domainId, domain, JSON.stringify(plan), now, now + 60_000, new Date(now).toISOString());
  const assessment = await readTlsAssessmentForScan(env, { workspaceId: workspace, scanId });
  assert.equal(assessment.coverage.unexecutable, 1);
  assert.equal(assessment.quality, expected, `TLS module quality for ${unexecutableReason}`);
  const certificates = resolveSecurityCheckDomainStates({ scan_quality: { status: 'complete', modules_skipped: [] },
    modules: { certificate_intelligence: {}, tls_assessment: assessment }, findings: [] }).find(row => row.domain_key === 'certificates_trust');
  if (expected === 'complete') {
    assert.notEqual(certificates.state, 'provisional', 'a complete TLS run is not provisional');
    assert.ok(!/not assessed|provisional/.test(certificates.summary), certificates.summary);
  } else {
    assert.notEqual(certificates.state, 'assessed_healthy', 'an unrun check never reads healthy');
  }
}
console.log(JSON.stringify({synthetic_tls_jobs:1000,live_customer_domains:0,load_deliveries:2000,
  load_completed:1000,load_charged_connections:1000,load_charged_bytes:430000,
  total_collector_calls:collectorCalls,scope_revocation_races:2,
  interruption_recovery_cases:2,
  elapsed_ms:Math.round(performance.now()-started)}));
sql.close();
