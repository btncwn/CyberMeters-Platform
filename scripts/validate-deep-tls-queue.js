import { test } from 'node:test';
import { assertProbeRequest } from './lib/probe-contract-fixture.mjs';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, writeFileSync, cpSync, mkdtempSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { TLS_POLICY_VERSION, TLS_PROFILE_VERSION, TLS_SLICE_LIMITS, TLS_SPECIAL_CONSENT_VERSION, TLS_SPECIAL_CONTROLS_AVAILABLE, TLS_SPECIAL_SLICE_DURATION_MS, tlsSliceDurationMs, tlsEndpointIdentity } from '../shared/tls/catalog.js';
import { projectTlsCollectorReceipt, validateTlsAssessmentRequest } from '../workers/network-probe/src/tls-contract.js';
import { processExposureMessage, readTlsAssessmentForScan, tlsProbeScope } from '../workers/scan-api/src/engines/exposure-jobs.js';
import { loadTlsAssessmentModuleForScan } from '../workers/scan-api/src/engines/scan-engine.js';
import { loadTlsEndpoints, buildBudgetedTlsCheckPlan } from '../workers/scan-api/src/engines/tls-planner.js';
import { resolveSecurityCheckDomainStates } from '../workers/scan-api/src/engines/security-check-domains.js';

const sql=new DatabaseSync(':memory:');
sql.exec(`CREATE TABLE workspaces(id TEXT PRIMARY KEY,deleted_at TEXT);
  CREATE TABLE scans(id TEXT PRIMARY KEY,workspace_id TEXT,domain_id TEXT,domain TEXT,status TEXT);
  CREATE TABLE workspace_domains(workspace_id TEXT,domain_id TEXT,verification_status TEXT);
  CREATE TABLE network_targets(id TEXT PRIMARY KEY,workspace_id TEXT,authorization_status TEXT,addresses_json TEXT,scope_state TEXT DEFAULT 'in_scope');`);
sql.exec(readFileSync(new URL('../database/migrations/119-external-exposure-jobs.sql',import.meta.url),'utf8'));
sql.exec(readFileSync(new URL('../database/migrations/120-tls-authorization.sql',import.meta.url),'utf8'));
sql.exec(readFileSync(new URL('../database/migrations/135-active-check-consents.sql',import.meta.url),'utf8'));
const prepare=(query,args=[])=>({bind:(...values)=>prepare(query,values),first:async()=>sql.prepare(query).get(...args)||null,
  all:async()=>({results:sql.prepare(query).all(...args)}),run:async()=>({meta:{changes:sql.prepare(query).run(...args).changes}})});
const sent=[];
const env={cybermeters_db:{prepare},SCAN_QUEUE:{send:async message=>sent.push(message)},TLS_ASSESSMENT_MODE:'evidence-v1'};
const check={control:'protocol',protocol:'tls1_2',cipher_id:null};
const lookupTlsDns=async(_host,type)=>type==='A'?{Status:0,Answer:[{type:1,name:_host+'.',data:'8.8.8.8'}]}:{Status:0,Answer:[]};
let collectorCalls=0;
const collectTlsAssessment=async(_env,input)=>{
  collectorCalls++;
  // Every request must pass the probe's own contract, as in production
  // (22 Oct 2026: an extra plan-only scope key made every request invalid_scope).
  { const verdict=validateTlsAssessmentRequest(input); if(!verdict.ok)console.error("PROBE_CONTRACT", verdict.reason, JSON.stringify(input.scope), input.checks?.map(c=>c.control).join(",")); assert.equal(verdict.ok,true); }
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
      generation:0,special_consent:false,special_checks:{},consent_version:null}}],selected:[{endpoint_index:0,check}],static_results:[],results:[],
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
  const workspace='w_interrupt',domain=`${scanId.replaceAll('_','-')}.example.org`,domainId=`d_${scanId}`,now=Date.now();
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
const interruptedCollector=async(_env,input)=>{assertProbeRequest(input);throw new Error('simulated collector interruption');};
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
sql.prepare("INSERT INTO network_targets(id,workspace_id,authorization_status,addresses_json) VALUES(? ,?,'attested',?)").run('target_scope',scopeWorkspace,'["8.8.8.8"]');
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
// The planner offers an authorised service only while its network target is
// in scope: its address is observed in the workspace's verified DNS
// (network-ownership.js). Out of scope, the service is not planned at all.
{
  const scan={id:'scope_plan',workspace_id:scopeWorkspace,domain_id:scopeDomainId,domain:scopeDomain};
  const lookup=async(host,type)=>type==='A'?{Status:0,Answer:[{name:`${host}.`,type:1,data:'8.8.8.8'}]}:{Status:0,Answer:[]};
  const services=async()=>(await loadTlsEndpoints(env,scan,{lookup})).endpoints.filter(e=>e.scope.kind==='authorized_service').length;
  assert.equal(await services(),1,'an in-scope target\'s service is planned');
  const deferred=async()=>(await loadTlsEndpoints(env,scan,{lookup})).deferred_services;
  assert.deepEqual(await deferred(),[],'nothing deferred while in scope');
  sql.prepare("UPDATE network_targets SET scope_state='out_of_scope' WHERE id='target_scope'").run();
  assert.equal(await services(),0,'an out-of-scope target\'s service is not planned');
  assert.deepEqual(await deferred(),[{hostname:scopeDomain,port:587,reason:'network_target_out_of_scope'}],'...and it is listed as deferred, with the reason');
  sql.prepare("UPDATE network_targets SET scope_state=NULL WHERE id='target_scope'").run();
  assert.equal(await services(),0,'an unchecked target\'s service is not planned');
  assert.deepEqual(await deferred(),[{hostname:scopeDomain,port:587,reason:'network_target_scope_unchecked'}],'...and it is listed as deferred, unchecked');
  sql.prepare("UPDATE network_targets SET scope_state='in_scope' WHERE id='target_scope'").run();
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
// The same atomic fence holds for network-target scope: a target that leaves
// verified DNS after collection cannot have its evidence written.
{
  const generation=sql.prepare('SELECT generation FROM workspace_tls_authorizations WHERE workspace_id=?').get(scopeWorkspace).generation;
  // The earlier jobs' leases are released so this tenant is not busy.
  sql.prepare("UPDATE external_exposure_jobs SET lease_until=0 WHERE workspace_id=?").run(scopeWorkspace);
  const third=scopedJob('scope_target',generation);
  const leaveScopeBeforeReceipt=async(...args)=>{
    const receipt=await collectTlsAssessment(...args);
    sql.prepare("UPDATE network_targets SET scope_state='out_of_scope' WHERE id='target_scope'").run();
    return receipt;
  };
  assert.equal((await processExposureMessage(third.message,env,{lookupTlsDns,collectTlsAssessment:leaveScopeBeforeReceipt})).outcome,'tls_fence_lost');
  assert.equal(JSON.parse(sql.prepare('SELECT plan_json FROM external_exposure_jobs WHERE scan_id=?').get('scope_target').plan_json).tls.results.length,0);
  sql.prepare("UPDATE network_targets SET scope_state='in_scope' WHERE id='target_scope'").run();
}
// A normal check must carry a valid projected scope even when the plan
// contains Active Checks grants. Intrusive controls remain withheld.
// C-28: current Active Checks authority is projected to the probe wire scope.
await test('special-control scope matches the probe contract', async () => {
  const workspace='w_special',scanId='tls_special_slices',domainId='d_special',domain='special.example.org',now=Date.now();
  sql.prepare('INSERT INTO workspaces VALUES(?,NULL)').run(workspace);
  sql.prepare('INSERT INTO scans VALUES(?,?,?,?,?)').run(scanId,workspace,domainId,domain,'queued');
  sql.prepare("INSERT INTO workspace_domains VALUES(?,?,'verified')").run(workspace,domainId);
  // The legacy switch stays OFF: only the Active Checks grant authorises the
  // intrusive controls (migration 135). The legacy row just carries generation 1.
  sql.prepare('INSERT INTO workspace_tls_authorizations(workspace_id,enabled,generation,consent_version,updated_at) VALUES(?,0,1,NULL,?)')
    .run(workspace,new Date(now).toISOString());
  sql.prepare(`INSERT INTO active_check_consents(id,workspace_id,kind,domain_id,domain,hosts_json,checks_json,actor_user_id,actor_workspace_role,
      signer_name,signer_title,authority_text,authority_version,created_at) VALUES('acc_special',?,'grant',?,?,'[]',?,'u','owner','Pat','IT','text','v',?)`)
    .run(workspace,domainId,domain,JSON.stringify(['tls_intrusive_robot','tls_intrusive_ccs']),new Date(now).toISOString());
  const authoriseActiveCheck=async()=>({authorised:true,reason:'authorised',consent_id:'acc_special'});
  const endpoint={hostname:domain,sni:domain,address:'8.8.8.8',port:443,transport:'tcp',application_protocol:'https',
    dns_addresses:['8.8.8.8'],dns_observed_at:new Date(now).toISOString()};
  const controls=['protocol'];
  const selected=controls.map(control=>({endpoint_index:0,check:{control,protocol:'tls1_2',cipher_id:null}}));
  const plan={content_state:'not_requested',checks:[],tls:{profile_version:TLS_PROFILE_VERSION,policy_version:TLS_POLICY_VERSION,
    endpoints:[{endpoint,endpoint_identity:tlsEndpointIdentity(endpoint),scope:{kind:'standard_https',service_authorization_id:null,
      generation:1,special_consent:true,special_checks:{robot:'acc_special',ccs:'acc_special'},consent_version:'active-checks-2026-10-22'}}],selected,static_results:[],results:[],
    cursor:0,gaps:[],omitted_checks:0,omitted_services:0,state:'pending'}};
  sql.prepare('INSERT INTO external_exposure_jobs(scan_id,workspace_id,domain_id,domain,plan_json,created_ms,deadline_ms,updated_at) VALUES(?,?,?,?,?,?,?,?)')
    .run(scanId,workspace,domainId,domain,JSON.stringify(plan),now,now+30*60_000,new Date(now).toISOString());
  const reservations=[];
  const specialCollector=async(_env,input)=>{
    assertProbeRequest(input);
    assert.equal(input.scope.special_consent, true);
    assert.equal(input.scope.consent_version, TLS_SPECIAL_CONSENT_VERSION);
    assert.equal(Object.hasOwn(input.scope, 'special_checks'), false);
    // Request mutant: replacing the projection with raw plan scope reproduces
    // the real probe rejection; the fake must never accept this drift again.
    const rawScope = plan.tls.endpoints[0].scope;
    assert.deepEqual(validateTlsAssessmentRequest({...input, scope: rawScope}), {ok: false, reason: 'invalid_scope'});
    assert.equal(rawScope.consent_version, 'active-checks-2026-10-22', 'stored authority is unchanged');
    // The wire projection does not release an intrusive engine. Its genuine
    // contract refusal stays visible rather than a fake accepting the request.
    for (const [control, max_connections] of [['robot',21],['ccs',5]]) {
      const verdict = validateTlsAssessmentRequest({...input, checks:[{control,protocol:'tls1_2',cipher_id:null}], max_connections});
      assert.deepEqual([verdict.ok, verdict.reason ?? null], TLS_SPECIAL_CONTROLS_AVAILABLE ? [true,null] : [false,'control_unavailable']);
    }
    assert.deepEqual(validateTlsAssessmentRequest({...input,
      scope: tlsProbeScope({...rawScope, consent_version: 'unknown-authority-version'})}), {ok: false, reason: 'invalid_scope'});
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
  assert.equal((await processExposureMessage(message,env,{lookupTlsDns,collectTlsAssessment:specialCollector,authoriseActiveCheck})).outcome,'complete');
  assert.deepEqual(reservations,[['protocol',16]]);
  const finished=sql.prepare('SELECT charged_requests,plan_json FROM external_exposure_jobs WHERE scan_id=?').get(scanId);
  assert.equal(finished.charged_requests,1);
  assert.equal(JSON.parse(finished.plan_json).tls.results.length,1);
});
// RELEASE_RESERVATION_FIXTURE_BEGIN
// This sibling runs the original three-slice proof with released engines only
// in an isolated source copy; the real catalog and production switch stay OFF.
await test('released intrusive controls keep protocol/ROBOT/CCS reservations isolated', async () => {
  if (!TLS_SPECIAL_CONTROLS_AVAILABLE) {
    const root = dirname(dirname(fileURLToPath(import.meta.url)));
    const fixture = mkdtempSync(join(tmpdir(), 'tls-reservations-release-'));
    try {
      for (const tree of ['shared', 'workers/scan-api/src', 'workers/network-probe/src', 'scripts/lib', 'database/migrations']) {
        cpSync(join(root, tree), join(fixture, tree), {recursive:true});
      }
      symlinkSync(join(root, 'workers/scan-api/node_modules'), join(fixture, 'workers/scan-api/node_modules'), 'dir');
      const catalog = join(fixture, 'shared/tls/catalog.js');
      const original = readFileSync(catalog, 'utf8');
      assert.ok(original.includes('TLS_SPECIAL_CONTROLS_AVAILABLE = false'));
      writeFileSync(catalog, original.replace('TLS_SPECIAL_CONTROLS_AVAILABLE = false', 'TLS_SPECIAL_CONTROLS_AVAILABLE = true'));
      const source = readFileSync(fileURLToPath(import.meta.url), 'utf8');
      const start = source.indexOf('\n// RELEASE_RESERVATION_FIXTURE_BEGIN');
      const end = source.indexOf('\n// RELEASE_RESERVATION_FIXTURE_END', start);
      assert.ok(start > 0 && end > start);
      // Reuse this exact sibling and its database setup, without the unrelated
      // queue/planner tests whose purpose is to prove the engine is withheld.
      writeFileSync(join(fixture, 'scripts/validate-deep-tls-queue.js'),
        source.slice(0, source.indexOf('const started=performance.now();')) + source.slice(start, end));
      const output = execFileSync(process.execPath, [join(fixture, 'scripts/validate-deep-tls-queue.js')],
        {encoding:'utf8', timeout:30000});
      assert.match(output, /TLS_RESERVATIONS_RELEASED_OK/);
      assert.equal(readFileSync(join(root, 'shared/tls/catalog.js'), 'utf8'), original, 'production switch unchanged');
      return;
    } finally { rmSync(fixture, {recursive:true, force:true}); }
  }
  const workspace='w_reservations',scanId='tls_reservation_slices',domainId='d_reservations',domain='reservations.example.org',now=Date.now();
  sql.prepare('INSERT INTO workspaces VALUES(?,NULL)').run(workspace);
  sql.prepare('INSERT INTO scans VALUES(?,?,?,?,?)').run(scanId,workspace,domainId,domain,'queued');
  sql.prepare("INSERT INTO workspace_domains VALUES(?,?,'verified')").run(workspace,domainId);
  // The legacy switch stays OFF: only the Active Checks grant authorises the
  // intrusive controls (migration 135). The legacy row just carries generation 1.
  sql.prepare('INSERT INTO workspace_tls_authorizations(workspace_id,enabled,generation,consent_version,updated_at) VALUES(?,0,1,NULL,?)')
    .run(workspace,new Date(now).toISOString());
  sql.prepare(`INSERT INTO active_check_consents(id,workspace_id,kind,domain_id,domain,hosts_json,checks_json,actor_user_id,actor_workspace_role,
      signer_name,signer_title,authority_text,authority_version,created_at) VALUES('acc_reservations',?,'grant',?,?,'[]',?,'u','owner','Pat','IT','text','v',?)`)
    .run(workspace,domainId,domain,JSON.stringify(['tls_intrusive_robot','tls_intrusive_ccs']),new Date(now).toISOString());
  const authoriseActiveCheck=async()=>({authorised:true,reason:'authorised',consent_id:'acc_reservations'});
  const endpoint={hostname:domain,sni:domain,address:'8.8.8.8',port:443,transport:'tcp',application_protocol:'https',
    dns_addresses:['8.8.8.8'],dns_observed_at:new Date(now).toISOString()};
  const controls=['protocol','robot','ccs'];
  const selected=controls.map(control=>({endpoint_index:0,check:{control,protocol:'tls1_2',cipher_id:null}}));
  const plan={content_state:'not_requested',checks:[],tls:{profile_version:TLS_PROFILE_VERSION,policy_version:TLS_POLICY_VERSION,
    endpoints:[{endpoint,endpoint_identity:tlsEndpointIdentity(endpoint),scope:{kind:'standard_https',service_authorization_id:null,
      generation:1,special_consent:true,special_checks:{robot:'acc_reservations',ccs:'acc_reservations'},consent_version:'active-checks-2026-10-22'}}],selected,static_results:[],results:[],
    cursor:0,gaps:[],omitted_checks:0,omitted_services:0,state:'pending'}};
  sql.prepare('INSERT INTO external_exposure_jobs(scan_id,workspace_id,domain_id,domain,plan_json,created_ms,deadline_ms,updated_at) VALUES(?,?,?,?,?,?,?,?)')
    .run(scanId,workspace,domainId,domain,JSON.stringify(plan),now,now+30*60_000,new Date(now).toISOString());
  const reservations=[];
  const specialCollector=async(_env,input)=>{
    const verdict = validateTlsAssessmentRequest(input);
    if (!verdict.ok) console.error('PROBE_CONTRACT', verdict.reason);
    assert.equal(verdict.ok, true, `Probe request rejected: ${verdict.reason}`);
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
  assert.equal((await processExposureMessage(message,env,{lookupTlsDns,collectTlsAssessment:specialCollector,authoriseActiveCheck})).outcome,'pending');
  assert.equal((await processExposureMessage(message,env,{lookupTlsDns,collectTlsAssessment:specialCollector,authoriseActiveCheck})).outcome,'pending');
  assert.equal((await processExposureMessage(message,env,{lookupTlsDns,collectTlsAssessment:specialCollector,authoriseActiveCheck})).outcome,'complete');
  assert.deepEqual(reservations,[['protocol',16],['robot',21],['ccs',5]]);
  const finished=sql.prepare('SELECT charged_requests,plan_json FROM external_exposure_jobs WHERE scan_id=?').get(scanId);
  assert.equal(finished.charged_requests,27);
  assert.equal(JSON.parse(finished.plan_json).tls.results.length,3);
  console.log("TLS_RESERVATIONS_RELEASED_OK protocol16 robot21 ccs5 charged27");
});
// RELEASE_RESERVATION_FIXTURE_END
// The planner asks Active Checks consent per intrusive control and per address and
// records only the granted ones. With the controls unavailable it still asks
// (22 Oct 2026, Executive: a grant must read "Authorised — not yet available"),
// records the grant as granted_checks only, and never makes it runnable: no
// special_checks, no special_consent, nothing new reaches the probe.
{
  const scan={id:'tls_plan_consent',workspace_id:'w_special',domain_id:'d_special',domain:'special.example.org'};
  const asked=[];
  const authorise=async(_env,q)=>{asked.push([q.check,q.host,q.address,q.domain,q.workspaceId]);
    return q.check==='tls_intrusive_robot'?{authorised:true,consent_id:'acc_plan'}:{authorised:false,reason:'check_not_in_grant',consent_id:null};};
  const off=await loadTlsEndpoints(env,scan,{lookup:lookupTlsDns,authorise,specialControlsAvailable:false});
  assert.equal(asked.length,3,'one consent lookup per intrusive control while the engine is withheld');
  assert.equal(off.endpoints[0].scope.special_consent,false);
  assert.deepEqual(off.endpoints[0].scope.special_checks,{},'a grant is never runnable while the engine is withheld');
  assert.deepEqual(off.endpoints[0].scope.granted_checks,{robot:'acc_plan'});
  asked.length=0;
  const on=await loadTlsEndpoints(env,scan,{lookup:lookupTlsDns,authorise,specialControlsAvailable:true,trigger:'manual'});
  assert.deepEqual(asked,['tls_intrusive_heartbleed','tls_intrusive_robot','tls_intrusive_ccs'].map(c=>[c,'special.example.org','8.8.8.8','special.example.org','w_special']));
  assert.deepEqual(on.endpoints[0].scope.special_checks,{robot:'acc_plan'});
  assert.equal(on.endpoints[0].scope.special_consent,true,'a scan a person started runs the granted control');
  // F1: the signed consent is "on demand". A scheduled scan, or one with no
  // trigger, never runs an intrusive control; it states why.
  for(const trigger of ['scheduled',undefined]){
    const held=await loadTlsEndpoints(env,scan,{lookup:lookupTlsDns,authorise,specialControlsAvailable:true,trigger});
    assert.deepEqual(held.endpoints[0].scope.special_checks,{},`${trigger} scan: never runnable`);
    assert.equal(held.endpoints[0].scope.special_consent,false);
    assert.deepEqual(held.endpoints[0].scope.held_checks,{robot:'scheduled_or_unknown_origin'});
    const planned=buildBudgetedTlsCheckPlan({endpoints:held.endpoints,cipherCatalog:[],observedHttpsHosts:['special.example.org'],scanId:'held'});
    assert.ok(!planned.selected.some(r=>r.check.control==='robot'),'a held control is never selected for the probe');
    assert.deepEqual(planned.static_results.filter(r=>r.check.control==='robot').map(r=>[r.state,r.reason]),[['unexecutable','scheduled_or_unknown_origin']]);
  }
  // F1: a grant for the host does not reach a shared provider edge, and the
  // customer is told so, not "requires your authorisation".
  const edge=async(_env,q)=>q.check==='tls_intrusive_robot'
    ?{authorised:false,reason:'address_out_of_scope',consent_id:null,address_scope:'address_is_shared_provider_infrastructure'}
    :{authorised:false,reason:'check_not_in_grant',consent_id:null};
  const atEdge=await loadTlsEndpoints(env,scan,{lookup:lookupTlsDns,authorise:edge,specialControlsAvailable:true,trigger:'manual'});
  assert.deepEqual(atEdge.endpoints[0].scope.special_checks,{});
  assert.deepEqual(atEdge.endpoints[0].scope.held_checks,{robot:'provider_infrastructure_not_tested'});
  const unowned=async(_env,q)=>q.check==='tls_intrusive_robot'
    ?{authorised:false,reason:'address_out_of_scope',consent_id:null,address_scope:'address_not_observed_in_verified_dns'}
    :{authorised:false,reason:'check_not_in_grant',consent_id:null};
  const atUnowned=await loadTlsEndpoints(env,scan,{lookup:lookupTlsDns,authorise:unowned,specialControlsAvailable:true,trigger:'manual'});
  assert.deepEqual(atUnowned.endpoints[0].scope.held_checks,{robot:'address_not_verified_not_tested'});
}
// F1 (24 Oct 2026): an explicitly authorised additional TLS service is planned
// on its own authority, without waiting for the website checks to have seen
// HTTPS on that host. Normal checks and granted specials both run; a standard
// host still waits for an observation; a tight budget keeps the named service
// even when a discovered host sorts before it.
{
  const ep=(hostname,address,kind,scope={})=>{const endpoint={hostname,sni:hostname,address,port:443,transport:'tcp',
    application_protocol:'https',dns_addresses:[address],dns_observed_at:new Date().toISOString()};
    return {endpoint,endpoint_identity:tlsEndpointIdentity(endpoint),scope:{kind,...scope}};};
  const granted={special_consent:true,special_checks:{heartbleed:'acc_f1',robot:'acc_f1',ccs:'acc_f1'},granted_checks:{},held_checks:{}};
  const service=ep('probe.special.example.org','8.8.4.4','authorized_service',{service_authorization_id:'svc_f1',generation:1,...granted});
  const standard=ep('alpha.example.org','8.8.8.8','standard_https',{special_consent:false,special_checks:{},granted_checks:{},held_checks:{}});
  const plan=buildBudgetedTlsCheckPlan({endpoints:[standard,service],cipherCatalog:[],observedHttpsHosts:[],scanId:'f1_fresh'});
  const onService=plan.selected.filter(r=>r.endpoint_index===1).map(r=>r.check.control);
  assert.ok(onService.includes('certificate')&&onService.includes('protocol'),'F1: normal checks are planned on the authorised service with no previous observation');
  if(TLS_SPECIAL_CONTROLS_AVAILABLE){
    for(const control of ['heartbleed','robot','ccs'])assert.ok(onService.includes(control),`F1: the granted ${control} test is planned on the authorised service`);
  }
  assert.ok(!plan.deferred_hosts.some(d=>d.hostname==='probe.special.example.org'),'F1: the authorised service is never deferred for a missing website observation');
  assert.deepEqual(plan.deferred_hosts.filter(d=>d.hostname==='alpha.example.org').map(d=>d.reason),['https_service_not_observed'],
    'control: a discovered standard host still waits for an HTTPS observation');
  const serviceRows=plan.selected.filter(r=>r.endpoint_index===1).length;
  const tight=buildBudgetedTlsCheckPlan({endpoints:[standard,service],cipherCatalog:[],observedHttpsHosts:['alpha.example.org'],scanId:'f1_tight',maxChecks:serviceRows});
  assert.ok(tight.selected.length===serviceRows&&tight.selected.every(r=>r.endpoint_index===1),'F1: a tight budget keeps the named service first');
  assert.deepEqual(tight.deferred_hosts.filter(d=>d.hostname==='alpha.example.org').map(d=>d.reason),['tls_plan_budget']);
  // Scheduled: the service's normal checks still run; its specials are held, with the reason.
  const scheduled=ep('probe.special.example.org','8.8.4.4','authorized_service',{service_authorization_id:'svc_f1',generation:1,special_consent:false,
    special_checks:{},granted_checks:{},held_checks:{heartbleed:'scheduled_or_unknown_origin',robot:'scheduled_or_unknown_origin',ccs:'scheduled_or_unknown_origin'}});
  const held=buildBudgetedTlsCheckPlan({endpoints:[scheduled],cipherCatalog:[],observedHttpsHosts:[],scanId:'f1_scheduled'});
  assert.ok(held.selected.some(r=>r.check.control==='certificate'),'scheduled: the authorised service still gets its normal checks');
  assert.ok(!held.selected.some(r=>['heartbleed','robot','ccs'].includes(r.check.control)),'scheduled: no special test is selected');
  assert.deepEqual(held.static_results.map(r=>[r.check.control,r.state,r.reason]).sort(),
    [['ccs','unexecutable','scheduled_or_unknown_origin'],['heartbleed','unexecutable','scheduled_or_unknown_origin'],['robot','unexecutable','scheduled_or_unknown_origin']]);
}
// R0 P1 on #974 (Seat 3, fix ported from #973): with the declared service
// selected at job creation, the first-scan re-plan must still pick up the
// domain's own web host once this job saw HTTPS on it, keeping the service.
{
  const { replanTlsFromOwnResults } = await import('../workers/scan-api/src/engines/exposure-jobs.js');
  const ep=(hostname,address,scope)=>({endpoint:{hostname,sni:hostname,address,port:443,transport:'tcp',application_protocol:'https'},
    endpoint_identity:`${hostname}|${hostname}|${address}|443|tcp|https`,scope});
  const apex=ep('shop.example.org','192.0.2.40',{kind:'standard_https',special_consent:false,special_checks:{}});
  const probe=ep('probe.shop.example.org','192.0.2.41',{kind:'authorized_service',service_authorization_id:'tlsservice_x',special_consent:true,
    special_checks:{heartbleed:'acc_f1',robot:'acc_f1',ccs:'acc_f1'}});
  const endpoints=[apex,probe];
  const tls=buildBudgetedTlsCheckPlan({endpoints,cipherCatalog:[],observedHttpsHosts:[],scanId:'scan_f1_declared'});
  assert.ok(tls.selected.length>0&&tls.selected.every(r=>r.endpoint_index===1),'precondition: only the declared service is selected at creation');
  assert.ok(tls.deferred_hosts.some(h=>h.hostname==='shop.example.org'&&h.reason==='https_service_not_observed'),'precondition: the web host waits');
  const plan={checks:[],hosts:['shop.example.org'],tls:{...tls,endpoints,results:[],state:'pending'}};
  const own=[{rule_id:'client-secret',url:'https://shop.example.org/',state:'not_found',comparable:true,reason:'explicit_absence'}];
  assert.equal(replanTlsFromOwnResults(plan,own),true,'F1: the re-plan runs although the declared service is already selected');
  assert.ok(plan.tls.selected.some(r=>r.endpoint_index===0),'F1: the web host is planned after this job\'s own HTTPS observation');
  if(TLS_SPECIAL_CONTROLS_AVAILABLE)assert.ok(plan.tls.selected.some(r=>r.endpoint_index===1&&r.check.control==='heartbleed'),'F1: the declared service stays planned');
  // A standard plan that already selected checks is still untouched.
  const std={checks:[],hosts:['shop.example.org'],tls:{...buildBudgetedTlsCheckPlan({endpoints:[apex],cipherCatalog:[],observedHttpsHosts:['shop.example.org'],scanId:'std'}),endpoints:[apex],results:[],state:'pending'}};
  assert.equal(replanTlsFromOwnResults(std,own),false,'a plan with standard checks already selected is not re-planned');
}
// F1: the authorised service is planned only while its current DNS answer equals
// the authorised IP target; otherwise it is not planned and the gap says why.
{
  const scan={id:'scope_mismatch',workspace_id:scopeWorkspace,domain_id:scopeDomainId,domain:scopeDomain};
  const moved=async(host,type)=>type==='A'?{Status:0,Answer:[{name:`${host}.`,type:1,data:'9.9.9.9'}]}:{Status:0,Answer:[]};
  const plannedMoved=await loadTlsEndpoints(env,scan,{lookup:moved});
  assert.equal(plannedMoved.endpoints.filter(e=>e.scope.kind==='authorized_service').length,0,'DNS mismatch: the service is not planned');
  assert.ok(plannedMoved.gaps.some(g=>g.port===587&&g.reason==='dns_target_mismatch_or_unavailable'),'DNS mismatch: the gap is stated with its reason');
}
// F1 end to end through loadTlsEndpoints: an HTTPS (443) authorised service, a
// scan a person started and a grant for all three specials → the budgeted plan
// gives that endpoint its normal checks and the three specials with NO previous
// website observation; the same service with a moved DNS answer is not planned.
{
  sql.prepare(`INSERT INTO workspace_tls_service_authorizations
    (id,workspace_id,domain_id,hostname,sni,port,application_protocol,network_target_id,authorization_status,generation,authorized_by,authorized_at,updated_at)
    VALUES(?,?,?,?,?,?,?,?,'active',1,'admin',?,?)`).run('service_f1_https',scopeWorkspace,scopeDomainId,scopeDomain,scopeDomain,443,'https','target_scope',new Date().toISOString(),new Date().toISOString());
  try {
    const scan={id:'f1_e2e',workspace_id:scopeWorkspace,domain_id:scopeDomainId,domain:scopeDomain};
    const at=(address)=>async(host,type)=>type==='A'?{Status:0,Answer:[{name:`${host}.`,type:1,data:address}]}:{Status:0,Answer:[]};
    const grant=async()=>({authorised:true,consent_id:'acc_f1_e2e'});
    const loaded=await loadTlsEndpoints(env,scan,{lookup:at('8.8.8.8'),authorise:grant,specialControlsAvailable:TLS_SPECIAL_CONTROLS_AVAILABLE,trigger:'manual'});
    const index=loaded.endpoints.findIndex(e=>e.scope.kind==='authorized_service'&&e.endpoint.port===443);
    assert.ok(index>=0,'F1 e2e: the 443 authorised service is loaded');
    if(TLS_SPECIAL_CONTROLS_AVAILABLE){
      assert.deepEqual(Object.keys(loaded.endpoints[index].scope.special_checks).sort(),['ccs','heartbleed','robot'],'F1 e2e: a manual scan with a grant makes the three specials runnable');
    }
    const plan=buildBudgetedTlsCheckPlan({endpoints:loaded.endpoints,cipherCatalog:[],observedHttpsHosts:[],scanId:'f1_e2e'});
    const controls=plan.selected.filter(r=>r.endpoint_index===index).map(r=>r.check.control);
    assert.ok(controls.includes('certificate')&&controls.includes('protocol'),'F1 e2e: normal checks are planned on the 443 service');
    if(TLS_SPECIAL_CONTROLS_AVAILABLE)for(const c of ['heartbleed','robot','ccs'])assert.ok(controls.includes(c),`F1 e2e: ${c} is planned on the 443 service`);
    // The domain's own standard HTTPS endpoint (same host:443 here) still waits
    // for a website observation; the authorised service beside it does not.
    const standard=loaded.endpoints.findIndex(e=>e.scope.kind==='standard_https'&&e.endpoint.port===443);
    assert.ok(standard>=0&&!plan.selected.some(r=>r.endpoint_index===standard),'F1 e2e control: the unobserved standard endpoint is not planned');
    const moved=await loadTlsEndpoints(env,scan,{lookup:at('9.9.9.9'),authorise:grant,specialControlsAvailable:TLS_SPECIAL_CONTROLS_AVAILABLE,trigger:'manual'});
    assert.ok(!moved.endpoints.some(e=>e.scope.kind==='authorized_service'&&e.endpoint.port===443),'F1 e2e: a 443 service whose DNS moved is not planned');
    assert.ok(moved.gaps.some(g=>g.port===443&&g.application_protocol==='https'&&g.reason==='dns_target_mismatch_or_unavailable'),'F1 e2e: ...and the 443 gap is stated');
  } finally {
    sql.prepare("UPDATE workspace_tls_service_authorizations SET authorization_status='revoked' WHERE id='service_f1_https'").run();
  }
}
// F1 rerun (24 Oct 2026): one slice duration per special, shared by scan-api and
// the probe contract. ROBOT's slice holds its 25 s engine run plus overhead.
{
  assert.deepEqual(TLS_SPECIAL_SLICE_DURATION_MS,{heartbleed:25000,robot:50000,ccs:25000});
  assert.equal(tlsSliceDurationMs([{control:'robot',protocol:'tls1_2',cipher_id:null}]),50000);
  assert.equal(tlsSliceDurationMs([{control:'protocol',protocol:'tls1_2',cipher_id:null}]),TLS_SLICE_LIMITS.durationMs,'normal slices keep 25 s');
  assert.equal(tlsSliceDurationMs([]),TLS_SLICE_LIMITS.durationMs);
  const t=Date.now(), iso=ms=>new Date(t+ms).toISOString();
  const base={schema_version:'tls-assessment-request-v1',request_id:'r_dur',workspace_id:'w1',scan_id:'s1',domain_id:'d1',domain:'acme.org',
    endpoint:{hostname:'probe.acme.org',sni:'probe.acme.org',address:'8.8.8.8',port:443,transport:'tcp',application_protocol:'https',
      dns_addresses:['8.8.8.8'],dns_observed_at:iso(-1000)},
    scope:{kind:'authorized_service',service_authorization_id:'svc1',generation:2,special_consent:true,consent_version:TLS_SPECIAL_CONSENT_VERSION},
    max_bytes:20000};
  const robot={...base,checks:[{control:'robot',protocol:'tls1_2',cipher_id:null}],max_connections:21};
  const normal={...base,scope:{...base.scope,special_consent:false,consent_version:null},checks:[{control:'protocol',protocol:'tls1_2',cipher_id:null}],max_connections:4};
  assert.equal(validateTlsAssessmentRequest({...robot,deadline_at:iso(45000)},t).ok,true,'a ROBOT slice may run 45 s');
  assert.equal(validateTlsAssessmentRequest({...robot,deadline_at:iso(51000)},t).reason,'invalid_deadline','but never past its 50 s slice');
  assert.equal(validateTlsAssessmentRequest({...normal,deadline_at:iso(30000)},t).reason,'invalid_deadline','a normal slice stays capped at 25 s');
  assert.equal(validateTlsAssessmentRequest({...normal,deadline_at:iso(20000)},t).ok,true);
  // scan-api sizes the slice from the same helper (the 25 s cut was the F1 defect).
  const src=readFileSync(new URL('../workers/scan-api/src/engines/exposure-jobs.js',import.meta.url),'utf8');
  assert.ok(src.includes('const remaining=Math.min(tlsSliceDurationMs(items.map(item=>item.check)),row.deadline_ms-now);'),'the TLS slice timer uses the shared per-special duration');
}
// A revoked grant stops the intrusive control in SQL itself: even when the
// JavaScript precheck still says yes, the reservation fence refuses, and no
// connection is opened.
{
  const workspace='w_special',scanId='tls_special_revoked',domainId='d_special',domain='special.example.org',now=Date.now();
  sql.prepare('INSERT INTO scans VALUES(?,?,?,?,?)').run(scanId,workspace,domainId,domain,'queued');
  sql.prepare(`INSERT INTO active_check_consents(id,workspace_id,kind,domain_id,domain,hosts_json,checks_json,actor_user_id,actor_workspace_role,
      signer_name,signer_title,authority_text,authority_version,created_at) VALUES('acc_revoked',?,'grant',?,?,'[]',?,'u','owner','Pat','IT','text','v',?)`)
    .run(workspace,domainId,domain,JSON.stringify(['tls_intrusive_robot']),new Date(now).toISOString());
  sql.prepare(`INSERT INTO active_check_consents(id,workspace_id,kind,grant_id,actor_user_id,actor_workspace_role,created_at)
      VALUES('acc_revoked_r',?,'revocation','acc_revoked','u','owner',?)`).run(workspace,new Date(now).toISOString());
  const endpoint={hostname:domain,sni:domain,address:'8.8.8.8',port:443,transport:'tcp',application_protocol:'https',
    dns_addresses:['8.8.8.8'],dns_observed_at:new Date(now).toISOString()};
  const plan={content_state:'not_requested',checks:[],tls:{profile_version:TLS_PROFILE_VERSION,policy_version:TLS_POLICY_VERSION,
    endpoints:[{endpoint,endpoint_identity:tlsEndpointIdentity(endpoint),scope:{kind:'standard_https',service_authorization_id:null,
      generation:1,special_consent:true,special_checks:{robot:'acc_revoked'},consent_version:'active-checks-2026-10-22'}}],
    selected:[{endpoint_index:0,check:{control:'robot',protocol:'tls1_2',cipher_id:null}}],static_results:[],results:[],
    cursor:0,gaps:[],omitted_checks:0,omitted_services:0,state:'pending'}};
  sql.prepare('INSERT INTO external_exposure_jobs(scan_id,workspace_id,domain_id,domain,plan_json,created_ms,deadline_ms,updated_at) VALUES(?,?,?,?,?,?,?,?)')
    .run(scanId,workspace,domainId,domain,JSON.stringify(plan),now,now+30*60_000,new Date(now).toISOString());
  let collectorCalls=0;
  const outcome=(await processExposureMessage({kind:'external_exposure',v:1,scan_id:scanId,workspace_id:workspace},env,{lookupTlsDns,
    collectTlsAssessment:async()=>{collectorCalls++;throw new Error('must not connect');},
    authoriseActiveCheck:async()=>({authorised:true,reason:'authorised',consent_id:'acc_revoked'})})).outcome;
  assert.equal(collectorCalls,0,'a revoked Active Checks grant must never reach the collector');
  assert.notEqual(outcome,'pending');
  assert.equal(JSON.parse(sql.prepare('SELECT plan_json FROM external_exposure_jobs WHERE scan_id=?').get(scanId).plan_json).tls.results.length,0);
}
// A live grant that names a DIFFERENT check is refused by the fence too: the
// planned control must be in the grant's own checks_json.
{
  const workspace='w_special',scanId='tls_special_wrong_check',domainId='d_special',domain='special.example.org',now=Date.now();
  sql.prepare('INSERT INTO scans VALUES(?,?,?,?,?)').run(scanId,workspace,domainId,domain,'queued');
  sql.prepare(`INSERT INTO active_check_consents(id,workspace_id,kind,domain_id,domain,hosts_json,checks_json,actor_user_id,actor_workspace_role,
      signer_name,signer_title,authority_text,authority_version,created_at) VALUES('acc_ccs_only',?,'grant',?,?,'[]',?,'u','owner','Pat','IT','text','v',?)`)
    .run(workspace,domainId,domain,JSON.stringify(['tls_intrusive_ccs']),new Date(now).toISOString());
  const endpoint={hostname:domain,sni:domain,address:'8.8.8.8',port:443,transport:'tcp',application_protocol:'https',
    dns_addresses:['8.8.8.8'],dns_observed_at:new Date(now).toISOString()};
  const plan={content_state:'not_requested',checks:[],tls:{profile_version:TLS_PROFILE_VERSION,policy_version:TLS_POLICY_VERSION,
    endpoints:[{endpoint,endpoint_identity:tlsEndpointIdentity(endpoint),scope:{kind:'standard_https',service_authorization_id:null,
      generation:1,special_consent:true,special_checks:{robot:'acc_ccs_only'},consent_version:'active-checks-2026-10-22'}}],
    selected:[{endpoint_index:0,check:{control:'robot',protocol:'tls1_2',cipher_id:null}}],static_results:[],results:[],
    cursor:0,gaps:[],omitted_checks:0,omitted_services:0,state:'pending'}};
  sql.prepare('INSERT INTO external_exposure_jobs(scan_id,workspace_id,domain_id,domain,plan_json,created_ms,deadline_ms,updated_at) VALUES(?,?,?,?,?,?,?,?)')
    .run(scanId,workspace,domainId,domain,JSON.stringify(plan),now,now+30*60_000,new Date(now).toISOString());
  let collectorCalls=0;
  await processExposureMessage({kind:'external_exposure',v:1,scan_id:scanId,workspace_id:workspace},env,{lookupTlsDns,
    collectTlsAssessment:async()=>{collectorCalls++;throw new Error('must not connect');},
    authoriseActiveCheck:async()=>({authorised:true,reason:'authorised',consent_id:'acc_ccs_only'})});
  assert.equal(collectorCalls,0,'a grant for another check must never authorise ROBOT');
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
  // Heartbeat not offered is stated as not applicable (24 Oct 2026); a check
  // CyberMeters did not run stays unexecutable.
  assert.deepEqual([assessment.coverage.unexecutable, assessment.coverage.not_applicable],
    unexecutableReason === 'heartbeat_unavailable' ? [0, 1] : [1, 0]);
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
