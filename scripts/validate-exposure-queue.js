#!/usr/bin/env node
import { assertProbeRequest } from './lib/probe-contract-fixture.mjs';
// Real SQLite, production job functions, controlled Queue delivery harness.
// The 1,000 jobs are synthetic records, never 1,000 live customer domains.
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, writeFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import { validateExposureReceipt } from '../workers/network-probe/src/exposure-contract.js';
import { EXPOSURE_RULES } from '../shared/exposure/catalog.js';
import { exposureIdentity } from '../shared/exposure/redaction.js';
import { TLS_POLICY_VERSION, TLS_PROFILE_VERSION, tlsEndpointIdentity } from '../shared/tls/catalog.js';
import { WEBSITE_CONTENT_LIMITS, sanitizeWebsitePageDiscovery, validateWebsiteContentReceipt } from '../workers/network-probe/src/website-content-contract.js';
import { ensureExposureReady,processExposureMessage,readExposureForScan,orderExposureAssets,unresolvedExposureChecks,mergeWebsiteContentPlan,EXPOSURE_JOB_LIMITS } from '../workers/scan-api/src/engines/exposure-jobs.js';
import { loadTlsEndpoints, buildBudgetedTlsCheckPlan } from '../workers/scan-api/src/engines/tls-planner.js';

function harness(){
  const sql=new DatabaseSync(':memory:');
  sql.exec(`CREATE TABLE workspaces(id TEXT PRIMARY KEY,deleted_at TEXT);CREATE TABLE scans(id TEXT PRIMARY KEY,workspace_id TEXT,domain_id TEXT,domain TEXT,status TEXT);CREATE TABLE workspace_domains(workspace_id TEXT,domain_id TEXT,verification_status TEXT);CREATE TABLE workspace_assets(id TEXT,workspace_id TEXT,domain_id TEXT,hostname TEXT,first_seen TEXT,status TEXT,risk_level TEXT,last_observation_scan_id TEXT);CREATE TABLE asset_lifecycle_observations(id TEXT,workspace_id TEXT,domain_id TEXT,asset_id TEXT,scan_id TEXT,observation_state TEXT,dns_state TEXT,http_state TEXT,source_detail_json TEXT NOT NULL DEFAULT '{}',observed_at TEXT);CREATE TABLE website_pages(workspace_id TEXT,domain_id TEXT,path TEXT,last_observation_json TEXT,last_checked_at TEXT);`);
  sql.exec(readFileSync(new URL('../database/migrations/119-external-exposure-jobs.sql',import.meta.url),'utf8'));
  const prepare=(text,args=[])=>({bind:(...next)=>prepare(text,next),first:async()=>sql.prepare(text).get(...args)||null,all:async()=>({results:sql.prepare(text).all(...args)}),run:async()=>({meta:{changes:sql.prepare(text).run(...args).changes}})});
  const sent=[];const env={EXPOSURE_SCAN_MODE:'evidence-v1',cybermeters_db:{prepare},SCAN_QUEUE:{send:async body=>{sent.push(body);}}};
  const now=Date.now();
  const rule=EXPOSURE_RULES.find(r=>r.id==='env-config');
  function seed(i,{workspace=`ws_${i}`,count=1}={}){
    const scan={id:`scan_${i}`,workspace_id:workspace,domain_id:`dom_${i}`,domain:`asset${String(i).replaceAll('_','-')}.example.com`,status:'queued'};
    sql.prepare('INSERT OR IGNORE INTO workspaces VALUES(?,NULL)').run(workspace);
    sql.prepare('INSERT INTO scans VALUES(?,?,?,?,?)').run(...Object.values(scan));
    sql.prepare("INSERT INTO workspace_domains VALUES(?,?,'verified')").run(workspace,scan.domain_id);
    const checks=rule.paths.slice(0,count).map(path=>({rule_id:rule.id,url:`https://${scan.domain}${path}`}));
    sql.prepare('INSERT INTO external_exposure_jobs(scan_id,workspace_id,domain_id,domain,plan_json,created_ms,deadline_ms,updated_at) VALUES(?,?,?,?,?,?,?,?)').run(scan.id,workspace,scan.domain_id,scan.domain,JSON.stringify({checks}),now,now+EXPOSURE_JOB_LIMITS.completionMs,new Date(now).toISOString());
    return {scan,body:{kind:'external_exposure',v:1,scan_id:scan.id,workspace_id:workspace}};
  }
  let calls=0;
  async function collect(env,input){
    assertProbeRequest(input);
    calls++;
    const end=Date.now();
    const receipt = {schema_version:'exposure-receipt-v1',request_id:input.request_id,workspace_id:input.workspace_id,scan_id:input.scan_id,origin:input.origin,
      started_at:new Date(end).toISOString(),finished_at:new Date(end).toISOString(),quality:'complete',
      results:input.checks.map(c=>({...c,identity:exposureIdentity(c.rule_id,c.url),state:'not_found',comparable:true,finding:null,observation:null,indicators:[],reason:null})),
      telemetry:{requests:input.checks.length+2,redirects:0,retries:0,bytes_wire:120,bytes_decoded:120,duration_ms:0,byte_limit_exceeded:false,controls_completed:2},
      discoveries:{paths:[],hosts:[]},
      limitations:['listed_paths_only','no_authentication_or_exploitation','transport_overread_is_counted']};
    assert.equal(validateExposureReceipt(input,receipt).ok,true);return receipt;
  }
  return {sql,env,sent,seed,collect,get calls(){return calls;},now};
}
let assertions=0;const check=(value)=>{assert.ok(value);assertions++;};
function enableContent(h,scan){
  const row=h.sql.prepare('SELECT plan_json FROM external_exposure_jobs WHERE scan_id=?').get(scan.id);
  const plan=JSON.parse(row.plan_json);plan.content_state='pending';
  h.sql.prepare('UPDATE external_exposure_jobs SET plan_json=? WHERE scan_id=?').run(JSON.stringify(plan),scan.id);
}
function contentReceipt(input,{paths=[],results=[]}={}){
  assertProbeRequest(input);
  const stamp=new Date().toISOString(),origin=`https://${input.domain}`;
  const page=sanitizeWebsitePageDiscovery({pages:[],partial_reasons:['homepage_unavailable'],counts:{fetched:1}},input.domain);
  const receipt={schema_version:'website-content-receipt-v1',request_id:input.request_id,workspace_id:input.workspace_id,scan_id:input.scan_id,domain:input.domain,
    started_at:stamp,finished_at:stamp,quality:'partial',page_discovery:page,results,
    discoveries:[{origin,paths,hosts:[],technologies:[],controls_completed:2}],
    telemetry:{requests:3,redirects:0,retries:0,bytes_wire:120,bytes_decoded:120,duration_ms:0,byte_limit_exceeded:false,controls_completed:2},
    limitations:['same_scan_shared_bounded_content','no_authentication_or_exploitation','transport_overread_is_counted']};
  assert.deepEqual(validateWebsiteContentReceipt(input,receipt),{ok:true});return receipt;
}
{
 const h=harness(),{body,scan}=h.seed('content_once');enableContent(h,scan);let reads=0;
 const collectWebsiteContent=async(_env,input)=>{reads++;return contentReceipt(input,{paths:['/assets/current.js','/config/current.php']});};
 const [a,b]=await Promise.all([processExposureMessage(body,h.env,{collectWebsiteContent}),processExposureMessage(body,h.env,{collectWebsiteContent})]);
 check(reads===1);check([a,b].some(r=>r.outcome==='pending'));
 const row=h.sql.prepare('SELECT * FROM external_exposure_jobs WHERE scan_id=?').get(scan.id),plan=JSON.parse(row.plan_json);
 check(plan.content_state==='complete'&&row.cursor===0&&row.charged_requests===3);
 check(plan.checks.some(c=>c.url.endsWith('/assets/current.js.map')));
 check(plan.checks.some(c=>c.url.endsWith('/config/current.php.bak')));
 check(plan.checks[0].url!==`https://${scan.domain}/.env`);
 await processExposureMessage(body,h.env,{collectWebsiteContent,collect:h.collect});
 check(reads===1&&h.calls===1);
 const report=await readExposureForScan(h.env,{workspaceId:scan.workspace_id,scanId:scan.id});
 check(report.page_discovery.coverage==='not_run'&&report.costs.charged_requests>3);
 check(await readExposureForScan(h.env,{workspaceId:'another_workspace',scanId:scan.id})===null);
}
{
 const h=harness(),{body,scan}=h.seed('content_reuse');enableContent(h,scan);
 const url=`https://${scan.domain}/.env`;
 const row={rule_id:'env-config',url,identity:exposureIdentity('env-config',url),state:'uncertain',comparable:false,finding:null,observation:null,indicators:[],reason:'incomplete_controls'};
 await processExposureMessage(body,h.env,{collectWebsiteContent:async(_env,input)=>contentReceipt(input,{results:[row]})});
 const stored=h.sql.prepare('SELECT * FROM external_exposure_jobs WHERE scan_id=?').get(scan.id);
 check(JSON.parse(stored.plan_json).checks.length===0&&stored.state==='complete');
 const report=await readExposureForScan(h.env,{workspaceId:scan.workspace_id,scanId:scan.id});
 check(report.checks.length===1&&report.checks[0].state==='uncertain'&&report.coverage.uncertain===1);
 await processExposureMessage(body,h.env,{collect:h.collect});check(h.calls===0);
}
{
 const h=harness(),{body,scan}=h.seed('content_crash');enableContent(h,scan);
 await processExposureMessage(body,h.env,{collectWebsiteContent:async(_env,input)=>{assertProbeRequest(input);throw new Error('SENSITIVE_BODY_MUST_NOT_PERSIST');}});
 const failed=h.sql.prepare('SELECT * FROM external_exposure_jobs WHERE scan_id=?').get(scan.id);
 check(failed.charged_requests===WEBSITE_CONTENT_LIMITS.requests);
 check(failed.charged_bytes===WEBSITE_CONTENT_LIMITS.bytes+WEBSITE_CONTENT_LIMITS.overreadBytes);
 check(!JSON.stringify(failed).includes('SENSITIVE_BODY'));
 await processExposureMessage(body,h.env,{collectWebsiteContent:async(_env,input)=>contentReceipt(input)});
 const retried=h.sql.prepare('SELECT * FROM external_exposure_jobs WHERE scan_id=?').get(scan.id);
 check(retried.charged_requests===WEBSITE_CONTENT_LIMITS.requests+3&&retried.unknown_attempts===1);
}
{
 const h=harness(),{body,scan}=h.seed('content_revoked');enableContent(h,scan);let aborted=false;
 await processExposureMessage(body,h.env,{collectWebsiteContent:async(_env,_input,{signal})=>{
   assertProbeRequest(_input);
   h.sql.exec("UPDATE workspace_domains SET verification_status='pending'");
   return new Promise((resolve,reject)=>signal.addEventListener('abort',()=>{aborted=true;reject(new Error('cancelled'));},{once:true}));
 }});
 const row=h.sql.prepare('SELECT * FROM external_exposure_jobs WHERE scan_id=?').get(scan.id);
 check(aborted&&row.state==='cancelled'&&row.charged_requests===32);
 check(!JSON.parse(row.plan_json).page_discovery&&row.results_json==='[]');
}
{
 const h=harness(),{body,scan}=h.seed('content_late');enableContent(h,scan);
 const outcome=await processExposureMessage(body,h.env,{collectWebsiteContent:async(_env,input)=>{
   h.sql.prepare("UPDATE external_exposure_jobs SET lease_token='replacement' WHERE scan_id=?").run(scan.id);
   return contentReceipt(input);
 }});
 const row=h.sql.prepare('SELECT * FROM external_exposure_jobs WHERE scan_id=?').get(scan.id);
 check(outcome.outcome==='fence_lost'&&row.charged_requests===32&&row.results_json==='[]');
 check(JSON.parse(row.plan_json).content_state==='pending');
}
{
 const domain='owned.example.com',origin=`https://${domain}`;
 const observed={rule_id:'client-secret',url:origin+'/config.json'};
 const php={rule_id:'runtime-debug',url:origin+'/phpinfo.php'};
 const other={rule_id:'git-metadata',url:origin+'/.git/config'};
 const plan={checks:[other,php,observed],retest_checks:[],omitted_checks:0};
 mergeWebsiteContentPlan(plan,{results:[],discoveries:[{origin,paths:['/config.json'],hosts:[],technologies:['php']}],page_discovery:{}},domain);
 const index=c=>plan.checks.findIndex(row=>row.rule_id===c.rule_id&&row.url===c.url);
 check(index(observed)<index(other));check(index(php)<index(other));
 check(plan.checks.some(c=>c.rule_id===other.rule_id&&c.url===other.url));
}
{
 const h=harness(),{body,scan}=h.seed('once');
 const [a,b]=await Promise.all([processExposureMessage(body,h.env,{collect:h.collect}),processExposureMessage(body,h.env,{collect:h.collect})]);
 check(h.calls===1);check([a,b].some(r=>r.outcome==='complete'));
 await processExposureMessage(body,h.env,{collect:h.collect});check(h.calls===1);
 const result=await readExposureForScan(h.env,{workspaceId:scan.workspace_id,scanId:scan.id});
 check(result.coverage.completed===1);check(result.costs.charged_requests===3);
 check(await readExposureForScan(h.env,{workspaceId:'foreign',scanId:scan.id})===null);
 check((await processExposureMessage({...body,workspace_id:'foreign'},h.env,{collect:h.collect})).outcome==='identity_mismatch');
}
// A terminal host result is stored once, removes unrun path checks without
// charging them, and leaves an earlier content condition waiting for a retest.
for(const outcome of [
  {state:'host_does_not_resolve',reason:'authoritative_no_address',statuses:[],requests:0},
  {state:'target_unavailable',reason:'server_error',statuses:[500,503],requests:2},
  {state:'target_unavailable',reason:'edge_origin_unreachable',statuses:[522,523],requests:2},
]){
 const h=harness(),{body,scan}=h.seed(`terminal_${outcome.state}_${outcome.reason}`,{count:1});
 const first=h.sql.prepare('SELECT plan_json FROM external_exposure_jobs WHERE scan_id=?').get(scan.id);
 const plan=JSON.parse(first.plan_json);
 const original=plan.checks[0];
 plan.checks=EXPOSURE_RULES.flatMap(rule=>rule.paths.map(path=>({rule_id:rule.id,url:`https://${scan.domain}${path}`})));
 check(plan.checks.length===139);
 plan.retest_checks=[original];
 h.sql.prepare('UPDATE external_exposure_jobs SET plan_json=? WHERE scan_id=?').run(JSON.stringify(plan),scan.id);
 const terminalReceipt=async(_env,input)=>{
  assertProbeRequest(input);
  const stamp=new Date().toISOString();
  const summary=status=>({status,content_type:status?'text/html':null,body_length:status?20:0,normalized_length:status?20:0,
    body_sha256:status?'0'.repeat(64):null,normalized_sha256:status?'0'.repeat(64):null});
  const receipt={schema_version:'exposure-receipt-v1',request_id:input.request_id,workspace_id:input.workspace_id,scan_id:input.scan_id,origin:input.origin,
    started_at:stamp,finished_at:stamp,baseline:outcome.statuses.length?outcome.statuses.map(summary):[summary(0)],
    host_outcome:{state:outcome.state,reason:outcome.reason,statuses:outcome.statuses},quality:'partial',results:[],
    telemetry:{requests:outcome.requests,redirects:0,retries:0,bytes_wire:outcome.requests*20,bytes_decoded:outcome.requests*20,
      duration_ms:0,byte_limit_exceeded:false,controls_completed:outcome.requests},
    discoveries:{paths:[],hosts:[]},limitations:['listed_paths_only','no_authentication_or_exploitation','transport_overread_is_counted']};
  assert.deepEqual(validateExposureReceipt(input,receipt),{ok:true});return receipt;
 };
 const result=await processExposureMessage(body,h.env,{collect:terminalReceipt});
 const stored=h.sql.prepare('SELECT * FROM external_exposure_jobs WHERE scan_id=?').get(scan.id),next=JSON.parse(stored.plan_json);
 check(result.outcome==='complete'&&stored.cursor===0&&next.checks.length===0);
 check(next.host_outcomes.length===1&&next.host_outcomes[0].skipped_checks===139);
 check(JSON.stringify(next.retest_checks)===JSON.stringify([original]));
 check(stored.charged_requests===outcome.requests);
 const report=await readExposureForScan(h.env,{workspaceId:scan.workspace_id,scanId:scan.id});
 check(report.quality==='partial'&&report.incomplete_reason===outcome.state);
 check(report.coverage.execution_complete_hosts===1&&report.coverage.completed===0);
 check(report.host_outcomes[0].statuses.join(',')===outcome.statuses.join(','));
}
{
 const h=harness(),{body,scan}=h.seed('foreign_pending');
 const before=h.sql.prepare('SELECT * FROM external_exposure_jobs WHERE scan_id=?').get(scan.id);
 const result=await processExposureMessage({...body,workspace_id:'foreign'},h.env,{collect:h.collect});
 check(result.action==='ack'&&result.outcome==='identity_mismatch');
 check(h.calls===0&&h.sent.length===0);
 check(JSON.stringify(h.sql.prepare('SELECT * FROM external_exposure_jobs WHERE scan_id=?').get(scan.id))===JSON.stringify(before));
}
{
 const h=harness(),{body,scan}=h.seed('crash');
 h.sql.prepare("UPDATE external_exposure_jobs SET state='running',lease_until=?,lease_token='dead',charged_requests=12,charged_bytes=?,attempts=1").run(h.now-1,EXPOSURE_JOB_LIMITS.byteReservation);
 await processExposureMessage(body,h.env,{collect:h.collect});
 const result=await readExposureForScan(h.env,{workspaceId:scan.workspace_id,scanId:scan.id});
 check(result.costs.unknown_attempts===1);check(result.costs.charged_requests===15);check(result.costs.charged_bytes===EXPOSURE_JOB_LIMITS.byteReservation+120);
}
{
 const h=harness(),{body}=h.seed('retry');
 for(let i=0;i<3;i++)await processExposureMessage(body,h.env,{collect:async(_env,input)=>{assertProbeRequest(input);throw Error('SENSITIVE_VALUE_NOT_FOR_LOGS');}});
 check(h.sql.prepare('SELECT charged_requests FROM external_exposure_jobs').get().charged_requests===36);
 const result=await processExposureMessage(body,h.env,{collect:h.collect});check(result.outcome==='completion_budget');check(h.calls===0);
}
{
 // 22 Oct 2026 (blackbullbarbers.co.uk, first scan): no earlier job had observed
 // HTTPS, so every TLS host was deferred and nothing selected; the last content
 // slice ended the job 'complete' before the replan could run, although this
 // job's own content checks had observed HTTPS. The replan now runs before the
 // job's state is decided, so its TLS checks are planned.
 const firstScan=async(processMessage)=>{
   const h=harness(),{body,scan}=h.seed(`first_tls_${Math.random().toString(36).slice(2,8)}`,{count:3});
   const row=h.sql.prepare('SELECT plan_json FROM external_exposure_jobs WHERE scan_id=?').get(scan.id),plan=JSON.parse(row.plan_json);
   const endpoint={hostname:scan.domain,sni:scan.domain,address:'8.8.8.8',port:443,transport:'tcp',application_protocol:'https',
     dns_addresses:['8.8.8.8'],dns_observed_at:new Date().toISOString()};
   plan.hosts=[scan.domain];
   plan.tls={profile_version:TLS_PROFILE_VERSION,policy_version:TLS_POLICY_VERSION,scan_id:scan.id,
     endpoints:[{endpoint,endpoint_identity:tlsEndpointIdentity(endpoint),scope:{kind:'standard_https',service_authorization_id:null,generation:0,special_consent:false,special_checks:{},consent_version:null}}],
     selected:[],static_results:[],results:[],cursor:0,gaps:[],omitted_checks:0,omitted_services:0,
     deferred_hosts:[{hostname:scan.domain,port:443,reason:'https_service_not_observed'}],deferred_endpoints:[],state:'pending'};
   h.sql.prepare('UPDATE external_exposure_jobs SET plan_json=? WHERE scan_id=?').run(JSON.stringify(plan),scan.id);
   const outcome=await processMessage(body,h.env,{collect:h.collect});
   const after=h.sql.prepare('SELECT state,plan_json FROM external_exposure_jobs WHERE scan_id=?').get(scan.id);
   return {outcome:outcome.outcome,state:after.state,tls:JSON.parse(after.plan_json).tls};
 };
 const real=await firstScan(processExposureMessage);
 check(real.state==='pending'&&real.outcome==='pending');
 check(real.tls.replanned_from_job===true&&real.tls.selected.length>0);
 check(!real.tls.deferred_hosts.some((d)=>d.reason==='https_service_not_observed'));
 // Mutant: the replan moved back after the completion decision -> 0 TLS, complete.
 const source=readFileSync(new URL('../workers/scan-api/src/engines/exposure-jobs.js',import.meta.url),'utf8');
 const anchor='    if(cursor>=plan.checks.length)replanTlsFromOwnResults(plan,results);\n';
 check(source.split(anchor).length===2);
 const { mkdtempSync, rmSync } = await import('node:fs'); const { tmpdir } = await import('node:os'); const { join } = await import('node:path');
 const dir=mkdtempSync(join(tmpdir(),'cm-first-tls-'));
 try{
   const relinked=source.replace(anchor,'').replace(/from '(\.{1,2}\/[^']+)'/g,(_m,spec)=>`from '${new URL(spec,new URL('../workers/scan-api/src/engines/exposure-jobs.js',import.meta.url))}'`);
   const target=join(dir,'exposure-jobs-first-tls-mutant.mjs');writeFileSync(target,relinked);
   const mutant=await import(`file://${target}`);
   const m=await firstScan(mutant.processExposureMessage);
   check(m.state==='complete'&&m.tls.selected.length===0);
 }finally{rmSync(dir,{recursive:true,force:true});}
}
{
 // 22 Oct 2026 (sheshire.co.uk, scan_8120f550): the failure cap counts
 // CONSECUTIVE thrown slices. Two transient failures, a stored slice, then a
 // third failure must not end a healthy job; its remaining slice still runs.
 const h=harness(),{body}=h.seed('streak',{count:14});
 const fail=async(_env,input)=>{assertProbeRequest(input);throw Error('transient collector error');};
 await processExposureMessage(body,h.env,{collect:fail});
 await processExposureMessage(body,h.env,{collect:fail});
 check((await processExposureMessage(body,h.env,{collect:h.collect})).outcome==='pending');
 check(h.sql.prepare('SELECT failure_count FROM external_exposure_jobs').get().failure_count===0);
 await processExposureMessage(body,h.env,{collect:fail});
 const finished=await processExposureMessage(body,h.env,{collect:h.collect});
 check(finished.outcome==='complete');check(h.calls===2);
 // Mutant: no streak reset on a stored slice -> the job ends as completion_budget.
 const source=readFileSync(new URL('../workers/scan-api/src/engines/exposure-jobs.js',import.meta.url),'utf8');
 const anchor='results_json=?,costs_json=?,failure_count=0,';
 check(source.split(anchor).length===2);
 const { mkdtempSync, rmSync } = await import('node:fs'); const { tmpdir } = await import('node:os'); const { join } = await import('node:path');
 const dir=mkdtempSync(join(tmpdir(),'cm-exposure-streak-'));
 try{
   const relinked=source.replace(anchor,'results_json=?,costs_json=?,').replace(/from '(\.{1,2}\/[^']+)'/g,(_m,spec)=>`from '${new URL(spec,new URL('../workers/scan-api/src/engines/exposure-jobs.js',import.meta.url))}'`);
   const target=join(dir,'exposure-jobs-mutant.mjs');writeFileSync(target,relinked);
   const mutant=await import(`file://${target}`);
   const m=harness(),{body:mb}=m.seed('streak_mutant',{count:14});
   await mutant.processExposureMessage(mb,m.env,{collect:fail});await mutant.processExposureMessage(mb,m.env,{collect:fail});
   await mutant.processExposureMessage(mb,m.env,{collect:m.collect});await mutant.processExposureMessage(mb,m.env,{collect:fail});
   check((await mutant.processExposureMessage(mb,m.env,{collect:m.collect})).outcome==='completion_budget');
   check(JSON.parse(m.sql.prepare('SELECT plan_json FROM external_exposure_jobs').get().plan_json).finish_reason==='completion_budget');
 }finally{rmSync(dir,{recursive:true,force:true});}
}
{
 const h=harness(),{body}=h.seed('limit');
 h.sql.prepare('UPDATE external_exposure_jobs SET charged_requests=?').run(EXPOSURE_JOB_LIMITS.requests-2);
 check((await processExposureMessage(body,h.env,{collect:h.collect})).outcome==='network_budget');check(h.calls===0);
}
{
 const h=harness(),first=h.seed('tenant1',{workspace:'shared'}),second=h.seed('tenant2',{workspace:'shared'});
 h.sql.prepare("UPDATE external_exposure_jobs SET state='running',lease_until=?,lease_token='held' WHERE scan_id=?").run(Date.now()+30000,first.scan.id);
 for(let delivery=0;delivery<8;delivery++){
   const decision=await processExposureMessage(second.body,h.env,{collect:h.collect});
   check(decision.outcome==='tenant_busy'&&decision.action==='ack');
 }
 check(h.calls===0);check(h.sent.length===8); // exceeds Queue max_retries=3 safely

 h.sql.prepare('UPDATE external_exposure_jobs SET lease_until=0,charged_requests=? WHERE scan_id=?').run(EXPOSURE_JOB_LIMITS.workspaceRequests,first.scan.id);
 // 1a: a job that has not started waits for the hourly window instead of
 // ending partial; it stays pending and is re-sent after a delay.
 const sentBefore=h.sent.length;
 const waited=await processExposureMessage(second.body,h.env,{collect:h.collect});
 check(waited.outcome==='workspace_window_wait'&&waited.action==='ack');check(h.calls===0);
 check(h.sql.prepare('SELECT state FROM external_exposure_jobs WHERE scan_id=?').get(second.scan.id).state==='pending');
 check(h.sent.length===sentBefore+1);
 // Once the other domain's job leaves the hourly window, the waiting job runs.
 h.sql.prepare('UPDATE external_exposure_jobs SET created_ms=? WHERE scan_id=?').run(Date.now()-EXPOSURE_JOB_LIMITS.windowMs-1,first.scan.id);
 const ran=await processExposureMessage(second.body,h.env,{collect:h.collect});
 check(ran.outcome!=='workspace_window_wait'&&ran.outcome!=='network_budget');check(h.calls===1);
}
{
 // A job that already started and then meets a full window ends honestly as
 // budget_exhausted; only a job that has not started waits.
 const h=harness(),first=h.seed('window1',{workspace:'shared'}),second=h.seed('window2',{workspace:'shared'});
 h.sql.prepare('UPDATE external_exposure_jobs SET charged_requests=? WHERE scan_id=?').run(EXPOSURE_JOB_LIMITS.workspaceRequests,first.scan.id);
 h.sql.prepare('UPDATE external_exposure_jobs SET attempts=1 WHERE scan_id=?').run(second.scan.id);
 check((await processExposureMessage(second.body,h.env,{collect:h.collect})).outcome==='network_budget');check(h.calls===0);
}
{
 // 1a: a workspace with two verified domains has a two-domain hourly window, so
 // the second domain runs in the same hour as the first instead of waiting.
 const h=harness(),first=h.seed('scaled1',{workspace:'scaled'}),second=h.seed('scaled2',{workspace:'scaled'});
 h.sql.prepare('UPDATE external_exposure_jobs SET charged_requests=? WHERE scan_id=?').run(EXPOSURE_JOB_LIMITS.workspaceRequests,first.scan.id);
 const plan=JSON.parse(h.sql.prepare('SELECT plan_json FROM external_exposure_jobs WHERE scan_id=?').get(second.scan.id).plan_json);
 plan.workspace_window={domains:2,requests:EXPOSURE_JOB_LIMITS.workspaceRequests*2,bytes:EXPOSURE_JOB_LIMITS.workspaceBytes*2};
 h.sql.prepare('UPDATE external_exposure_jobs SET plan_json=? WHERE scan_id=?').run(JSON.stringify(plan),second.scan.id);
 const ran=await processExposureMessage(second.body,h.env,{collect:h.collect});
 check(ran.outcome!=='workspace_window_wait'&&ran.outcome!=='network_budget');check(h.calls===1);
 // A window that is not exactly n domain shares is ignored (one share applies).
 const third=h.seed('scaled3',{workspace:'scaled'});
 const forged=JSON.parse(h.sql.prepare('SELECT plan_json FROM external_exposure_jobs WHERE scan_id=?').get(third.scan.id).plan_json);
 forged.workspace_window={domains:2,requests:EXPOSURE_JOB_LIMITS.workspaceRequests*50,bytes:EXPOSURE_JOB_LIMITS.workspaceBytes*50};
 h.sql.prepare('UPDATE external_exposure_jobs SET plan_json=? WHERE scan_id=?').run(JSON.stringify(forged),third.scan.id);
 check((await processExposureMessage(third.body,h.env,{collect:h.collect})).outcome==='workspace_window_wait');
}
{
 // The first claim replaces the queue-wait deadline with the run deadline.
 const h=harness(),{body,scan}=h.seed('deadline');
 // A job not yet started carries the queue-wait deadline (as createJob writes it).
 h.sql.prepare('UPDATE external_exposure_jobs SET deadline_ms=created_ms+? WHERE scan_id=?').run(EXPOSURE_JOB_LIMITS.queueWaitMs,scan.id);
 const before=h.sql.prepare('SELECT deadline_ms FROM external_exposure_jobs WHERE scan_id=?').get(scan.id);
 await processExposureMessage(body,h.env,{collect:h.collect});
 const after=h.sql.prepare('SELECT deadline_ms,attempts FROM external_exposure_jobs WHERE scan_id=?').get(scan.id);
 check(after.attempts>=1);check(after.deadline_ms<before.deadline_ms);
 check(after.deadline_ms<=Date.now()+EXPOSURE_JOB_LIMITS.completionMs);
}
{
 const h=harness(),{body}=h.seed('revoke');
 h.sql.exec("UPDATE workspace_domains SET verification_status='pending'");
 check((await processExposureMessage(body,h.env,{collect:h.collect})).outcome==='authority_lost');check(h.calls===0);
}
{
 const h=harness(),{body}=h.seed('midflight');let aborted=false;
 await processExposureMessage(body,h.env,{collect:async(env,input,{signal})=>{
   assertProbeRequest(input);
   h.sql.exec("UPDATE workspace_domains SET verification_status='pending'");
   return await new Promise((resolve,reject)=>signal.addEventListener('abort',()=>{aborted=true;reject(new Error('cancelled'));},{once:true}));
 }});
 check(aborted);const row=h.sql.prepare('SELECT state,charged_requests,results_json FROM external_exposure_jobs').get();
 check(row.state==='cancelled'&&row.charged_requests===12&&row.results_json==='[]');
}
{
 const h=harness(),{body,scan}=h.seed('deadline');h.sql.prepare('UPDATE external_exposure_jobs SET deadline_ms=?').run(h.now-1);
 check((await processExposureMessage(body,h.env,{collect:h.collect})).outcome==='completion_budget');
 const result=await readExposureForScan(h.env,{workspaceId:scan.workspace_id,scanId:scan.id});check(result.coverage.budget_exhausted===1&&result.coverage.completed===0);
}
{
 const h=harness(),{scan}=h.seed('admit');h.sql.exec('DELETE FROM external_exposure_jobs');
 check(await ensureExposureReady(h.env,scan,{trigger:'scheduled',scheduled_scan_id:'scheduled_1'})===false);
 const row=h.sql.prepare('SELECT * FROM external_exposure_jobs').get();
 check(JSON.parse(row.plan_json).checks.length>20);check(JSON.parse(row.dispatch_json).trigger==='scheduled');
 await ensureExposureReady(h.env,scan);check(h.sql.prepare('SELECT count(*) n FROM external_exposure_jobs').get().n===1);
}
// C-52 N02 witness: through the real createJob, an absent trigger reaches the
// real TLS planner as null and selects ZERO intrusive checks (held, stated); the
// same grant on an explicit 'manual' trigger selects them.
for(const [body,expectSpecials] of [[{},false],[{trigger:'scheduled'},false],[{trigger:'manual'},true]]){
 const h=harness(),{scan}=h.seed(`n02_${body.trigger||'none'}`);h.sql.exec('DELETE FROM external_exposure_jobs');
 h.sql.exec(readFileSync(new URL('../database/migrations/120-tls-authorization.sql',import.meta.url),'utf8'));
 h.sql.exec(`CREATE TABLE IF NOT EXISTS network_targets(id TEXT PRIMARY KEY,workspace_id TEXT,authorization_status TEXT,addresses_json TEXT,scope_state TEXT DEFAULT 'in_scope')`);
 h.env.TLS_ASSESSMENT_MODE='evidence-v1';
 const seen=[];
 const loader=(e,s,o)=>{seen.push(o.trigger);return loadTlsEndpoints(e,s,{...o,
   lookup:async(host,type)=>type==='A'?{Status:0,Answer:[{type:1,name:`${host}.`,data:'8.8.8.8'}]}:{Status:0,Answer:[]},
   authorise:async()=>({authorised:true,reason:'authorised',consent_id:'acc_n02'}),specialControlsAvailable:true});};
 await ensureExposureReady(h.env,scan,body,{loadTlsEndpoints:loader});
 const tls=JSON.parse(h.sql.prepare('SELECT plan_json FROM external_exposure_jobs').get().plan_json).tls;
 // The persisted scope is what the post-HTTP replan reads; plan from it as the replan does.
 const scope=tls.endpoints[0].scope;
 const host=tls.endpoints[0].endpoint.hostname;
 const replan=buildBudgetedTlsCheckPlan({endpoints:tls.endpoints,cipherCatalog:[],observedHttpsHosts:[host],scanId:scan.id});
 const specials=replan.selected.filter(r=>['heartbleed','robot','ccs'].includes(r.check.control));
 check(seen.length===1&&seen[0]===(body.trigger??null));
 if(expectSpecials){check(scope.special_consent===true&&Object.keys(scope.special_checks).length===3&&specials.length>0);}
 else{
  check(scope.special_consent===false&&Object.keys(scope.special_checks).length===0);
  check(specials.length===0);
  const held=replan.static_results.filter(r=>['heartbleed','robot','ccs'].includes(r.check.control));
  check(held.length>0&&held.every(r=>r.state==='unexecutable'&&r.reason==='scheduled_or_unknown_origin'));
 }
}
{
 const h=harness(),{body,scan}=h.seed('late');
 const result=await processExposureMessage(body,h.env,{collect:async(env,input)=>{
   h.sql.prepare("UPDATE external_exposure_jobs SET lease_token='replacement',charged_requests=24,charged_bytes=? WHERE scan_id=?").run(EXPOSURE_JOB_LIMITS.byteReservation*2,scan.id);
   return h.collect(env,input);
 }});
 const row=h.sql.prepare('SELECT cursor,charged_requests,lease_token,results_json FROM external_exposure_jobs').get();
 check(result.outcome==='fence_lost');check(row.cursor===0&&row.charged_requests===24&&row.lease_token==='replacement'&&row.results_json==='[]');
}
{
 const h=harness(),{body}=h.seed('outbox');let sends=0;
 h.env.SCAN_QUEUE.send=async(message)=>{if(++sends===1)throw new Error('queue_unavailable');h.sent.push(message);};
 await processExposureMessage(body,h.env,{collect:h.collect});
 const row=h.sql.prepare('SELECT state,charged_requests FROM external_exposure_jobs').get();
 check(row.state==='complete'&&row.charged_requests===3);
 await processExposureMessage(body,h.env,{collect:h.collect});check(h.calls===1&&sends===2);
}
{
 const original={rule_id:'source-map',url:'https://assetretained.example.com/assets/runtime.js.map'};
 const hit={...original,state:'finding',comparable:true};
 const timedOut={...original,state:'uncertain',comparable:false};
 const fromA=unresolvedExposureChecks([], [hit]);
 const fromB=unresolvedExposureChecks(fromA,[timedOut]);check(fromB.length===1);
 const h=harness(),{scan}=h.seed('retained');
 h.sql.prepare("UPDATE external_exposure_jobs SET state='complete',plan_json=?,results_json=?").run(JSON.stringify({checks:[original],retest_checks:fromB}),JSON.stringify([timedOut]));
 const next={...scan,id:'scan_retained_c'};
 h.sql.prepare('INSERT INTO scans VALUES(?,?,?,?,?)').run(...Object.values(next));
 await ensureExposureReady(h.env,next);
 const planned=JSON.parse(h.sql.prepare('SELECT plan_json FROM external_exposure_jobs WHERE scan_id=?').get(next.id).plan_json);
 check(planned.checks.some(c=>c.rule_id===original.rule_id&&c.url===original.url));
 check(unresolvedExposureChecks(fromB,[{...original,state:'not_found',comparable:true}]).length===0);
}
const load=harness(),loadStart=performance.now(),jobs=[];
for(let i=0;i<1000;i++)jobs.push(load.seed(`load${i}`,{workspace:'load_tenant'}));
for(const job of jobs){await processExposureMessage(job.body,load.env,{collect:load.collect});await processExposureMessage(job.body,load.env,{collect:load.collect});}
const sums=load.sql.prepare("SELECT count(*) jobs,SUM(charged_requests) requests,SUM(charged_bytes) bytes FROM external_exposure_jobs WHERE state='complete'").get();
check(sums.jobs===1000);check(load.calls===1000);check(sums.requests===3000&&sums.bytes===120000);
// Continuously inject higher-priority arrivals while servicing an ageing pool.
const assets=Array.from({length:1000},(_,i)=>({hostname:`asset${String(i).padStart(4,'0')}.example.com`,first_seen:new Date(load.now-86400000).toISOString(),last_attempt_ms:load.now-86400000,has_finding:i<10}));
const seen=new Set();
for(let round=0;round<350;round++){
 const now=load.now+round*60000;
 assets.push({hostname:`new${round}.example.com`,first_seen:new Date(now).toISOString(),last_attempt_ms:0,has_finding:true});
 const selected=orderExposureAssets(assets,now).slice(0,4);
 for(const asset of selected){seen.add(asset.hostname);asset.last_attempt_ms=now;}
}
check(assets.slice(0,1000).every(a=>seen.has(a.hostname)));
const legacyElapsed=Math.round(performance.now()-loadStart);
const shared=harness(),sharedStart=performance.now();let contentCalls=0;
for(let i=0;i<1000;i++){
 const {body,scan}=shared.seed(`shared${i}`,{workspace:`shared_tenant_${i%10}`});enableContent(shared,scan);
 const deps={collect:shared.collect,collectWebsiteContent:async(_env,input)=>{contentCalls++;return contentReceipt(input);}};
 for(let delivery=0;delivery<4;delivery++)await processExposureMessage(body,shared.env,deps);
}
const sharedTotals=shared.sql.prepare("SELECT count(*) jobs,SUM(charged_requests) requests,SUM(charged_bytes) bytes FROM external_exposure_jobs WHERE state='complete'").get();
check(sharedTotals.jobs===1000&&contentCalls===1000&&shared.calls===1000);
check(sharedTotals.requests===6000&&sharedTotals.bytes===240000);
check(shared.sql.prepare('SELECT max(n) max_requests FROM (SELECT sum(charged_requests) n FROM external_exposure_jobs GROUP BY workspace_id)').get().max_requests===600);
const metrics={kind:'controlled_synthetic_queue',live_customer_domains:0,synthetic_asset_jobs:1000,deliveries:2000,collector_calls:load.calls,completed:sums.jobs,charged_requests:sums.requests,charged_bytes:sums.bytes,elapsed_ms:legacyElapsed,fairness_initial_assets_seen:assets.slice(0,1000).filter(a=>seen.has(a.hostname)).length,shared_content:{synthetic_jobs:1000,tenants:10,deliveries:4000,content_collector_calls:contentCalls,exposure_collector_calls:shared.calls,completed:sharedTotals.jobs,charged_requests:sharedTotals.requests,charged_bytes:sharedTotals.bytes,elapsed_ms:Math.round(performance.now()-sharedStart),transport:'controlled_receipts_not_live_network'},assertions};
const output=process.argv.indexOf('--output');if(output>=0)writeFileSync(process.argv[output+1],JSON.stringify(metrics,null,2)+'\n');
console.log(JSON.stringify(metrics));
// Plan sizing and per-domain completeness carry their own fixtures and source
// mutants; run them here so CI executes them with the queue harness.
const { spawnSync }=await import('node:child_process');
const { fileURLToPath }=await import('node:url');
const repoRoot=fileURLToPath(new URL('..',import.meta.url));
const planTests=spawnSync(process.execPath,['--test','workers/scan-api/test/exposure-plan-sizing.test.js',
  'workers/scan-api/test/exposure-phase-budget.test.js'],{cwd:repoRoot,stdio:'inherit',timeout:120000});
if(planTests.status!==0){console.error('exposure plan sizing tests failed');process.exit(1);}
