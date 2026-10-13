// Existing scan Queue continuations. Only the scan row grants tenant/scope.
// Receipts contain static indicators, never bodies; the ordinary scan report
// subsequently stores these cleaned observations in R2 with canonical findings.
import { exposureIdentity } from '../../../../shared/exposure/redaction.js';
import { planExposureChecks } from '../../../../shared/exposure/discovery.js';
import { EXPOSURE_LIMITS, validateExposureRequest, validateExposureReceipt } from '../../../network-probe/src/exposure-contract.js';
import { readBoundedJson, isProbeHostname } from '../../../network-probe/src/contract.js';
import { WEBSITE_CONTENT_LIMITS, validateWebsiteContentRequest, validateWebsiteContentReceipt } from '../../../network-probe/src/website-content-contract.js';

export const EXPOSURE_JOB_LIMITS = Object.freeze({
  hosts:4, checks:1024, requests:1024, bytes:64*1024*1024,
  workspaceRequests:4096, workspaceBytes:128*1024*1024,
  windowMs:60*60*1000, completionMs:15*60*1000, leaseMs:30000,
  attempts:150, failures:3, byteReservation:EXPOSURE_LIMITS.bytes+131072,
});
const terminal = state => ['complete','cancelled','budget_exhausted'].includes(state);
const changed = result => result?.meta?.changes === 1;
const json = (value, fallback) => { try { return JSON.parse(value); } catch { return fallback; } };
const messageFor = row => ({kind:'external_exposure',v:1,scan_id:row.scan_id,workspace_id:row.workspace_id});
const AUTHORITY = `EXISTS(SELECT 1 FROM scans s JOIN workspaces w ON w.id=s.workspace_id
  JOIN workspace_domains wd ON wd.workspace_id=s.workspace_id AND wd.domain_id=s.domain_id
  WHERE s.id=external_exposure_jobs.scan_id AND s.workspace_id=external_exposure_jobs.workspace_id
  AND s.domain_id=external_exposure_jobs.domain_id AND s.domain=external_exposure_jobs.domain
  AND s.status='queued' AND w.deleted_at IS NULL AND wd.verification_status='verified')`;

// A bounded preference (one hour) cannot indefinitely outrank an ageing asset.
// Never-checked and previously exposed assets receive a head start, not a
// permanently privileged bucket. SQL uses the same ordering before LIMIT.
export function orderExposureAssets(assets, now=Date.now()) {
  const score = row => (Number(row.last_attempt_ms) || Date.parse(row.first_seen) || now)
    - (!row.last_attempt_ms ? 3600000 : 0) - (row.has_finding ? 3600000 : 0);
  return [...assets].sort((a,b)=>score(a)-score(b)||String(a.hostname).localeCompare(String(b.hostname)));
}
export function unresolvedExposureChecks(previous=[],results=[]) {
  const retained=new Map(previous.map(c=>[c.rule_id+'|'+c.url,c]));
  for(const row of results){
    const key=row.rule_id+'|'+row.url;
    if(row.state==='finding')retained.set(key,{rule_id:row.rule_id,url:row.url});
    else if(row.comparable===true&&['not_found','observed'].includes(row.state))retained.delete(key);
  }
  return [...retained.values()];
}
function safeHost(host, domain) {
  return isProbeHostname(host) && (host === domain || host.endsWith('.'+domain));
}

async function createJob(env, scan, now, dispatch) {
  const db=env.cybermeters_db;
  const assets=await db.prepare(`SELECT a.hostname,a.first_seen,v.last_attempt_ms,
    CASE WHEN a.risk_level IN ('critical','high','medium') THEN 1 ELSE 0 END AS has_finding
    FROM workspace_assets a LEFT JOIN external_exposure_visits v
      ON v.workspace_id=a.workspace_id AND v.domain_id=a.domain_id AND v.hostname=a.hostname
    WHERE a.workspace_id=? AND a.domain_id=? AND a.status='active' AND (a.hostname=? OR a.hostname LIKE ?)
    ORDER BY COALESCE(NULLIF(v.last_attempt_ms,0),CAST(strftime('%s',a.first_seen) AS INTEGER)*1000,?)
      - CASE WHEN COALESCE(v.last_attempt_ms,0)=0 THEN 3600000 ELSE 0 END
      - CASE WHEN a.risk_level IN ('critical','high','medium') THEN 3600000 ELSE 0 END,
      a.hostname LIMIT 32`).bind(scan.workspace_id,scan.domain_id,scan.domain,'%.'+scan.domain,now).all();
  const assetCount=await db.prepare("SELECT count(*) AS total FROM workspace_assets WHERE workspace_id=? AND domain_id=? AND status='active' AND (hostname=? OR hostname LIKE ?)").bind(scan.workspace_id,scan.domain_id,scan.domain,'%.'+scan.domain).first();
  const pages=await db.prepare(`SELECT path,last_observation_json FROM website_pages
    WHERE workspace_id=? AND domain_id=? ORDER BY last_checked_at DESC LIMIT 100`)
    .bind(scan.workspace_id,scan.domain_id).all();
  // Prior explicit URLs are retained by this execution ledger, not reconstructed
  // from secret values. The canonical finding identity is managed downstream.
  const previous=await db.prepare(`SELECT plan_json,results_json FROM external_exposure_jobs
    WHERE workspace_id=? AND domain_id=? AND state IN ('complete','budget_exhausted')
    ORDER BY created_ms DESC,updated_at DESC LIMIT 1`).bind(scan.workspace_id,scan.domain_id).first();
  const previousFindings=unresolvedExposureChecks(json(previous?.plan_json,{}).retest_checks||[],json(previous?.results_json,[]));
  const candidates=orderExposureAssets(assets.results||[],now).filter(a=>safeHost(a.hostname,scan.domain));
  const hosts=[scan.domain,...candidates.filter(a=>a.hostname!==scan.domain).slice(0,EXPOSURE_JOB_LIMITS.hosts-1).map(a=>a.hostname)];
  const checks=[];
  for(const hostname of hosts){
    const origin=`https://${hostname}`;
    const observations=hostname===scan.domain?{rotationKey:scan.id,paths:(pages.results||[]).map(p=>p.path),urls:(pages.results||[]).map(p=>origin+p.path)}:{rotationKey:scan.id};
    const planned=planExposureChecks({origin,observations,previousFindings:previousFindings.map(r=>({ruleId:r.rule_id,url:r.url}))});
    for(const check of planned.checks||[])checks.push({rule_id:check.ruleId||check.rule_id,url:check.url});
  }
  const plan={content_state:'pending',retest_checks:previousFindings,checks:checks.slice(0,EXPOSURE_JOB_LIMITS.checks),hosts,
    pending_assets:Math.max(0,(assetCount?.total||0)-hosts.filter(host=>candidates.some(a=>a.hostname===host)).length),discovered_hosts:[],
    omitted_checks:Math.max(0,checks.length-EXPOSURE_JOB_LIMITS.checks),catalog_version:'1'};
  await db.prepare(`INSERT OR IGNORE INTO external_exposure_jobs
    (scan_id,workspace_id,domain_id,domain,plan_json,dispatch_json,created_ms,deadline_ms,updated_at)
    SELECT ?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM scans s JOIN workspaces w ON w.id=s.workspace_id
      JOIN workspace_domains wd ON wd.workspace_id=s.workspace_id AND wd.domain_id=s.domain_id
      WHERE s.id=? AND s.workspace_id=? AND s.domain_id=? AND s.status='queued'
      AND w.deleted_at IS NULL AND wd.verification_status='verified')`)
    .bind(scan.id,scan.workspace_id,scan.domain_id,scan.domain,JSON.stringify(plan),JSON.stringify(dispatch),now,now+EXPOSURE_JOB_LIMITS.completionMs,new Date(now).toISOString(),scan.id,scan.workspace_id,scan.domain_id).run();
}

// Called before the ordinary scan claim. Free/unverified scans never enter this
// feature. Configuration is explicit so rollout requires migration 119 first.
export async function ensureExposureReady(env,scan,body={}) {
  if(env.EXPOSURE_SCAN_MODE!=='evidence-v1'||!scan.workspace_id||scan.status!=='queued')return true;
  const now=Date.now();
  let row=await env.cybermeters_db.prepare('SELECT * FROM external_exposure_jobs WHERE scan_id=? AND workspace_id=?').bind(scan.id,scan.workspace_id).first();
  if(!row){await createJob(env,scan,now,{trigger:body.trigger==='scheduled'?'scheduled':'manual',...(typeof body.scheduled_scan_id==='string'&&/^[a-zA-Z0-9_-]{1,100}$/.test(body.scheduled_scan_id)?{scheduled_scan_id:body.scheduled_scan_id}:{}),...(typeof body.user_id==='string'&&/^[a-zA-Z0-9_-]{1,100}$/.test(body.user_id)?{user_id:body.user_id}:{})});row=await env.cybermeters_db.prepare('SELECT * FROM external_exposure_jobs WHERE scan_id=? AND workspace_id=?').bind(scan.id,scan.workspace_id).first();}
  if(!row)throw new Error('exposure_authority_lost');
  if(terminal(row.state))return true;
  await env.SCAN_QUEUE.send(messageFor(row));
  return false;
}

async function resumeDomain(env,row) {
  await env.SCAN_QUEUE.send({...json(row.dispatch_json,{}),v:1,scan_id:row.scan_id,workspace_id:row.workspace_id,domain_id:row.domain_id,domain:row.domain});
}
async function deferBusy(env,row,outcome) {
  // Contention is not an execution failure. Cloudflare's delivery retry limit
  // must not dead-letter healthy work while another tenant slice owns its slot.
  // A fresh delayed continuation retains the original absolute job deadline.
  await env.SCAN_QUEUE.send(messageFor(row),{delaySeconds:30});
  return {action:'ack',outcome};
}
async function canRun(env,row) {
  return !!await env.cybermeters_db.prepare(`SELECT scan_id FROM external_exposure_jobs WHERE scan_id=? AND workspace_id=? AND ${AUTHORITY}`)
    .bind(row.scan_id,row.workspace_id).first();
}
async function finishWithoutProbe(env,row,state,reason,now) {
  const result=await env.cybermeters_db.prepare(`UPDATE external_exposure_jobs SET state=?,updated_at=?,lease_token=NULL,lease_until=0
    WHERE scan_id=? AND workspace_id=? AND state IN ('pending','running') AND lease_until<=?`)
    .bind(state,new Date(now).toISOString(),row.scan_id,row.workspace_id,now).run();
  if(changed(result)||terminal(row.state))await resumeDomain(env,row);
  return {action:'ack',outcome:reason};
}

export async function collectExposure(env,input,{signal}={}) {
  if(!validateExposureRequest(input).ok)throw new Error('invalid_exposure_request');
  if(!env.NETWORK_PROBE?.fetch)throw new Error('collector_unavailable');
  const abort = new Promise((_, reject) => {
    if(signal?.aborted)reject(new Error('collector_aborted'));
    else signal?.addEventListener('abort',()=>reject(new Error('collector_aborted')),{once:true});
  });
  const response=await Promise.race([abort,env.NETWORK_PROBE.fetch('https://network-probe.internal/exposure',{
    method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(input),signal,
  })]);
  if(!response.ok){await response.body?.cancel();throw new Error('collector_unavailable');}
  const receipt=await Promise.race([abort,readBoundedJson(response.body,EXPOSURE_LIMITS.responseBytes)]);
  if(signal?.aborted||!validateExposureReceipt(input,receipt).ok)throw new Error('invalid_exposure_receipt');
  return receipt;
}

// Public-page discovery runs once in the same private collector/budget ledger.
// Only the cleaned page projection, rule outcomes and candidate paths cross
// this boundary; response bodies, cookies and headers remain process-local.
export async function collectWebsiteContent(env,input,{signal}={}) {
  if(!validateWebsiteContentRequest(input).ok)throw new Error('invalid_content_request');
  if(!env.NETWORK_PROBE?.fetch)throw new Error('collector_unavailable');
  let abortListener;
  const abort=new Promise((_,reject)=>{
    abortListener=()=>reject(new Error('collector_aborted'));
    if(signal?.aborted)abortListener();else signal?.addEventListener('abort',abortListener,{once:true});
  });
  try{
    const response=await Promise.race([abort,env.NETWORK_PROBE.fetch('https://network-probe.internal/website-content',{
      method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(input),signal,
    })]);
    if(!response.ok){await response.body?.cancel();throw new Error('collector_unavailable');}
    const receipt=await Promise.race([abort,readBoundedJson(response.body,WEBSITE_CONTENT_LIMITS.responseBytes)]);
    if(signal?.aborted||!validateWebsiteContentReceipt(input,receipt).ok)throw new Error('invalid_content_receipt');
    return receipt;
  }finally{signal?.removeEventListener('abort',abortListener);}
}

// Reference planning is pure and bounded. A body already evaluated in this scan
// is not downloaded by the exposure phase again, even when its outcome was
// uncertain. That uncertainty remains visible and cannot clear an old finding.
export function mergeWebsiteContentPlan(plan,receipt,domain) {
  const readKeys=new Set(receipt.results.map(r=>r.rule_id+'|'+r.url));
  const retained=plan.checks.filter(c=>!readKeys.has(c.rule_id+'|'+c.url));
  const candidates=[];
  const seen=new Set(retained.map(c=>c.rule_id+'|'+c.url));
  const priorities=new Map();
  for(const observed of receipt.discoveries){
    const url=new URL(observed.origin);
    if(!safeHost(url.hostname,domain))continue;
    const next=planExposureChecks({origin:observed.origin,observations:{paths:observed.paths,technologies:observed.technologies}});
    for(const c of next.checks){
      priorities.set(c.ruleId+'|'+c.url,c.priority);
      if(c.source==='catalog')continue;
      const key=c.ruleId+'|'+c.url;
      if(readKeys.has(key)||seen.has(key))continue;
      seen.add(key);candidates.push({rule_id:c.ruleId,url:c.url});
    }
  }
  // Previously positive retests stay first. Freshly observed references then
  // precede the baseline catalogue instead of starving behind it.
  const retests=new Set((plan.retest_checks||[]).map(c=>c.rule_id+'|'+c.url));
  const baseline=retained.filter(c=>!retests.has(c.rule_id+'|'+c.url))
    .sort((a,b)=>(priorities.get(b.rule_id+'|'+b.url)||0)-(priorities.get(a.rule_id+'|'+a.url)||0));
  const ordered=[...retained.filter(c=>retests.has(c.rule_id+'|'+c.url)),...candidates,...baseline];
  const allowance=Math.max(0,EXPOSURE_JOB_LIMITS.checks-receipt.results.length);
  plan.omitted_checks=(plan.omitted_checks||0)+Math.max(0,ordered.length-allowance);
  plan.checks=ordered.slice(0,allowance);
  plan.retest_checks=unresolvedExposureChecks(plan.retest_checks||[],receipt.results);
  plan.discovered_hosts=[...new Set([...(plan.discovered_hosts||[]),...receipt.discoveries.flatMap(d=>d.hosts)])]
    .filter(h=>safeHost(h,domain)).slice(0,128);
  plan.page_discovery=receipt.page_discovery;
  plan.content_state='complete';
  return plan;
}

export async function processExposureMessage(body,env,deps={}) {
  if(body?.kind!=='external_exposure'||body.v!==1||typeof body.scan_id!=='string'||!/^[a-zA-Z0-9_-]{1,100}$/.test(body.scan_id))return {action:'ack',outcome:'malformed'};
  const db=env.cybermeters_db,now=deps.now?.()??Date.now();
  let row=await db.prepare('SELECT * FROM external_exposure_jobs WHERE scan_id=?').bind(body.scan_id).first();
  if(!row)return {action:'ack',outcome:'missing'};
  if(body.workspace_id!==row.workspace_id)return {action:'ack',outcome:'identity_mismatch'};
  if(terminal(row.state)){await resumeDomain(env,row);return {action:'ack',outcome:'terminal'};}
  if(!await canRun(env,row))return finishWithoutProbe(env,row,'cancelled','authority_lost',now);
  if(row.lease_until>now)return deferBusy(env,row,'lease_held');
  if(now>=row.deadline_ms||row.attempts>=EXPOSURE_JOB_LIMITS.attempts||row.failure_count>=EXPOSURE_JOB_LIMITS.failures)
    return finishWithoutProbe(env,row,'budget_exhausted','completion_budget',now);
  const plan=json(row.plan_json,{checks:[]});
  const contentPhase=plan.content_state==='pending';
  if(!contentPhase&&row.cursor>=plan.checks.length)return finishWithoutProbe(env,row,'complete','complete',now);
  const origin=contentPhase?`https://${row.domain}`:new URL(plan.checks[row.cursor].url).origin;
  const checks=[];
  for(const check of contentPhase?[]:plan.checks.slice(row.cursor,row.cursor+EXPOSURE_LIMITS.checks)){
    if(new URL(check.url).origin!==origin)break;checks.push(check);
  }
  const token=crypto.randomUUID().replaceAll('-','');
  const limits=contentPhase?WEBSITE_CONTENT_LIMITS:EXPOSURE_LIMITS;
  const reservationRequests=limits.requests, reservationBytes=contentPhase
    ?WEBSITE_CONTENT_LIMITS.bytes+WEBSITE_CONTENT_LIMITS.overreadBytes:EXPOSURE_JOB_LIMITS.byteReservation;
  // This single conditional write serialises both per-job and tenant-window
  // budgets; no read-then-increment race. A crashed prior lease stays charged.
  const claimed=await db.prepare(`UPDATE external_exposure_jobs SET state='running',lease_token=?,lease_until=?,
    charged_requests=charged_requests+?,charged_bytes=charged_bytes+?,attempts=attempts+1,
    unknown_attempts=unknown_attempts+CASE WHEN state='running' THEN 1 ELSE 0 END,updated_at=?
    WHERE scan_id=? AND workspace_id=? AND cursor=? AND state IN ('pending','running') AND lease_until<=?
    AND charged_requests+?<=? AND charged_bytes+?<=? AND ${AUTHORITY}
    AND NOT EXISTS(SELECT 1 FROM external_exposure_jobs j WHERE j.workspace_id=external_exposure_jobs.workspace_id
      AND j.scan_id<>external_exposure_jobs.scan_id AND j.lease_until>?)
    AND (SELECT COALESCE(SUM(j.charged_requests),0) FROM external_exposure_jobs j
      WHERE j.workspace_id=external_exposure_jobs.workspace_id AND j.created_ms>=?)+?<=?
    AND (SELECT COALESCE(SUM(j.charged_bytes),0) FROM external_exposure_jobs j
      WHERE j.workspace_id=external_exposure_jobs.workspace_id AND j.created_ms>=?)+?<=?`)
    .bind(token,now+EXPOSURE_JOB_LIMITS.leaseMs,reservationRequests,reservationBytes,new Date(now).toISOString(),
      row.scan_id,row.workspace_id,row.cursor,now,reservationRequests,EXPOSURE_JOB_LIMITS.requests,
      reservationBytes,EXPOSURE_JOB_LIMITS.bytes,now,now-EXPOSURE_JOB_LIMITS.windowMs,reservationRequests,
      EXPOSURE_JOB_LIMITS.workspaceRequests,now-EXPOSURE_JOB_LIMITS.windowMs,reservationBytes,EXPOSURE_JOB_LIMITS.workspaceBytes).run();
  if(!changed(claimed)){
    const active=await db.prepare('SELECT scan_id FROM external_exposure_jobs WHERE workspace_id=? AND lease_until>? LIMIT 1').bind(row.workspace_id,now).first();
    if(active)return deferBusy(env,row,'tenant_busy');
    return finishWithoutProbe(env,row,'budget_exhausted','network_budget',now);
  }
  // Record service by actual attempted slice, never by alphabetical selection.
  await db.prepare(`INSERT INTO external_exposure_visits(workspace_id,domain_id,hostname,last_attempt_ms,last_scan_id)
    VALUES(?,?,?,?,?) ON CONFLICT(workspace_id,domain_id,hostname) DO UPDATE SET last_attempt_ms=excluded.last_attempt_ms,last_scan_id=excluded.last_scan_id`)
    .bind(row.workspace_id,row.domain_id,new URL(origin).hostname,now,row.scan_id).run();
  const controller=new AbortController();
  const remaining=Math.min(limits.durationMs,row.deadline_ms-now);
  const timer=setTimeout(()=>controller.abort(),remaining);
  let polling=false;
  const watchdog=setInterval(async()=>{
    if(polling)return;polling=true;
    try{if(!await canRun(env,row))controller.abort();}catch{controller.abort();}finally{polling=false;}
  },250);
  const input={schema_version:contentPhase?'website-content-request-v1':'exposure-request-v1',request_id:token,workspace_id:row.workspace_id,scan_id:row.scan_id,
    ...(contentPhase?{domain:row.domain}:{origin,checks}),deadline_at:new Date(now+remaining).toISOString(),max_requests:reservationRequests,max_bytes:limits.bytes};
  let receipt;
  try{
    receipt=await (contentPhase?(deps.collectWebsiteContent||collectWebsiteContent):(deps.collect||collectExposure))(env,input,{signal:controller.signal});
    const validate=contentPhase?validateWebsiteContentReceipt:validateExposureReceipt;
    if(controller.signal.aborted||!validate(input,receipt,{now:deps.now?.()??Date.now()}).ok)throw new Error('invalid_receipt');
    const t=receipt.telemetry;
    if(Math.max(t.bytes_wire,t.bytes_decoded)>reservationBytes)throw new Error('unbounded_receipt');
    const costs=json(row.costs_json,{});
    for(const key of ['requests','redirects','retries','bytes_wire','bytes_decoded','duration_ms'])costs[key]=(costs[key]||0)+t[key];
    plan.retest_checks=unresolvedExposureChecks(plan.retest_checks||[],receipt.results);
    const results=[...json(row.results_json,[]),...receipt.results.map(r=>({...r,observed_at:receipt.finished_at}))];
    // Reuse references extracted during the bounded read; never fetch a URL
    // merely because an API document lists it. Only catalog-compatible passive
    // candidates are admitted, and every addition shares the original budget.
    if(contentPhase)mergeWebsiteContentPlan(plan,receipt,row.domain);
    const seen=new Set(plan.checks.map(c=>c.rule_id+'|'+c.url));
    const next=!contentPhase&&receipt.discoveries?.paths?.length?planExposureChecks({origin,observations:{paths:receipt.discoveries.paths}}):{checks:[]};
    for(const candidate of next.checks||[]){
      if(candidate.source==='catalog')continue;
      const key=candidate.ruleId+'|'+candidate.url;
      if(seen.has(key))continue;seen.add(key);
      if(plan.checks.length>=EXPOSURE_JOB_LIMITS.checks){plan.omitted_checks=(plan.omitted_checks||0)+1;continue;}
      plan.checks.push({rule_id:candidate.ruleId,url:candidate.url});
    }
    if(!contentPhase)plan.discovered_hosts=[...new Set([...(plan.discovered_hosts||[]),...(receipt.discoveries?.hosts||[])])].filter(h=>safeHost(h,row.domain)).slice(0,128);
    const cursor=contentPhase?0:row.cursor+checks.length,state=cursor>=plan.checks.length?'complete':'pending';
    // Receipt + progress + refund are one atomic, fenced commit. A late result
    // from a replaced process cannot refund its already-charged reservation.
    const stored=await db.prepare(`UPDATE external_exposure_jobs SET state=?,cursor=?,plan_json=?,results_json=?,costs_json=?,
      charged_requests=charged_requests-?+?,charged_bytes=charged_bytes-?+?,lease_token=NULL,lease_until=0,updated_at=?
      WHERE scan_id=? AND workspace_id=? AND lease_token=? AND lease_until>? AND ${AUTHORITY}`)
      .bind(state,cursor,JSON.stringify(plan),JSON.stringify(results),JSON.stringify(costs),reservationRequests,t.requests,
        reservationBytes,Math.max(t.bytes_wire,t.bytes_decoded),receipt.finished_at,row.scan_id,row.workspace_id,token,deps.now?.()??Date.now()).run();
    if(!changed(stored))return {action:'retry',delaySeconds:30,outcome:'fence_lost'};
    if(state==='complete')await resumeDomain(env,row);else await env.SCAN_QUEUE.send(messageFor(row));
    return {action:'ack',outcome:state};
  }catch{
    // Unknown IO is charged in full. Error strings cannot leak to storage/logs.
    const active=await canRun(env,row).catch(()=>false);
    await db.prepare(`UPDATE external_exposure_jobs SET state=?,failure_count=failure_count+1,unknown_attempts=unknown_attempts+1,
      lease_token=NULL,lease_until=0,updated_at=? WHERE scan_id=? AND workspace_id=? AND lease_token=?`)
      .bind(active?'pending':'cancelled',new Date(deps.now?.()??Date.now()).toISOString(),row.scan_id,row.workspace_id,token).run();
    if(!active){await resumeDomain(env,row);return {action:'ack',outcome:'cancelled'};}
    return {action:'retry',delaySeconds:5,outcome:'uncertain_attempt_charged'};
  }finally{clearTimeout(timer);clearInterval(watchdog);}
}

export async function handleExposureBatch(batch,env,ctx,deps={}) {
  for(const message of batch.messages||[]){
    let result;
    try{result=await processExposureMessage(message.body,env,deps);}catch{result={action:'retry',delaySeconds:30};}
    if(result.action==='retry')message.retry({delaySeconds:result.delaySeconds||30});else message.ack();
  }
}

export async function readExposureForScan(env,{workspaceId,scanId}) {
  if(!workspaceId)return null;
  const row=await env.cybermeters_db.prepare('SELECT * FROM external_exposure_jobs WHERE scan_id=? AND workspace_id=?').bind(scanId,workspaceId).first();
  if(!row)return null;
  const plan=json(row.plan_json,{checks:[]}),results=json(row.results_json,[]);
  const reason=row.state==='cancelled'?'authority_lost':row.state==='budget_exhausted'?'budget_exhausted':'queued';
  const pending=plan.checks.slice(row.cursor).map(c=>({...c,identity:exposureIdentity(c.rule_id,c.url),state:reason,comparable:false,finding:null,reason,observed_at:null}));
  const checks=[...results,...pending];
  const coverage={completed:0,pending:0,blocked:0,not_applicable:0,budget_exhausted:plan.omitted_checks||0,uncertain:0,pending_assets:plan.pending_assets||0};
  for(const check of checks){
    if(check.comparable)coverage.completed++;
    else if(check.state==='blocked')coverage.blocked++;
    else if(check.state==='not_applicable')coverage.not_applicable++;
    else if(check.state==='budget_exhausted'||/(?:budget_exhausted|deadline_exhausted|request_limit|body_limit|wire_limit|decoded_limit)/.test(check.reason||''))coverage.budget_exhausted++;
    else if(check.state==='queued')coverage.pending++;
    else coverage.uncertain++;
  }
  return {source:'external_exposure',version:'1',quality:row.state==='complete'&&checks.every(r=>r.comparable)?'complete':'partial',
    page_discovery:plan.content_state==='complete'?plan.page_discovery:null,
    coverage,checks,hostname_references:{candidates:(plan.discovered_hosts||[]).map(hostname=>({hostname,sources:['exposure_content']}))},costs:{...json(row.costs_json,{}),charged_requests:row.charged_requests,charged_bytes:row.charged_bytes,
      unknown_attempts:row.unknown_attempts,attempts:row.attempts},observed_at:row.updated_at};
}
