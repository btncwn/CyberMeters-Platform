// Existing scan Queue continuations. Only the scan row grants tenant/scope.
// Receipts contain static indicators, never bodies; the ordinary scan report
// subsequently stores these cleaned observations in R2 with canonical findings.
import { exposureIdentity } from '../../../../shared/exposure/redaction.js';
import { planExposureChecks } from '../../../../shared/exposure/discovery.js';
import { EXPOSURE_LIMITS, validateExposureRequest, validateExposureReceipt } from '../../../network-probe/src/exposure-contract.js';
import { readBoundedJson, isProbeHostname } from '../../../network-probe/src/contract.js';
import { WEBSITE_CONTENT_LIMITS, validateWebsiteContentRequest, validateWebsiteContentReceipt } from '../../../network-probe/src/website-content-contract.js';
import { TLS_SLICE_LIMITS, TLS_SPECIAL_CONNECTION_LIMITS, TLS_TRUST_BUNDLE, TLS_SPECIAL_CONSENT_VERSION, isWeakTlsCipher, tlsProtocolRisk } from '../../../../shared/tls/catalog.js';
import { TLS_CIPHER_CATALOG } from '../../../../shared/tls/cipher-catalog.generated.js';
import { validateTlsAssessmentRequest, validateTlsAssessmentReceipt } from '../../../network-probe/src/tls-contract.js';
import { buildTlsCheckPlan, loadTlsEndpoints, refreshTlsEndpoint, tlsScopeStillAuthorized } from './tls-planner.js';

export const EXPOSURE_JOB_LIMITS = Object.freeze({
  hosts:4, checks:1024, requests:1024, bytes:64*1024*1024,
  workspaceRequests:4096, workspaceBytes:128*1024*1024,
  windowMs:60*60*1000, completionMs:15*60*1000, leaseMs:30000,
  attempts:150, failures:3, byteReservation:EXPOSURE_LIMITS.bytes+131072,
  // Authoritative no-address evidence older than the lifecycle recheck window
  // (attack-surface-lifecycle RECHECK_OBSERVATION_WINDOW_DAYS) is stale: the
  // name is planned again rather than skipped on an old answer.
  noAddressEvidenceMs:30*24*60*60*1000,
});
// The lifecycle observation's own vocabulary for "this name has no A/AAAA":
// NXDOMAIN for both address types (dns_state absent), NOERROR with no address
// for both (asset-intel DNS_NAME_WITHOUT_ADDRESS), or the probe's strict
// preflight proof (asset-intel http_not_applicable_no_address). Each is only
// ever produced from matching authoritative answers for BOTH families.
const NO_ADDRESS_DNS_REASONS=new Set(['dns_name_without_address','authoritative_a_aaaa_absence']);
const NO_ADDRESS_HTTP_REASON='http_not_applicable_no_address';
export const EXPOSURE_INCOMPLETE_REASONS=Object.freeze(['authority_lost','budget_exhausted','checks_not_finished','checks_inconclusive',
  'checks_blocked','check_budget_exhausted','assets_awaiting_rotation','http_not_applicable_no_address','no_checks_planned']);
const terminal = state => ['complete','cancelled','budget_exhausted'].includes(state);
const changed = result => result?.meta?.changes === 1;
const json = (value, fallback) => { try { return JSON.parse(value); } catch { return fallback; } };
const messageFor = row => ({kind:'external_exposure',v:1,scan_id:row.scan_id,workspace_id:row.workspace_id});
function priorTlsRiskChecks(previousPlan) {
  const tls=previousPlan?.tls;
  if(!Array.isArray(tls?.results)||!Array.isArray(tls.endpoints))return [];
  return tls.results.filter(row => row?.state === 'accepted' && row.evidence?.authenticated_finished === true &&
    (row.control === 'protocol' && tlsProtocolRisk(row.protocol) ||
      row.control === 'cipher' && isWeakTlsCipher(row.cipher_id) ||
      row.control === 'key_exchange' && (row.evidence?.negotiated?.pfs === false ||
        Number.isInteger(row.evidence?.negotiated?.group_bits) && row.evidence.negotiated.group_bits < 2048) ||
      row.control === 'certificate' && (row.evidence?.certificates?.trust === 'invalid' || row.evidence?.certificates?.hostname === false) ||
      row.control === 'compression' && row.evidence?.extensions?.compression === true ||
      ['heartbleed','robot','ccs'].includes(row.control) && row.evidence?.vulnerability?.status === 'confirmed'))
    .map(row => ({endpoint_identity:tls.endpoints[row.endpoint_index]?.endpoint_identity,
      control:row.control,protocol:row.protocol,cipher_id:row.cipher_id||null}))
    .filter(row=>row.endpoint_identity);
}
const AUTHORITY = `EXISTS(SELECT 1 FROM scans s JOIN workspaces w ON w.id=s.workspace_id
  JOIN workspace_domains wd ON wd.workspace_id=s.workspace_id AND wd.domain_id=s.domain_id
  WHERE s.id=external_exposure_jobs.scan_id AND s.workspace_id=external_exposure_jobs.workspace_id
  AND s.domain_id=external_exposure_jobs.domain_id AND s.domain=external_exposure_jobs.domain
  AND s.status='queued' AND w.deleted_at IS NULL AND wd.verification_status='verified')`;
// The TLS permission generation and service scope must still hold in the same
// SQLite statement that reserves network budget and the statement that stores
// evidence. An asynchronous DNS lookup or collector can otherwise outlive a
// revocation between the JavaScript precheck and commit.
const TLS_SCOPE_FENCE = `COALESCE((SELECT a.generation FROM workspace_tls_authorizations a
    WHERE a.workspace_id=external_exposure_jobs.workspace_id),0)=?
  AND (?=0 OR EXISTS(SELECT 1 FROM workspace_tls_authorizations a
    WHERE a.workspace_id=external_exposure_jobs.workspace_id AND a.enabled=1 AND a.consent_version=?))
  AND (?='standard_https' OR EXISTS(SELECT 1 FROM workspace_tls_service_authorizations sa
    JOIN network_targets t ON t.id=sa.network_target_id AND t.workspace_id=sa.workspace_id
    WHERE sa.id=? AND sa.workspace_id=external_exposure_jobs.workspace_id
      AND sa.domain_id=external_exposure_jobs.domain_id AND sa.authorization_status='active'
      AND sa.hostname=? AND sa.sni=? AND sa.port=? AND sa.application_protocol=?
      AND t.authorization_status='attested'
      AND EXISTS(SELECT 1 FROM json_each(t.addresses_json) WHERE value=?)))`;
const tlsScopeParams = entry => [entry.scope.generation,entry.scope.special_consent?1:0,TLS_SPECIAL_CONSENT_VERSION,
  entry.scope.kind,entry.scope.service_authorization_id,entry.endpoint.hostname,entry.endpoint.sni,
  entry.endpoint.port,entry.endpoint.application_protocol,entry.endpoint.address];

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

// HTTP catalog checks are skipped for a name ONLY on current authoritative
// A/AAAA absence recorded by this asset's latest lifecycle observation. The
// ip_addresses column is never consulted: an empty or old value is not evidence.
// A transient failure (unavailable/incomplete/not_assessed) keeps the name
// planned so the collector attempts it again; an observation that is not the
// asset's latest, or is older than the recheck window, is stale and ignored.
export function exposureHostHttpApplicability(asset,now=Date.now()) {
  if(!asset?.observation_scan_id||asset.observation_scan_id!==asset.last_observation_scan_id)return {applicable:true,reason:'no_current_observation'};
  const observedMs=Date.parse(asset.observation_at||'');
  if(!Number.isFinite(observedMs)||now-observedMs>EXPOSURE_JOB_LIMITS.noAddressEvidenceMs||observedMs>now+60000)return {applicable:true,reason:'observation_stale'};
  const authoritative=asset.dns_state==='absent'||NO_ADDRESS_DNS_REASONS.has(asset.dns_reason)||asset.http_reason===NO_ADDRESS_HTTP_REASON;
  if(!authoritative)return {applicable:true,reason:'address_evidence_not_authoritative'};
  return {applicable:false,reason:'authoritative_no_address',evidence:{scan_id:asset.observation_scan_id,observed_at:new Date(observedMs).toISOString(),
    dns_state:asset.dns_state||null,dns_reason:asset.dns_reason||null,http_reason:asset.http_reason||null}};
}

// One fixed, customer-safe word for WHY exposure evidence cannot support a
// conclusion, derived from the job's terminal state and its coverage. A job
// that finished with inconclusive checks is "finished", not "assessed", and is
// never confused with a job the scan budget cut off. null means nothing is
// outstanding. Order states the most decisive cause first.
export function exposureIncompleteReason(state,coverage,plannedChecks) {
  if(state==='cancelled')return 'authority_lost';
  if(state==='budget_exhausted')return 'budget_exhausted';
  if(state!=='complete')return 'checks_not_finished';
  if(coverage.uncertain>0)return 'checks_inconclusive';
  if(coverage.blocked>0)return 'checks_blocked';
  if(coverage.budget_exhausted>0)return 'check_budget_exhausted';
  if(coverage.pending>0)return 'checks_not_finished';
  if(coverage.pending_assets>0)return 'assets_awaiting_rotation';
  if(coverage.completed===0)return plannedChecks===0&&coverage.not_applicable_hosts>0?'http_not_applicable_no_address':'no_checks_planned';
  return null;
}

async function createJob(env, scan, now, dispatch) {
  const db=env.cybermeters_db;
  // The asset's LATEST lifecycle observation (unique per asset+scan) carries the
  // DNS/HTTP signal states this planner reads for address applicability.
  const assets=await db.prepare(`SELECT a.hostname,a.first_seen,v.last_attempt_ms,
    CASE WHEN a.risk_level IN ('critical','high','medium') THEN 1 ELSE 0 END AS has_finding,
    a.last_observation_scan_id,alo.scan_id AS observation_scan_id,alo.observed_at AS observation_at,alo.dns_state,
    json_extract(alo.source_detail_json,'$.dns_resolution.reason') AS dns_reason,
    json_extract(alo.source_detail_json,'$.http_https_service.reason') AS http_reason
    FROM workspace_assets a LEFT JOIN external_exposure_visits v
      ON v.workspace_id=a.workspace_id AND v.domain_id=a.domain_id AND v.hostname=a.hostname
    LEFT JOIN asset_lifecycle_observations alo
      ON alo.workspace_id=a.workspace_id AND alo.asset_id=a.id AND alo.scan_id=a.last_observation_scan_id
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
  const candidates=[],notApplicable=[];
  for(const asset of orderExposureAssets(assets.results||[],now).filter(a=>safeHost(a.hostname,scan.domain))){
    const verdict=exposureHostHttpApplicability(asset,now);
    if(verdict.applicable)candidates.push(asset);
    else notApplicable.push({hostname:asset.hostname,reason:verdict.reason,evidence:verdict.evidence});
  }
  // A name with no address frees its slot for the next applicable asset; the
  // apex is planned unless its own current observation says it has no address.
  const apexApplicable=!notApplicable.some(h=>h.hostname===scan.domain);
  const hosts=[...(apexApplicable?[scan.domain]:[]),...candidates.filter(a=>a.hostname!==scan.domain)
    .slice(0,EXPOSURE_JOB_LIMITS.hosts-(apexApplicable?1:0)).map(a=>a.hostname)];
  const checks=[];
  for(const hostname of hosts){
    const origin=`https://${hostname}`;
    const observations=hostname===scan.domain?{rotationKey:scan.id,paths:(pages.results||[]).map(p=>p.path),urls:(pages.results||[]).map(p=>origin+p.path)}:{rotationKey:scan.id};
    const planned=planExposureChecks({origin,observations,previousFindings:previousFindings.map(r=>({ruleId:r.rule_id,url:r.url}))});
    for(const check of planned.checks||[])checks.push({rule_id:check.ruleId||check.rule_id,url:check.url});
  }
  const exposureCheckLimit=env.TLS_ASSESSMENT_MODE==='evidence-v1'?384:EXPOSURE_JOB_LIMITS.checks;
  const plan={content_state:'pending',retest_checks:previousFindings,checks:checks.slice(0,exposureCheckLimit),hosts,
    exposure_check_limit:exposureCheckLimit,
    pending_assets:Math.max(0,(assetCount?.total||0)-hosts.filter(host=>candidates.some(a=>a.hostname===host)).length-notApplicable.length),
    hosts_not_applicable:notApplicable,discovered_hosts:[],
    omitted_checks:Math.max(0,checks.length-exposureCheckLimit),catalog_version:'1'};
  if(env.EXPOSURE_SCAN_MODE!=='evidence-v1'){
    plan.content_state='not_requested';plan.checks=[];plan.omitted_checks=0;
  }
  if(env.TLS_ASSESSMENT_MODE==='evidence-v1'){
    const endpoints=await loadTlsEndpoints(env,scan);
    const tlsPlan=buildTlsCheckPlan({endpoints:endpoints.endpoints,cipherCatalog:TLS_CIPHER_CATALOG,
      previousFindings:priorTlsRiskChecks(json(previous?.plan_json,{})),scanId:scan.id,maxChecks:512});
    plan.tls={...tlsPlan,endpoints:endpoints.endpoints,gaps:endpoints.gaps,scope_generation:endpoints.scope_generation,
      omitted_services:endpoints.omitted_services,results:[],state:'pending'};
  }
  await db.prepare(`INSERT OR IGNORE INTO external_exposure_jobs
    (scan_id,workspace_id,domain_id,domain,plan_json,dispatch_json,created_ms,deadline_ms,updated_at)
    SELECT ?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM scans s JOIN workspaces w ON w.id=s.workspace_id
      JOIN workspace_domains wd ON wd.workspace_id=s.workspace_id AND wd.domain_id=s.domain_id
      WHERE s.id=? AND s.workspace_id=? AND s.domain_id=? AND s.status='queued'
      AND w.deleted_at IS NULL AND wd.verification_status='verified')`)
    .bind(scan.id,scan.workspace_id,scan.domain_id,scan.domain,JSON.stringify(plan),JSON.stringify(dispatch),now,
      now+(env.TLS_ASSESSMENT_MODE==='evidence-v1'?30*60*1000:EXPOSURE_JOB_LIMITS.completionMs),
      new Date(now).toISOString(),scan.id,scan.workspace_id,scan.domain_id).run();
}

// Called before the ordinary scan claim. Free/unverified scans never enter this
// feature. Configuration is explicit so rollout requires migration 119 first.
export async function ensureExposureReady(env,scan,body={}) {
  if((env.EXPOSURE_SCAN_MODE!=='evidence-v1'&&env.TLS_ASSESSMENT_MODE!=='evidence-v1')||!scan.workspace_id||scan.status!=='queued')return true;
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

export async function collectTlsAssessment(env,input,{signal}={}) {
  if(!validateTlsAssessmentRequest(input).ok)throw new Error('invalid_tls_request');
  if(!env.NETWORK_PROBE?.fetch)throw new Error('collector_unavailable');
  const controller=new AbortController();
  const abort=()=>controller.abort();
  const aborted=new Promise((_,reject)=>controller.signal.addEventListener('abort',()=>reject(new Error('collector_aborted')),{once:true}));
  signal?.addEventListener('abort',abort,{once:true});
  const timer=setTimeout(abort,Math.max(1,Date.parse(input.deadline_at)-Date.now()));
  try{
    if(signal?.aborted)throw new Error('collector_aborted');
    const pending=env.NETWORK_PROBE.fetch('https://network-probe.internal/tls-assessment',{
      method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(input),signal:controller.signal,
    });
    pending.then(response=>{if(controller.signal.aborted)response.body?.cancel().catch(()=>{});}).catch(()=>{});
    const response=await Promise.race([pending,aborted]);
    if(!response.ok){await response.body?.cancel();throw new Error('collector_unavailable');}
    const receipt=await Promise.race([readBoundedJson(response.body,TLS_SLICE_LIMITS.responseBytes),aborted]);
    if(controller.signal.aborted||!validateTlsAssessmentReceipt(input,receipt).ok)throw new Error('invalid_tls_receipt');
    return receipt;
  }finally{clearTimeout(timer);signal?.removeEventListener('abort',abort);}
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
  const allowance=Math.max(0,(plan.exposure_check_limit||EXPOSURE_JOB_LIMITS.checks)-receipt.results.length);
  plan.omitted_checks=(plan.omitted_checks||0)+Math.max(0,ordered.length-allowance);
  plan.checks=ordered.slice(0,allowance);
  plan.retest_checks=unresolvedExposureChecks(plan.retest_checks||[],receipt.results);
  plan.discovered_hosts=[...new Set([...(plan.discovered_hosts||[]),...receipt.discoveries.flatMap(d=>d.hosts)])]
    .filter(h=>safeHost(h,domain)).slice(0,128);
  plan.page_discovery=receipt.page_discovery;
  plan.content_state='complete';
  return plan;
}

function nextTlsChecks(plan) {
  const tls=plan.tls,first=tls?.selected?.[tls.cursor];
  if(!first)return [];
  if(['heartbleed','robot','ccs'].includes(first.check.control))return [first];
  const batch=[];
  for(const row of tls.selected.slice(tls.cursor,tls.cursor+TLS_SLICE_LIMITS.checks)){
    if(row.endpoint_index!==first.endpoint_index||['heartbleed','robot','ccs'].includes(row.check.control))break;
    batch.push(row);
  }
  return batch;
}

async function storeUnrunTlsSlice(env,row,plan,items,state,reason,now) {
  const tls=plan.tls,oldCursor=tls.cursor;
  for(const item of items)tls.results.push({endpoint_index:item.endpoint_index,...item.check,state,reason,observed_at:new Date(now).toISOString(),engine:null,evidence:null,physical_telemetry:{connections:0,bytes_sent:0,bytes_received:0,duration_ms:0}});
  tls.cursor+=items.length;
  const complete=tls.cursor>=tls.selected.length;
  tls.state=complete?'complete':'pending';
  const result=await env.cybermeters_db.prepare(`UPDATE external_exposure_jobs SET plan_json=?,state=?,updated_at=?
    WHERE scan_id=? AND workspace_id=? AND state IN ('pending','running') AND lease_until<=?
      AND CAST(json_extract(plan_json,'$.tls.cursor') AS INTEGER)=? AND ${AUTHORITY}`)
    .bind(JSON.stringify(plan),complete?'complete':'pending',new Date(now).toISOString(),row.scan_id,row.workspace_id,now,oldCursor).run();
  if(!changed(result))return {action:'retry',delaySeconds:30,outcome:'tls_fence_lost'};
  if(complete)await resumeDomain(env,row);else await env.SCAN_QUEUE.send(messageFor(row));
  return {action:'ack',outcome:reason};
}

async function processTlsSlice(env,row,plan,now,deps={}) {
  const tls=plan.tls,items=nextTlsChecks(plan),entry=tls.endpoints[items[0]?.endpoint_index];
  if(!items.length||!entry)return finishWithoutProbe(env,row,'complete','tls_complete',now);
  // A rollout rollback must also stop TLS slices planned by an earlier Worker
  // version. Keep ordinary exposure work and the scan continuation intact.
  if(env.TLS_ASSESSMENT_MODE!=='evidence-v1')
    return storeUnrunTlsSlice(env,row,plan,tls.selected.slice(tls.cursor),'unexecutable','feature_disabled',now);
  const scan={id:row.scan_id,workspace_id:row.workspace_id,domain_id:row.domain_id,domain:row.domain};
  if(!await tlsScopeStillAuthorized(env,scan,entry))
    return storeUnrunTlsSlice(env,row,plan,items,'not_authorized','scope_changed',now);
  const endpoint=await refreshTlsEndpoint(entry,{lookup:deps.lookupTlsDns}).catch(()=>null);
  if(!endpoint)return storeUnrunTlsSlice(env,row,plan,items,'uncertain','dns_authority_changed',now);
  if(!await tlsScopeStillAuthorized(env,scan,entry))
    return storeUnrunTlsSlice(env,row,plan,items,'not_authorized','scope_changed',now);
  const token=crypto.randomUUID().replaceAll('-',''),db=env.cybermeters_db;
  const reservationRequests=TLS_SPECIAL_CONNECTION_LIMITS[items[0].check.control]||TLS_SLICE_LIMITS.connections;
  const reservationBytes=TLS_SLICE_LIMITS.bytes+TLS_SLICE_LIMITS.overreadBytes;
  const claimed=await db.prepare(`UPDATE external_exposure_jobs SET state='running',lease_token=?,lease_until=?,
    charged_requests=charged_requests+?,charged_bytes=charged_bytes+?,attempts=attempts+1,
    unknown_attempts=unknown_attempts+CASE WHEN state='running' THEN 1 ELSE 0 END,updated_at=?
    WHERE scan_id=? AND workspace_id=? AND cursor=? AND state IN ('pending','running') AND lease_until<=?
      AND CAST(json_extract(plan_json,'$.tls.cursor') AS INTEGER)=?
      AND charged_requests+?<=? AND charged_bytes+?<=? AND ${AUTHORITY}
      AND NOT EXISTS(SELECT 1 FROM external_exposure_jobs j WHERE j.workspace_id=external_exposure_jobs.workspace_id
        AND j.scan_id<>external_exposure_jobs.scan_id AND j.lease_until>?)
      AND (SELECT COALESCE(SUM(j.charged_requests),0) FROM external_exposure_jobs j
        WHERE j.workspace_id=external_exposure_jobs.workspace_id AND j.created_ms>=?)+?<=?
      AND (SELECT COALESCE(SUM(j.charged_bytes),0) FROM external_exposure_jobs j
        WHERE j.workspace_id=external_exposure_jobs.workspace_id AND j.created_ms>=?)+?<=?
      AND ${TLS_SCOPE_FENCE}`)
    .bind(token,now+EXPOSURE_JOB_LIMITS.leaseMs,reservationRequests,reservationBytes,new Date(now).toISOString(),
      row.scan_id,row.workspace_id,row.cursor,now,tls.cursor,reservationRequests,EXPOSURE_JOB_LIMITS.requests,
      reservationBytes,EXPOSURE_JOB_LIMITS.bytes,now,now-EXPOSURE_JOB_LIMITS.windowMs,reservationRequests,
      EXPOSURE_JOB_LIMITS.workspaceRequests,now-EXPOSURE_JOB_LIMITS.windowMs,reservationBytes,EXPOSURE_JOB_LIMITS.workspaceBytes,
      ...tlsScopeParams(entry)).run();
  if(!changed(claimed)){
    const active=await db.prepare('SELECT scan_id FROM external_exposure_jobs WHERE workspace_id=? AND lease_until>? LIMIT 1').bind(row.workspace_id,now).first();
    if(active)return deferBusy(env,row,'tenant_busy');
    return finishWithoutProbe(env,row,'budget_exhausted','tls_network_budget',now);
  }
  const controller=new AbortController();
  const remaining=Math.min(TLS_SLICE_LIMITS.durationMs,row.deadline_ms-now);
  const timer=setTimeout(()=>controller.abort(),remaining);
  let polling=false;
  const watchdog=setInterval(async()=>{
    if(polling)return;polling=true;
    try{if(!await canRun(env,row)||!await tlsScopeStillAuthorized(env,scan,entry))controller.abort();}
    catch{controller.abort();}finally{polling=false;}
  },1000);
  const input={schema_version:'tls-assessment-request-v1',request_id:token,workspace_id:row.workspace_id,scan_id:row.scan_id,
    domain_id:row.domain_id,domain:row.domain,endpoint,scope:entry.scope,checks:items.map(item=>item.check),
    deadline_at:new Date(now+remaining).toISOString(),max_connections:reservationRequests,max_bytes:TLS_SLICE_LIMITS.bytes};
  try{
    if(!await tlsScopeStillAuthorized(env,scan,entry))throw new Error('tls_scope_revoked');
    const receipt=await (deps.collectTlsAssessment||collectTlsAssessment)(env,input,{signal:controller.signal});
    if(controller.signal.aborted||!validateTlsAssessmentReceipt(input,receipt,{now:deps.now?.()??Date.now()}).ok)throw new Error('invalid_receipt');
    const t=receipt.telemetry,actualBytes=t.bytes_sent+t.bytes_received;
    if(actualBytes>reservationBytes)throw new Error('unbounded_receipt');
    const costs=json(row.costs_json,{});
    costs.requests=(costs.requests||0)+t.connections;
    costs.bytes_wire=(costs.bytes_wire||0)+actualBytes;
    costs.duration_ms=(costs.duration_ms||0)+t.duration_ms;
    costs.tls_connections=(costs.tls_connections||0)+t.connections;
    costs.tls_bytes_sent=(costs.tls_bytes_sent||0)+t.bytes_sent;
    costs.tls_bytes_received=(costs.tls_bytes_received||0)+t.bytes_received;
    costs.tls_duration_ms=(costs.tls_duration_ms||0)+t.duration_ms;
    tls.results.push(...receipt.results.map(result=>({endpoint_index:items[0].endpoint_index,...result})));
    tls.cursor+=items.length;
    tls.state=tls.cursor>=tls.selected.length?'complete':'pending';
    const state=tls.state==='complete'?'complete':'pending';
    const stored=await db.prepare(`UPDATE external_exposure_jobs SET state=?,plan_json=?,costs_json=?,
      charged_requests=charged_requests-?+?,charged_bytes=charged_bytes-?+?,lease_token=NULL,lease_until=0,updated_at=?
      WHERE scan_id=? AND workspace_id=? AND lease_token=? AND lease_until>? AND ${AUTHORITY}
        AND ${TLS_SCOPE_FENCE}`)
      .bind(state,JSON.stringify(plan),JSON.stringify(costs),reservationRequests,t.connections,reservationBytes,actualBytes,
        receipt.finished_at,row.scan_id,row.workspace_id,token,deps.now?.()??Date.now(),...tlsScopeParams(entry)).run();
    if(!changed(stored))return {action:'retry',delaySeconds:30,outcome:'tls_fence_lost'};
    if(state==='complete')await resumeDomain(env,row);else await env.SCAN_QUEUE.send(messageFor(row));
    return {action:'ack',outcome:state};
  }catch{
    const active=await canRun(env,row).catch(()=>false);
    await db.prepare(`UPDATE external_exposure_jobs SET state=?,failure_count=failure_count+1,unknown_attempts=unknown_attempts+1,
      lease_token=NULL,lease_until=0,updated_at=? WHERE scan_id=? AND workspace_id=? AND lease_token=?`)
      .bind(active?'pending':'cancelled',new Date(deps.now?.()??Date.now()).toISOString(),row.scan_id,row.workspace_id,token).run();
    if(!active){await resumeDomain(env,row);return {action:'ack',outcome:'cancelled'};}
    return {action:'retry',delaySeconds:5,outcome:'tls_uncertain_attempt_charged'};
  }finally{clearTimeout(timer);clearInterval(watchdog);}
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
  if(!contentPhase&&row.cursor>=plan.checks.length){
    if(plan.tls?.selected?.length>plan.tls.cursor)return processTlsSlice(env,row,plan,now,deps);
    return finishWithoutProbe(env,row,'complete','complete',now);
  }
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
    const cursor=contentPhase?0:row.cursor+checks.length;
    const state=cursor>=plan.checks.length && (!plan.tls || plan.tls.cursor>=plan.tls.selected.length)?'complete':'pending';
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
  if(plan.content_state==='not_requested')return null;
  const reason=row.state==='cancelled'?'authority_lost':row.state==='budget_exhausted'?'budget_exhausted':'queued';
  const pending=plan.checks.slice(row.cursor).map(c=>({...c,identity:exposureIdentity(c.rule_id,c.url),state:reason,comparable:false,finding:null,reason,observed_at:null}));
  const checks=[...results,...pending];
  const notApplicableHosts=(Array.isArray(plan.hosts_not_applicable)?plan.hosts_not_applicable:[]).filter(h=>typeof h?.hostname==='string');
  const coverage={completed:0,pending:0,blocked:0,not_applicable:0,budget_exhausted:plan.omitted_checks||0,uncertain:0,pending_assets:plan.pending_assets||0,
    not_applicable_hosts:notApplicableHosts.length};
  for(const check of checks){
    if(check.comparable)coverage.completed++;
    else if(check.state==='blocked')coverage.blocked++;
    else if(check.state==='not_applicable')coverage.not_applicable++;
    else if(check.state==='budget_exhausted'||/(?:budget_exhausted|deadline_exhausted|request_limit|body_limit|wire_limit|decoded_limit)/.test(check.reason||''))coverage.budget_exhausted++;
    else if(check.state==='queued')coverage.pending++;
    else coverage.uncertain++;
  }
  // job_state says whether the job FINISHED; quality and incomplete_reason say
  // whether what it observed can support a conclusion. They are different facts.
  return {source:'external_exposure',version:'1',quality:row.state==='complete'&&checks.every(r=>r.comparable)?'complete':'partial',
    job_state:row.state,incomplete_reason:exposureIncompleteReason(row.state,coverage,checks.length),
    hosts_not_applicable:notApplicableHosts.map(h=>({hostname:h.hostname,reason:h.reason,observed_at:h.evidence?.observed_at||null})),
    page_discovery:plan.content_state==='complete'?plan.page_discovery:null,
    coverage,checks,hostname_references:{candidates:(plan.discovered_hosts||[]).map(hostname=>({hostname,sources:['exposure_content']}))},costs:{...json(row.costs_json,{}),charged_requests:row.charged_requests,charged_bytes:row.charged_bytes,
      unknown_attempts:row.unknown_attempts,attempts:row.attempts},observed_at:row.updated_at};
}

export async function readTlsAssessmentForScan(env,{workspaceId,scanId}) {
  if(!workspaceId)return null;
  const row=await env.cybermeters_db.prepare('SELECT * FROM external_exposure_jobs WHERE scan_id=? AND workspace_id=?').bind(scanId,workspaceId).first();
  const tls=json(row?.plan_json,{}).tls;
  if(!tls)return null;
  const pendingState=row.state==='cancelled'?'not_authorized':row.state==='budget_exhausted'?'uncertain':'uncertain';
  const pendingReason=row.state==='cancelled'?'authority_lost':row.state==='budget_exhausted'?'budget_exhausted':'pending';
  const all=[...tls.static_results,...tls.results,...tls.selected.slice(tls.cursor).map(item=>({endpoint_index:item.endpoint_index,...item.check,
    state:pendingState,reason:pendingReason,observed_at:null,engine:null,evidence:null,
    physical_telemetry:{connections:0,bytes_sent:0,bytes_received:0,duration_ms:0}}))];
  const endpoints=tls.endpoints.map((entry,index)=>({
    ...entry.endpoint,endpoint_identity:entry.endpoint_identity,scope:entry.scope,
    checks:all.filter(item=>item.endpoint_index===index).map(({endpoint_index,check,...rest})=>({...(check||{}),...rest,
      endpoint_identity:entry.endpoint_identity})),
  }));
  const coverage={planned:all.length+(tls.omitted_checks||0),completed:0,uncertain:0,unexecutable:0,not_authorized:0,not_applicable:0,
    omitted_checks:tls.omitted_checks||0,omitted_services:tls.omitted_services||0,endpoint_gaps:tls.gaps.length};
  for(const item of all){
    if(['accepted','rejected'].includes(item.state))coverage.completed++;
    else if(item.state==='not_authorized')coverage.not_authorized++;
    else if(item.state==='not_applicable')coverage.not_applicable++;
    else if(item.state==='unexecutable')coverage.unexecutable++;
    else coverage.uncertain++;
  }
  const costs=json(row.costs_json,{});
  const quality=row.state==='complete'&&coverage.uncertain===0&&coverage.unexecutable===0&&coverage.not_authorized===0&&
    coverage.omitted_checks===0&&coverage.omitted_services===0&&coverage.endpoint_gaps===0?'complete':'partial';
  return {source:'tls_assessment',version:tls.profile_version,policy_version:tls.policy_version,quality,coverage,endpoints,
    gaps:tls.gaps,trust_store_context:TLS_TRUST_BUNDLE,
    costs:{connections:costs.tls_connections||0,bytes_sent:costs.tls_bytes_sent||0,
      bytes_received:costs.tls_bytes_received||0,duration_ms:costs.tls_duration_ms||0,
      charged_connections:row.charged_requests,charged_bytes:row.charged_bytes,unknown_attempts:row.unknown_attempts,
      attempts:row.attempts},limitations:['tcp_tls_only_quic_not_assessed','observed_endpoint_not_origin_inference','no_external_revocation_fetch'],
    observed_at:row.updated_at,findings:[]};
}
