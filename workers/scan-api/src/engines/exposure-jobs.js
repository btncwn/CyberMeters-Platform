// Existing scan Queue continuations. Only the scan row grants tenant/scope.
// Receipts contain static indicators, never bodies; the ordinary scan report
// subsequently stores these cleaned observations in R2 with canonical findings.
import { ACTIVE_CHECK_AUTHORITY_VERSION } from './active-check-consent.js';
import { exposureIdentity } from '../../../../shared/exposure/redaction.js';
import { validRemoteAccessEvidence } from '../../../../shared/exposure/remote-access.js';
import { planExposureChecks } from '../../../../shared/exposure/discovery.js';
import { EXPOSURE_LIMITS, validateExposureRequest, validateExposureReceipt } from '../../../network-probe/src/exposure-contract.js';
import { readBoundedJson, isProbeHostname } from '../../../network-probe/src/contract.js';
import { WEBSITE_CONTENT_LIMITS, validateWebsiteContentRequest, validateWebsiteContentReceipt } from '../../../network-probe/src/website-content-contract.js';
import { TLS_SLICE_LIMITS, TLS_SPECIAL_CONNECTION_LIMITS, TLS_SPECIAL_CONSENT_VERSION, TLS_TRUST_BUNDLE, isWeakTlsCipher, tlsProtocolRisk } from '../../../../shared/tls/catalog.js';
import { TLS_CIPHER_CATALOG } from '../../../../shared/tls/cipher-catalog.generated.js';
import { blockingTlsNotAuthorized, blockingTlsUnexecutable, classifyTlsRefusals, tlsControlOutcome } from './tls-quality.js';
import { validateTlsAssessmentRequest, validateTlsAssessmentReceipt } from '../../../network-probe/src/tls-contract.js';
import { buildBudgetedTlsCheckPlan, loadTlsEndpoints, refreshTlsEndpoint, tlsScopeStillAuthorized, TLS_SPECIAL_CHECK_IDS } from './tls-planner.js';
import { getEffectiveDomainLimit, getEffectivePlanState } from './entitlements.js';

export const EXPOSURE_JOB_LIMITS = Object.freeze({
  hosts:4,
  requests:1024, bytes:64*1024*1024,
  workspaceRequests:4096, workspaceBytes:128*1024*1024,
  windowMs:60*60*1000, completionMs:15*60*1000, leaseMs:30000,
  attempts:150, maxPlannedAttempts:2048, failures:3, byteReservation:EXPOSURE_LIMITS.bytes+131072,
  // Authoritative no-address evidence older than the lifecycle recheck window
  // (attack-surface-lifecycle RECHECK_OBSERVATION_WINDOW_DAYS) is stale: the
  // name is planned again rather than skipped on an old answer.
  noAddressEvidenceMs:30*24*60*60*1000,
  // workspaceRequests/workspaceBytes are one domain's share of the hourly
  // workspace window. The window grows with the workspace's verified domains,
  // up to its plan's domain limit and never past windowDomainsCeiling.
  windowDomainsCeiling:25,
  // A job that has not started yet waits for its turn (another domain's job
  // running, or the hourly window full) instead of ending partial. The run
  // deadline starts at the first slice; the wait itself is bounded below the
  // interrupted-scan recovery's six-hour queued bound.
  queueWaitMs:5*60*60*1000, windowWaitDelaySeconds:300,
});

// The hourly window for one workspace: one domain's share per verified domain.
export async function workspaceExposureWindow(env,workspaceId) {
  const base={domains:1,requests:EXPOSURE_JOB_LIMITS.workspaceRequests,bytes:EXPOSURE_JOB_LIMITS.workspaceBytes};
  try{
    const row=await env.cybermeters_db.prepare(`SELECT w.owner_user_id AS owner,
        (SELECT COUNT(*) FROM workspace_domains wd WHERE wd.workspace_id=w.id AND wd.verification_status='verified') AS domains
      FROM workspaces w WHERE w.id=? AND w.deleted_at IS NULL`).bind(workspaceId).first();
    const verified=Number(row?.domains)||0;
    if(!row?.owner||verified<=1)return base;
    const plan=await getEffectivePlanState(row.owner,env);
    const planDomains=Number(getEffectiveDomainLimit(plan?.plan,plan?.is_trial));
    const domains=Math.max(1,Math.min(verified,Number.isFinite(planDomains)?planDomains:1,EXPOSURE_JOB_LIMITS.windowDomainsCeiling));
    return {domains,requests:base.requests*domains,bytes:base.bytes*domains};
  }catch{return base;}
}
function windowFor(plan) {
  const w=plan?.workspace_window,max=EXPOSURE_JOB_LIMITS.windowDomainsCeiling;
  const ok=Number.isSafeInteger(w?.domains)&&w.domains>=1&&w.domains<=max&&
    w.requests===EXPOSURE_JOB_LIMITS.workspaceRequests*w.domains&&w.bytes===EXPOSURE_JOB_LIMITS.workspaceBytes*w.domains;
  return ok?w:{domains:1,requests:EXPOSURE_JOB_LIMITS.workspaceRequests,bytes:EXPOSURE_JOB_LIMITS.workspaceBytes};
}
const runMsFor=plan=>plan?.tls?30*60*1000:EXPOSURE_JOB_LIMITS.completionMs;
// The lifecycle observation's own vocabulary for "this name has no A/AAAA":
// NXDOMAIN for both address types (dns_state absent), NOERROR with no address
// for both (asset-intel DNS_NAME_WITHOUT_ADDRESS), or the probe's strict
// preflight proof (asset-intel http_not_applicable_no_address). Each is only
// ever produced from matching authoritative answers for BOTH families.
const NO_ADDRESS_DNS_REASONS=new Set(['dns_name_without_address','authoritative_a_aaaa_absence']);
const NO_ADDRESS_HTTP_REASON='http_not_applicable_no_address';
export const EXPOSURE_INCOMPLETE_REASONS=Object.freeze(['authority_lost','budget_exhausted','checks_not_finished','checks_inconclusive',
  'checks_blocked','check_budget_exhausted','assets_awaiting_rotation','http_not_applicable_no_address','host_does_not_resolve',
  'target_unavailable','no_checks_planned']);
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
  AND (?=0 OR (json_array_length(?)>0 AND NOT EXISTS(SELECT 1 FROM json_each(?) c WHERE NOT EXISTS(
    SELECT 1 FROM active_check_consents g WHERE g.id=json_extract(c.value,'$[0]') AND g.kind='grant'
      AND g.workspace_id=external_exposure_jobs.workspace_id AND g.domain_id=external_exposure_jobs.domain_id
      AND EXISTS(SELECT 1 FROM json_each(g.checks_json) k WHERE k.value=json_extract(c.value,'$[1]'))
      AND NOT EXISTS(SELECT 1 FROM active_check_consents r WHERE r.kind='revocation' AND r.grant_id=g.id)))))
  AND (?='standard_https' OR EXISTS(SELECT 1 FROM workspace_tls_service_authorizations sa
    JOIN network_targets t ON t.id=sa.network_target_id AND t.workspace_id=sa.workspace_id
    WHERE sa.id=? AND sa.workspace_id=external_exposure_jobs.workspace_id
      AND sa.domain_id=external_exposure_jobs.domain_id AND sa.authorization_status='active'
      AND sa.hostname=? AND sa.sni=? AND sa.port=? AND sa.application_protocol=?
      AND t.authorization_status='attested' AND t.scope_state='in_scope'
      AND EXISTS(SELECT 1 FROM json_each(t.addresses_json) WHERE value=?)))`;
// [consent id, check id] for every planned intrusive control: the fence proves
// each grant is live AND still names that exact check.
const specialConsentIds = entry => JSON.stringify(Object.entries(entry.scope.special_checks||{})
  .filter(([control,id]) => id && TLS_SPECIAL_CHECK_IDS[control]).map(([control,id]) => [id,TLS_SPECIAL_CHECK_IDS[control]]));
const tlsScopeParams = entry => [entry.scope.generation,entry.scope.special_consent?1:0,specialConsentIds(entry),specialConsentIds(entry),
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
    // Portal vulnerability assessment happens downstream with the cached feed.
    // Retain its observed address too: a later timeout must not lose the exact
    // retest preference merely because the collector reports an observation.
    if(row.state==='finding'||row.rule_id==='remote-access-portal'&&row.state==='observed'&&validRemoteAccessEvidence(row.portal))retained.set(key,{rule_id:row.rule_id,url:row.url});
    else if(row.rule_id!=='remote-access-portal'&&row.comparable===true&&['not_found','not_present_soft404','observed'].includes(row.state))retained.delete(key);
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
  if(coverage.target_unavailable_hosts>0)return 'target_unavailable';
  if(coverage.non_resolving_hosts>0)return 'host_does_not_resolve';
  if(coverage.not_applicable_hosts>0)return 'http_not_applicable_no_address';
  if(coverage.blocked>0)return 'checks_blocked';
  if(coverage.budget_exhausted>0)return 'check_budget_exhausted';
  if(coverage.pending>0)return 'checks_not_finished';
  if(coverage.pending_assets>0)return 'assets_awaiting_rotation';
  if(coverage.completed===0)return plannedChecks===0&&coverage.not_applicable_hosts>0?'http_not_applicable_no_address':'no_checks_planned';
  return null;
}

// A host whose content checks drew an origin answer over HTTPS has an
// observed HTTPS service, whatever the status (challenge, 4xx, soft 404).
function observedHttpsHostsFrom(results,hosts) {
  return [...new Set((Array.isArray(results)?results:[]).filter(row=>
    row?.comparable===true||['soft_404_or_common_response','authentication_rate_limit_or_challenge',
      'server_or_redirect_failure'].includes(row?.reason)).map(row=>{
    try{const url=new URL(row.url);return url.protocol==='https:'?url.hostname:null;}catch{return null;}
  }).filter(host=>host&&hosts.includes(host)))];
}

// The largest TLS plan that still fits this job's limits beside its HTTP checks.
function sizeTlsPlan(plan,tlsArgs,referenceAllowance=[]) {
  let low=0,high=512,tlsPlan=buildBudgetedTlsCheckPlan({...tlsArgs,maxChecks:0});
  while(low<high){
    const mid=Math.ceil((low+high)/2);
    const candidate=buildBudgetedTlsCheckPlan({...tlsArgs,maxChecks:mid});
    if(fitsExposureJobLimits({...plan,checks:[...plan.checks,...referenceAllowance],tls:candidate})){
      low=mid;tlsPlan=candidate;
    }else high=mid-1;
  }
  return tlsPlan;
}

// First scan of a domain (21 Oct 2026): the TLS plan is built when the job is
// created, from the PREVIOUS job's observations, so a domain with no previous
// job deferred every host as https_service_not_observed and TLS ended partial
// for every new customer. Once this job's own content checks have run, re-plan
// that deferred part once from this job's results. Nothing selected earlier is
// changed; only hosts deferred for lack of an HTTPS observation are reconsidered.
export function replanTlsFromOwnResults(plan,results) {
  const tls=plan?.tls;
  // A plan that already selected checks is untouched, except when every
  // selected check belongs to a declared TLS service (F1: planned without an
  // HTTP observation) and none has run yet; the re-plan keeps them selected.
  // (Ported from #973, Seat 3: without it a declared service blocked the
  // first-scan re-plan of the domain's own web hosts.)
  if(!tls||tls.replanned_from_job||(tls.cursor||0)>0)return false;
  if(!(tls.selected||[]).every(r=>(tls.endpoints||[])[r.endpoint_index]?.scope?.kind==='authorized_service'))return false;
  const deferred=(tls.deferred_hosts||[]).filter(h=>h?.reason==='https_service_not_observed');
  if(!deferred.length)return false;
  const observed=observedHttpsHostsFrom(results,plan.hosts||[]);
  if(!observed.some(host=>deferred.some(d=>d.hostname===host)))return false;
  const sized=sizeTlsPlan(plan,{endpoints:tls.endpoints||[],cipherCatalog:TLS_CIPHER_CATALOG,
    previousFindings:[],observedHttpsHosts:observed,scanId:tls.scan_id||''});
  const kept=(tls.deferred_hosts||[]).filter(h=>h?.reason!=='https_service_not_observed');
  plan.tls={...tls,...sized,deferred_hosts:[...sized.deferred_hosts,...kept],
    replanned_from_job:true,cursor:0,results:[],state:'pending'};
  return true;
}

async function createJob(env, scan, now, dispatch, deps = {}) {
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
  const plan={content_state:'pending',retest_checks:previousFindings,checks,hosts,host_outcomes:[],
    exposure_check_limit:0,
    pending_assets:Math.max(0,(assetCount?.total||0)-hosts.filter(host=>candidates.some(a=>a.hostname===host)).length-notApplicable.length),
    hosts_not_applicable:notApplicable,discovered_hosts:[],
    host_coverage:[...new Set([...(assets.results||[]).map(a=>a.hostname),...hosts,
      ...notApplicable.map(a=>a.hostname)].filter(host=>safeHost(host,scan.domain)))].map(hostname=>{
      const asset=(assets.results||[]).find(item=>item.hostname===hostname);
      return {hostname,last_checked_at:Number.isSafeInteger(asset?.last_attempt_ms)&&asset.last_attempt_ms>0
        ?new Date(asset.last_attempt_ms).toISOString():null};
    }),
    hosts_total:Math.max(assetCount?.total||0,new Set([...(assets.results||[]).map(a=>a.hostname),
      ...hosts,...notApplicable.map(a=>a.hostname)].filter(host=>safeHost(host,scan.domain))).size),
    omitted_checks:0,catalog_version:'1'};
  if(env.EXPOSURE_SCAN_MODE!=='evidence-v1'){
    plan.content_state='not_requested';plan.checks=[];plan.omitted_checks=0;
  }
  if(env.TLS_ASSESSMENT_MODE==='evidence-v1'){
    const endpoints=await (deps.loadTlsEndpoints??loadTlsEndpoints)(env,scan,{trigger:dispatch?.trigger??null});
    const observedHttpsHosts=observedHttpsHostsFrom(json(previous?.results_json,[]),hosts);
    const tlsArgs={endpoints:endpoints.endpoints,cipherCatalog:TLS_CIPHER_CATALOG,
      previousFindings:priorTlsRiskChecks(json(previous?.plan_json,{})),observedHttpsHosts,scanId:scan.id};
    // Keep a bounded allowance for content references not known until the
    // first collector slice. TLS may defer complete host groups, but cannot
    // consume the time or bytes needed for the selected HTTP catalog.
    const reserveHost=hosts[hosts.length-1];
    const referenceAllowance=reserveHost?Array.from({length:32},(_,index)=>({
      rule_id:'env-config',url:`https://${reserveHost}/cm-reference-${index}`})):[];
    const tlsPlan=sizeTlsPlan(plan,tlsArgs,referenceAllowance);
    plan.tls={...tlsPlan,deferred_hosts:[...tlsPlan.deferred_hosts,...(endpoints.deferred_services||[])],
      endpoints:endpoints.endpoints,gaps:endpoints.gaps,scope_generation:endpoints.scope_generation,
      omitted_services:endpoints.omitted_services,results:[],state:'pending'};
  }
  const admitted=budgetedExposurePrefix(plan,plan.checks);
  plan.omitted_checks+=plan.checks.length-admitted;
  plan.checks=plan.checks.slice(0,admitted);
  plan.exposure_check_limit=admitted;
  plan.network_budget=sizeExposureJobBudget(plan);
  plan.workspace_window=await workspaceExposureWindow(env,scan.workspace_id);
  await db.prepare(`INSERT OR IGNORE INTO external_exposure_jobs
    (scan_id,workspace_id,domain_id,domain,plan_json,dispatch_json,created_ms,deadline_ms,updated_at)
    SELECT ?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM scans s JOIN workspaces w ON w.id=s.workspace_id
      JOIN workspace_domains wd ON wd.workspace_id=s.workspace_id AND wd.domain_id=s.domain_id
      WHERE s.id=? AND s.workspace_id=? AND s.domain_id=? AND s.status='queued'
      AND w.deleted_at IS NULL AND wd.verification_status='verified')`)
    .bind(scan.id,scan.workspace_id,scan.domain_id,scan.domain,JSON.stringify(plan),JSON.stringify(dispatch),now,
      // Until its first slice runs the deadline is the queue wait; the claim
      // that starts it replaces this with the run deadline (runMsFor).
      now+EXPOSURE_JOB_LIMITS.queueWaitMs,
      new Date(now).toISOString(),scan.id,scan.workspace_id,scan.domain_id).run();
}

// Called before the ordinary scan claim. Free/unverified scans never enter this
// feature. Configuration is explicit so rollout requires migration 119 first.
export async function ensureExposureReady(env,scan,body={},deps={}) {
  if((env.EXPOSURE_SCAN_MODE!=='evidence-v1'&&env.TLS_ASSESSMENT_MODE!=='evidence-v1')||!scan.workspace_id||scan.status!=='queued')return true;
  const now=Date.now();
  let row=await env.cybermeters_db.prepare('SELECT * FROM external_exposure_jobs WHERE scan_id=? AND workspace_id=?').bind(scan.id,scan.workspace_id).first();
  // C-52 N02: an absent trigger stays null; only 'manual' runs intrusive checks.
  if(!row){await createJob(env,scan,now,{trigger:body.trigger==='scheduled'||body.trigger==='manual'?body.trigger:null,...(typeof body.scheduled_scan_id==='string'&&/^[a-zA-Z0-9_-]{1,100}$/.test(body.scheduled_scan_id)?{scheduled_scan_id:body.scheduled_scan_id}:{}),...(typeof body.user_id==='string'&&/^[a-zA-Z0-9_-]{1,100}$/.test(body.user_id)?{user_id:body.user_id}:{})},deps);row=await env.cybermeters_db.prepare('SELECT * FROM external_exposure_jobs WHERE scan_id=? AND workspace_id=?').bind(scan.id,scan.workspace_id).first();}
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
// The claim failed for a job that has not started: if its own budget still
// fits the first slice, the shared hourly window is what refused it.
function windowFull(row,requests,bytes,budget) {
  return Number(row.charged_requests||0)+requests<=budget.requests&&Number(row.charged_bytes||0)+bytes<=budget.bytes;
}
async function deferForWindow(env,row) {
  // The hourly window is full with other domains' work. A job that has not
  // started waits for it to roll instead of ending partial.
  await env.SCAN_QUEUE.send(messageFor(row),{delaySeconds:EXPOSURE_JOB_LIMITS.windowWaitDelaySeconds});
  return {action:'ack',outcome:'workspace_window_wait'};
}
async function canRun(env,row) {
  return !!await env.cybermeters_db.prepare(`SELECT scan_id FROM external_exposure_jobs WHERE scan_id=? AND workspace_id=? AND ${AUTHORITY}`)
    .bind(row.scan_id,row.workspace_id).first();
}
// The probe's TLS request contract (network-probe/src/tls-contract.js) accepts
// exactly these scope keys. The plan's scope also carries the per-control
// Active Checks grants (special_checks, #838), which stay in the plan; sending
// them made every deep-TLS request invalid_scope (22 Oct 2026).
export const TLS_PROBE_SCOPE_KEYS = Object.freeze(['kind','service_authorization_id','generation','special_consent','consent_version']);
export function tlsProbeScope(scope) {
  const projected = Object.fromEntries(TLS_PROBE_SCOPE_KEYS.map(key=>[key,scope?.[key]??null]));
  // The Worker checks the current per-control Active Checks grant before this
  // projection. The probe carries its own protocol version, not that grant's
  // authority-text version. Unknown authority versions remain rejected.
  // When ACTIVE_CHECK_AUTHORITY_VERSION is bumped, review/update this mapping
  // and the pinned current-version fixture before releasing intrusive engines.
  if (scope?.special_consent === true && scope.consent_version === ACTIVE_CHECK_AUTHORITY_VERSION)
    projected.consent_version = TLS_SPECIAL_CONSENT_VERSION;
  return projected;
}

async function finishWithoutProbe(env,row,state,reason,now) {
  // The finish reason is kept with the plan, so "budget_exhausted" can always
  // be told apart: completion_budget, network_budget, tls_network_budget, ...
  const result=await env.cybermeters_db.prepare(`UPDATE external_exposure_jobs SET state=?,updated_at=?,lease_token=NULL,lease_until=0,
    plan_json=json_set(plan_json,'$.finish_reason',?)
    WHERE scan_id=? AND workspace_id=? AND state IN ('pending','running') AND lease_until<=?`)
    .bind(state,new Date(now).toISOString(),reason,row.scan_id,row.workspace_id,now).run();
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
  // Content can reveal safe, catalog-compatible references that were unknown
  // when the initial plan was sized. Re-size against the real candidate set;
  // the existing hourly ceilings still decide the largest admissible prefix.
  plan.content_result_checks=receipt.results.map(result=>({rule_id:result.rule_id,url:result.url}));
  const allowance=budgetedExposurePrefix(plan,ordered);
  plan.exposure_check_limit=allowance+plan.content_result_checks.length;
  plan.omitted_checks=(plan.omitted_checks||0)+Math.max(0,ordered.length-allowance);
  plan.checks=ordered.slice(0,allowance);
  plan.retest_checks=unresolvedExposureChecks(plan.retest_checks||[],receipt.results);
  plan.discovered_hosts=[...new Set([...(plan.discovered_hosts||[]),...receipt.discoveries.flatMap(d=>d.hosts)])]
    .filter(h=>safeHost(h,domain)).slice(0,128);
  plan.page_discovery=receipt.page_discovery;
  plan.content_state='complete';
  return plan;
}

function tlsSliceAt(selected,cursor) {
  const first=selected?.[cursor];
  if(!first)return [];
  if(['heartbleed','robot','ccs'].includes(first.check.control))return [first];
  const batch=[];
  for(const row of selected.slice(cursor,cursor+TLS_SLICE_LIMITS.checks)){
    if(row.endpoint_index!==first.endpoint_index||['heartbleed','robot','ccs'].includes(row.check.control))break;
    batch.push(row);
  }
  return batch;
}
function nextTlsChecks(plan) { return tlsSliceAt(plan.tls?.selected,plan.tls?.cursor||0); }

// Reserve each planned collector slice, including redirects/TLS retry capacity,
// plus 20% for uncertain attempts. Successful receipts refund unused capacity.
// The hourly workspace ceilings remain absolute even when a plan needs more.
export function estimateExposureJobBudget(plan) {
  const checks=Array.isArray(plan?.checks)?plan.checks:[];
  let httpSlices=0;
  const originOf=check=>{try{return new URL(check?.url).origin;}catch{return null;}};
  for(let i=0;i<checks.length;){
    const origin=originOf(checks[i]);
    let count=0;
    do{i++;count++;}while(origin&&count<EXPOSURE_LIMITS.checks&&i<checks.length&&originOf(checks[i])===origin);
    httpSlices++;
  }
  const selected=Array.isArray(plan?.tls?.selected)?plan.tls.selected:[];
  let tlsSlices=0,tlsRequests=0;
  for(let i=0;i<selected.length;){
    const slice=tlsSliceAt(selected,i);
    if(!slice.length)break;
    tlsSlices++;
    tlsRequests+=TLS_SPECIAL_CONNECTION_LIMITS[slice[0].check.control]||TLS_SLICE_LIMITS.connections;
    i+=slice.length;
  }
  const content=plan?.content_state==='not_requested'?0:1;
  const slices=content+httpSlices+tlsSlices;
  const requests=content*WEBSITE_CONTENT_LIMITS.requests+httpSlices*EXPOSURE_LIMITS.requests+tlsRequests;
  const bytes=content*(WEBSITE_CONTENT_LIMITS.bytes+WEBSITE_CONTENT_LIMITS.overreadBytes)
    +httpSlices*EXPOSURE_JOB_LIMITS.byteReservation
    +tlsSlices*(TLS_SLICE_LIMITS.bytes+TLS_SLICE_LIMITS.overreadBytes);
  // Slices run serially. Reserve deadline margin against every collector's
  // maximum wait, not just the median observed on a small workspace.
  const durationMs=content*WEBSITE_CONTENT_LIMITS.durationMs+
    httpSlices*EXPOSURE_LIMITS.durationMs+tlsSlices*TLS_SLICE_LIMITS.durationMs;
  const headroom=value=>Math.ceil(value*6/5);
  return {requests:headroom(requests),bytes:headroom(bytes),attempts:headroom(slices),
    durationMs:headroom(durationMs)};
}
export function sizeExposureJobBudget(plan) {
  const estimate=estimateExposureJobBudget(plan);
  return {requests:Math.min(EXPOSURE_JOB_LIMITS.workspaceRequests,estimate.requests),
    bytes:Math.min(EXPOSURE_JOB_LIMITS.workspaceBytes,estimate.bytes),
    attempts:Math.min(EXPOSURE_JOB_LIMITS.maxPlannedAttempts,estimate.attempts)};
}
function fitsExposureJobLimits(plan) {
  const estimate=estimateExposureJobBudget(plan);
  return estimate.requests<=EXPOSURE_JOB_LIMITS.workspaceRequests&&
    estimate.bytes<=EXPOSURE_JOB_LIMITS.workspaceBytes&&
    estimate.attempts<=EXPOSURE_JOB_LIMITS.maxPlannedAttempts&&
    estimate.durationMs<=(plan?.tls?30*60*1000:EXPOSURE_JOB_LIMITS.completionMs);
}
export function budgetedExposurePrefix(plan,candidates,checkCeiling=candidates.length+(plan?.content_result_checks?.length||0)) {
  const contentChecks=Array.isArray(plan?.content_result_checks)?plan.content_result_checks:[];
  let low=0,high=Math.min(candidates.length,Math.max(0,checkCeiling-contentChecks.length));
  while(low<high){
    const mid=Math.ceil((low+high)/2);
    if(fitsExposureJobLimits({...plan,checks:[...contentChecks,...candidates.slice(0,mid)]}))low=mid;
    else high=mid-1;
  }
  return low;
}
function exposureJobBudget(plan) {
  const budget=plan?.network_budget;
  const valid=(key,ceiling)=>Number.isSafeInteger(budget?.[key])&&budget[key]>0&&budget[key]<=ceiling;
  return valid('requests',EXPOSURE_JOB_LIMITS.workspaceRequests)&&
    valid('bytes',EXPOSURE_JOB_LIMITS.workspaceBytes)&&
    valid('attempts',EXPOSURE_JOB_LIMITS.maxPlannedAttempts)
    ? budget : EXPOSURE_JOB_LIMITS;
}
function growExposureJobBudget(plan) {
  if(!plan.network_budget)return;
  const next=sizeExposureJobBudget(plan);
  for(const key of ['requests','bytes','attempts'])plan.network_budget[key]=Math.max(plan.network_budget[key],next[key]);
}

// Consecutive failures of ONE TLS slice before it is recorded and skipped.
// Below the job-wide cap (EXPOSURE_JOB_LIMITS.failures), so one stubborn slice
// can never end the job by itself.
export const TLS_SLICE_FAILURE_CAP = 2;
const TLS_SLICE_FAILURE_REASONS = new Set(['invalid_receipt','unbounded_receipt','tls_scope_revoked']);
export function tlsSliceFailureReason(error,aborted) {
  if(aborted)return 'slice_time_limit_or_abort';
  const message=String(error?.message||'');
  return TLS_SLICE_FAILURE_REASONS.has(message)?message:'collector_error';
}

async function storeUnrunTlsSlice(env,row,plan,items,state,reason,now,detail={}) {
  const tls=plan.tls,oldCursor=tls.cursor;
  for(const item of items)tls.results.push({endpoint_index:item.endpoint_index,...item.check,state,reason,...detail,observed_at:new Date(now).toISOString(),engine:null,evidence:null,physical_telemetry:{connections:0,bytes_sent:0,bytes_received:0,duration_ms:0}});
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
  if(!await tlsScopeStillAuthorized(env,scan,entry,{authorise:deps.authoriseActiveCheck}))
    return storeUnrunTlsSlice(env,row,plan,items,'not_authorized','scope_changed',now);
  const endpoint=await refreshTlsEndpoint(entry,{lookup:deps.lookupTlsDns}).catch(()=>null);
  if(!endpoint)return storeUnrunTlsSlice(env,row,plan,items,'uncertain','dns_authority_changed',now);
  if(!await tlsScopeStillAuthorized(env,scan,entry,{authorise:deps.authoriseActiveCheck}))
    return storeUnrunTlsSlice(env,row,plan,items,'not_authorized','scope_changed',now);
  const token=crypto.randomUUID().replaceAll('-',''),db=env.cybermeters_db;
  const budget=exposureJobBudget(plan);
  const reservationRequests=TLS_SPECIAL_CONNECTION_LIMITS[items[0].check.control]||TLS_SLICE_LIMITS.connections;
  const reservationBytes=TLS_SLICE_LIMITS.bytes+TLS_SLICE_LIMITS.overreadBytes;
  const window=windowFor(plan);
  const claimed=await db.prepare(`UPDATE external_exposure_jobs SET state='running',lease_token=?,lease_until=?,
    charged_requests=charged_requests+?,charged_bytes=charged_bytes+?,attempts=attempts+1,
    deadline_ms=CASE WHEN attempts=0 THEN ? ELSE deadline_ms END,
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
    .bind(token,now+EXPOSURE_JOB_LIMITS.leaseMs,reservationRequests,reservationBytes,now+runMsFor(plan),new Date(now).toISOString(),
      row.scan_id,row.workspace_id,row.cursor,now,tls.cursor,reservationRequests,budget.requests,
      reservationBytes,budget.bytes,now,now-EXPOSURE_JOB_LIMITS.windowMs,reservationRequests,
      window.requests,now-EXPOSURE_JOB_LIMITS.windowMs,reservationBytes,window.bytes,
      ...tlsScopeParams(entry)).run();
  if(!changed(claimed)){
    const active=await db.prepare('SELECT scan_id FROM external_exposure_jobs WHERE workspace_id=? AND lease_until>? LIMIT 1').bind(row.workspace_id,now).first();
    if(active)return deferBusy(env,row,'tenant_busy');
    if(Number(row.attempts)===0&&windowFull(row,reservationRequests,reservationBytes,budget))return deferForWindow(env,row);
    return finishWithoutProbe(env,row,'budget_exhausted','tls_network_budget',now);
  }
  const controller=new AbortController();
  const remaining=Math.min(TLS_SLICE_LIMITS.durationMs,row.deadline_ms-now);
  const timer=setTimeout(()=>controller.abort(),remaining);
  let polling=false;
  const watchdog=setInterval(async()=>{
    if(polling)return;polling=true;
    try{if(!await canRun(env,row)||!await tlsScopeStillAuthorized(env,scan,entry,{authorise:deps.authoriseActiveCheck}))controller.abort();}
    catch{controller.abort();}finally{polling=false;}
  },1000);
  const input={schema_version:'tls-assessment-request-v1',request_id:token,workspace_id:row.workspace_id,scan_id:row.scan_id,
    domain_id:row.domain_id,domain:row.domain,endpoint,scope:tlsProbeScope(entry.scope),checks:items.map(item=>item.check),
    deadline_at:new Date(now+remaining).toISOString(),max_connections:reservationRequests,max_bytes:TLS_SLICE_LIMITS.bytes};
  try{
    if(!await tlsScopeStillAuthorized(env,scan,entry,{authorise:deps.authoriseActiveCheck}))throw new Error('tls_scope_revoked');
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
    // A stored slice resets the failure streak: the cap ends a job only on
    // CONSECUTIVE thrown slices (22 Oct 2026: two transient content errors and
    // one TLS error ended a healthy sheshire.co.uk job before any TLS ran).
    const stored=await db.prepare(`UPDATE external_exposure_jobs SET state=?,plan_json=?,costs_json=?,failure_count=0,
      charged_requests=charged_requests-?+?,charged_bytes=charged_bytes-?+?,lease_token=NULL,lease_until=0,updated_at=?
      WHERE scan_id=? AND workspace_id=? AND lease_token=? AND lease_until>? AND ${AUTHORITY}
        AND ${TLS_SCOPE_FENCE}`)
      .bind(state,JSON.stringify(plan),JSON.stringify(costs),reservationRequests,t.connections,reservationBytes,actualBytes,
        receipt.finished_at,row.scan_id,row.workspace_id,token,deps.now?.()??Date.now(),...tlsScopeParams(entry)).run();
    if(!changed(stored))return {action:'retry',delaySeconds:30,outcome:'tls_fence_lost'};
    if(state==='complete')await resumeDomain(env,row);else await env.SCAN_QUEUE.send(messageFor(row));
    return {action:'ack',outcome:state};
  }catch(error){
    const active=await canRun(env,row).catch(()=>false);
    // F1 (24 Oct 2026): a slice that keeps failing (ROBOT on a server that
    // stays silent after a bad key exchange ran past its time limit three
    // times) used to end the whole job through the job-wide failure cap, so
    // every check after it, the domain's own included, never ran and the score
    // was withheld. The failure is now counted per slice: after
    // TLS_SLICE_FAILURE_CAP consecutive failures that slice is recorded as
    // 'unexecutable / slice_failed' (with the failure reason) and the job
    // continues. The last failure is kept on the plan for diagnosis. The
    // attempt's reservation stays charged: an unknown attempt may have opened
    // its connections.
    const at=new Date(deps.now?.()??Date.now());
    const key=String(tls.cursor);
    const failures=((tls.slice_failures&&tls.slice_failures[key])||0)+1;
    tls.slice_failures={...(tls.slice_failures||{}),[key]:failures};
    tls.last_slice_failure={cursor:tls.cursor,endpoint_index:items[0].endpoint_index,control:items[0].check.control,
      reason:tlsSliceFailureReason(error,controller.signal.aborted),attempts:failures,at:at.toISOString()};
    // Once a slice is given up the streak resets, so the job-wide failure cap
    // bounds CONSECUTIVE failures only. Total work stays bounded: every retry
    // charges an attempt (budget.attempts), the job has a deadline, and the
    // request/byte budgets keep their unrefunded reservations.
    const giveUp=active&&failures>=TLS_SLICE_FAILURE_CAP;
    await db.prepare(`UPDATE external_exposure_jobs SET state=?,failure_count=CASE WHEN ?=1 THEN 0 ELSE failure_count+1 END,
      unknown_attempts=unknown_attempts+1,plan_json=?,lease_token=NULL,lease_until=0,updated_at=?
      WHERE scan_id=? AND workspace_id=? AND lease_token=?`)
      .bind(active?'pending':'cancelled',giveUp?1:0,JSON.stringify(plan),at.toISOString(),row.scan_id,row.workspace_id,token).run();
    if(!active){await resumeDomain(env,row);return {action:'ack',outcome:'cancelled'};}
    if(giveUp)return storeUnrunTlsSlice(env,row,plan,items,'unexecutable','slice_failed',at.getTime(),
      {failure_reason:tls.last_slice_failure.reason,failure_attempts:failures});
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
  const plan=json(row.plan_json,{checks:[]}),budget=exposureJobBudget(plan);
  if(now>=row.deadline_ms||row.attempts>=budget.attempts||row.failure_count>=EXPOSURE_JOB_LIMITS.failures)
    return finishWithoutProbe(env,row,'budget_exhausted','completion_budget',now);
  const contentPhase=plan.content_state==='pending';
  if(!contentPhase&&row.cursor>=plan.checks.length){
    replanTlsFromOwnResults(plan,json(row.results_json,[]));
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
  const window=windowFor(plan);
  const claimed=await db.prepare(`UPDATE external_exposure_jobs SET state='running',lease_token=?,lease_until=?,
    charged_requests=charged_requests+?,charged_bytes=charged_bytes+?,attempts=attempts+1,
    deadline_ms=CASE WHEN attempts=0 THEN ? ELSE deadline_ms END,
    unknown_attempts=unknown_attempts+CASE WHEN state='running' THEN 1 ELSE 0 END,updated_at=?
    WHERE scan_id=? AND workspace_id=? AND cursor=? AND state IN ('pending','running') AND lease_until<=?
    AND charged_requests+?<=? AND charged_bytes+?<=? AND ${AUTHORITY}
    AND NOT EXISTS(SELECT 1 FROM external_exposure_jobs j WHERE j.workspace_id=external_exposure_jobs.workspace_id
      AND j.scan_id<>external_exposure_jobs.scan_id AND j.lease_until>?)
    AND (SELECT COALESCE(SUM(j.charged_requests),0) FROM external_exposure_jobs j
      WHERE j.workspace_id=external_exposure_jobs.workspace_id AND j.created_ms>=?)+?<=?
    AND (SELECT COALESCE(SUM(j.charged_bytes),0) FROM external_exposure_jobs j
      WHERE j.workspace_id=external_exposure_jobs.workspace_id AND j.created_ms>=?)+?<=?`)
    .bind(token,now+EXPOSURE_JOB_LIMITS.leaseMs,reservationRequests,reservationBytes,now+runMsFor(plan),new Date(now).toISOString(),
      row.scan_id,row.workspace_id,row.cursor,now,reservationRequests,budget.requests,
      reservationBytes,budget.bytes,now,now-EXPOSURE_JOB_LIMITS.windowMs,reservationRequests,
      window.requests,now-EXPOSURE_JOB_LIMITS.windowMs,reservationBytes,window.bytes).run();
  if(!changed(claimed)){
    const active=await db.prepare('SELECT scan_id FROM external_exposure_jobs WHERE workspace_id=? AND lease_until>? LIMIT 1').bind(row.workspace_id,now).first();
    if(active)return deferBusy(env,row,'tenant_busy');
    if(Number(row.attempts)===0&&windowFull(row,reservationRequests,reservationBytes,budget))return deferForWindow(env,row);
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
    if(!contentPhase&&receipt.host_outcome){
      // The collector proved a terminal host outcome with one DNS resolution or
      // two 5xx control responses. No catalogue path on that host was tested.
      const removed=plan.checks.filter((check,index)=>index>=row.cursor&&new URL(check.url).origin===origin);
      plan.checks=plan.checks.filter((check,index)=>index<row.cursor||new URL(check.url).origin!==origin);
      plan.host_outcomes=[...(plan.host_outcomes||[]),{hostname:new URL(origin).hostname,
        state:receipt.host_outcome.state,reason:receipt.host_outcome.reason,
        statuses:receipt.host_outcome.statuses,skipped_checks:removed.length,observed_at:receipt.finished_at}];
    }
    if(!contentPhase&&!receipt.host_outcome&&Array.isArray(receipt.baseline)){
      const baselines=Array.isArray(plan.http_baselines)?plan.http_baselines.filter(item=>item.origin!==origin):[];
      plan.http_baselines=[...baselines,{origin,controls:receipt.baseline,observed_at:receipt.finished_at}].slice(-32);
    }
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
      const nextCheck={rule_id:candidate.ruleId,url:candidate.url};
      const contentCount=plan.content_result_checks?.length||0;
      if(budgetedExposurePrefix(plan,[...plan.checks,nextCheck])<plan.checks.length+1){
        plan.omitted_checks=(plan.omitted_checks||0)+1;continue;
      }
      plan.checks.push(nextCheck);
      plan.exposure_check_limit=contentCount+plan.checks.length;
    }
    if(!contentPhase)plan.discovered_hosts=[...new Set([...(plan.discovered_hosts||[]),...(receipt.discoveries?.hosts||[])])].filter(h=>safeHost(h,row.domain)).slice(0,128);
    growExposureJobBudget(plan);
    const cursor=contentPhase?0:row.cursor+(receipt.host_outcome?0:checks.length);
    // A first scan defers every host (no earlier job observed HTTPS), so its TLS
    // plan is empty and the last content slice would end the job before the
    // replan in processExposureMessage could run (22 Oct 2026, blackbullbarbers.co.uk:
    // HTTPS observed by this job's own checks, 0 TLS checks). Replan here, from
    // this job's results, before deciding whether the job is complete.
    if(cursor>=plan.checks.length)replanTlsFromOwnResults(plan,results);
    const state=cursor>=plan.checks.length && (!plan.tls || plan.tls.cursor>=plan.tls.selected.length)?'complete':'pending';
    // Receipt + progress + refund are one atomic, fenced commit. A late result
    // from a replaced process cannot refund its already-charged reservation.
    const stored=await db.prepare(`UPDATE external_exposure_jobs SET state=?,cursor=?,plan_json=?,results_json=?,costs_json=?,failure_count=0,
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
  const priorPortals=new Set((plan.retest_checks||[]).filter(c=>c.rule_id==='remote-access-portal').map(c=>c.url));
  // Hiding the known portal's browser page is not evidence that the remote
  // service was removed or patched. Keep the raw receipt, but project this
  // retest as inconclusive so it cannot verify a case or claim healthy coverage.
  const checks=[...results,...pending].map(c=>c.rule_id==='remote-access-portal'&&priorPortals.has(c.url)&&['not_found','not_present_soft404'].includes(c.state)
    ? {...c,state:'uncertain',comparable:false,reason:'remote_access_retest_inconclusive'} : c);
  // The durable job can exhaust after HTTP finished while deep TLS is still
  // pending. Its terminal state must not downgrade already completed HTTP.
  const httpComplete=row.cursor>=plan.checks.length && plan.content_state!=='pending' &&
    (row.state==='complete'||row.state==='budget_exhausted'&&Boolean(plan.tls));
  const notApplicableHosts=(Array.isArray(plan.hosts_not_applicable)?plan.hosts_not_applicable:[]).filter(h=>typeof h?.hostname==='string');
  const hostOutcomes=(Array.isArray(plan.host_outcomes)?plan.host_outcomes:[]).filter(h=>
    typeof h?.hostname==='string'&&['target_unavailable','host_does_not_resolve'].includes(h.state));
  const checkedAt=new Map();
  for(const check of results){
    try{
      const hostname=new URL(check.url).hostname;
      if(check.observed_at&&(!checkedAt.has(hostname)||check.observed_at>checkedAt.get(hostname)))checkedAt.set(hostname,check.observed_at);
    }catch{/* A malformed historical URL cannot establish host coverage. */}
  }
  for(const host of hostOutcomes)if(host.observed_at)checkedAt.set(host.hostname,host.observed_at);
  for(const host of notApplicableHosts)if(host.evidence?.scan_id===scanId&&host.evidence?.observed_at)
    checkedAt.set(host.hostname,host.evidence.observed_at);
  const hostCoverage=(Array.isArray(plan.host_coverage)?plan.host_coverage:[])
    .filter(host=>typeof host?.hostname==='string'&&safeHost(host.hostname,row.domain))
    .map(host=>({hostname:host.hostname,checked_this_scan:checkedAt.has(host.hostname),
      last_checked_at:checkedAt.get(host.hostname)||host.last_checked_at||null,
      evidence_state:hostOutcomes.find(item=>item.hostname===host.hostname)?.state||
        (notApplicableHosts.some(item=>item.hostname===host.hostname&&item.evidence?.scan_id===scanId)?'host_does_not_resolve':
          checkedAt.has(host.hostname)?'checked':'awaiting_rotation')}));
  const deferredPriorFindings=unresolvedExposureChecks(plan.retest_checks||[],results)
    .filter(item=>[...hostOutcomes,...notApplicableHosts].some(host=>{
      try{return new URL(item.url).hostname===host.hostname;}catch{return false;}
    })).length;
  const coverage={completed:0,pending:0,blocked:0,not_applicable:0,budget_exhausted:plan.omitted_checks||0,uncertain:0,recorded_total:checks.length,omitted_checks:plan.omitted_checks||0,pending_assets:plan.pending_assets||0,
    not_applicable_hosts:notApplicableHosts.length,target_unavailable_hosts:hostOutcomes.filter(h=>h.state==='target_unavailable').length,
    non_resolving_hosts:hostOutcomes.filter(h=>h.state==='host_does_not_resolve').length,
    hosts_total:Number.isSafeInteger(plan.hosts_total)?plan.hosts_total:null,
    hosts_checked:hostCoverage.filter(host=>host.checked_this_scan).length,
    deferred_prior_findings:deferredPriorFindings,
    execution_complete_hosts:hostOutcomes.length};
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
  return {source:'external_exposure',version:'1',quality:httpComplete&&checks.every(r=>r.comparable)&&
    hostOutcomes.length===0&&notApplicableHosts.length===0&&coverage.omitted_checks===0&&
    coverage.pending_assets===0?'complete':'partial',
    job_state:row.state,phase_state:httpComplete?'complete':row.state,
    incomplete_reason:exposureIncompleteReason(httpComplete?'complete':row.state,coverage,checks.length),
    hosts_not_applicable:notApplicableHosts.map(h=>({hostname:h.hostname,reason:h.reason,observed_at:h.evidence?.observed_at||null})),
    host_outcomes:hostOutcomes,host_coverage:hostCoverage,
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
  const all=classifyTlsRefusals([...tls.static_results,...tls.results,...tls.selected.slice(tls.cursor).map(item=>({endpoint_index:item.endpoint_index,...item.check,
    state:pendingState,reason:pendingReason,observed_at:null,engine:null,evidence:null,
    physical_telemetry:{connections:0,bytes_sent:0,bytes_received:0,duration_ms:0}}))]);
  const endpoints=tls.endpoints.map((entry,index)=>({
    ...entry.endpoint,endpoint_identity:entry.endpoint_identity,scope:entry.scope,
    checks:(()=>{
      const rows=all.filter(item=>item.endpoint_index===index).map(({endpoint_index,check,...rest})=>
        ({...(check||{}),...rest,endpoint_identity:entry.endpoint_identity}));
      // The customer outcome per control (compression used, 0-RTT advertised,
      // OCSP stapled, renegotiation refused, downgrade blocked); raw state stays.
      return rows.map(row=>{const outcome=tlsControlOutcome(row,rows);return outcome?{...row,customer_outcome:outcome}:row;});
    })(),
  }));
  const coverage={planned:all.length+(tls.omitted_checks||0),completed:0,uncertain:0,unexecutable:0,not_authorized:0,not_applicable:0,
    omitted_checks:tls.omitted_checks||0,omitted_services:tls.omitted_services||0,endpoint_gaps:tls.gaps.length,
    deferred_hosts:tls.deferred_hosts?.length||0,deferred_endpoints:tls.deferred_endpoints?.length||0};
  for(const item of all){
    if(['accepted','rejected'].includes(item.state))coverage.completed++;
    else if(item.state==='not_authorized')coverage.not_authorized++;
    else if(item.state==='not_applicable')coverage.not_applicable++;
    else if(item.state==='unexecutable')coverage.unexecutable++;
    else coverage.uncertain++;
  }
  const costs=json(row.costs_json,{});
  const tlsComplete=row.state==='complete'&&tls.cursor>=tls.selected.length;
  const quality=tlsComplete&&tls.selected.length>0&&coverage.completed>0&&coverage.uncertain===0&&blockingTlsUnexecutable(all)===0&&blockingTlsNotAuthorized(all)===0&&
    coverage.omitted_checks===0&&coverage.omitted_services===0&&coverage.endpoint_gaps===0?'complete':'partial';
  return {source:'tls_assessment',version:tls.profile_version,policy_version:tls.policy_version,quality,
    phase_state:tlsComplete?'complete':row.state,coverage,endpoints,
    gaps:tls.gaps,scope_deferrals:{hosts:tls.deferred_hosts||[],endpoints:tls.deferred_endpoints||[]},trust_store_context:TLS_TRUST_BUNDLE,
    costs:{connections:costs.tls_connections||0,bytes_sent:costs.tls_bytes_sent||0,
      bytes_received:costs.tls_bytes_received||0,duration_ms:costs.tls_duration_ms||0,
      charged_connections:row.charged_requests,charged_bytes:row.charged_bytes,unknown_attempts:row.unknown_attempts,
      attempts:row.attempts},limitations:['tcp_tls_only_quic_not_assessed','observed_endpoint_not_origin_inference','no_external_revocation_fetch'],
    observed_at:row.updated_at,findings:[]};
}
