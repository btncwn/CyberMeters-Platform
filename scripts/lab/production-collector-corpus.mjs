// Lab-only measurement adapter. Transport, scope, limits and detection stay in
// production modules; no HTML/header text is written to the corpus report.
import fs from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { createBoundedHttpSession } from '../../workers/network-probe/src/bounded-http-session.js';
import { isProbeHostname } from '../../workers/network-probe/src/contract.js';
import { siteHosts } from '../../workers/scan-api/src/engines/page-discovery.js';
import { EXPOSURE_LIMITS, validateExposureRequest } from '../../workers/network-probe/src/exposure-contract.js';
import { evaluateExposure } from '../../shared/exposure/evaluate.js';
import { REMOTE_ACCESS_TABLE_VERSION } from '../../shared/exposure/remote-access.js';
import { phpRuntimeObservation, PHP_RUNTIME_TABLE_VERSION } from '../../workers/scan-api/src/engines/php-runtime.js';
import { classifyFetchObservation } from '../../workers/scan-api/src/lib/fetch-observation.js';
import { classifyServiceability } from '../../workers/scan-api/src/lib/serviceability.js';

export function corpusRequest(host, origin = `https://${host}`) {
  return { schema_version:'exposure-request-v1', request_id:'corpus', workspace_id:'local_corpus', scan_id:'local_corpus',
    origin, deadline_at:new Date(Date.now()+EXPOSURE_LIMITS.durationMs).toISOString(),
    checks:[{rule_id:'remote-access-portal',url:origin+'/'}],
    max_requests:EXPOSURE_LIMITS.requests, max_bytes:EXPOSURE_LIMITS.bytes };
}
// Asset scheduling is outside each origin's strict transport boundary. Reuse
// production's www/apex normalisation and subdomain scope; never widen fetchBounded.
export function sameSiteRedirectOrigin(host, response) {
  if(response?.error!=='off_origin_redirect'||![301,302,303,307,308].includes(response.status))return null;
  try {
    const target=new URL(response.headers.location,response.url);
    const root=[...siteHosts(host)][0];
    if(!root||target.protocol!=='https:'||target.username||target.password||target.port||target.href.length>1024
      ||!isProbeHostname(target.hostname)||!(target.hostname===root||target.hostname.endsWith('.'+root))
      ||target.origin===new URL(response.url).origin)return null;
    return target.origin;
  } catch { return null; }
}

// tech-scan admits serviceable 2xx headers independently of body completeness
// and exposure controls. If a later body read failed after a first chunk,
// tech-scan would already have cancelled its reader and admitted the headers.
export function phpHeaderObservation(response, host) {
  const capped=response?.truncated&&['body_limit','wire_limit','decoded_limit'].includes(response.error);
  const firstChunkObserved=(response?.bytesRead||0)>0;
  if(!response||response.error&&!capped&&!firstChunkObserved)return {observation:null,reason:response?.error||'transport_unavailable'};
  const serviceability=classifyServiceability(classifyFetchObservation({response:{status:response.status,headers:new Headers(response.headers)},executed:true}));
  if(serviceability.serviceable!==true)return {observation:null,reason:serviceability.reason};
  let inScope=false;
  try { const observed=new URL(response.url).hostname;inScope=observed===host||observed.endsWith('.'+host); } catch {}
  const observation=phpRuntimeObservation({poweredBy:response.headers['x-powered-by'],server:response.headers.server,
    url:inScope&&response.status>=200&&response.status<300?response.url:null});
  return {observation,reason:observation.state};
}

export function unknownKind(reason) {
  if (/^(body_limit|wire_limit|decoded_limit|byte_budget_exhausted)$/.test(reason)) return 'size';
  if (/timeout|deadline/.test(reason)) return 'time';
  if (/decode|encoding/.test(reason)) return 'decode';
  if (/206/.test(reason)) return 'partial_206';
  if (/control/.test(reason)) return 'control';
  if (/redirect/.test(reason)) return 'redirect';
  if (/authentication|restricted|challenge/.test(reason)) return 'access';
  if (/dns/.test(reason)) return 'dns';
  if (/status|target_unavailable/.test(reason)) return 'status';
  return 'transport_or_other';
}
const metadata = response => ({status:response.status, bytes_retained:response.bytes?.length || 0,
  truncated:response.truncated, error:response.error, ...(response.status===206?{unknown_kind:'partial_206'}:response.error?{unknown_kind:unknownKind(response.error)}:{})});

export async function measureCorpusHost(host, {dependencies={}, request=corpusRequest(host)}={}) {
  const valid=validateExposureRequest(request); if(!valid.ok)throw new Error(valid.reason);
  // Only retain one additional public header for the existing PHP parser. This
  // changes no HTTP request, TLS/DNS check, byte/time limit or redirect rule.
  const session=await createBoundedHttpSession(request,dependencies,{headerNames:['x-powered-by']});
  const controls=[]; let response=null;
  try {
    const token=randomBytes(16).toString('hex');
    // Same two random-path controls and early host outcomes as runExposureCollector.
    for(const suffix of ['', '.txt']) {
      const control=await session.fetchBounded(`${request.origin}/.cybermeters-missing-${token}${suffix}`);
      controls.push(control);
      if(!control.error&&!control.truncated)session.telemetry.controls_completed++;
      if(controls.length===1&&control.error==='dns_no_address')break;
      if(controls.length===1&&control.status>=500&&control.status<=599)await new Promise(resolve=>setTimeout(resolve,2000));
    }
    const unavailable=controls[0]?.error==='dns_no_address' || controls.length===2&&controls.every(c=>!c.error&&!c.truncated&&c.status>=500&&c.status<=599);
    if(!unavailable)response=await session.fetchBounded(request.checks[0].url);
    let evaluated=response?evaluateExposure({rule:'remote-access-portal',response,controls}):{state:'uncertain',comparable:false,reason:controls[0]?.error||'target_unavailable'};
    if(response) {
      const boundedPrefix=response.truncated&&['body_limit','wire_limit','decoded_limit'].includes(response.error);
      if(response.error&&!boundedPrefix || response.truncated&&!['finding','observed'].includes(evaluated.state) || session.telemetry.controls_completed!==2)
        evaluated={state:'uncertain',comparable:false,reason:response.error||'incomplete_controls'};
    }
    const controlsUsable=evaluateExposure({rule:'remote-access-portal',response:{url:request.origin+'/',status:404,body:''},controls}).comparable===true;
    const badControl=controls.find(c=>c.error||c.truncated||![200,404,410].includes(c.status));
    const reason=!response?controls[0]?.error||'target_unavailable':badControl?'control_'+(badControl.error||'status_'+badControl.status)
      :!controlsUsable?'control_content':response.status===206?'partial_206':evaluated.reason;
    const {observation,reason:phpReason}=phpHeaderObservation(response,new URL(request.origin).hostname);
    session.telemetry.duration_ms=Date.now()-session.started;
    return { origin:request.origin,redirect_origin:sameSiteRedirectOrigin(host,response),php_reason:phpReason,reason, unknown_kind:!response?unknownKind(reason):!controlsUsable?'control':unknownKind(reason), controls_usable:controlsUsable,
      controls:controls.map(metadata), response:response?metadata(response):null,
      telemetry:{...session.telemetry}, portal:evaluated.portal||null, portal_state:evaluated.state,
      portal_comparable:evaluated.comparable===true, php_runtime:observation,
      header_sha256:observation?createHash('sha256').update(JSON.stringify([response.headers.server,response.headers['x-powered-by']])).digest('hex'):null };
  } finally { session.close(); }
}

export async function measureCorpusOrigins(host, options={}) {
  const apex=await measureCorpusHost(host,options);
  if(!apex.redirect_origin)return [{origin_role:'listed_origin',selected_for_summary:true,...apex}];
  const target=await measureCorpusHost(host,{...options,request:corpusRequest(host,apex.redirect_origin)});
  // One cross-origin transition only. A further redirect stays an unknown row.
  return [{origin_role:'redirect_target',selected_for_summary:true,...target},
    {origin_role:'listed_origin',selected_for_summary:false,...apex}];
}

export function projectCorpusRecord(measured, mode, corpusId) {
  const {php_runtime,portal,...rest}=measured;
  const record={corpus_id:corpusId,classification:'unknown',...rest};
  if(mode==='remote-access') {
    if(portal){record.portal=portal;record.classification='review_required';}
    else if(measured.portal_comparable)record.classification='not_detected';
  } else {
    record.reason=measured.php_reason;
    record.unknown_kind=unknownKind(record.reason);
    if(php_runtime) {
      record.state=php_runtime.state;
      if(php_runtime.reported_version)record.reported_version=php_runtime.reported_version;
      record.classification=['outdated','hidden'].includes(php_runtime.state)?'review_required'
        :['fixed','absent'].includes(php_runtime.state)?'not_detected':'unknown';
      record.unknown_kind='version';
    }
  }
  if(record.classification!=='unknown')delete record.unknown_kind;
  return record;
}
const counts=records=>({total:records.length,tp:0,fp:0,unknown:records.filter(r=>r.classification==='unknown').length,
  not_detected:records.filter(r=>r.classification==='not_detected').length,review_required:records.filter(r=>r.classification==='review_required').length});
const tally=(records,key)=>Object.fromEntries([...new Set(records.map(r=>r[key]))].sort().map(reason=>[reason,records.filter(r=>r[key]===reason).length]));
export const originUnknownReasons=(records,role)=>tally(records.filter(r=>r.origin_role===role&&r.classification==='unknown'),'reason');

export async function runProductionCorpus(mode, argv=process.argv.slice(2)) {
  const at=argv.indexOf('--output'); if(at<0||!argv[at+1])throw new Error('--output required');
  const corpus=fs.readFileSync(new URL('./free-scan-corpus.txt',import.meta.url),'utf8');
  const hosts=corpus.split(/\r?\n/).map(v=>v.trim().split(/\s+/)[0]).filter(v=>/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v));
  if(hosts.length!==105)throw new Error('Expected the existing105-domain corpus');
  const groups=new Array(hosts.length); let cursor=0,finished=0;
  async function worker() {
    for(;;) {
      const i=cursor++; if(i>=hosts.length)return;
      const corpusId=`entry-${String(i+1).padStart(3,'0')}`;
      try { groups[i]=(await measureCorpusOrigins(hosts[i])).map(row=>projectCorpusRecord(row,mode,corpusId)); }
      catch { groups[i]=[{corpus_id:corpusId,selected_for_summary:true,classification:'unknown',reason:'measurement_failed',unknown_kind:'measurement'}]; }
      if(++finished%10===0)console.log(`Corpus ${finished}/${hosts.length}`);
    }
  }
  await Promise.all([worker(),worker(),worker()]);
  const records=groups.flat(),selected=records.filter(r=>r.selected_for_summary),unknown=selected.filter(r=>r.classification==='unknown');
  const report={schema:`${mode}-corpus-v3`,observed_at:new Date().toISOString(),corpus_sha256:createHash('sha256').update(corpus).digest('hex'),
    table_version:mode==='remote-access'?REMOTE_ACCESS_TABLE_VERSION:PHP_RUNTIME_TABLE_VERSION,
    collector:'production bounded session/evaluator; one same-site asset origin transition with fresh controls',limits_per_origin:EXPOSURE_LIMITS,
    scope:'Existing105-domain corpus and one same-site origin named by its redirect. Each origin gets its own bounded GETs and controls; no login paths, authentication or production writes. PHP uses production header/serviceability admission under this exposure transport.',
    counts:counts(selected),origin_counts:counts(records),listed_origin_counts:counts(records.filter(r=>r.origin_role==='listed_origin')),
    redirect_origin_counts:counts(records.filter(r=>r.origin_role==='redirect_target')),
    unknown_by_reason:tally(unknown,'reason'),unknown_by_kind:tally(unknown,'unknown_kind'),
    listed_origin_unknown_by_reason:originUnknownReasons(records,'listed_origin'),
    redirect_origin_unknown_by_reason:originUnknownReasons(records,'redirect_target'),
    limitation:'Headline counts use one selected origin per corpus entry, redirect target when allowed, otherwise listed origin. The original listed/apex row is retained separately. One cross-origin transition only; no ground-truth label or accuracy is inferred. No F2 absence from partial bodies; PHP headers remain admissible on local body caps/206 as in production. Per-response retained bytes and aggregate wire/decoded overread stay explicit; no raw bodies/header text persisted.',records};
  fs.writeFileSync(argv[at+1],JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify({counts:report.counts,origin_counts:report.origin_counts,unknown_by_reason:report.unknown_by_reason}));
  if(report.counts.review_required||records.some(r=>r.reason==='measurement_failed'))process.exitCode=1;
}
