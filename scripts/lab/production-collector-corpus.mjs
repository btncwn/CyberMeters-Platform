// Lab-only measurement adapter. Transport, scope, limits and detection stay in
// production modules; no HTML/header text is written to the corpus report.
import fs from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { createBoundedHttpSession } from '../../workers/network-probe/src/bounded-http-session.js';
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
    const observation=controlsUsable&&response&&!response.error&&!response.truncated&&response.status!==206
      &&classifyServiceability(classifyFetchObservation({response:{status:response.status,headers:new Headers(response.headers)},executed:true})).serviceable===true
      ?phpRuntimeObservation({poweredBy:response.headers['x-powered-by'],server:response.headers.server,url:response.url}):null;
    session.telemetry.duration_ms=Date.now()-session.started;
    return { reason, unknown_kind:!response?unknownKind(reason):!controlsUsable?'control':unknownKind(reason), controls_usable:controlsUsable,
      controls:controls.map(metadata), response:response?metadata(response):null,
      telemetry:{...session.telemetry}, portal:evaluated.portal||null, portal_state:evaluated.state,
      portal_comparable:evaluated.comparable===true, php_runtime:observation,
      header_sha256:observation?createHash('sha256').update(JSON.stringify([response.headers.server,response.headers['x-powered-by']])).digest('hex'):null };
  } finally { session.close(); }
}

export async function runProductionCorpus(mode, argv=process.argv.slice(2)) {
  const at=argv.indexOf('--output'); if(at<0||!argv[at+1])throw new Error('--output required');
  const corpus=fs.readFileSync(new URL('./free-scan-corpus.txt',import.meta.url),'utf8');
  const hosts=corpus.split(/\r?\n/).map(v=>v.trim().split(/\s+/)[0]).filter(v=>/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v));
  if(hosts.length!==105)throw new Error('Expected the existing105-domain corpus');
  const records=new Array(hosts.length); let cursor=0,finished=0;
  async function worker() {
    for(;;) {
      const i=cursor++; if(i>=hosts.length)return;
      const record={corpus_id:`entry-${String(i+1).padStart(3,'0')}`,classification:'unknown'};
      try {
        const measured=await measureCorpusHost(hosts[i]);
        const {php_runtime,portal,...rest}=measured; Object.assign(record,rest);
        if(mode==='remote-access') {
          if(portal){record.portal=portal;record.classification='review_required';}
          else if(measured.portal_comparable)record.classification='not_detected';
        } else if(php_runtime) {
          record.state=php_runtime.state; record.reason=php_runtime.state;
          if(php_runtime.reported_version)record.reported_version=php_runtime.reported_version;
          record.classification=['outdated','hidden'].includes(php_runtime.state)?'review_required'
            :['fixed','absent'].includes(php_runtime.state)?'not_detected':'unknown';
          record.unknown_kind='version';
        }
      } catch { record.reason='measurement_failed';record.unknown_kind='measurement'; }
      if(record.classification!=='unknown')delete record.unknown_kind;
      records[i]=record;if(++finished%10===0)console.log(`Corpus ${finished}/${hosts.length}`);
    }
  }
  await Promise.all([worker(),worker(),worker()]);
  const unknown=records.filter(r=>r.classification==='unknown');
  const tally=key=>Object.fromEntries([...new Set(unknown.map(r=>r[key]))].sort().map(reason=>[reason,unknown.filter(r=>r[key]===reason).length]));
  const report={schema:`${mode}-corpus-v2`,observed_at:new Date().toISOString(),corpus_sha256:createHash('sha256').update(corpus).digest('hex'),
    table_version:mode==='remote-access'?REMOTE_ACCESS_TABLE_VERSION:PHP_RUNTIME_TABLE_VERSION,
    collector:'production createBoundedHttpSession + two exposure controls + existing detectors; homepage only',limits:EXPOSURE_LIMITS,
    scope:'Existing105-domain corpus; same-origin bounded GETs and two negative controls; no login-path enumeration, authentication or production writes. PHP parsing uses these exposure-transport responses, not the separate production technology transport.',
    counts:{total:hosts.length,tp:0,fp:0,unknown:unknown.length,not_detected:records.filter(r=>r.classification==='not_detected').length,review_required:records.filter(r=>r.classification==='review_required').length},
    unknown_by_reason:tally('reason'),unknown_by_kind:tally('unknown_kind'),
    limitation:'No ground-truth label or positive accuracy is inferred. Candidates require independent triage; no portal/runtime absence is inferred from partial bodies. Retained-byte metadata is exact per response; wire/decoded counters are aggregate delivered chunks, including overread. No raw bodies or header text persisted.',records};
  fs.writeFileSync(argv[at+1],JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({counts:report.counts,unknown_by_reason:report.unknown_by_reason}));
  if(report.counts.review_required||records.some(r=>r.reason==='measurement_failed'))process.exitCode=1;
}
