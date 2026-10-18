import { isProbeHostname } from './contract.js';
import { EXPOSURE_RULES, RULES_BY_ID, EXPOSURE_INDICATORS } from '../../../shared/exposure/catalog.js';
import { isRulePathAllowed, exposureIdentity, safeExposureUrl } from '../../../shared/exposure/redaction.js';

export const EXPOSURE_LIMITS = Object.freeze({ requests:12, checks:10, bytes:524288, responseBytes:131072, requestBytes:16384, durationMs:15000, bodyBytes:32768 });

// This contract accepts a reviewed rule identifier and an exact verified origin,
// never a transport override, executable, headers, credentials or DNS answer.
export function validateExposureRequest(input, now=Date.now()) {
  const fail=reason=>({ok:false,reason});
  if(!input||typeof input!=='object'||Array.isArray(input))return fail('invalid_request');
  const allowed=['schema_version','request_id','workspace_id','scan_id','origin','deadline_at','checks','max_requests','max_bytes'];
  if(Object.keys(input).some(key=>!allowed.includes(key)))return fail('unknown_request_field');
  if(input.schema_version!=='exposure-request-v1')return fail('unknown_schema');
  for(const key of ['request_id','workspace_id','scan_id'])if(typeof input[key]!=='string'||!/^[a-zA-Z0-9_-]{1,100}$/.test(input[key]))return fail('invalid_identity');
  const deadline=Date.parse(input.deadline_at);
  if(!Number.isFinite(deadline)||deadline<=now||deadline>now+15000)return fail('invalid_deadline');
  let origin;
  try{origin=new URL(input.origin);}catch{return fail('invalid_origin');}
  if(input.origin!==origin.origin||!['http:','https:'].includes(origin.protocol)||origin.port||!isProbeHostname(origin.hostname))return fail('invalid_origin');
  if(!Number.isInteger(input.max_requests)||input.max_requests<3||input.max_requests>12)return fail('request_limit');
  if(!Number.isInteger(input.max_bytes)||input.max_bytes<4096||input.max_bytes>524288)return fail('byte_limit');
  if(!Array.isArray(input.checks)||input.checks.length<1||input.checks.length>10||input.checks.length>input.max_requests-2)return fail('check_limit');
  const seen=new Set();
  for(const check of input.checks){
    if(!check||typeof check!=='object'||Array.isArray(check)||Object.keys(check).some(key=>!['rule_id','url'].includes(key)))return fail('invalid_check');
    if(typeof check.rule_id!=='string'||!Object.hasOwn(RULES_BY_ID,check.rule_id))return fail('unknown_rule');
    let url;try{url=new URL(check.url);}catch{return fail('invalid_url');}
    if(typeof check.url!=='string'||check.url.length>1024||url.origin!==origin.origin||url.username||url.password||url.search||url.hash||url.href!==check.url)return fail('off_origin_check');
    const rule=RULES_BY_ID[check.rule_id];
    if(!isRulePathAllowed(rule,url.pathname))return fail('unapproved_path');
    const key=check.rule_id+'|'+check.url;if(seen.has(key))return fail('duplicate_check');seen.add(key);
  }
  return {ok:true};
}

// Strict output shape prevents response bodies, headers, tokens or arbitrary
// response-derived text leaking through an otherwise valid private receipt.
export function validateExposureReceipt(request,receipt,{now=Date.now()}={}) {
  const fail=reason=>({ok:false,reason});
  const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).every(key=>keys.includes(key));
  if(!exact(receipt,['schema_version','request_id','workspace_id','scan_id','origin','started_at','finished_at','quality','results','baseline','host_outcome','discoveries','telemetry','limitations'])||receipt.schema_version!=='exposure-receipt-v1')return fail('invalid_receipt');
  for(const key of ['request_id','workspace_id','scan_id','origin'])if(receipt[key]!==request[key])return fail('identity_mismatch');
  const start=Date.parse(receipt.started_at),finish=Date.parse(receipt.finished_at),deadline=Date.parse(request.deadline_at);
  if(!Number.isFinite(start)||!Number.isFinite(finish)||start>finish||start<deadline-15000||finish>deadline+1000||finish>now+1000||now-finish>60000)return fail('time_mismatch');
  const outcome=receipt.host_outcome;
  if(outcome!=null&&(!exact(outcome,['state','reason','statuses'])||
      !['host_does_not_resolve','target_unavailable'].includes(outcome.state)||
      !Array.isArray(outcome.statuses)||
      (outcome.state==='host_does_not_resolve'&&(outcome.reason!=='authoritative_no_address'||outcome.statuses.length!==0))||
      (outcome.state==='target_unavailable'&&(!['server_error','edge_origin_unreachable'].includes(outcome.reason)||outcome.statuses.length!==2||
        outcome.statuses.some(status=>!Number.isInteger(status)||status<500||status>599)))))return fail('invalid_host_outcome');
  if(!Array.isArray(receipt.results)||receipt.results.length!==(outcome?0:request.checks.length))return fail('result_count');
  const validSummary=s=>exact(s,['status','content_type','body_length','normalized_length','body_sha256','normalized_sha256'])&&
    Number.isSafeInteger(s.status)&&s.status>=0&&s.status<=599&&Number.isSafeInteger(s.body_length)&&s.body_length>=0&&s.body_length<=32768&&
    Number.isSafeInteger(s.normalized_length)&&s.normalized_length>=0&&s.normalized_length<=32768&&
    (s.content_type===null||typeof s.content_type==='string'&&/^[a-z0-9.+-]+\/[a-z0-9.+-]+$/.test(s.content_type))&&
    [s.body_sha256,s.normalized_sha256].every(h=>h===null||typeof h==='string'&&/^[a-f0-9]{64}$/.test(h));
  if(receipt.baseline!==undefined&&(!Array.isArray(receipt.baseline)||receipt.baseline.length!==(outcome?.state==='host_does_not_resolve'?1:2)||!receipt.baseline.every(validSummary)))return fail('invalid_baseline');
  if(outcome?.state==='host_does_not_resolve'&&(receipt.baseline?.length!==1||receipt.baseline[0].status!==0))return fail('unproved_no_address');
  if(outcome?.state==='target_unavailable'&&(!receipt.baseline||receipt.baseline.length!==2||
      receipt.baseline.some((row,i)=>row.status!==outcome.statuses[i])||
      outcome.reason==='edge_origin_unreachable'&&outcome.statuses.some(status=>![522,523].includes(status))))return fail('unproved_server_error');
  const near=(a,b)=>Math.abs(a-b)<=Math.max(16,Math.ceil(Math.max(a,b)*0.05));
  if(!exact(receipt.discoveries,['paths','hosts'])||!Array.isArray(receipt.discoveries.paths)||!Array.isArray(receipt.discoveries.hosts)||receipt.discoveries.paths.length>32||receipt.discoveries.hosts.length>32)return fail('invalid_discoveries');
  if(receipt.discoveries.paths.some(path=>!EXPOSURE_RULES.some(rule=>isRulePathAllowed(rule,path)))||receipt.discoveries.hosts.some(host=>!isProbeHostname(host)||!host.endsWith('.'+new URL(request.origin).hostname)))return fail('unsafe_discoveries');
  const t=receipt.telemetry;
  if(!exact(t,['requests','redirects','retries','bytes_wire','bytes_decoded','duration_ms','byte_limit_exceeded','controls_completed']))return fail('invalid_telemetry');
  for(const key of ['requests','redirects','retries','bytes_wire','bytes_decoded','duration_ms','controls_completed'])if(!Number.isSafeInteger(t[key])||t[key]<0)return fail('invalid_counter');
  if(t.requests>request.max_requests||t.redirects>t.requests||t.retries!==0||t.controls_completed>2||t.duration_ms!==finish-start||typeof t.byte_limit_exceeded!=='boolean')return fail('counter_mismatch');
  if(outcome&&(receipt.quality!=='partial'||receipt.discoveries?.paths?.length||receipt.discoveries?.hosts?.length||
      outcome.state==='host_does_not_resolve'&&(t.requests!==0||t.controls_completed!==0)||
      outcome.state==='target_unavailable'&&(t.requests<2||t.controls_completed!==2)))return fail('host_outcome_mismatch');
  // A received transport/decompressor chunk may cross the cut-off before it is
  // destroyed. Actual counters remain honest; these are not processed bytes.
  if(t.bytes_wire>request.max_bytes+131072||t.bytes_decoded>request.max_bytes+131072)return fail('unbounded_overread');
  if((t.bytes_wire>request.max_bytes||t.bytes_decoded>request.max_bytes)&&!t.byte_limit_exceeded)return fail('unreported_overread');
  for(let i=0;i<receipt.results.length;i++){
    const row=receipt.results[i],expected=request.checks[i];
    if(!exact(row,['rule_id','url','identity','indicators','state','comparable','finding','observation','reason','response_summary'])||row.rule_id!==expected.rule_id||row.url!==expected.url||row.identity!==exposureIdentity(expected.rule_id,expected.url))return fail('result_identity');
    if(!['finding','observed','not_found','not_present_soft404','blocked','uncertain','not_applicable'].includes(row.state)||typeof row.comparable!=='boolean'||(row.reason!==null&&!/^[a-z0-9_]{1,80}$/.test(row.reason)))return fail('invalid_result');
    if(row.state==='not_present_soft404'){
      const [first,second]=receipt.baseline||[];
      const observed=row.response_summary;
      if(!row.comparable||row.reason!=='matches_two_negative_controls'||!Array.isArray(row.indicators)||row.indicators.length!==0||
          !validSummary(first)||!validSummary(second)||!validSummary(observed)||
          [first,second,observed].some(s=>s.status!==200||!s.content_type||s.body_length===0||!s.normalized_sha256)||
          first.content_type!==second.content_type||first.content_type!==observed.content_type||
          first.normalized_sha256!==second.normalized_sha256||first.normalized_sha256!==observed.normalized_sha256||
          !near(first.normalized_length,second.normalized_length)||!near(first.normalized_length,observed.normalized_length)||
          !near(second.normalized_length,observed.normalized_length))return fail('unproved_soft404');
    }else if(row.response_summary!==undefined)return fail('unexpected_response_summary');
    if(!Array.isArray(row.indicators)||row.indicators.length>12||row.indicators.some(value=>typeof value!=='string'||value.length>120||!EXPOSURE_INDICATORS.includes(value)))return fail('unsafe_indicators');
    if(['blocked','uncertain','not_applicable'].includes(row.state)&&row.comparable)return fail('false_comparability');
    if(row.state==='finding'||row.state==='observed'){
      const f=row.state==='finding'?row.finding:row.observation,rule=RULES_BY_ID[row.rule_id];
      if(!exact(f,['rule_id','family','severity','indicators','identity','safe_url'])||f.rule_id!==row.rule_id||typeof f.family!=='string'||f.family!==rule.family||!(row.state==='observed'?['info']:['low','medium','high']).includes(f.severity)||!Array.isArray(f.indicators)||f.indicators.length<1||f.indicators.length>12||f.indicators.some(value=>typeof value!=='string'||value.length>120||!EXPOSURE_INDICATORS.includes(value))||f.safe_url!==safeExposureUrl(row.url,EXPOSURE_RULES)||f.identity!==row.identity)return fail('unsafe_finding');
    }
    if(row.state!=='finding'&&row.finding!==null||row.state!=='observed'&&row.observation!==null)return fail('unexpected_finding');
  }
  const comparableUrls=new Set(receipt.results.filter(row=>row.comparable).map(row=>row.url));
  if(comparableUrls.size&&(t.controls_completed!==2||t.requests<comparableUrls.size+2))return fail('unproven_physical_coverage');
  const quality=!outcome&&receipt.results.every(row=>row.comparable)&&!t.byte_limit_exceeded?'complete':'partial';
  if(receipt.quality!==quality)return fail('quality_mismatch');
  if(!Array.isArray(receipt.limitations)||receipt.limitations.length!==3||receipt.limitations.some(value=>!['listed_paths_only','no_authentication_or_exploitation','transport_overread_is_counted'].includes(value)))return fail('scope_mismatch');
  return {ok:true};
}
