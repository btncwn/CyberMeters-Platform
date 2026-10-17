import { createBoundedHttpSession } from './bounded-http-session.js';
import { isPublicProbeAddress, isProbeHostname } from './contract.js';
import { validateExposureRequest } from './exposure-contract.js';
import { EXPOSURE_RULES, RULES_BY_ID } from '../../../shared/exposure/catalog.js';
import { exposureIdentity, safeExposureUrl, isRulePathAllowed, isSafeExposurePath, sha256Text } from '../../../shared/exposure/redaction.js';
import { evaluateExposure, exposureEvaluatorProgramSource } from '../../../shared/exposure/evaluate.js';

// The sole production entrypoint passes JSON data. Dependency injection exists
// exclusively for controlled local transport tests and is never accepted on wire.
export function matchesSoft404Baseline(baseline, observed) {
  if(!Array.isArray(baseline)||baseline.length!==2||!observed)return false;
  const [first,second]=baseline;
  const near=(a,b)=>Math.abs(a-b)<=Math.max(16,Math.ceil(Math.max(a,b)*0.05));
  return [first,second,observed].every(row=>row?.status===200&&row.content_type&&row.body_length>0&&row.normalized_sha256)&&
    first.content_type===second.content_type&&first.content_type===observed.content_type&&
    first.normalized_sha256===second.normalized_sha256&&first.normalized_sha256===observed.normalized_sha256&&
    near(first.normalized_length,second.normalized_length)&&near(first.normalized_length,observed.normalized_length)&&near(second.normalized_length,observed.normalized_length);
}

export async function runExposureCollector(input, dependencies={}) {
  const valid=validateExposureRequest(input);if(!valid.ok)throw new Error(valid.reason);
  const {randomBytes}=await import('node:crypto');
  const session=await createBoundedHttpSession(input,dependencies);
  const {started,telemetry,fetchBounded}=session,origin=new URL(input.origin);
  try{
    const token=randomBytes(16).toString('hex');
    const controls=[];
    // Persist only bounded response metadata. The body stays inside this worker.
    const summary=response=>{
      if(response.error||response.truncated)return {status:0,content_type:null,body_length:0,normalized_length:0,body_sha256:null,normalized_sha256:null};
      const body=String(response.body||'').slice(0,32768);
      const normalized=body.toLowerCase().replace(/https?:\/\/[^\s<>"']+|\/[.a-z0-9_/%-]+/g,'/path')
        .replace(/[a-f0-9]{8,}|\d+/g,'#').replace(/\s+/g,' ').trim();
      const contentType=String(response.headers?.['content-type']||'').split(';')[0].trim().toLowerCase();
      return {status:Number(response.status)||0,content_type:/^[a-z0-9.+-]+\/[a-z0-9.+-]+$/.test(contentType)?contentType:null,
        body_length:Buffer.byteLength(body),normalized_length:Buffer.byteLength(normalized),body_sha256:sha256Text(body),normalized_sha256:sha256Text(normalized)};
    };
    for(const suffix of ['', '.txt']){
      const response=await fetchBounded(`${input.origin}/.cybermeters-missing-${token}${suffix}`);
      controls.push(response);
      if(!response.error&&!response.truncated)telemetry.controls_completed++;
    }
    const baseline=controls.map(summary);
    const results=[];
    const discoveredPaths=new Set(),discoveredHosts=new Set();
    for(const check of input.checks){
      const response=await fetchBounded(check.url);
      let evaluated;
      try{evaluated=evaluateExposure({rule:check.rule_id,response,controls});}catch{evaluated={state:'uncertain',comparable:false,finding:null,reason:'evaluation_failed'};}
      // Only a local per-body cap may retain a positive bounded-prefix claim.
      // Network/decode/budget failures and every truncated negative stay unknown.
      const boundedPrefix=response.truncated&&['body_limit','wire_limit','decoded_limit'].includes(response.error);
      if(response.error&&!boundedPrefix||response.truncated&&!['finding','observed'].includes(evaluated.state)||telemetry.controls_completed!==2)evaluated={state:'uncertain',comparable:false,finding:null,reason:response.error||'incomplete_controls'};
      // A weaker page-shape resemblance remains inconclusive. Only two stable,
      // same-status/content-type controls and an exact normalized body match
      // establish a path-specific soft-404 absence.
      const observed=summary(response);
      if(!response.error&&!response.truncated&&telemetry.controls_completed===2&&matchesSoft404Baseline(baseline,observed))
        evaluated={state:'not_present_soft404',comparable:true,finding:null,observation:null,reason:'matches_two_negative_controls'};
      for(const path of evaluated.discoveries?.paths||[])if(discoveredPaths.size<32&&EXPOSURE_RULES.some(rule=>isRulePathAllowed(rule,path)))discoveredPaths.add(path);
      for(const host of evaluated.discoveries?.hosts||[])if(discoveredHosts.size<32&&isProbeHostname(host)&&host.endsWith('.'+origin.hostname))discoveredHosts.add(host);
      const finding=evaluated.state==='finding'&&evaluated.finding?{
        rule_id:check.rule_id,family:RULES_BY_ID[check.rule_id].family,severity:evaluated.finding.severity,
        indicators:evaluated.finding.evidence?.indicators||[],identity:exposureIdentity(check.rule_id,check.url),safe_url:safeExposureUrl(check.url,EXPOSURE_RULES),
      }:null;
      const observation=evaluated.state==='observed'&&evaluated.observation?{rule_id:check.rule_id,family:RULES_BY_ID[check.rule_id].family,severity:'info',indicators:evaluated.observation.evidence?.indicators||[],identity:exposureIdentity(check.rule_id,check.url),safe_url:safeExposureUrl(check.url,EXPOSURE_RULES)}:null;
      results.push({rule_id:check.rule_id,url:check.url,identity:exposureIdentity(check.rule_id,check.url),indicators:evaluated.finding?.evidence?.indicators||evaluated.observation?.evidence?.indicators||[],state:evaluated.state,comparable:evaluated.comparable===true,finding,observation,reason:/^[a-z0-9_]{1,80}$/.test(evaluated.reason||'')?evaluated.reason:null,
        ...(evaluated.state==='not_present_soft404'?{response_summary:observed}:{})});
    }
    const finished=Date.now();telemetry.duration_ms=finished-started;
    return {schema_version:'exposure-receipt-v1',request_id:input.request_id,workspace_id:input.workspace_id,scan_id:input.scan_id,origin:input.origin,started_at:new Date(started).toISOString(),finished_at:new Date(finished).toISOString(),baseline,discoveries:{paths:[...discoveredPaths],hosts:[...discoveredHosts]},quality:results.every(row=>row.comparable)&&!telemetry.byte_limit_exceeded?'complete':'partial',results,telemetry,limitations:['listed_paths_only','no_authentication_or_exploitation','transport_overread_is_counted']};
  }finally{session.close();}
}

// Reviewed built-in module source only, never request-provided code or modules.
export function exposureCollectorProgram() {
  return `const __name=(value)=>value;\n${exposureEvaluatorProgramSource()}\nconst isPublicProbeAddress=${isPublicProbeAddress.toString()};\nconst isProbeHostname=${isProbeHostname.toString()};\nconst validateExposureRequest=${validateExposureRequest.toString()};\nconst createBoundedHttpSession=${createBoundedHttpSession.toString()};\nconst matchesSoft404Baseline=${matchesSoft404Baseline.toString()};\nconst runExposureCollector=${runExposureCollector.toString()};\nlet raw='';for await(const chunk of process.stdin){raw+=chunk;if(Buffer.byteLength(raw)>16384)throw new Error('body_limit');}try{const result=await runExposureCollector(JSON.parse(raw));process.stdout.write(JSON.stringify(result));}catch{process.exitCode=1;}`;
}
