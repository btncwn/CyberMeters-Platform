import { createBoundedHttpSession } from './bounded-http-session.js';
import { isProbeHostname } from './contract.js';
import { validateWebsiteContentRequest, sanitizeWebsitePageDiscovery, isWebsiteContentUrl } from './website-content-contract.js';
import { runPageDiscoveryModule } from '../../scan-api/src/engines/page-discovery.js';
import { SECURITY_HEADERS } from '../../scan-api/src/engines/security-headers-config.js';
import { EXPOSURE_RULES, RULES_BY_ID } from '../../../shared/exposure/catalog.js';
import { exposureIdentity, safeExposureUrl, isRulePathAllowed, isSafeExposurePath } from '../../../shared/exposure/redaction.js';
import { discoverExposureReferences } from '../../../shared/exposure/discovery.js';
import { evaluateExposure } from '../../../shared/exposure/evaluate.js';

export async function runWebsiteContentCollector(input,dependencies={}){
  const valid=validateWebsiteContentRequest(input);if(!valid.ok)throw new Error(valid.reason);
  const {randomBytes}=await import('node:crypto');
  const session=await createBoundedHttpSession({...input,origin:`https://${input.domain}`},dependencies,{bodyBytes:262144,approveUrl:url=>isWebsiteContentUrl(url,input.domain),headerNames:[...SECURITY_HEADERS.map(h=>h.name),'server','x-powered-by','x-jenkins','x-grafana-version'],retainCookies:true});
  const {started,deadline,telemetry,controller}=session;
  const controls=new Map(),readUrls=new Set(),redirects=new Set();
  let transportPartial=false;
  const exposureView=response=>{
    const prefix=response.bytes?.subarray(0,32768);
    return response.bytesRead>32768?{...response,bytes:prefix,body:prefix?.toString('utf8')||response.body.slice(0,32768),bytesRead:32768,truncated:true,error:response.error||'body_limit'}:response;
  };
  const getControls=async origin=>{
    if(!controls.has(origin))controls.set(origin,(async()=>{
      const token=randomBytes(16).toString('hex'),out=[];
      for(const suffix of ['', '.txt']){
        const response=exposureView(await session.requestOnce(`${origin}/.cybermeters-missing-${token}${suffix}`));
        // A redirect is not the same-origin absent-path baseline we requested.
        if([301,302,303,307,308].includes(response.status))response.error='control_redirect';
        out.push(response);
        if(!response.error&&!response.truncated)telemetry.controls_completed++;
      }
      return out;
    })());
    return controls.get(origin);
  };
  const fetchImpl=async (value,options={})=>{
    if(options.method&&options.method!=='GET')throw new Error('unsupported_method');
    let parsed;try{parsed=new URL(value);}catch{throw new Error('invalid_url');}
    // Query strings from script cache-busters or sitemap hints are never sent.
    // The body for the canonical origin/path is cached once for this scan.
    parsed.search='';parsed.hash='';
    if(!isWebsiteContentUrl(parsed.href,input.domain)){transportPartial=true;throw new Error('out_of_scope');}
    if(options.signal?.aborted)throw new Error('request_aborted');
    const onAbort=()=>controller.abort();
    options.signal?.addEventListener('abort',onAbort,{once:true});
    let response;
    try{await getControls(parsed.origin);if(options.signal?.aborted)throw new Error('request_aborted');response=await session.requestOnce(parsed.href);}finally{options.signal?.removeEventListener('abort',onAbort);}
    readUrls.add(parsed.href);
    if(response.error||response.truncated)transportPartial=true;
    const boundedPrefix=response.truncated&&['body_limit','wire_limit','decoded_limit'].includes(response.error);
    if(response.error&&!boundedPrefix)throw new Error(response.error);
    if([301,302,303,307,308].includes(response.status)&&!redirects.has(parsed.href)){redirects.add(parsed.href);telemetry.redirects++;}
    const headers=new Headers();
    for(const [name,value] of Object.entries(response.headers)){if(Array.isArray(value))for(const item of value)headers.append(name,item);else headers.set(name,value);}
    // Data is already decompressed under the shared cap; avoid telling callers
    // that the transient Response still contains encoded bytes.
    headers.delete('content-encoding');headers.delete('content-length');
    const result=new Response([101,204,205,304].includes(response.status)?null:response.bytes||response.body,{status:response.status,headers});
    Object.defineProperty(result,'url',{value:parsed.href});
    return result;
  };
  try{
    const rawPage=await runPageDiscoveryModule(input.domain,{fetchImpl,signal:controller.signal,remainingMs:()=>Math.max(0,deadline-Date.now()),...(dependencies.pageLimits?{limits:dependencies.pageLimits}:{})}).catch(()=>({source:'page_discovery',pages:[],partial_reasons:['aborted'],counts:{fetched:Math.min(28,readUrls.size)}}));
    if(transportPartial||session.stopped())rawPage.partial_reasons=[...new Set([...(rawPage.partial_reasons||[]),'shared_transport_partial'])];
    const page_discovery=sanitizeWebsitePageDiscovery(rawPage,input.domain),results=[],discoveryMap=new Map(),apex=input.domain.replace(/^www\./,'');
    for(const [origin,pending] of controls){const values=await pending;discoveryMap.set(origin,{origin,paths:new Set(),hosts:new Set(),technologies:new Set(),controls_completed:values.filter(r=>!r.error&&!r.truncated).length});}
    for(const url of readUrls){
      const response=await session.responses.get(url),parsed=new URL(url),entry=discoveryMap.get(parsed.origin);
      if(!response||!entry)continue;
      // Inspect the exact bodies and response headers already read by the page
      // module. This adds zero network requests, including source-map hints.
      const refs=discoverExposureReferences({origin:url,body:response.body,headers:response.headers,maxBytes:262144});
      for(const path of refs.paths)if(entry.paths.size<128&&isSafeExposurePath(path))entry.paths.add(path);
      for(const host of refs.discoveredHosts)if(entry.hosts.size<32&&isProbeHostname(host)&&host.endsWith('.'+apex))entry.hosts.add(host);
      const h=response.headers,b=response.body.slice(0,32768);
      const signals={php:/\bPHP\b/i.test(h['x-powered-by']||''),spring:/\bWhitelabel Error Page\b|org\.springframework\./.test(b),jenkins:!!h['x-jenkins']||/<title>[^<]*Jenkins/i.test(b),grafana:!!h['x-grafana-version']||/grafanaBootData\s*=/.test(b),elasticsearch:/"cluster_name"\s*:/.test(b)&&/"lucene_version"\s*:/.test(b),couchdb:/"couchdb"\s*:\s*"Welcome"/.test(b),prometheus:/<title>Prometheus/.test(b),ignition:/Spatie\\\\Ignition|Laravel Ignition/.test(b)};
      for(const [label,found] of Object.entries(signals))if(found)entry.technologies.add(label);
      const baseline=await controls.get(parsed.origin);
      // The shared page reader has a larger body cap than the exposure rule
      // evaluator. A complete page read is not proof that this 32KiB evaluator
      // saw the suffix: preserve bounded-prefix positives, never clear on it.
      const evaluationResponse=exposureView(response);
      for(const rule of EXPOSURE_RULES){
        if(!isRulePathAllowed(rule,parsed.pathname))continue;
        let evaluated;try{evaluated=evaluateExposure({rule:rule.id,response:evaluationResponse,controls:baseline});}catch{evaluated={state:'uncertain',comparable:false,reason:'evaluation_failed'};}
        const boundedPrefix=evaluationResponse.truncated&&['body_limit','wire_limit','decoded_limit'].includes(evaluationResponse.error);
        if(evaluationResponse.error&&!boundedPrefix||evaluationResponse.truncated&&!['finding','observed'].includes(evaluated.state)||entry.controls_completed!==2)evaluated={state:'uncertain',comparable:false,reason:evaluationResponse.error||'incomplete_controls'};
        const identity=exposureIdentity(rule.id,url),indicators=evaluated.finding?.evidence?.indicators||evaluated.observation?.evidence?.indicators||[];
        const project=(finding,severity)=>finding?{rule_id:rule.id,family:RULES_BY_ID[rule.id].family,severity,indicators,identity,safe_url:safeExposureUrl(url,EXPOSURE_RULES)}:null;
        results.push({rule_id:rule.id,url,identity,indicators,state:evaluated.state,comparable:evaluated.comparable===true,finding:evaluated.state==='finding'?project(evaluated.finding,evaluated.finding?.severity):null,observation:evaluated.state==='observed'?project(evaluated.observation,'info'):null,reason:/^[a-z0-9_]{1,80}$/.test(evaluated.reason||'')?evaluated.reason:null});
      }
    }
    const discoveries=[...discoveryMap.values()].map(d=>({...d,paths:[...d.paths],hosts:[...d.hosts],technologies:[...d.technologies]}));
    const finished=Date.now();telemetry.duration_ms=finished-started;
    return {schema_version:'website-content-receipt-v1',request_id:input.request_id,workspace_id:input.workspace_id,scan_id:input.scan_id,domain:input.domain,started_at:new Date(started).toISOString(),finished_at:new Date(finished).toISOString(),quality:page_discovery.coverage==='complete'&&results.every(r=>r.comparable)&&!telemetry.byte_limit_exceeded?'complete':'partial',page_discovery,results,discoveries,telemetry,limitations:['same_scan_shared_bounded_content','no_authentication_or_exploitation','transport_overread_is_counted']};
  }finally{session.close();}
}
