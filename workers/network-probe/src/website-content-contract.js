import { isProbeHostname } from './contract.js';
import { validateExposureReceipt } from './exposure-contract.js';
import { EXPOSURE_RULES, RULES_BY_ID } from '../../../shared/exposure/catalog.js';
import { isSafeExposurePath, isRulePathAllowed } from '../../../shared/exposure/redaction.js';
import { PAGE_DISCOVERY_VERSION, PAGE_DISCOVERY_LIMITS, siteHosts, isRequestablePath } from '../../scan-api/src/engines/page-discovery.js';
import { SECURITY_HEADERS } from '../../scan-api/src/engines/security-headers-config.js';

export const WEBSITE_CONTENT_LIMITS = Object.freeze({requests:32,bytes:2097152,overreadBytes:131072,durationMs:25000,requestBytes:16384,responseBytes:262144});
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).every(key=>keys.includes(key));
const count=value=>Number.isSafeInteger(value)&&value>=0&&value<=1000000?value:0;
const choices=(value,values,fallback=null)=>values.includes(value)?value:fallback;
const hosts=values=>(Array.isArray(values)?values:[]).filter(isProbeHostname);
const same=(a,b)=>JSON.stringify(a,(_,value)=>value&&typeof value==='object'&&!Array.isArray(value)?Object.fromEntries(Object.entries(value).sort(([x],[y])=>x.localeCompare(y))):value)===JSON.stringify(b,(_,value)=>value&&typeof value==='object'&&!Array.isArray(value)?Object.fromEntries(Object.entries(value).sort(([x],[y])=>x.localeCompare(y))):value);
export function isWebsiteContentUrl(value,domain){
  try{const u=new URL(value);return u.href===value&&['http:','https:'].includes(u.protocol)&&!u.port&&!u.username&&!u.password&&!u.search&&!u.hash&&siteHosts(domain).has(u.hostname)&&isSafeExposurePath(u.pathname)&&isRequestablePath(u.pathname);}catch{return false;}
}
export function validateWebsiteContentRequest(input,now=Date.now()){
  const fail=reason=>({ok:false,reason});
  if(!exact(input,['schema_version','request_id','workspace_id','scan_id','domain','deadline_at','max_requests','max_bytes'])||input.schema_version!=='website-content-request-v1')return fail('invalid_request');
  for(const key of ['request_id','workspace_id','scan_id'])if(typeof input[key]!=='string'||!/^[a-zA-Z0-9_-]{1,100}$/.test(input[key]))return fail('invalid_identity');
  if(!isProbeHostname(input.domain)||input.domain!==input.domain.toLowerCase())return fail('invalid_domain');
  const deadline=Date.parse(input.deadline_at);if(!Number.isFinite(deadline)||deadline<=now||deadline>now+25000)return fail('invalid_deadline');
  if(!Number.isInteger(input.max_requests)||input.max_requests<3||input.max_requests>32)return fail('request_limit');
  if(!Number.isInteger(input.max_bytes)||input.max_bytes<4096||input.max_bytes>2097152)return fail('byte_limit');
  return {ok:true};
}

// Project only bounded, typed observations. Untrusted headers, cookie values,
// path parameters, HTML, parser diagnostics and arbitrary body text never persist.
export function sanitizeWebsitePageDiscovery(value,domain){
  const input=value||{},url=value=>isWebsiteContentUrl(value,domain)?value:null;
  const pages=(Array.isArray(input.pages)?input.pages:[]).slice(0,15).flatMap(p=>{
    if(!p||!isSafeExposurePath(p.path)||!url(p.requested_url))return [];
    const out={path:p.path,source:choices(p.source,['homepage','homepage_link','sitemap','javascript','well_known'],'homepage_link'),requested_url:p.requested_url,sensitive_kind:choices(p.sensitive_kind,['login','admin','checkout','account']),sensitive_basis:choices(p.sensitive_basis,['path','password_field']),outcome:choices(p.outcome,['observed','unavailable','redirected_offsite','not_found','error_status','refused','not_html','soft_404'],'unavailable'),status_code:Number.isInteger(p.status_code)&&p.status_code>=100&&p.status_code<=599?p.status_code:null,final_url:url(p.final_url)};
    for(const key of ['redirected','https','password_field'])if(typeof p[key]==='boolean')out[key]=p[key];
    if(out.outcome==='observed'&&!out.final_url)out.outcome='unavailable';
    if(p.offsite_host&&isProbeHostname(p.offsite_host))out.offsite_host=p.offsite_host;
    if('content_type' in p)out.content_type=choices(p.content_type,['text/plain','application/json','application/xml','text/xml','application/octet-stream','application/javascript','text/javascript']);
    if(p.soft_404_basis)out.soft_404_basis=choices(p.soft_404_basis,['redirected_to_homepage','same_content_as_homepage','same_as_unknown_path_response','same_structure_as_homepage']);
    if(p.security_headers){const names=SECURITY_HEADERS.map(h=>h.name);out.security_headers={present:(p.security_headers.present||[]).filter(h=>names.includes(h)),missing:(p.security_headers.missing||[]).filter(h=>names.includes(h))};}
    if(Array.isArray(p.cookies))out.cookies=p.cookies.slice(0,20).map(c=>({name:/^(?:__Host-|__Secure-)?(?:session|sessionid|PHPSESSID|JSESSIONID|csrftoken|XSRF-TOKEN|connect\.sid|ASP\.NET_SessionId)$/i.test(c.name||'')?c.name:'[redacted-cookie-name]',secure:c.secure===true,httponly:c.httponly===true,samesite:choices(c.samesite,['strict','lax','none']),...(c.deletes===true?{deletes:true}:{})}));
    if(Array.isArray(p.forms))out.forms=p.forms.slice(0,10).map(f=>({method:choices(f.method,['get','post'],'get'),action_kind:choices(f.action_kind,['same_origin','other_origin','unparseable'],'unparseable'),action_scheme:choices(f.action_scheme,['http','https']),action_host:isProbeHostname(f.action_host)?f.action_host:null,has_password:f.has_password===true}));
    if(p.mixed_content)out.mixed_content={count:count(p.mixed_content.count),hosts:hosts(p.mixed_content.hosts).slice(0,10)};
    if(Array.isArray(p.third_party_scripts))out.third_party_scripts=hosts(p.third_party_scripts).slice(0,20);
    return [out];
  });
  const reasons=['aborted','fetch_limit','time_budget','fetch_timeout','invalid_domain','homepage_redirects_offsite','homepage_error_status','homepage_unavailable','catch_all_baseline_unavailable','page_limit','shared_transport_partial','unsafe_metadata_omitted'];
  const partial=[...new Set((input.partial_reasons||[]).filter(r=>reasons.includes(r)))];
  if(pages.length!==(input.pages||[]).length)partial.push('unsafe_metadata_omitted');
  const sources=Object.fromEntries(['homepage_links','robots_sitemaps','sitemap_urls','javascript_paths','well_known_probed','unsafe_skipped'].map(k=>[k,count(input.sources?.[k])]));
  const javascript=Object.fromEntries(['scripts_read','paths_found','api_paths_found','paths_checked','paths_seen'].map(k=>[k,count(input.javascript?.[k])]));
  const apex=domain.replace(/^www\./,'');
  return {source:'page_discovery',version:PAGE_DISCOVERY_VERSION,coverage:pages.length===0?'not_run':partial.length?'partial':choices(input.coverage,['complete','partial'],'partial'),partial_reasons:[...new Set(partial)].sort(),homepage_url:url(input.homepage_url),limits:{max_pages:PAGE_DISCOVERY_LIMITS.maxPages,max_fetches:PAGE_DISCOVERY_LIMITS.maxFetches},counts:{fetched:count(input.counts?.fetched),observed:pages.filter(p=>p.outcome==='observed').length,not_found:pages.filter(p=>p.outcome==='not_found').length,sensitive:pages.filter(p=>p.outcome==='observed'&&p.sensitive_kind).length},sources,javascript,hostname_references:{candidates:(input.hostname_references?.candidates||[]).filter(c=>isProbeHostname(c.hostname)&&c.hostname.endsWith('.'+apex)).slice(0,100).map(c=>({hostname:c.hostname,sources:(c.sources||[]).filter(s=>['robots_txt','sitemap','javascript'].includes(s))})),truncated:input.hostname_references?.truncated===true},pages};
}

function validateReceipt(request,receipt,{now=Date.now()}={}){
  const fail=reason=>({ok:false,reason});
  if(!exact(receipt,['schema_version','request_id','workspace_id','scan_id','domain','started_at','finished_at','quality','page_discovery','results','discoveries','telemetry','limitations'])||receipt.schema_version!=='website-content-receipt-v1')return fail('invalid_receipt');
  for(const key of ['request_id','workspace_id','scan_id','domain'])if(receipt[key]!==request[key])return fail('identity_mismatch');
  const start=Date.parse(receipt.started_at),finish=Date.parse(receipt.finished_at),deadline=Date.parse(request.deadline_at);
  if(!Number.isFinite(start)||!Number.isFinite(finish)||start>finish||start<deadline-25000||finish>deadline+1000||finish>now+1000||now-finish>60000)return fail('time_mismatch');
  if(!same(receipt.page_discovery,sanitizeWebsitePageDiscovery(receipt.page_discovery,request.domain)))return fail('unsafe_page_discovery');
  if(receipt.page_discovery.counts.fetched>28)return fail('page_fetch_limit');
  const t=receipt.telemetry;
  if(!exact(t,['requests','redirects','retries','bytes_wire','bytes_decoded','duration_ms','byte_limit_exceeded','controls_completed']))return fail('invalid_telemetry');
  for(const key of ['requests','redirects','retries','bytes_wire','bytes_decoded','duration_ms','controls_completed'])if(!Number.isSafeInteger(t[key])||t[key]<0)return fail('invalid_counter');
  if(t.requests>request.max_requests||t.redirects>t.requests||t.retries!==0||t.duration_ms!==finish-start||typeof t.byte_limit_exceeded!=='boolean'||t.controls_completed>8)return fail('counter_mismatch');
  if(t.bytes_wire>request.max_bytes+131072||t.bytes_decoded>request.max_bytes+131072)return fail('unbounded_overread');
  if((t.bytes_wire>request.max_bytes||t.bytes_decoded>request.max_bytes)&&!t.byte_limit_exceeded)return fail('unreported_overread');
  if(!Array.isArray(receipt.discoveries)||receipt.discoveries.length>4)return fail('invalid_discoveries');
  const origins=new Map(),apex=request.domain.replace(/^www\./,'');
  for(const d of receipt.discoveries){
    if(!exact(d,['origin','paths','hosts','technologies','controls_completed'])||!isWebsiteContentUrl(d.origin+'/',request.domain)||origins.has(d.origin)||!Number.isInteger(d.controls_completed)||d.controls_completed<0||d.controls_completed>2||!Array.isArray(d.paths)||d.paths.length>128||d.paths.some(p=>!isSafeExposurePath(p))||!Array.isArray(d.hosts)||d.hosts.length>32||d.hosts.some(h=>!isProbeHostname(h)||!h.endsWith('.'+apex)))return fail('unsafe_discoveries');
    if(!Array.isArray(d.technologies)||d.technologies.length>8||d.technologies.some(t=>!['php','spring','jenkins','grafana','elasticsearch','couchdb','prometheus','ignition'].includes(t)))return fail('unsafe_technology');
    origins.set(d.origin,d);
  }
  if([...origins.values()].reduce((n,d)=>n+d.controls_completed,0)!==t.controls_completed)return fail('control_mismatch');
  if(!Array.isArray(receipt.results)||receipt.results.length>128)return fail('result_limit');
  const identities=new Set(),compared=new Set();
  for(const row of receipt.results){
    let origin;try{const u=new URL(row.url);origin=u.origin;if(!isWebsiteContentUrl(row.url,request.domain)||!isRulePathAllowed(RULES_BY_ID[row.rule_id],u.pathname))return fail('result_identity');}catch{return fail('result_identity');}
    if(row.comparable&&!['finding','observed'].includes(row.state)&&['body_limit','wire_limit','decoded_limit','byte_budget_exhausted','request_budget_exhausted','deadline_exhausted','incomplete_controls','evaluation_failed'].includes(row.reason))return fail('false_comparability');
    if(!origins.has(origin)||identities.has(row.identity))return fail('result_identity');identities.add(row.identity);
    const d=origins.get(origin),synthetic={...request,origin,checks:[{rule_id:row.rule_id,url:row.url}],deadline_at:new Date(start+15000).toISOString()};
    // Reuse the existing strict finding projection contract. The surrounding
    // receipt validates this longer shared stage's actual time and budgets.
    const checked=validateExposureReceipt(synthetic,{schema_version:'exposure-receipt-v1',request_id:request.request_id,workspace_id:request.workspace_id,scan_id:request.scan_id,origin,started_at:new Date(start).toISOString(),finished_at:new Date(start).toISOString(),quality:row.comparable?'complete':'partial',results:[row],discoveries:{paths:[],hosts:[]},telemetry:{requests:row.comparable?3:0,redirects:0,retries:0,bytes_wire:0,bytes_decoded:0,duration_ms:0,byte_limit_exceeded:false,controls_completed:d.controls_completed},limitations:['listed_paths_only','no_authentication_or_exploitation','transport_overread_is_counted']},{now:start});
    if(!checked.ok)return fail(checked.reason);
    if(row.comparable)compared.add(row.url);
  }
  if(t.requests<compared.size+t.controls_completed)return fail('unproven_physical_coverage');
  const quality=receipt.page_discovery.coverage==='complete'&&receipt.results.every(r=>r.comparable)&&!t.byte_limit_exceeded?'complete':'partial';
  if(receipt.quality!==quality)return fail('quality_mismatch');
  if(!same(receipt.limitations,['same_scan_shared_bounded_content','no_authentication_or_exploitation','transport_overread_is_counted']))return fail('scope_mismatch');
  return {ok:true};
}

export function validateWebsiteContentReceipt(request,receipt,options={}){
  try{return validateReceipt(request,receipt,options);}catch{return {ok:false,reason:'invalid_receipt'};}
}
