import { dnsQuery } from './dns.js';
import { isAuthorised, ACTIVE_CHECK_AUTHORITY_VERSION } from './active-check-consent.js';
import { observedNetworkAddresses } from './network-ownership.js';
import { isPublicProbeAddress, isProbeHostname } from '../../../network-probe/src/contract.js';
import { TLS_PROFILE_VERSION, TLS_POLICY_VERSION, TLS_PROTOCOLS, TLS_SPECIAL_CONTROLS, TLS_SPECIAL_CONTROLS_AVAILABLE, TLS_AUTHORISATION_REQUIRED_REASON, TLS_AUTHORISED_NOT_RELEASED_REASON, TLS_AUTHORISED_ON_DEMAND_REASON, TLS_PROVIDER_EDGE_REASON, TLS_ADDRESS_NOT_OWNED_REASON, applicableTlsControl, isTlsService, tlsEndpointIdentity } from '../../../../shared/tls/catalog.js';

const MAX_SERVICES_PER_SCAN = 4;
const MAX_ENDPOINTS_PER_SCAN = 8;
const MAX_CHECKS_PER_SCAN = 1024;
const MAX_DNS_ADDRESSES = 16;
const id = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,100}$/.test(value);
const canonicalAddress = value => {
  if (!isPublicProbeAddress(value)) return null;
  if (value.includes(':')) { try { return new URL(`http://[${value}]/`).hostname.slice(1,-1); } catch { return null; } }
  return value;
};
const safeHostname = (host,domain) => isProbeHostname(host) && (host === domain || host.endsWith('.' + domain));
const offset = (seed,count) => count ? [...seed].reduce((sum,char) => (sum * 31 + char.charCodeAt(0)) >>> 0,0) % count : 0;
// The intrusive TLS controls are Active Checks: each one is authorised per domain,
// host and resolved address by its own grant (engines/active-check-consent.js),
// never by the legacy workspace-wide switch (migration 120, now history only).
export const TLS_SPECIAL_CHECK_IDS = Object.freeze({heartbleed:'tls_intrusive_heartbleed',robot:'tls_intrusive_robot',ccs:'tls_intrusive_ccs'});
const consentIds = checks => [...new Set(Object.values(checks||{}).filter(Boolean))];
const rotate = (values,seed) => values.length ? [...values.slice(offset(seed,values.length)),...values.slice(0,offset(seed,values.length))] : [];

export function parseTlsDnsAnswers(results, hostname) {
  const addresses = [];
  for (const [type,response] of results) {
    if (response?.Status !== 0 || !Array.isArray(response.Answer)) continue;
    const allowedNames = new Set([hostname]);
    for (let depth=0; depth<8; depth++) {
      let expanded=false;
      for (const answer of response.Answer) {
        const owner=String(answer.name||'').replace(/\.$/,'').toLowerCase();
        const target=String(answer.data||'').replace(/\.$/,'').toLowerCase();
        if (answer.type === 5 && allowedNames.has(owner) && isProbeHostname(target) && !allowedNames.has(target)) {
          allowedNames.add(target); expanded=true;
        }
      }
      if (!expanded) break;
    }
    for (const answer of response.Answer) {
      if (answer.type !== (type === 'A' ? 1 : 28) || typeof answer.data !== 'string' ||
          typeof answer.name !== 'string' || !allowedNames.has(answer.name.replace(/\.$/,'').toLowerCase())) continue;
      const normalized = canonicalAddress(answer.data);
      if (normalized) addresses.push(normalized);
    }
  }
  return [...new Set(addresses)].slice(0,MAX_DNS_ADDRESSES);
}

function selectAddresses(addresses,scanId,hostname) {
  const v4 = rotate(addresses.filter(x => !x.includes(':')).sort(),scanId+hostname+'4');
  const v6 = rotate(addresses.filter(x => x.includes(':')).sort(),scanId+hostname+'6');
  return [v4[0],v6[0],v4[1],v6[1]].filter(Boolean);
}

// `trigger` is the scan's own trigger. Intrusive controls run only on a scan a
// person started ('manual'): the signed consent says "on demand". Anything
// else, including a missing trigger, holds them (F1).
export async function loadTlsEndpoints(env,scan,{lookup = dnsQuery,now = () => Date.now(),authorise = isAuthorised,specialControlsAvailable = TLS_SPECIAL_CONTROLS_AVAILABLE,trigger = null} = {}) {
  if (!id(scan.workspace_id) || !id(scan.domain_id) || !id(scan.id) || !isProbeHostname(scan.domain)) throw new Error('invalid_scan');
  const db = env.cybermeters_db;
  // The workspace's owned addresses, resolved at most once for this plan.
  let ownershipOnce = null;
  const ownership = (environment,workspaceId,options) => (ownershipOnce ??= observedNetworkAddresses(environment,workspaceId,options));
  // The legacy row still carries the service-scope generation; its `enabled`
  // switch no longer authorises anything.
  const auth = await db.prepare(`SELECT generation FROM workspace_tls_authorizations WHERE workspace_id=?`).bind(scan.workspace_id).first();
  const generation = Number.isSafeInteger(auth?.generation) ? auth.generation : 0;
  const services = await db.prepare(`SELECT a.id,a.domain_id,a.hostname,a.sni,a.port,a.application_protocol,a.network_target_id,
      t.addresses_json,t.authorization_status AS target_authorization_status,t.scope_state AS target_scope_state,w.deleted_at,d.verification_status
    FROM workspace_tls_service_authorizations a
    JOIN network_targets t ON t.id=a.network_target_id AND t.workspace_id=a.workspace_id
    JOIN workspace_domains d ON d.workspace_id=a.workspace_id AND d.domain_id=a.domain_id
    JOIN workspaces w ON w.id=a.workspace_id
    WHERE a.workspace_id=? AND a.authorization_status='active' ORDER BY a.authorized_at,a.id LIMIT 64`).bind(scan.workspace_id).all();
  const authorised = (services.results||[]).filter(row => row.domain_id === scan.domain_id &&
    row.deleted_at === null && row.verification_status === 'verified' && row.target_authorization_status === 'attested' &&
    safeHostname(row.hostname,scan.domain) && row.sni === row.hostname && isTlsService(row.port,row.application_protocol));
  // A service whose network target is not in scope (its address is not observed
  // in the verified domain's DNS, or not checked yet) is not planned, and says
  // so: it is listed as deferred with the reason, never dropped silently.
  const outOfScope = authorised.filter(row => row.target_scope_state !== 'in_scope').map(row => ({hostname:row.hostname,port:row.port,
    reason:row.target_scope_state === 'out_of_scope' ? 'network_target_out_of_scope' : 'network_target_scope_unchecked'}));
  const eligible = rotate(authorised.filter(row => row.target_scope_state === 'in_scope'),scan.id);
  const selected = eligible.slice(0,MAX_SERVICES_PER_SCAN-1);
  const deferredServices=[...outOfScope,...eligible.slice(MAX_SERVICES_PER_SCAN-1).map(row=>({hostname:row.hostname,port:row.port,reason:'service_scope_limit'}))];
  const candidates = [{ hostname:scan.domain,sni:scan.domain,port:443,application_protocol:'https',kind:'standard_https',service_authorization_id:null,allowed_addresses:null },
    ...selected.map(row => ({ ...row,kind:'authorized_service',service_authorization_id:row.id,
      allowed_addresses:(() => { try { const list=JSON.parse(row.addresses_json);return Array.isArray(list)?new Set(list.map(canonicalAddress).filter(Boolean)):new Set(); } catch { return new Set(); } })() }))];
  const endpoints = [], gaps = [];
  for (const candidate of candidates) {
    let dns;
    try {
      const answers = await Promise.allSettled(['A','AAAA'].map(type => lookup(candidate.hostname,type)));
      dns = parseTlsDnsAnswers(answers.map((r,index) => [['A','AAAA'][index],r.status === 'fulfilled' ? r.value : null]),candidate.hostname);
    } catch { dns = []; }
    if (candidate.allowed_addresses) dns = dns.filter(address => candidate.allowed_addresses.has(address));
    const selectedAddresses = selectAddresses(dns,scan.id,candidate.hostname);
    if (!selectedAddresses.length) {
      gaps.push({hostname:candidate.hostname,port:candidate.port,application_protocol:candidate.application_protocol,
        reason:candidate.allowed_addresses ? 'dns_target_mismatch_or_unavailable' : 'dns_unavailable'});
      continue;
    }
    const observed = new Date(now()).toISOString();
    for (const address of selectedAddresses) {
      if (endpoints.length >= MAX_ENDPOINTS_PER_SCAN) { gaps.push({hostname:candidate.hostname,port:candidate.port,
        application_protocol:candidate.application_protocol,reason:'endpoint_limit'}); break; }
      const endpoint = {hostname:candidate.hostname,sni:candidate.sni,address,port:candidate.port,transport:'tcp',
        application_protocol:candidate.application_protocol,dns_addresses:dns,dns_observed_at:observed};
      // One Active Checks decision per intrusive control, for this exact address.
      // A grant only makes a control runnable once the engine is released
      // (special_checks). While it is withheld, a grant is still recorded
      // (granted_checks, plan only) so the customer sees "Authorised — not yet
      // available" rather than "requires your authorisation". The address
      // ownership is resolved once per plan, not once per control.
      const special_checks = {}, granted_checks = {}, held_checks = {};
      for (const [control,check] of Object.entries(TLS_SPECIAL_CHECK_IDS)) {
        const decision = await authorise(env,{workspaceId:scan.workspace_id,domain:scan.domain,host:candidate.hostname,check,address},
          {observedNetworkAddresses:ownership});
        // A grant that covers the host but not this address is stated as such,
        // never as "requires your authorisation": a shared provider edge, or an
        // address not observed in a verified domain's DNS.
        if (decision?.authorised !== true && decision?.reason === 'address_out_of_scope') {
          held_checks[control] = decision.address_scope === 'address_is_shared_provider_infrastructure' ? TLS_PROVIDER_EDGE_REASON : TLS_ADDRESS_NOT_OWNED_REASON;
          continue;
        }
        if (decision?.authorised !== true || !decision.consent_id) continue;
        if (specialControlsAvailable && trigger === 'manual') special_checks[control] = decision.consent_id;
        else if (specialControlsAvailable) held_checks[control] = TLS_AUTHORISED_ON_DEMAND_REASON;
        else granted_checks[control] = decision.consent_id;
      }
      const consent = consentIds(special_checks).length > 0;
      endpoints.push({endpoint,endpoint_identity:tlsEndpointIdentity(endpoint),
        scope:{kind:candidate.kind,service_authorization_id:candidate.service_authorization_id,generation,
          special_consent:consent,special_checks,granted_checks,held_checks,consent_version:consent?ACTIVE_CHECK_AUTHORITY_VERSION:null}});
    }
  }
  return {endpoints,gaps,scope_generation:generation,special_consent:endpoints.some(e => e.scope.special_consent),omitted_services:0,deferred_services:deferredServices};
}

export async function refreshTlsEndpoint(entry,{lookup = dnsQuery,now = () => Date.now()} = {}) {
  if (!entry?.endpoint || !isPublicProbeAddress(entry.endpoint.address)) return null;
  const answers = await Promise.allSettled(['A','AAAA'].map(type => lookup(entry.endpoint.hostname,type)));
  const addresses = parseTlsDnsAnswers(answers.map((r,index) => [['A','AAAA'][index],r.status === 'fulfilled' ? r.value : null]),entry.endpoint.hostname);
  if (!addresses.includes(entry.endpoint.address)) return null;
  return { ...entry.endpoint,dns_addresses:addresses,dns_observed_at:new Date(now()).toISOString() };
}

export async function tlsScopeStillAuthorized(env,scan,entry,{authorise} = {}) {
  authorise = authorise || isAuthorised;
  const db=env.cybermeters_db;
  const base=await db.prepare(`SELECT w.id AS workspace_id,d.domain_id,a.generation
    FROM workspaces w JOIN workspace_domains d ON d.workspace_id=w.id AND d.domain_id=? AND d.verification_status='verified'
    LEFT JOIN workspace_tls_authorizations a ON a.workspace_id=w.id
    WHERE w.id=? AND w.deleted_at IS NULL`).bind(scan.domain_id,scan.workspace_id).first();
  if (!base) return false;
  if (Number(base?.generation||0) !== entry.scope.generation) return false;
  // Every intrusive control this entry carries must still hold its own grant for
  // this exact address; a revoked or narrowed grant ends the phase.
  if (entry.scope.special_consent) {
    const checks = entry.scope.special_checks || {};
    if (!consentIds(checks).length) return false;
    for (const [control,consentId] of Object.entries(checks)) {
      const decision = await authorise(env,{workspaceId:scan.workspace_id,domain:scan.domain,host:entry.endpoint.hostname,check:TLS_SPECIAL_CHECK_IDS[control],address:entry.endpoint.address});
      if (decision?.authorised !== true || decision.consent_id !== consentId) return false;
    }
  }
  if (entry.scope.kind === 'standard_https') return entry.endpoint.hostname === scan.domain && entry.endpoint.port === 443 && entry.endpoint.application_protocol === 'https';
  const service=await db.prepare(`SELECT a.id,t.addresses_json FROM workspace_tls_service_authorizations a
    JOIN network_targets t ON t.id=a.network_target_id AND t.workspace_id=a.workspace_id AND t.authorization_status='attested' AND t.scope_state='in_scope'
    WHERE a.id=? AND a.workspace_id=? AND a.domain_id=? AND a.authorization_status='active'
      AND a.hostname=? AND a.sni=? AND a.port=? AND a.application_protocol=?`)
    .bind(entry.scope.service_authorization_id,scan.workspace_id,scan.domain_id,entry.endpoint.hostname,entry.endpoint.sni,
      entry.endpoint.port,entry.endpoint.application_protocol).first();
  if (!service) return false;
  try { return JSON.parse(service.addresses_json).map(canonicalAddress).includes(entry.endpoint.address); }
  catch { return false; }
}

const productControls = ['protocol','key_exchange','certificate','ocsp','compression','secure_renegotiation','fallback_scsv','extended_master_secret','session_resumption','early_data','sni_alpn',...TLS_SPECIAL_CONTROLS];
export function buildTlsCheckPlan({endpoints,cipherCatalog=[],previousFindings=[],scanId='',maxChecks=MAX_CHECKS_PER_SCAN}) {
  const all = [];
  for (let endpointIndex = 0; endpointIndex < endpoints.length; endpointIndex++) {
    const entry = endpoints[endpointIndex];
    for (const protocol of TLS_PROTOCOLS) {
      for (const control of productControls) {
        const check = {control,protocol,cipher_id:null};
        const special = TLS_SPECIAL_CONTROLS.includes(control);
        const status = !applicableTlsControl(control,protocol) ? 'not_applicable'
          : special && !TLS_SPECIAL_CONTROLS_AVAILABLE ? 'unexecutable'
          : special && !entry.scope.special_checks?.[control] ? 'not_authorized' : 'pending';
        all.push({endpoint_index:endpointIndex,check,state:status,
          reason:status === 'unexecutable' ? 'engine_capability_limit' : status === 'pending' ? null : status});
      }
      const ciphers = cipherCatalog.filter(row => row.protocol === protocol && typeof row.name === 'string' && /^[A-Za-z0-9_-]{1,96}$/.test(row.name));
      for (const cipher of ciphers) all.push({endpoint_index:endpointIndex,
        check:{control:'cipher',protocol,cipher_id:cipher.name},state:cipher.executable ? 'pending' : 'unexecutable',
        reason:cipher.executable ? null : (cipher.reason === 'requires_credentials' ? 'requires_credentials' : 'engine_unsupported')});
      if (!ciphers.length) all.push({endpoint_index:endpointIndex,check:{control:'cipher',protocol,cipher_id:null},
        state:'unexecutable',reason:'cipher_catalog_unavailable'});
    }
  }
  const priority = new Set(previousFindings.map(row => `${row.endpoint_identity}|${row.control}|${row.protocol}|${row.cipher_id||''}`));
  const pending = all.filter(row => row.state === 'pending');
  const key = row => `${endpoints[row.endpoint_index].endpoint_identity}|${row.check.control}|${row.check.protocol}|${row.check.cipher_id||''}`;
  const retests = pending.filter(row => priority.has(key(row)));
  const buckets = endpoints.map((endpoint,index) => {
    const rows=pending.filter(row => row.endpoint_index === index && !priority.has(key(row)));
    const protocols=rows.filter(row => row.check.control === 'protocol');
    const specials=rows.filter(row => TLS_SPECIAL_CONTROLS.includes(row.check.control));
    const controls=rotate(rows.filter(row => row.check.control !== 'protocol' && row.check.control !== 'cipher' &&
      !TLS_SPECIAL_CONTROLS.includes(row.check.control)),scanId+endpoint.endpoint_identity+'controls');
    const ciphers=rotate(rows.filter(row => row.check.control === 'cipher'),scanId+endpoint.endpoint_identity+'ciphers');
    const mixed=[...protocols,...specials];
    while(controls.length||ciphers.length){
      if(controls.length)mixed.push(controls.shift());
      for(let n=0;n<2&&ciphers.length;n++)mixed.push(ciphers.shift());
    }
    return mixed;
  });
  const ordered = [...retests];
  while (buckets.some(bucket => bucket.length)) for (const bucket of buckets) if (bucket.length) ordered.push(...bucket.splice(0,8));
  const selected = ordered.slice(0,Math.max(0,Math.min(maxChecks,MAX_CHECKS_PER_SCAN)));
  const omitted = Math.max(0,pending.length-selected.length);
  return {profile_version:TLS_PROFILE_VERSION,policy_version:TLS_POLICY_VERSION,selected,static_results:all.filter(row => row.state !== 'pending'),
    pending_total:pending.length,omitted_checks:omitted,cursor:0,scan_id:scanId};
}

// The scheduled HTTPS profile plans representative evidence instead of the
// full native cipher cross product. Scope reductions are explicit, never
// silently counted as completed checks. A previously positive endpoint wins
// its host/port group so an exact retest is not lost during address rotation.
export function buildBudgetedTlsCheckPlan({endpoints,cipherCatalog=[],previousFindings=[],observedHttpsHosts=[],scanId='',maxChecks=512}) {
  const observed=new Set(observedHttpsHosts);
  const groups=new Map(),deferredHosts=[],deferredEndpoints=[];
  for(let index=0;index<endpoints.length;index++){
    const entry=endpoints[index],host=entry?.endpoint?.hostname,port=entry?.endpoint?.port;
    if(!host||entry.endpoint.application_protocol!=='https'||!observed.has(host)){
      if(host)deferredHosts.push({hostname:host,port,reason:entry.endpoint.application_protocol==='https'?'https_service_not_observed':'non_https_service'});
      continue;
    }
    const key=`${host}|${port}`;
    if(!groups.has(key))groups.set(key,[]);
    groups.get(key).push({entry,index});
  }
  const prior=new Set(previousFindings.map(row=>row.endpoint_identity));
  const selected=[],staticResults=[];
  for(const [key,group] of [...groups].sort(([a],[b])=>a.localeCompare(b))){
    group.sort((a,b)=>Number(prior.has(b.entry.endpoint_identity))-Number(prior.has(a.entry.endpoint_identity))||
      String(a.entry.endpoint.address).localeCompare(String(b.entry.endpoint.address)));
    const {entry,index}=group[0];
    for(const spare of group.slice(1))deferredEndpoints.push({hostname:spare.entry.endpoint.hostname,port:spare.entry.endpoint.port,
      address:spare.entry.endpoint.address,reason:'representative_address_scope'});
    const rows=[];
    const add=(control,protocol,cipherId=null)=>{
      if(!applicableTlsControl(control,protocol))return;
      rows.push({endpoint_index:index,check:{control,protocol,cipher_id:cipherId},state:'pending',reason:null});
    };
    // Certificate and chain facts precede version, cipher-class and optional
    // active checks. Old protocols get one version check, not hundreds of
    // duplicate cipher handshakes.
    for(const protocol of ['tls1_3','tls1_2'])for(const control of ['certificate','key_exchange','ocsp'])add(control,protocol);
    for(const protocol of [...TLS_PROTOCOLS].reverse())add('protocol',protocol);
    for(const protocol of ['tls1_3','tls1_2']){
      for(const control of ['compression','secure_renegotiation','fallback_scsv','extended_master_secret',
        'session_resumption','early_data','sni_alpn'])add(control,protocol);
      const valid=cipherCatalog.filter(row=>row.protocol===protocol&&row.executable&&
        typeof row.name==='string'&&/^[A-Za-z0-9_-]{1,96}$/.test(row.name));
      const classes=[/GCM|CHACHA20|POLY1305/,/AES.*(?:SHA|CBC)/,/3DES|DES-CBC3|RC4|NULL|EXP-/];
      for(const pattern of classes){
        const choices=valid.filter(row=>pattern.test(row.name)).sort((a,b)=>a.name.localeCompare(b.name));
        const candidate=rotate(choices,scanId+key+protocol+pattern.source)[0];
        if(candidate)add('cipher',protocol,candidate.name);
      }
    }
    // Intrusive controls (S3-B): planned only with this address's own grant and
    // a released engine; otherwise stated as "not tested — requires your
    // authorisation", which never counts against the assessment's completeness.
    for(const control of TLS_SPECIAL_CONTROLS){
      if(TLS_SPECIAL_CONTROLS_AVAILABLE&&entry.scope?.special_checks?.[control])add(control,'tls1_2');
      else if(!applicableTlsControl(control,'tls1_2'))continue;
      // Authorised, but held: a scheduled scan, or a shared provider edge (F1).
      else if(entry.scope?.held_checks?.[control])staticResults.push({endpoint_index:index,
        check:{control,protocol:'tls1_2',cipher_id:null},state:'unexecutable',reason:entry.scope.held_checks[control]});
      // Authorised by the customer but the engine is not released: stated as
      // "Authorised — not yet available", never as needing authorisation.
      else if(entry.scope?.granted_checks?.[control]||entry.scope?.special_checks?.[control])staticResults.push({endpoint_index:index,
        check:{control,protocol:'tls1_2',cipher_id:null},state:'unexecutable',reason:TLS_AUTHORISED_NOT_RELEASED_REASON});
      else staticResults.push({endpoint_index:index,check:{control,protocol:'tls1_2',cipher_id:null},
        state:'not_authorized',reason:TLS_AUTHORISATION_REQUIRED_REASON});
    }
    const unique=[...new Map(rows.map(row=>[`${row.check.control}|${row.check.protocol}|${row.check.cipher_id||''}`,row])).values()];
    if(selected.length+unique.length>Math.max(0,Math.min(maxChecks,MAX_CHECKS_PER_SCAN))){
      deferredHosts.push({hostname:entry.endpoint.hostname,port:entry.endpoint.port,reason:'tls_plan_budget'});
      continue;
    }
    selected.push(...unique);
  }
  return {profile_version:TLS_PROFILE_VERSION,policy_version:TLS_POLICY_VERSION,selected,static_results:staticResults,
    pending_total:selected.length,omitted_checks:0,deferred_hosts:[...new Map(deferredHosts.map(row=>[`${row.hostname}|${row.port}|${row.reason}`,row])).values()],
    deferred_endpoints:deferredEndpoints,cursor:0,scan_id:scanId,plan_scope:'observed_https_representative'};
}
