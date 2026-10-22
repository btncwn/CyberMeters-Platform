import { getEffectivePlan } from '../engines/entitlements.js';
import { checkScanLimit, getOperationAdmission, getMonthStart, getMonthResetAt, getPlanLimits, getWorkspaceBillingUserId } from '../engines/plan-usage.js';
import { NETWORK_LIMITS, NETWORK_PORTS, normalizeNetworkTarget, normalizeNetworkPorts } from '../engines/network-targets.js';
import { createId } from '../lib/util.js';
import { networkReceiptHash } from '../engines/network-scan-dispatch.js';
import { buildNetworkSuggestions, hostsNeedingResolution, NETWORK_SUGGESTION_LIMITS, resolveHostAddresses } from '../engines/network-suggestions.js';
import { checkNetworkTargetScope, evaluateTargetScope, NETWORK_SCOPE_VERSION, networkScopeProjection, observedNetworkAddresses, scopeMessage } from '../engines/network-ownership.js';
import { liveRangeGrant, NETWORK_RANGE_AUTHORITY_TEXT, NETWORK_RANGE_AUTHORITY_VERSION, NETWORK_RANGE_DECLARATION, NETWORK_RANGE_LIMITS, rangeConsentProjection, rangeGrantCoversPorts } from '../engines/network-range-consent.js';

const parseJson = value => value ? JSON.parse(value) : null;
export const networkTargetProjection = (row,rangeConsent=null) => ({ id:row.id,target:row.target,target_type:row.target_type,address_count:row.address_count,label:row.label,authorization_status:row.authorization_status,authorized_by:row.authorized_by,authorized_at:row.authorized_at,created_at:row.created_at,scope:networkScopeProjection(row),range_consent:rangeConsent });
const scopeRefusal = decision => ({ state:decision.state,reason:decision.reason,message:scopeMessage(decision.reason),unobserved:decision.unobserved,shared:decision.shared });
const scopeStale = row => !row.scope_state || !(Date.parse(row.scope_checked_at) > Date.now()-24*3600_000);
export const networkScanProjection = row => ({ id:row.id,target_id:row.target_id,target:row.target,authorised_by:row.range_consent_id?'declared_range_consent':'verified_dns',range_consent_id:row.range_consent_id||null,status:row.status,quality:row.quality,ports:parseJson(row.ports_json),retest_of:row.retest_of,created_at:row.created_at,started_at:row.started_at,completed_at:row.completed_at,reason:row.reason,coverage:parseJson(row.coverage_json),receipt_sha256:row.receipt_sha256 });
async function bodyJson(request) {
  const reader=request.body?.getReader();
  if(!reader) throw new Error('invalid_json_body');
  const chunks=[];let size=0;
  while(true) {
    const {done,value}=await reader.read();if(done)break;
    size+=value.byteLength;if(size>4096){await reader.cancel();throw new Error('request_body_too_large');}chunks.push(value);
  }
  const all=new Uint8Array(size);let offset=0;
  for(const chunk of chunks){all.set(chunk,offset);offset+=chunk.length;}
  try {const body=JSON.parse(new TextDecoder().decode(all));if(!body||Array.isArray(body)||typeof body!=='object')throw 0;return body;}catch{throw new Error('invalid_json_body');}
}
function strictKeys(body,keys){if(Object.keys(body).some(k=>!keys.includes(k)))throw new Error('unsupported_network_field');}

// Declared-range consent (migration 138). An address not observed in verified
// DNS is scanned only under a grant naming its target's exact addresses and
// ports; shared provider infrastructure is never grantable.
const RANGE_CONSENT_KEYS=['ports','signer_name','signer_title','authority_confirmed','authority_version'];
const RANGE_CONSENT_ID=/^nrc_[a-zA-Z0-9_-]{1,100}$/;
const REVOCATION_REASON_MAX=240;
function parseRangeConsent(input,addressCount) {
  if(!input||typeof input!=='object'||Array.isArray(input))throw new Error('invalid_range_consent');
  if(Object.keys(input).some(k=>!RANGE_CONSENT_KEYS.includes(k)))throw new Error('unsupported_network_field');
  if(input.authority_confirmed!==true||input.authority_version!==NETWORK_RANGE_AUTHORITY_VERSION)throw new Error('network_range_authority_required');
  const text=(v,max)=>typeof v==='string'&&v.trim().length>0&&v.trim().length<=max?v.trim():null;
  const signer_name=text(input.signer_name,NETWORK_RANGE_LIMITS.name),signer_title=text(input.signer_title,NETWORK_RANGE_LIMITS.title);
  if(!signer_name||!signer_title)throw new Error('invalid_range_consent_signer');
  return {ports:normalizeNetworkPorts(input.ports,addressCount),signer_name,signer_title};
}
// The recorded role is the signer's real one, never a default: the membership
// row, or 'owner' for the workspace owner without one. Anyone else gets null and
// the caller refuses (403) rather than writing a role nobody holds.
async function rangeActor(db,request,user,workspaceId) {
  const member=await db.prepare('SELECT role FROM workspace_members WHERE workspace_id=? AND user_id=? LIMIT 1').bind(workspaceId,user.id).first();
  let role=member?.role||null;
  if(!role&&await db.prepare('SELECT 1 FROM workspaces WHERE id=? AND owner_user_id=? LIMIT 1').bind(workspaceId,user.id).first())role='owner';
  if(!role)return null;
  return {user_id:user.id,email:user.email||null,role,ip:request.headers.get('CF-Connecting-IP')||null,ua:(request.headers.get('User-Agent')||'').slice(0,300)||null};
}
const ROLE_UNRECORDED={error:'Forbidden — your workspace role could not be recorded'};
// The grant row and its audit, in one batch with whatever precedes them. The
// insert names the target's exact address list, so a target that changed since
// it was read is never covered.
function rangeGrantStatements(db,{id,workspaceId,targetId,target,addressesJson,consent,actor,now}) {
  return [
    db.prepare(`INSERT INTO network_range_consents (id,workspace_id,kind,network_target_id,target,addresses_json,ports_json,actor_user_id,actor_email,actor_workspace_role,signer_name,signer_title,ip_address,user_agent,authority_text,authority_version,created_at) SELECT ?,?,'grant',?,?,?,?,?,?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM workspaces WHERE id=? AND deleted_at IS NULL) AND EXISTS(SELECT 1 FROM network_targets WHERE id=? AND workspace_id=? AND addresses_json=?) AND (SELECT COUNT(*) FROM network_range_consents WHERE workspace_id=? AND kind='grant' AND created_at>?)<?`)
      .bind(id,workspaceId,targetId,target,addressesJson,JSON.stringify(consent.ports),actor.user_id,actor.email,actor.role,consent.signer_name,consent.signer_title,actor.ip,actor.ua,NETWORK_RANGE_AUTHORITY_TEXT,NETWORK_RANGE_AUTHORITY_VERSION,now,workspaceId,targetId,workspaceId,addressesJson,workspaceId,new Date(Date.parse(now)-24*3600_000).toISOString(),NETWORK_RANGE_LIMITS.grants_per_day),
    db.prepare(`INSERT INTO audit_events (id,workspace_id,user_id,actor_type,event_type,entity_type,entity_id,description,metadata_json,created_at) SELECT ?,?,?,'customer','network_range_consent_granted','network_range_consent',?,'Declared network range authorisation granted',?,? WHERE changes()=1`)
      .bind(createId('audit'),workspaceId,actor.user_id,id,JSON.stringify({network_target_id:targetId,target,ports:consent.ports,authority_version:NETWORK_RANGE_AUTHORITY_VERSION,independently_verified:false}),now),
  ];
}
async function readScan(db,workspaceId,scanId) {
  return db.prepare('SELECT s.*,t.target FROM network_scans s JOIN network_targets t ON t.id=s.target_id AND t.workspace_id=s.workspace_id WHERE s.workspace_id=? AND s.id=?').bind(workspaceId,scanId).first();
}
async function monthlyUsage(db,ownerId) {
  const row=await db.prepare(`SELECT (SELECT COUNT(*) FROM scans s JOIN workspaces w ON w.id=s.workspace_id WHERE w.owner_user_id=? AND s.created_at>=?) + (SELECT COUNT(*) FROM network_scans n JOIN workspaces w ON w.id=n.workspace_id WHERE w.owner_user_id=? AND n.created_at>=?) AS cnt`).bind(ownerId,getMonthStart(),ownerId,getMonthStart()).first();
  if(!Number.isInteger(row?.cnt)||row.cnt<0)throw new Error('usage_unavailable');
  return row.cnt;
}

export async function networkAssetRoutes(rctx) {
  const {request,env,url,json,requireAuth,requireWorkspaceRole,consumeApiRateLimit,serverError}=rctx;
  const match=url.pathname.match(/^\/api\/workspaces\/([^/]+)\/(network-targets|network-scans|network-assets|network-suggestions|network-range-consents)(?:\/([^/]+)(?:\/(scans|retest|range-consents|revoke))?)?$/);
  if(!match)return null;
  const [,workspaceId,resource,id,action]=match;
  const user=await requireAuth(request,env);if(!user)return json({error:'Unauthorized'},401);
  const read=await requireWorkspaceRole(user,workspaceId,'workspace:read',env);if(!read)return json({error:'Forbidden'},403);
  const db=env.cybermeters_db;
  try {
    if(request.method==='GET'&&resource==='network-targets'&&!id) {
      let rows=await db.prepare('SELECT * FROM network_targets WHERE workspace_id=? ORDER BY created_at DESC,id').bind(workspaceId).all();
      // Show the customer why a target is or is not scanned: unchecked or day-old
      // decisions are refreshed here, bounded by a rate limit (DNS lookups).
      const stale=(rows.results||[]).filter(scopeStale);
      if(stale.length&&!await consumeApiRateLimit(env,[{scope:'workspace',scope_id:workspaceId}],'network_scope_check',30,3600)) {
        await checkNetworkTargetScope(env,workspaceId,stale);
        rows=await db.prepare('SELECT * FROM network_targets WHERE workspace_id=? ORDER BY created_at DESC,id').bind(workspaceId).all();
      }
      const manage=await requireWorkspaceRole(user,workspaceId,'domain:import',env);
      const scan=await requireWorkspaceRole(user,workspaceId,'scan:create',env);
      const owner=await getWorkspaceBillingUserId(workspaceId,user.id,env);
      const limits=getPlanLimits(await getEffectivePlan(owner,env));
      // One read for every target's live declared-range grant (no per-target query).
      const consents=(await db.prepare('SELECT * FROM network_range_consents WHERE workspace_id=? ORDER BY created_at DESC,id DESC LIMIT 500').bind(workspaceId).all()).results||[];
      const revoked=new Set(consents.filter(r=>r.kind==='revocation').map(r=>r.grant_id));
      const liveFor=t=>consents.find(g=>g.kind==='grant'&&!revoked.has(g.id)&&g.network_target_id===t.id&&g.addresses_json===t.addresses_json)||null;
      return json({targets:rows.results.map(t=>{const g=liveFor(t);return networkTargetProjection(t,g?rangeConsentProjection(g,null,{canManage:!!manage}):null);}),capabilities:{can_manage:!!manage,can_scan:!!scan&&limits.scans_per_month>0,collector_available:!!env.NETWORK_PROBE?.fetch&&!!env.SCAN_QUEUE?.send,allowed_ports:NETWORK_PORTS,limits:NETWORK_LIMITS,range_authority:{version:NETWORK_RANGE_AUTHORITY_VERSION,text:NETWORK_RANGE_AUTHORITY_TEXT,declaration:NETWORK_RANGE_DECLARATION}}});
    }
    // Suggestions are read-only: they never create a target or start a scan.
    // Targets still require the literal address + authorization POST below.
    if(request.method==='GET'&&resource==='network-suggestions'&&!id) {
      const rate=await consumeApiRateLimit(env,[{scope:'user',scope_id:user.id},{scope:'workspace',scope_id:workspaceId}],'network_suggestions',60,3600);
      if(rate)return json(rate.body,rate.status);
      const assets=(await db.prepare(`SELECT a.hostname,a.ip_addresses,a.cname,a.status,a.lifecycle_state,a.wildcard_dns,d.domain FROM workspace_assets a JOIN workspace_domains wd ON wd.workspace_id=a.workspace_id AND wd.domain_id=a.domain_id JOIN domains d ON d.id=a.domain_id WHERE a.workspace_id=? AND wd.verification_status='verified' AND a.status='active' ORDER BY a.last_seen DESC,a.hostname LIMIT ?`).bind(workspaceId,NETWORK_SUGGESTION_LIMITS.assets).all()).results||[];
      const targets=(await db.prepare('SELECT addresses_json FROM network_targets WHERE workspace_id=?').bind(workspaceId).all()).results||[];
      const registeredAddresses=targets.flatMap(row=>{try{const list=parseJson(row.addresses_json);return Array.isArray(list)?list:[];}catch{return [];}});
      const resolved=await resolveHostAddresses(hostsNeedingResolution(assets));
      return json(buildNetworkSuggestions({assets,registeredAddresses,resolved}));
    }
    if(request.method==='POST'&&resource==='network-targets'&&!id) {
      if(!await requireWorkspaceRole(user,workspaceId,'domain:import',env))return json({error:'Forbidden — admin role required'},403);
      const body=await bodyJson(request);strictKeys(body,['target','authorization_confirmed','label','range_consent']);
      if(body.authorization_confirmed!==true)return json({error:'network_authorization_required'},400);
      if(body.label!=null&&(typeof body.label!=='string'||body.label.length>120))throw new Error('invalid_network_label');
      const normalized=await normalizeNetworkTarget(body.target),targetId=createId('nettarget'),now=new Date().toISOString();
      const consent=body.range_consent!=null?parseRangeConsent(body.range_consent,normalized.address_count):null;
      // The attestation is necessary, not sufficient: every address must be
      // observed in this workspace's verified-domain DNS (network-ownership.js),
      // or the request must carry a declared-range consent for exactly these
      // addresses. Shared provider infrastructure is refused either way.
      const observed=await observedNetworkAddresses(env,workspaceId);
      const decision=evaluateTargetScope(normalized.addresses,observed);
      if(decision.state!=='in_scope'&&(!consent||decision.shared.length)){
        return json({error:'network_target_not_observed',scope:scopeRefusal(decision),range_consent:decision.shared.length?'not_grantable_shared':'required'},422);
      }
      const addressesJson=JSON.stringify(normalized.addresses);
      const scopeEvidence=JSON.stringify({version:NETWORK_SCOPE_VERSION,unobserved:decision.unobserved,shared:decision.shared,evidence:decision.evidence,roots:observed.roots,lookups_failed:observed.lookups_failed});
      const insert=db.prepare(`INSERT INTO network_targets (id,workspace_id,target,target_type,addresses_json,address_count,label,authorization_status,authorized_by,authorized_at,created_at,scope_state,scope_reason,scope_checked_at,scope_evidence_json) SELECT ?,?,?,?,?,?,?,'attested',?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM workspaces WHERE id=? AND deleted_at IS NULL) AND (SELECT COUNT(*) FROM network_targets WHERE workspace_id=?)<?`)
        .bind(targetId,workspaceId,normalized.target,normalized.target_type,addressesJson,normalized.address_count,body.label||null,user.id,now,now,decision.state,decision.reason,now,scopeEvidence,workspaceId,workspaceId,NETWORK_LIMITS.max_targets);
      // The audit selects the inserted identity so reaching the target cap leaves no false authorization event.
      const audit=db.prepare(`INSERT INTO audit_events (id,workspace_id,user_id,actor_type,event_type,entity_type,entity_id,description,metadata_json,created_at) SELECT ?,?,?,'customer','network_target_authorized','network_target',?,'Network scope authorization declared',?,? WHERE EXISTS(SELECT 1 FROM network_targets WHERE id=? AND workspace_id=?)`)
        .bind(createId('audit'),workspaceId,user.id,targetId,JSON.stringify({target:normalized.target,authorization_status:'attested',independently_verified:false,range_consent:!!consent,scope:{state:decision.state,reason:decision.reason,evidence:decision.evidence}}),now,targetId,workspaceId);
      const grantId=consent?createId('nrc'):null;
      const actor=consent?await rangeActor(db,request,user,workspaceId):null;
      if(consent&&!actor)return json(ROLE_UNRECORDED,403);
      const statements=[insert,audit,...(consent?rangeGrantStatements(db,{id:grantId,workspaceId,targetId,target:normalized.target,addressesJson,consent,actor,now}):[])];
      let result;try{result=await db.batch(statements);}catch(e){if(/unique/i.test(String(e?.message)))return json({error:'network_target_exists'},409);throw e;}
      if(result[0]?.meta?.changes!==1)return json({error:'network_target_limit'},409);
      const row=await db.prepare('SELECT * FROM network_targets WHERE id=? AND workspace_id=?').bind(targetId,workspaceId).first();
      let rangeConsent=null;
      if(consent) {
        const grant=await db.prepare("SELECT * FROM network_range_consents WHERE id=? AND workspace_id=? AND kind='grant'").bind(grantId,workspaceId).first();
        // The daily grant cap: the target exists (not scanned unless in scope); say so.
        if(!grant)return json({error:'network_range_consent_limit',target:networkTargetProjection(row)},429);
        rangeConsent=rangeConsentProjection(grant,null,{canManage:true});
      }
      return json({target:networkTargetProjection(row,rangeConsent)},201);
    }
    // A declared-range grant for an existing target.
    if(request.method==='POST'&&resource==='network-targets'&&id&&action==='range-consents') {
      if(!await requireWorkspaceRole(user,workspaceId,'domain:import',env))return json({error:'Forbidden — admin role required'},403);
      const target=await db.prepare('SELECT * FROM network_targets WHERE workspace_id=? AND id=?').bind(workspaceId,id).first();
      if(!target)return json({error:'Not found'},404);
      const normalized=await normalizeNetworkTarget(target.target);
      if(target.authorization_status!=='attested'||JSON.stringify(normalized.addresses)!==target.addresses_json)throw new Error('network_scope_mismatch');
      const consent=parseRangeConsent(await bodyJson(request),normalized.address_count);
      const decision=(await checkNetworkTargetScope(env,workspaceId,[target])).get(target.id);
      if(!decision||decision.shared.length)return json({error:'network_range_not_grantable',scope:scopeRefusal(decision||{state:'out_of_scope',reason:null,unobserved:[],shared:[]}),range_consent:'not_grantable_shared'},422);
      const grantId=createId('nrc'),now=new Date().toISOString();
      const actor=await rangeActor(db,request,user,workspaceId);
      if(!actor)return json(ROLE_UNRECORDED,403);
      await db.batch(rangeGrantStatements(db,{id:grantId,workspaceId,targetId:target.id,target:target.target,addressesJson:target.addresses_json,consent,actor,now}));
      const grant=await db.prepare("SELECT * FROM network_range_consents WHERE id=? AND workspace_id=? AND kind='grant'").bind(grantId,workspaceId).first();
      if(!grant) {
        const live=await db.prepare('SELECT id FROM workspaces WHERE id=? AND deleted_at IS NULL').bind(workspaceId).first();
        return live?json({error:'network_range_consent_limit'},429):json({error:'Not found'},404);
      }
      return json({consent:rangeConsentProjection(grant,null,{canManage:true})},201);
    }
    if(resource==='network-range-consents') {
      const canManage=!!await requireWorkspaceRole(user,workspaceId,'domain:import',env);
      if(request.method==='GET'&&!id) {
        const rows=(await db.prepare('SELECT * FROM network_range_consents WHERE workspace_id=? ORDER BY created_at DESC,id DESC LIMIT 200').bind(workspaceId).all()).results||[];
        const revocations=new Map(rows.filter(r=>r.kind==='revocation').map(r=>[r.grant_id,r]));
        return json({consents:rows.filter(r=>r.kind==='grant').map(g=>rangeConsentProjection(g,revocations.get(g.id),{canManage})),authority:{version:NETWORK_RANGE_AUTHORITY_VERSION,text:NETWORK_RANGE_AUTHORITY_TEXT,declaration:NETWORK_RANGE_DECLARATION},capabilities:{can_manage:canManage}});
      }
      if(request.method!=='POST'||!id||action!=='revoke')return json({error:'Not found'},404);
      if(!canManage)return json({error:'Forbidden — admin role required'},403);
      if(!RANGE_CONSENT_ID.test(id))return json({error:'Consent not found'},404);
      const grant=await db.prepare("SELECT * FROM network_range_consents WHERE id=? AND workspace_id=? AND kind='grant' LIMIT 1").bind(id,workspaceId).first();
      if(!grant)return json({error:'Consent not found'},404);
      // Optional reason, written once on the revocation row. No body = no reason.
      const raw=await request.text();
      let reason=null;
      if(raw.trim()) {
        if(raw.length>4096)throw new Error('request_body_too_large');
        let payload;try{payload=JSON.parse(raw);}catch{throw new Error('invalid_json_body');}
        if(!payload||typeof payload!=='object'||Array.isArray(payload))throw new Error('invalid_json_body');
        strictKeys(payload,['reason']);
        if(payload.reason!=null&&typeof payload.reason!=='string')throw new Error('invalid_revocation_reason');
        reason=(payload.reason||'').trim()||null;
        if(reason&&reason.length>REVOCATION_REASON_MAX)throw new Error('invalid_revocation_reason');
      }
      const actor=await rangeActor(db,request,user,workspaceId),revocationId=createId('nrc'),now=new Date().toISOString();
      if(!actor)return json(ROLE_UNRECORDED,403);
      const [inserted]=await db.batch([
        db.prepare(`INSERT INTO network_range_consents (id,workspace_id,kind,grant_id,actor_user_id,actor_email,actor_workspace_role,ip_address,user_agent,revocation_reason,created_at) SELECT ?,?,'revocation',?,?,?,?,?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM network_range_consents WHERE grant_id=? AND kind='revocation')`)
          .bind(revocationId,workspaceId,grant.id,actor.user_id,actor.email,actor.role,actor.ip,actor.ua,reason,now,grant.id),
        db.prepare(`INSERT INTO audit_events (id,workspace_id,user_id,actor_type,event_type,entity_type,entity_id,description,metadata_json,created_at) SELECT ?,?,?,'customer','network_range_consent_revoked','network_range_consent',?,'Declared network range authorisation revoked',?,? WHERE changes()=1`)
          .bind(createId('audit'),workspaceId,actor.user_id,grant.id,JSON.stringify({revocation_id:revocationId,reason_given:Boolean(reason)}),now),
      ]);
      if(inserted?.meta?.changes!==1)return json({error:'consent_already_revoked'},409);
      return json({consent:rangeConsentProjection(grant,{created_at:now,revocation_reason:reason},{canManage})});
    }
    if(request.method==='GET'&&resource==='network-scans'&&!action) {
      if(id) {
        const row=await readScan(db,workspaceId,id);if(!row)return json({error:'Not found'},404);
        let receipt=null;
        if(row.status==='completed') {
          if(row.receipt_key!==`network-reports/${workspaceId}/${row.id}.json`)return json({error:'network_receipt_unavailable'},503);
          const stored=await env.cybermeters_reports.get(`network-reports/${workspaceId}/${row.id}.json`);
          if(!stored)return json({error:'network_receipt_unavailable'},503);
          const text=await stored.text();
          if(text.length>1_048_576||await networkReceiptHash(text)!==row.receipt_sha256)return json({error:'network_receipt_unavailable'},503);
          receipt=JSON.parse(text);
          if(receipt?.scan_id!==row.id||receipt?.workspace_id!==workspaceId)return json({error:'network_receipt_unavailable'},503);
        }
        return json({scan:networkScanProjection(row),receipt,changes:parseJson(row.changes_json)||[]});
      }
      const rows=await db.prepare('SELECT s.*,t.target FROM network_scans s JOIN network_targets t ON t.id=s.target_id AND t.workspace_id=s.workspace_id WHERE s.workspace_id=? ORDER BY s.created_at DESC,s.id DESC LIMIT 100').bind(workspaceId).all();
      const total=(await db.prepare('SELECT COUNT(*) AS cnt FROM network_scans WHERE workspace_id=?').bind(workspaceId).first()).cnt;
      return json({scans:rows.results.map(networkScanProjection),scope:'latest_100',total,truncated:total>rows.results.length});
    }
    if(request.method==='GET'&&resource==='network-assets'&&!id) {
      const rawCursor=url.searchParams.get('cursor')||'0';
      if(!/^(0|[1-9]\d{0,5})$/.test(rawCursor))return json({error:'invalid_cursor'},400);
      const offset=Number(rawCursor);
      const rows=await db.prepare('SELECT * FROM network_assets WHERE workspace_id=? ORDER BY address,port LIMIT 257 OFFSET ?').bind(workspaceId,offset).all();
      const total=(await db.prepare('SELECT COUNT(*) AS cnt FROM network_assets WHERE workspace_id=?').bind(workspaceId).first()).cnt;
      const page=rows.results.slice(0,256);
      const recent=await db.prepare("SELECT id,completed_at,changes_json FROM network_scans WHERE workspace_id=? AND status='completed' ORDER BY completed_at DESC,id DESC LIMIT 25").bind(workspaceId).all();
      return json({total,next_cursor:rows.results.length>256?String(offset+256):null,assets:page.map(r=>({...r,service:parseJson(r.service_json),tls:parseJson(r.tls_json),service_json:undefined,tls_json:undefined})),changes:recent.results.flatMap(r=>(parseJson(r.changes_json)||[]).map(c=>({...c,scan_id:r.id,observed_at:r.completed_at})))});
    }
    if(request.method==='POST'&&((resource==='network-targets'&&id&&action==='scans')||(resource==='network-scans'&&id&&action==='retest'))) {
      if(!await requireWorkspaceRole(user,workspaceId,'scan:create',env))return json({error:'Forbidden — analyst role required'},403);
      if(!env.NETWORK_PROBE?.fetch||!env.SCAN_QUEUE?.send)return json({error:'network_collector_unavailable'},503);
      let targetId=id,retestOf=null,ports;
      const body=await bodyJson(request);
      if(action==='retest') {
        strictKeys(body,[]);const prior=await readScan(db,workspaceId,id);if(!prior)return json({error:'Not found'},404);
        if(!['completed','failed'].includes(prior.status))return json({error:'network_scan_active'},409);
        targetId=prior.target_id;ports=parseJson(prior.ports_json);retestOf=prior.id;
      } else {strictKeys(body,['ports']);ports=body.ports;}
      const target=await db.prepare('SELECT * FROM network_targets WHERE workspace_id=? AND id=?').bind(workspaceId,targetId).first();
      if(!target)return json({error:'Not found'},404);
      const normalized=await normalizeNetworkTarget(target.target);
      if(target.authorization_status!=='attested'||JSON.stringify(normalized.addresses)!==target.addresses_json)throw new Error('network_scope_mismatch');
      ports=normalizeNetworkPorts(ports,normalized.address_count);
      const owner=await getWorkspaceBillingUserId(workspaceId,user.id,env),limits=getPlanLimits(await getEffectivePlan(owner,env));
      const rejected=await checkScanLimit(user,workspaceId,env);
      if(rejected)return json(rejected.body,rejected.status);
      const rate=await consumeApiRateLimit(env,[{scope:'user',scope_id:user.id},{scope:'workspace',scope_id:workspaceId},{scope:'account',scope_id:owner}],'scan_start',limits.scan_starts_per_hour,3600,{failClosed:true});
      if(rate)return json(rate.body,rate.status);
      // Checked again now, after the plan and rate checks: DNS may have moved
      // since the target was declared (network-ownership.js).
      const decision=(await checkNetworkTargetScope(env,workspaceId,[target])).get(target.id);
      // Not observed in verified DNS: only a live declared-range grant for these
      // exact addresses that names every requested port authorises the scan.
      let rangeConsentId=null;
      if(decision?.state!=='in_scope') {
        const grant=decision&&!decision.shared.length?await liveRangeGrant(db,workspaceId,target):null;
        if(!grant||!rangeGrantCoversPorts(grant,ports)) {
          return json({error:'network_target_out_of_scope',scope:scopeRefusal(decision||{state:'out_of_scope',reason:null,unobserved:[],shared:[]}),range_consent:decision?.shared?.length?'not_grantable_shared':grant?'ports_not_covered':'required'},409);
        }
        rangeConsentId=grant.id;
      }
      const scanId=createId('netscan'),now=new Date().toISOString(),key=`network-reports/${workspaceId}/${scanId}.json`;
      // The quota predicate executes in the same D1 statement as admission.
      const admission=await getOperationAdmission(env,workspaceId,user.id,'scans');
      const quota=admission.state.is_trial||admission.state.plan==='free' ? admission : {
        sql:`((SELECT COUNT(*) FROM scans s JOIN workspaces w ON w.id=s.workspace_id WHERE w.owner_user_id=? AND s.created_at>=?) + (SELECT COUNT(*) FROM network_scans n JOIN workspaces w ON w.id=n.workspace_id WHERE w.owner_user_id=? AND n.created_at>=?))<?`,
        args:[owner,getMonthStart(),owner,getMonthStart(),limits.scans_per_month],
        rejection:async()=>({status:403,body:{error:'plan_limit_exceeded',resource:'scans_per_month',limit:limits.scans_per_month,usage:await monthlyUsage(db,owner),reset_at:getMonthResetAt()}})
      };
      const stamp=admission.state.is_trial ? "strftime('%Y-%m-%dT%H:%M:%fZ', 'now')" : '?';
      // A revocation landing between the read above and this insert still stops it.
      const insert=db.prepare(`INSERT INTO network_scans (id,workspace_id,target_id,requested_by,retest_of,ports_json,status,receipt_key,range_consent_id,created_at) SELECT ?,?,?,?,?,?,'queued',?,?,${stamp} WHERE EXISTS(SELECT 1 FROM workspaces WHERE id=? AND deleted_at IS NULL) AND (? IS NULL OR NOT EXISTS(SELECT 1 FROM network_range_consents WHERE kind='revocation' AND grant_id=? AND workspace_id=?)) AND ${quota.sql}`)
        .bind(scanId,workspaceId,targetId,user.id,retestOf,JSON.stringify(ports),key,rangeConsentId,...(admission.state.is_trial?[]:[now]),workspaceId,rangeConsentId,rangeConsentId,workspaceId,...quota.args);
      let admitted;try{admitted=await insert.run();}catch(e){if(/unique/i.test(String(e?.message)))return json({error:'network_scan_active'},409);throw e;}
      if(admitted.meta?.changes!==1){
        if(rangeConsentId&&await db.prepare("SELECT 1 FROM network_range_consents WHERE kind='revocation' AND grant_id=? AND workspace_id=?").bind(rangeConsentId,workspaceId).first())return json({error:'network_range_consent_revoked'},409);
        const rejected=await quota.rejection();return json(rejected.body,rejected.status);
      }
      try{await env.SCAN_QUEUE.send({kind:'network_probe',v:1,scan_id:scanId,workspace_id:workspaceId});}
      catch{await db.prepare("UPDATE network_scans SET status='failed',reason='dispatch_failed',completed_at=? WHERE id=? AND status='queued'").bind(new Date().toISOString(),scanId).run();return json({error:'network_dispatch_failed'},503);}
      return json({scan:networkScanProjection({...await readScan(db,workspaceId,scanId)})},202);
    }
    return json({error:'Not found'},404);
  } catch(error) {
    if(/^(invalid_|unsupported_network_|network_(target|pair|scope|authorization|range_authority)|request_body_)/.test(error?.message||''))return json({error:error.message},400);
    return serverError('network-assets',error);
  }
}
