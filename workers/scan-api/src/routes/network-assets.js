import { getEffectivePlan } from '../engines/entitlements.js';
import { checkScanLimit, getOperationAdmission, getMonthStart, getMonthResetAt, getPlanLimits, getWorkspaceBillingUserId } from '../engines/plan-usage.js';
import { NETWORK_LIMITS, NETWORK_PORTS, normalizeNetworkTarget, normalizeNetworkPorts } from '../engines/network-targets.js';
import { createId } from '../lib/util.js';
import { networkReceiptHash } from '../engines/network-scan-dispatch.js';
import { buildNetworkSuggestions, hostsNeedingResolution, NETWORK_SUGGESTION_LIMITS, resolveHostAddresses } from '../engines/network-suggestions.js';

const parseJson = value => value ? JSON.parse(value) : null;
export const networkTargetProjection = row => ({ id:row.id,target:row.target,target_type:row.target_type,address_count:row.address_count,label:row.label,authorization_status:row.authorization_status,authorized_by:row.authorized_by,authorized_at:row.authorized_at,created_at:row.created_at });
export const networkScanProjection = row => ({ id:row.id,target_id:row.target_id,target:row.target,status:row.status,quality:row.quality,ports:parseJson(row.ports_json),retest_of:row.retest_of,created_at:row.created_at,started_at:row.started_at,completed_at:row.completed_at,reason:row.reason,coverage:parseJson(row.coverage_json),receipt_sha256:row.receipt_sha256 });
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
  const match=url.pathname.match(/^\/api\/workspaces\/([^/]+)\/(network-targets|network-scans|network-assets|network-suggestions)(?:\/([^/]+)(?:\/(scans|retest))?)?$/);
  if(!match)return null;
  const [,workspaceId,resource,id,action]=match;
  const user=await requireAuth(request,env);if(!user)return json({error:'Unauthorized'},401);
  const read=await requireWorkspaceRole(user,workspaceId,'workspace:read',env);if(!read)return json({error:'Forbidden'},403);
  const db=env.cybermeters_db;
  try {
    if(request.method==='GET'&&resource==='network-targets'&&!id) {
      const rows=await db.prepare('SELECT * FROM network_targets WHERE workspace_id=? ORDER BY created_at DESC,id').bind(workspaceId).all();
      const manage=await requireWorkspaceRole(user,workspaceId,'domain:import',env);
      const scan=await requireWorkspaceRole(user,workspaceId,'scan:create',env);
      const owner=await getWorkspaceBillingUserId(workspaceId,user.id,env);
      const limits=getPlanLimits(await getEffectivePlan(owner,env));
      return json({targets:rows.results.map(networkTargetProjection),capabilities:{can_manage:!!manage,can_scan:!!scan&&limits.scans_per_month>0,collector_available:!!env.NETWORK_PROBE?.fetch&&!!env.SCAN_QUEUE?.send,allowed_ports:NETWORK_PORTS,limits:NETWORK_LIMITS}});
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
      const body=await bodyJson(request);strictKeys(body,['target','authorization_confirmed','label']);
      if(body.authorization_confirmed!==true)return json({error:'network_authorization_required'},400);
      if(body.label!=null&&(typeof body.label!=='string'||body.label.length>120))throw new Error('invalid_network_label');
      const normalized=await normalizeNetworkTarget(body.target),targetId=createId('nettarget'),now=new Date().toISOString();
      const insert=db.prepare(`INSERT INTO network_targets (id,workspace_id,target,target_type,addresses_json,address_count,label,authorization_status,authorized_by,authorized_at,created_at) SELECT ?,?,?,?,?,?,?,'attested',?,?,? WHERE EXISTS(SELECT 1 FROM workspaces WHERE id=? AND deleted_at IS NULL) AND (SELECT COUNT(*) FROM network_targets WHERE workspace_id=?)<?`)
        .bind(targetId,workspaceId,normalized.target,normalized.target_type,JSON.stringify(normalized.addresses),normalized.address_count,body.label||null,user.id,now,now,workspaceId,workspaceId,NETWORK_LIMITS.max_targets);
      // The audit selects the inserted identity so reaching the target cap leaves no false authorization event.
      const audit=db.prepare(`INSERT INTO audit_events (id,workspace_id,user_id,actor_type,event_type,entity_type,entity_id,description,metadata_json,created_at) SELECT ?,?,?,'customer','network_target_authorized','network_target',?,'Network scope authorization declared',?,? WHERE EXISTS(SELECT 1 FROM network_targets WHERE id=? AND workspace_id=?)`)
        .bind(createId('audit'),workspaceId,user.id,targetId,JSON.stringify({target:normalized.target,authorization_status:'attested',independently_verified:false}),now,targetId,workspaceId);
      let result;try{result=await db.batch([insert,audit]);}catch(e){if(/unique/i.test(String(e?.message)))return json({error:'network_target_exists'},409);throw e;}
      if(result[0]?.meta?.changes!==1)return json({error:'network_target_limit'},409);
      const row=await db.prepare('SELECT * FROM network_targets WHERE id=? AND workspace_id=?').bind(targetId,workspaceId).first();
      return json({target:networkTargetProjection(row)},201);
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
      const scanId=createId('netscan'),now=new Date().toISOString(),key=`network-reports/${workspaceId}/${scanId}.json`;
      // The quota predicate executes in the same D1 statement as admission.
      const admission=await getOperationAdmission(env,workspaceId,user.id,'scans');
      const quota=admission.state.is_trial||admission.state.plan==='free' ? admission : {
        sql:`((SELECT COUNT(*) FROM scans s JOIN workspaces w ON w.id=s.workspace_id WHERE w.owner_user_id=? AND s.created_at>=?) + (SELECT COUNT(*) FROM network_scans n JOIN workspaces w ON w.id=n.workspace_id WHERE w.owner_user_id=? AND n.created_at>=?))<?`,
        args:[owner,getMonthStart(),owner,getMonthStart(),limits.scans_per_month],
        rejection:async()=>({status:403,body:{error:'plan_limit_exceeded',resource:'scans_per_month',limit:limits.scans_per_month,usage:await monthlyUsage(db,owner),reset_at:getMonthResetAt()}})
      };
      const stamp=admission.state.is_trial ? "strftime('%Y-%m-%dT%H:%M:%fZ', 'now')" : '?';
      const insert=db.prepare(`INSERT INTO network_scans (id,workspace_id,target_id,requested_by,retest_of,ports_json,status,receipt_key,created_at) SELECT ?,?,?,?,?,?,'queued',?,${stamp} WHERE EXISTS(SELECT 1 FROM workspaces WHERE id=? AND deleted_at IS NULL) AND ${quota.sql}`)
        .bind(scanId,workspaceId,targetId,user.id,retestOf,JSON.stringify(ports),key,...(admission.state.is_trial?[]:[now]),workspaceId,...quota.args);
      let admitted;try{admitted=await insert.run();}catch(e){if(/unique/i.test(String(e?.message)))return json({error:'network_scan_active'},409);throw e;}
      if(admitted.meta?.changes!==1){const rejected=await quota.rejection();return json(rejected.body,rejected.status);}
      try{await env.SCAN_QUEUE.send({kind:'network_probe',v:1,scan_id:scanId,workspace_id:workspaceId});}
      catch{await db.prepare("UPDATE network_scans SET status='failed',reason='dispatch_failed',completed_at=? WHERE id=? AND status='queued'").bind(new Date().toISOString(),scanId).run();return json({error:'network_dispatch_failed'},503);}
      return json({scan:networkScanProjection({...await readScan(db,workspaceId,scanId)})},202);
    }
    return json({error:'Not found'},404);
  } catch(error) {
    if(/^(invalid_|unsupported_network_|network_(target|pair|scope|authorization)|request_body_)/.test(error?.message||''))return json({error:error.message},400);
    return serverError('network-assets',error);
  }
}
