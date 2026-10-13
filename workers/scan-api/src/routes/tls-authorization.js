import { createId } from '../lib/util.js';
import { isProbeHostname, readBoundedJson } from '../../../network-probe/src/contract.js';

export const TLS_SPECIAL_CONSENT_VERSION = 'tls-special-2026-10-13';
export const TLS_SERVICE_PORTS = Object.freeze({https:[443,8443],smtp:[25,587],smtps:[465],imap:[143],imaps:[993],pop3:[110],pop3s:[995]});
export const TLS_SERVICE_LIMIT = 64;
const identifier = value => typeof value === 'string' && /^[a-zA-Z0-9_-]{1,100}$/.test(value);
const strict = (body, keys) => body && typeof body === 'object' && !Array.isArray(body) && Object.keys(body).every(key => keys.includes(key));
export const tlsAuthorizationProjection = row => ({enabled:row?.enabled === 1,generation:row?.generation || 0,consent_version:row?.consent_version || null,authorized_by:row?.authorized_by || null,authorized_at:row?.authorized_at || null,revoked_by:row?.revoked_by || null,revoked_at:row?.revoked_at || null,updated_at:row?.updated_at || null});
export const tlsServiceProjection = row => Object.fromEntries(['id','domain_id','hostname','sni','port','application_protocol','network_target_id','authorization_status','generation','authorized_by','authorized_at','revoked_by','revoked_at','updated_at'].map(key => [key,row[key] ?? null]));

// Every scope query includes workspace_id. Authorization records never imply
// that the registered IP currently serves this hostname: the runner proves that
// DNS binding before each slice and never scans other tenants on a shared IP.
export async function tlsAuthorizationRoutes(rctx) {
  const {request,env,url,json,requireAuth,requireWorkspaceRole,serverError} = rctx;
  const match = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/tls-authorization(?:\/(services)(?:\/([^/]+)\/(revoke))?)?$/);
  if (!match) return null;
  const [,workspaceId,resource,serviceId,action] = match;
  const user = await requireAuth(request,env);
  if (!user) return json({error:'Unauthorized'},401);
  if (!await requireWorkspaceRole(user,workspaceId,'workspace:read',env)) return json({error:'Forbidden'},403);
  const db = env.cybermeters_db;
  try {
    if (!await db.prepare('SELECT id FROM workspaces WHERE id=? AND deleted_at IS NULL').bind(workspaceId).first()) return json({error:'Workspace not found'},404);
    const canManage = !!await requireWorkspaceRole(user,workspaceId,'domain:import',env);
    const assessmentAvailable = env.TLS_ASSESSMENT_MODE === 'evidence-v1';
    const readAuthorization = async () => tlsAuthorizationProjection(await db.prepare('SELECT * FROM workspace_tls_authorizations WHERE workspace_id=?').bind(workspaceId).first());
    const readServices = async () => (await db.prepare("SELECT * FROM workspace_tls_service_authorizations WHERE workspace_id=? AND authorization_status='active' ORDER BY authorized_at,id LIMIT 64").bind(workspaceId).all()).results.map(tlsServiceProjection);
    if (request.method === 'GET' && !serviceId) {
      if (resource) return json({services:await readServices(),capabilities:{can_manage:canManage,assessment_available:assessmentAvailable}});
      const [authorization,services,domains,targets] = await Promise.all([
        readAuthorization(),readServices(),
        db.prepare("SELECT d.id AS domain_id,d.domain FROM workspace_domains wd JOIN domains d ON d.id=wd.domain_id WHERE wd.workspace_id=? AND wd.verification_status='verified' ORDER BY d.domain").bind(workspaceId).all(),
        db.prepare("SELECT id,target FROM network_targets WHERE workspace_id=? AND authorization_status='attested' ORDER BY target,id LIMIT 32").bind(workspaceId).all(),
      ]);
      return json({authorization,services,verified_domains:domains.results,network_targets:targets.results,capabilities:{can_manage:canManage,assessment_available:assessmentAvailable},allowed_services:TLS_SERVICE_PORTS,max_services:TLS_SERVICE_LIMIT,consent_version:TLS_SPECIAL_CONSENT_VERSION});
    }
    if (!canManage) return json({error:'Forbidden — admin role required'},403);
    if (!((request.method === 'PUT' && !resource) || (request.method === 'POST' && resource))) return json({error:'Not found'},404);
    let body;
    try {body = await readBoundedJson(request.body,4096);} catch {return json({error:'invalid_tls_authorization_body'},400);}
    const now = new Date().toISOString();
    // Keep scope mutation and generation increment in the same transaction.
    // A failed write cannot emit an audit or revoke an unrelated tenant's job.
    const generationAfterChange = () => db.prepare(`INSERT INTO workspace_tls_authorizations(workspace_id,enabled,generation,updated_at)
      SELECT ?,0,1,? WHERE changes()=1
      ON CONFLICT(workspace_id) DO UPDATE SET generation=generation+1,updated_at=excluded.updated_at`).bind(workspaceId,now);
    const auditAfterChange = (event,entity,id,detail) => db.prepare(`INSERT INTO audit_events(id,workspace_id,user_id,actor_type,event_type,entity_type,entity_id,description,metadata_json,created_at)
      SELECT ?,?,?,'customer',?,?,?,'TLS scan permission changed',json_set(?,'$.generation',(SELECT generation FROM workspace_tls_authorizations WHERE workspace_id=?)),? WHERE changes()=1`)
      .bind(createId('audit'),workspaceId,user.id,event,entity,id,JSON.stringify(detail),workspaceId,now);
    if (request.method === 'PUT' && !resource) {
      if (!strict(body,['enabled','authorization_confirmed','consent_version']) || typeof body.enabled !== 'boolean') return json({error:'invalid_tls_authorization_body'},400);
      if (body.enabled && (body.authorization_confirmed !== true || body.consent_version !== TLS_SPECIAL_CONSENT_VERSION)) return json({error:'tls_explicit_authorization_required'},400);
      if (body.enabled && !assessmentAvailable) return json({error:'tls_assessment_unavailable'},409);
      const write = db.prepare(`INSERT INTO workspace_tls_authorizations(workspace_id,enabled,generation,consent_version,authorized_by,authorized_at,revoked_by,revoked_at,updated_at)
        SELECT ?,?,1,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM workspaces WHERE id=? AND deleted_at IS NULL)
        ON CONFLICT(workspace_id) DO UPDATE SET enabled=excluded.enabled,generation=generation+1,
        consent_version=CASE WHEN excluded.enabled=1 THEN excluded.consent_version ELSE consent_version END,
        authorized_by=CASE WHEN excluded.enabled=1 THEN excluded.authorized_by ELSE authorized_by END,
        authorized_at=CASE WHEN excluded.enabled=1 THEN excluded.authorized_at ELSE authorized_at END,
        revoked_by=excluded.revoked_by,revoked_at=excluded.revoked_at,updated_at=excluded.updated_at`)
        .bind(workspaceId,body.enabled?1:0,body.enabled?TLS_SPECIAL_CONSENT_VERSION:null,body.enabled?user.id:null,body.enabled?now:null,body.enabled?null:user.id,body.enabled?null:now,now,workspaceId);
      const results = await db.batch([write,auditAfterChange(body.enabled?'tls_special_authorized':'tls_special_revoked','workspace',workspaceId,{enabled:body.enabled,consent_version:TLS_SPECIAL_CONSENT_VERSION})]);
      if (results[0]?.meta?.changes !== 1) return json({error:'Workspace not found'},404);
      return json({authorization:await readAuthorization()});
    }
    if (action === 'revoke') {
      if (!strict(body,[]) || !identifier(serviceId)) return json({error:'invalid_tls_service'},400);
      const results = await db.batch([
        db.prepare(`UPDATE workspace_tls_service_authorizations SET authorization_status='revoked',generation=generation+1,revoked_by=?,revoked_at=?,updated_at=?
          WHERE id=? AND workspace_id=? AND authorization_status='active' AND EXISTS(SELECT 1 FROM workspaces WHERE id=? AND deleted_at IS NULL)`)
          .bind(user.id,now,now,serviceId,workspaceId,workspaceId),generationAfterChange(),auditAfterChange('tls_service_revoked','tls_service',serviceId,{}),
      ]);
      if (results[0]?.meta?.changes !== 1) return json({error:'TLS service not found'},404);
      return json({authorization:await readAuthorization(),services:await readServices()});
    }
    if (!strict(body,['domain_id','hostname','sni','port','application_protocol','network_target_id','authorization_confirmed']) || !identifier(body.domain_id) || !identifier(body.network_target_id) || !isProbeHostname(body.hostname) || body.sni !== body.hostname || !Object.hasOwn(TLS_SERVICE_PORTS,body.application_protocol) || !TLS_SERVICE_PORTS[body.application_protocol].includes(body.port)) return json({error:'invalid_tls_service'},400);
    if (body.authorization_confirmed !== true) return json({error:'tls_service_authorization_required'},400);
    if (!assessmentAvailable) return json({error:'tls_assessment_unavailable'},409);
    const domain = await db.prepare("SELECT d.domain FROM workspace_domains wd JOIN domains d ON d.id=wd.domain_id WHERE wd.workspace_id=? AND wd.domain_id=? AND wd.verification_status='verified'").bind(workspaceId,body.domain_id).first();
    if (!domain || !(body.hostname === domain.domain || body.hostname.endsWith('.'+domain.domain))) return json({error:'tls_service_scope_invalid'},400);
    const id = createId('tlsservice');
    const write = db.prepare(`INSERT INTO workspace_tls_service_authorizations(id,workspace_id,domain_id,hostname,sni,port,application_protocol,network_target_id,authorization_status,generation,authorized_by,authorized_at,updated_at)
      SELECT ?,?,?,?,?,?,?,?,'active',1,?,?,?
      WHERE EXISTS(SELECT 1 FROM workspaces WHERE id=? AND deleted_at IS NULL)
      AND EXISTS(SELECT 1 FROM workspace_domains wd JOIN domains d ON d.id=wd.domain_id WHERE wd.workspace_id=? AND wd.domain_id=? AND wd.verification_status='verified' AND d.domain=?)
      AND EXISTS(SELECT 1 FROM network_targets WHERE workspace_id=? AND id=? AND authorization_status='attested')
      AND (SELECT COUNT(*) FROM workspace_tls_service_authorizations WHERE workspace_id=? AND authorization_status='active')<64`)
      .bind(id,workspaceId,body.domain_id,body.hostname,body.sni,body.port,body.application_protocol,body.network_target_id,user.id,now,now,workspaceId,workspaceId,body.domain_id,domain.domain,workspaceId,body.network_target_id,workspaceId);
    let results;
    try {results = await db.batch([write,generationAfterChange(),auditAfterChange('tls_service_authorized','tls_service',id,{domain_id:body.domain_id,hostname:body.hostname,sni:body.sni,port:body.port,application_protocol:body.application_protocol,network_target_id:body.network_target_id})]);}
    catch (error) {if (/unique/i.test(String(error?.message))) return json({error:'tls_service_exists'},409);throw error;}
    if (results[0]?.meta?.changes !== 1) return json({error:'tls_service_scope_or_limit'},409);
    const row = await db.prepare('SELECT * FROM workspace_tls_service_authorizations WHERE workspace_id=? AND id=?').bind(workspaceId,id).first();
    return json({service:tlsServiceProjection(row),authorization:await readAuthorization()},201);
  } catch (error) {return serverError('tls-authorization',error);}
}
