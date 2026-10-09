import { canonicalDomain, boundedDnsJson, DnsActionError } from '../engines/cloudflare-dns.js';
import { providerKeyAvailable } from '../lib/provider-secrets.js';
import { getEffectivePlan } from '../engines/entitlements.js';
import { getWorkspaceBillingUserId } from '../engines/plan-usage.js';
import { planAllowsHostedPolicyManagement } from '../engines/hosted-dmarc.js';
import { DNS_ACTIONS, DNS_SCOPE_NOTE, loadDnsConnection, connectionView, changeView, loadDnsChange, connectDnsProvider, disconnectDnsProvider, dnsReportingReady, previewDnsChange, applyDnsChange, verifyDnsChange, rollbackDnsChange } from '../engines/dns-remediation.js';

const messages = {
  session_role_required: 'A workspace owner or admin session is required.',
  domain_not_verified: 'Verify this domain in this workspace first.',
  plan_required: 'An active paid plan or trial is required to apply a DNS change.',
  key_unavailable: 'DNS connections are temporarily unavailable.',
  record_drift: 'The record changed outside this preview. Review the current DNS records.',
  reporting_endpoint_required: 'Create a CyberMeters reporting address for this domain first.',
  preview_expired: 'This preview expired. Create a new preview.',
  connection_required: 'Connect this domain’s Cloudflare zone first.',
  connection_changed: 'The DNS connection changed. Create a new preview or reconnect the original zone.',
  provider_access_denied: 'Cloudflare did not grant access to this zone.',
  provider_unavailable: 'Cloudflare could not confirm this request. Check the saved change before trying another action.',
  action_in_progress: 'Another action is still being reconciled for this DNS name.',
  existing_record_conflict: 'The existing DNS records do not support this change. Review them before continuing.',
  unsupported_input: 'Check the explicit DNS change inputs.',
};
export async function dnsConnectionRoutes(rctx) {
  const { request, env, url, json, requireAuth, requireWorkspaceRole, consumeApiRateLimit } = rctx;
  const metadataMatch = url.pathname.match(/^\/api\/workspaces\/([^\/]+)\/dns-connections$/);
  const connectionMatch = url.pathname.match(/^\/api\/workspaces\/([^\/]+)\/domains\/([^\/]+)\/dns-connection$/);
  const previewMatch = url.pathname.match(/^\/api\/workspaces\/([^\/]+)\/domains\/([^\/]+)\/dns-changes\/preview$/);
  const itemMatch = url.pathname.match(/^\/api\/workspaces\/([^\/]+)\/domains\/([^\/]+)\/dns-changes\/([^\/]+)$/);
  const applyMatch = url.pathname.match(/^\/api\/workspaces\/([^\/]+)\/domains\/([^\/]+)\/dns-changes\/([^\/]+)\/apply$/);
  const verifyMatch = url.pathname.match(/^\/api\/workspaces\/([^\/]+)\/domains\/([^\/]+)\/dns-changes\/([^\/]+)\/verify$/);
  const rollbackMatch = url.pathname.match(/^\/api\/workspaces\/([^\/]+)\/domains\/([^\/]+)\/dns-changes\/([^\/]+)\/rollback$/);
  const match = metadataMatch || connectionMatch || previewMatch || applyMatch || verifyMatch || rollbackMatch || itemMatch;
  if (!match) return null;
  const workspaceId = match[1], db = env.cybermeters_db;
  try {
    const user = await requireAuth(request,env);
    if (!user) return json({error:'Unauthorized',code:'unauthorized'},401);
    const access = await requireWorkspaceRole(user,workspaceId,'workspace:read',env);
    if (!access) return json({error:'Forbidden',code:'forbidden'},403);
    const workspace = await db.prepare('SELECT id FROM workspaces WHERE id=? AND deleted_at IS NULL').bind(workspaceId).first();
    if (!workspace) return json({error:'Workspace not found',code:'workspace_not_found'},404);
    const canManage = !user.api_token_id && ['owner','admin'].includes(access.role);
    const capable = async () => {
      if (!canManage) return {can_manage:false,can_apply:false,reason:'session_role_required'};
      const owner = await getWorkspaceBillingUserId(workspaceId,user.id,env);
      const paid = planAllowsHostedPolicyManagement(await getEffectivePlan(owner,env));
      const key = providerKeyAvailable(env.DNS_PROVIDER_KEY);
      return {can_manage:true,can_apply:paid && key,reason:!key?'key_unavailable':!paid?'plan_required':null};
    };
    if (request.method === 'GET' && metadataMatch) {
      const domains = canManage ? (await db.prepare("SELECT d.id,d.domain FROM workspace_domains wd JOIN domains d ON d.id=wd.domain_id WHERE wd.workspace_id=? AND wd.verification_status='verified' AND wd.verified_at IS NOT NULL ORDER BY d.domain LIMIT 500").bind(workspaceId).all()).results || [] : [];
      return json({...await capable(),domains,supported_actions:DNS_ACTIONS,scope_note:DNS_SCOPE_NOTE});
    }
    if (!canManage) throw new DnsActionError('session_role_required',403);
    let domain;
    try { domain = canonicalDomain(decodeURIComponent(match[2])); } catch { throw new DnsActionError('unsupported_input',400); }
    const lookupDomain = () => db.prepare("SELECT d.id,d.domain FROM workspace_domains wd JOIN domains d ON d.id=wd.domain_id WHERE wd.workspace_id=? AND d.domain=? AND wd.verification_status='verified' AND wd.verified_at IS NOT NULL").bind(workspaceId,domain).first();
    const owned = await lookupDomain();
    if (!owned) throw new DnsActionError('domain_not_verified',403);
    const authorize = async (requirePaid) => {
      // Recheck the actual session and current membership after provider awaits.
      const currentUser = await requireAuth(request,env);
      if (!currentUser || currentUser.id !== user.id || currentUser.api_token_id) throw new DnsActionError('session_role_required',403);
      const current = await requireWorkspaceRole(currentUser,workspaceId,'workspace:manage',env);
      if (!current || !['owner','admin'].includes(current.role)) throw new DnsActionError('session_role_required',403);
      const active = await db.prepare('SELECT id FROM workspaces WHERE id=? AND deleted_at IS NULL').bind(workspaceId).first();
      if (!active || !(await lookupDomain())) throw new DnsActionError('domain_not_verified',403);
      if (requirePaid) {
        const owner = await getWorkspaceBillingUserId(workspaceId,user.id,env);
        if (!planAllowsHostedPolicyManagement(await getEffectivePlan(owner,env))) throw new DnsActionError('plan_required',403);
      }
    };
    const c = {env,db,workspaceId,domainId:owned.id,domain,userId:user.id,authorize};
    const metadata = async () => {
      await authorize(false);
      const connection = await loadDnsConnection(c), capabilities = await capable();
      const rows = (await db.prepare('SELECT * FROM dns_provider_changes WHERE workspace_id=? AND domain_id=? ORDER BY created_at DESC,id DESC LIMIT 20').bind(workspaceId,owned.id).all()).results || [];
      return {...capabilities,connection:connectionView(connection),reporting_ready:await dnsReportingReady(c),changes:rows.map(row=>changeView(row,{...capabilities,can_apply:capabilities.can_apply && !!connection && connection.credential_revision===row.credential_revision})),scope_note:DNS_SCOPE_NOTE};
    };
    const body = async () => {
      if (!/^application\/json(?:;|$)/i.test(request.headers.get('content-type') || '')) throw new DnsActionError('unsupported_input',400);
      try { return await boundedDnsJson(request,8192); } catch { throw new DnsActionError('unsupported_input',400); }
    };
    const limit = async () => {
      const limited = await consumeApiRateLimit(env,[{scope:'workspace',scope_id:workspaceId}],'dns_provider_change',30,60,{atomic:true,failClosed:true});
      return limited ? json(limited.body,limited.status) : null;
    };
    const result = async row => { await authorize(false); return json({change:changeView(row,await capable())}); };
    if (request.method === 'GET' && connectionMatch) return json(await metadata());
    if (request.method === 'PUT' && connectionMatch) {
      const limited = await limit(); if (limited) return limited;
      await connectDnsProvider(c,await body()); return json(await metadata());
    }
    if (request.method === 'DELETE' && connectionMatch) return json(await disconnectDnsProvider(c));
    if (request.method === 'POST' && previewMatch) {
      const limited = await limit(); if (limited) return limited;
      return await result(await previewDnsChange(c,await body()));
    }
    if (request.method === 'GET' && itemMatch) return await result(await loadDnsChange(c,itemMatch[3]));
    if (request.method === 'POST' && applyMatch) {
      const limited = await limit(); if (limited) return limited;
      return await result(await applyDnsChange(c,applyMatch[3],await body()));
    }
    if (request.method === 'POST' && verifyMatch) {
      const limited = await limit(); if (limited) return limited;
      return await result(await verifyDnsChange(c,verifyMatch[3],await body()));
    }
    if (request.method === 'POST' && rollbackMatch) {
      const limited = await limit(); if (limited) return limited;
      return await result(await rollbackDnsChange(c,rollbackMatch[3],await body()));
    }
    return json({error:'Not found',code:'not_found'},404);
  } catch (error) {
    const known = error instanceof DnsActionError || error?.code === 'key_unavailable';
    const code = known ? error.code : 'dns_action_unavailable';
    return json({error:messages[code] || 'The DNS action could not be completed. Review the saved change before continuing.',code},known ? error.status : 503);
  }
}
