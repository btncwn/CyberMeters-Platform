import { boundedDnsJson } from '../engines/cloudflare-dns.js';
import { createEntraSessionClient, EntraSessionError, normalizeEntraUpn } from '../engines/entra-sessions.js';
import { getEffectivePlan } from '../engines/entitlements.js';
import { getWorkspaceBillingUserId } from '../engines/plan-usage.js';
import { planAllowsHostedPolicyManagement } from '../engines/hosted-dmarc.js';
import { createAuditEvent } from '../lib/events.js';

const SCOPE = 'Customer-supplied accounts and explicitly requested Microsoft observations. No employee breach feed or automatic account intervention.';
const GUARD = `EXISTS(SELECT 1 FROM workspaces WHERE id=? AND deleted_at IS NULL) AND
 (EXISTS(SELECT 1 FROM workspace_members WHERE workspace_id=? AND user_id=? AND role IN ('owner','admin')) OR
 EXISTS(SELECT 1 FROM workspaces w WHERE w.id=? AND w.owner_user_id=? AND NOT EXISTS(SELECT 1 FROM workspace_members m WHERE m.workspace_id=w.id)))`;
const ACCOUNT_AVAILABLE = `NOT EXISTS(SELECT 1 FROM identity_response_actions
 WHERE workspace_id=? AND account_id=? AND status IN ('applying','uncertain'))`;
const bad = (code = 'invalid_input') => { throw new EntraSessionError(code); };
const text = (value, max) => typeof value === 'string' && value.trim().length <= max && !/[\x00-\x1f\x7f]/.test(value) ? value.trim() : bad();
const keys = (body, allowed) => { if (!body || Array.isArray(body) || Object.keys(body).some(k => !allowed.includes(k))) bad(); };
const bindingMatches = (account, data) => account.upn === data.upn && (!account.provider_user_id ||
  (account.provider_user_id === data.id && account.tenant_id === data.tenantId && account.client_id === data.clientId));
const accountView = row => ({ id: row.id, upn: row.upn, display_name: row.display_name, vip: row.vip === 1,
  source: row.source, tenant_id: row.tenant_id, client_id: row.client_id, provider_user_id: row.provider_user_id,
  observation: row.observation_json ? JSON.parse(row.observation_json) : null, updated_at: row.updated_at });
const actionView = row => ({ id: row.id, account_id: row.account_id, concern: row.concern, concern_source: 'customer_reported',
  status: row.status, requested_by: row.requested_by, preview: JSON.parse(row.preview_json),
  outcome: row.outcome_json ? JSON.parse(row.outcome_json) : null,
  verification: row.verification_json ? JSON.parse(row.verification_json) : null,
  created_at: row.created_at, expires_at: row.expires_at, updated_at: row.updated_at });

export async function identityWorkforceRoutes(rctx) {
  const { request, env, url, json, requireAuth, requireWorkspaceRole, consumeApiRateLimit } = rctx;
  const roster = url.pathname.match(/^\/api\/workspaces\/([^\/]+)\/identity-workforce$/);
  const member = url.pathname.match(/^\/api\/workspaces\/([^\/]+)\/identity-workforce\/([^\/]+)$/);
  const preview = url.pathname.match(/^\/api\/workspaces\/([^\/]+)\/identity-response\/preview$/);
  const action = url.pathname.match(/^\/api\/workspaces\/([^\/]+)\/identity-response\/([^\/]+)\/(apply|verify)$/);
  if (!roster && !member && !preview && !action) return null;
  const workspaceId = (roster || member || preview || action)[1], db = env.cybermeters_db;
  let claimedId = null, claimedActor = null;
  try {
    const user = await requireAuth(request, env);
    if (!user) return json({ error: 'Unauthorized' }, 401);
    const access = await requireWorkspaceRole(user, workspaceId, 'workspace:manage', env);
    if (user.api_token_id || !access || !['owner', 'admin'].includes(access.role)) return json({ error: 'An owner or admin session is required.' }, 403);
    const guardArgs = [workspaceId, workspaceId, user.id, workspaceId, user.id];
    const active = () => db.prepare(`SELECT 1 AS ok WHERE ${GUARD}`).bind(...guardArgs).first();
    if (!await active()) return json({ error: 'Workspace unavailable' }, 403);
    const authorize = async () => {
      const current = await requireAuth(request, env);
      if (!current || current.id !== user.id || current.api_token_id) return false;
      const role = await requireWorkspaceRole(current, workspaceId, 'workspace:manage', env);
      return !!role && ['owner', 'admin'].includes(role.role) && !!await active();
    };
    const account = id => db.prepare('SELECT * FROM identity_workforce_accounts WHERE workspace_id=? AND id=?').bind(workspaceId, id).first();
    const getAction = id => db.prepare('SELECT * FROM identity_response_actions WHERE workspace_id=? AND id=?').bind(workspaceId, id).first();
    const accountAvailable = id => db.prepare(`SELECT 1 AS ok WHERE ${ACCOUNT_AVAILABLE}`).bind(workspaceId, id).first();
    // Minimal audit index; the action row remains the authoritative outcome.
    // Never copy credentials, UPNs, concern text or provider bodies to metadata.
    const audit = (event_type, entity_type, entity_id) => createAuditEvent(env, {
      workspace_id: workspaceId, user_id: user.id, event_type, entity_type, entity_id,
      active_workspace_required: true,
    });
    if (roster && request.method === 'GET') {
      const accounts = await db.prepare('SELECT * FROM identity_workforce_accounts WHERE workspace_id=? ORDER BY vip DESC,upn LIMIT 200').bind(workspaceId).all();
      const actions = await db.prepare('SELECT * FROM identity_response_actions WHERE workspace_id=? ORDER BY created_at DESC,id DESC LIMIT 50').bind(workspaceId).all();
      return json({ accounts: (accounts.results || []).map(accountView), actions: (actions.results || []).map(actionView), scope_note: SCOPE });
    }
    if (!['POST', 'PATCH'].includes(request.method)) return json({ error: 'Method not allowed' }, 405);
    if (!/^application\/json(?:;|$)/i.test(request.headers.get('content-type') || '')) bad();
    let body; try { body = await boundedDnsJson(request, 8192); } catch { bad(); }
    const billingOwner = await getWorkspaceBillingUserId(workspaceId, user.id, env);
    const eligible = async () => planAllowsHostedPolicyManagement(await getEffectivePlan(billingOwner, env));
    // Reading an existing action's verification remains possible after a trial ends.
    if (!(action?.[3] === 'verify' && request.method === 'POST') && !await eligible()) return json({ error: 'An active paid plan or trial is required.' }, 403);
    const limited = await consumeApiRateLimit(env, [{ scope: 'workspace', scope_id: workspaceId }, { scope: 'account', scope_id: billingOwner }], 'identity_workforce_action', 60, 3600, { atomic: true, failClosed: true });
    if (limited) return json(limited.body, limited.status);
    const at = new Date().toISOString();
    const credentials = () => {
      keys(body.credentials, ['tenantId', 'clientId', 'clientSecret']);
      return createEntraSessionClient(body.credentials);
    };
    const boundClient = record => {
      if (!record?.provider_user_id) bad('entra_observation_required');
      const client = credentials();
      if (body.credentials.tenantId.toLowerCase() !== record.tenant_id || body.credentials.clientId.toLowerCase() !== record.client_id) bad('target_changed');
      return client;
    };
    if (roster && request.method === 'POST') {
      keys(body, ['upn', 'display_name', 'vip']);
      const upn = normalizeEntraUpn(body.upn), name = text(body.display_name ?? '', 256);
      if (body.vip !== undefined && typeof body.vip !== 'boolean') bad();
      const domain = await db.prepare("SELECT d.id FROM domains d JOIN workspace_domains wd ON wd.domain_id=d.id WHERE wd.workspace_id=? AND LOWER(d.domain)=? AND wd.verification_status='verified' AND wd.verified_at IS NOT NULL").bind(workspaceId, upn.split('@')[1]).first();
      if (!domain) return json({ error: 'Verify the email domain first, or add the exact account using Microsoft Entra.' }, 403);
      const id = 'iwa-' + crypto.randomUUID();
      const saved = await db.prepare(`INSERT INTO identity_workforce_accounts(id,workspace_id,upn,display_name,vip,source,domain_id,created_by,created_at,updated_at)
        SELECT ?,?,?,?,?, 'customer',?,?,?,? WHERE ${GUARD}
        AND (SELECT COUNT(*) FROM identity_workforce_accounts WHERE workspace_id=?)<200
        AND EXISTS(SELECT 1 FROM workspace_domains WHERE workspace_id=? AND domain_id=? AND verification_status='verified' AND verified_at IS NOT NULL)
        ON CONFLICT(workspace_id,upn) DO NOTHING`).bind(id, workspaceId, upn, name, body.vip ? 1 : 0, domain.id, user.id, at, at, ...guardArgs, workspaceId, workspaceId, domain.id).run();
      if (saved.meta?.changes !== 1) return json({ error: 'Account already exists, inventory is full, or authorization changed.' }, 409);
      await audit('identity_account_added', 'identity_account', id);
      return json({ account: accountView(await account(id)) }, 201);
    }
    if (member && request.method === 'PATCH') {
      keys(body, ['vip', 'display_name']);
      const record = await account(member[2]);
      if (!record) return json({ error: 'Account not found' }, 404);
      if (body.vip !== undefined && typeof body.vip !== 'boolean') bad();
      const name = text(body.display_name ?? record.display_name, 256);
      const saved = await db.prepare(`UPDATE identity_workforce_accounts SET vip=?,display_name=?,updated_at=? WHERE workspace_id=? AND id=? AND ${GUARD}`)
        .bind(body.vip === undefined ? record.vip : body.vip ? 1 : 0, name, at, workspaceId, record.id, ...guardArgs).run();
      if (saved.meta?.changes !== 1) bad('authorization_changed');
      await audit('identity_account_updated', 'identity_account', record.id);
      return json({ account: accountView(await account(record.id)) });
    }
    if (member && request.method === 'POST' && member[2] === 'observe') {
      keys(body, ['upn', 'credentials']);
      const upn = normalizeEntraUpn(body.upn), client = credentials();
      const existing = await db.prepare('SELECT * FROM identity_workforce_accounts WHERE workspace_id=? AND upn=?').bind(workspaceId, upn).first();
      if (existing?.provider_user_id) boundClient(existing);
      const observation = await client.observe(upn);
      if (existing && !bindingMatches(existing, observation)) bad('target_changed');
      if (!await authorize()) bad('authorization_changed');
      const id = existing?.id || 'iwa-' + crypto.randomUUID();
      const saved = existing
        ? await db.prepare(`UPDATE identity_workforce_accounts SET source='entra',tenant_id=?,client_id=?,provider_user_id=?,observation_json=?,updated_at=?
            WHERE id=? AND workspace_id=? AND upn=? AND ${GUARD}
            AND (provider_user_id IS NULL OR (provider_user_id=? AND tenant_id=? AND client_id=?))`)
          .bind(observation.tenantId, observation.clientId, observation.id, JSON.stringify(observation), at, id, workspaceId, upn, ...guardArgs, observation.id, observation.tenantId, observation.clientId).run()
        : await db.prepare(`INSERT INTO identity_workforce_accounts(id,workspace_id,upn,display_name,vip,source,tenant_id,client_id,provider_user_id,observation_json,created_by,created_at,updated_at)
            SELECT ?,?,?,?,0,'entra',?,?,?,?,?,?,? WHERE ${GUARD} AND (SELECT COUNT(*) FROM identity_workforce_accounts WHERE workspace_id=?)<200
            ON CONFLICT(workspace_id,upn) DO NOTHING`)
          .bind(id, workspaceId, upn, observation.displayName, observation.tenantId, observation.clientId, observation.id, JSON.stringify(observation), user.id, at, at, ...guardArgs, workspaceId).run();
      if (saved.meta?.changes !== 1) return json({ error: 'Account changed or could not be saved. Refresh and check again.' }, 409);
      await audit('identity_account_observed', 'identity_account', id);
      return json({ account: accountView(await account(id)) }, existing ? 200 : 201);
    }
    if (preview && request.method === 'POST') {
      keys(body, ['account_id', 'concern', 'credentials']);
      const record = await account(text(body.account_id, 100));
      if (!record) return json({ error: 'Account not found' }, 404);
      if (!await accountAvailable(record.id)) bad('account_response_unresolved');
      const concern = text(body.concern, 500); if (!concern) bad();
      const client = boundClient(record), target = await client.preview(record.upn);
      if (!bindingMatches(record, target)) bad('target_changed');
      if (!await authorize()) bad('authorization_changed');
      const id = 'ira-' + crypto.randomUUID();
      const saved = await db.prepare(`INSERT INTO identity_response_actions(id,workspace_id,account_id,requested_by,concern,preview_json,status,created_at,expires_at,updated_at)
        SELECT ?,?,?,?,?,?,'previewed',?,?,? WHERE ${GUARD}
        AND EXISTS(SELECT 1 FROM identity_workforce_accounts WHERE id=? AND workspace_id=? AND upn=? AND provider_user_id=? AND tenant_id=? AND client_id=?)
        AND ${ACCOUNT_AVAILABLE}`)
        .bind(id, workspaceId, record.id, user.id, concern, JSON.stringify(target), at, target.expiresAt, at, ...guardArgs, record.id, workspaceId, target.upn, target.id, target.tenantId, target.clientId, workspaceId, record.id).run();
      if (saved.meta?.changes !== 1) bad(!await accountAvailable(record.id) ? 'account_response_unresolved' : 'authorization_changed');
      await audit('identity_response_previewed', 'identity_response', id);
      return json({ action: actionView(await getAction(id)) }, 201);
    }
    if (action && request.method === 'POST') {
      keys(body, action[3] === 'apply' ? ['credentials', 'confirmed_upn'] : ['credentials']);
      const record = await getAction(action[2]);
      if (!record) return json({ error: 'Action not found' }, 404);
      const person = await account(record.account_id), client = boundClient(person);
      const original = JSON.parse(record.preview_json);
      if (!bindingMatches(person, original)) bad('target_changed');
      if (action[3] === 'verify') {
        if (!['provider_accepted', 'uncertain', 'applying'].includes(record.status)) return json({ error: 'This action has no provider request to verify.' }, 409);
        const current = await client.read(original.upn, original.id);
        if (!await authorize()) bad('authorization_changed');
        const baseline = Date.parse(original.sessionsValidFrom), observed = Date.parse(current.sessionsValidFrom);
        const verification = { checkedAt: new Date().toISOString(), sessionsValidFrom: current.sessionsValidFrom,
          state: Number.isFinite(observed) && (!Number.isFinite(baseline) || observed > baseline) ? 'provider_timestamp_advanced' : 'no_timestamp_advance_observed',
          logoutVerified: false, note: 'Microsoft session timestamp only. This does not prove logout from every app, or that this action caused the change.' };
        const saved = await db.prepare(`UPDATE identity_response_actions SET verification_json=?,updated_at=? WHERE id=? AND workspace_id=? AND ${GUARD}`)
          .bind(JSON.stringify(verification), verification.checkedAt, record.id, workspaceId, ...guardArgs).run();
        if (saved.meta?.changes !== 1) bad('authorization_changed');
        await audit('identity_response_checked', 'identity_response', record.id);
        return json({ action: actionView(await getAction(record.id)) });
      }
      if (record.requested_by !== user.id || record.status !== 'previewed' || Date.now() >= Date.parse(record.expires_at)) return json({ error: 'Preview expired or already used. An uncertain attempt must be investigated before any new request.' }, 409);
      if (normalizeEntraUpn(body.confirmed_upn) !== original.upn) bad('confirmation_required');
      // Claim both this action and the account atomically. A different preview
      // cannot bypass an in-flight request or an unresolved provider outcome.
      const claimed = await db.prepare(`UPDATE identity_response_actions SET status='applying',updated_at=? WHERE id=? AND workspace_id=? AND requested_by=? AND status='previewed' AND expires_at>? AND ${GUARD} AND ${ACCOUNT_AVAILABLE}`)
        .bind(at, record.id, workspaceId, user.id, at, ...guardArgs, workspaceId, person.id).run();
      if (claimed.meta?.changes !== 1) {
        if (!await accountAvailable(person.id)) bad('account_response_unresolved');
        return json({ error: 'Action already used or authorization changed.' }, 409);
      }
      claimedId = record.id;
      claimedActor = user.id;
      await audit('identity_response_requested', 'identity_response', record.id);
      const fresh = await client.preview(original.upn);
      if (fresh.id !== original.id || fresh.sessionsValidFrom !== original.sessionsValidFrom || !bindingMatches(person, fresh)) bad('target_changed');
      const outcome = await client.revoke(fresh, { confirmedUpn: original.upn, authorize: async () => {
        if (!await authorize() || !await eligible() || Date.now() >= Date.parse(record.expires_at)) return false;
        const latest = await account(person.id), state = await getAction(record.id);
        return !!latest && bindingMatches(latest, original) && state?.status === 'applying';
      } });
      // Record provider acceptance even if membership was revoked during the
      // outbound request; the actor/target are already frozen in this action.
      const saved = await db.prepare("UPDATE identity_response_actions SET status='provider_accepted',outcome_json=?,updated_at=? WHERE id=? AND workspace_id=? AND status='applying'")
        .bind(JSON.stringify(outcome), new Date().toISOString(), record.id, workspaceId).run();
      if (saved.meta?.changes !== 1) throw new EntraSessionError('outcome_not_saved', true);
      await audit('identity_response_provider_accepted', 'identity_response', record.id);
      claimedId = null;
      if (!await authorize()) return json({ error: 'Authorization changed. Check the action with a workspace administrator.' }, 403);
      return json({ action: actionView(await getAction(record.id)) });
    }
    return json({ error: 'Method not allowed' }, 405);
  } catch (error) {
    // Unknown storage/transport failures after claiming cannot be called clean
    // failures: Microsoft may already have applied the operation.
    const code = error instanceof EntraSessionError ? error.code : 'operation_unavailable';
    const uncertain = claimedId && (!(error instanceof EntraSessionError) || error.uncertain);
    if (claimedId) {
      try { await db.prepare("UPDATE identity_response_actions SET status=?,outcome_json=?,updated_at=? WHERE id=? AND workspace_id=? AND status='applying'")
        .bind(uncertain ? 'uncertain' : 'not_completed', JSON.stringify({ code, logoutVerified: false }), new Date().toISOString(), claimedId, workspaceId).run(); } catch { /* applying remains visibly unresolved, never auto-retried */ }
      await createAuditEvent(env, { workspace_id: workspaceId, user_id: claimedActor,
        event_type: uncertain ? 'identity_response_uncertain' : 'identity_response_not_completed',
        entity_type: 'identity_response', entity_id: claimedId, active_workspace_required: true });
    }
    const message = code === 'account_response_unresolved'
      ? 'This account already has an in-progress or uncertain session request. Check that action before any new request.'
      : code === 'entra_observation_required' ? 'Observe this account in Microsoft Entra before preparing a session request.'
      : uncertain ? 'The provider outcome is uncertain. Check this action before trying again.' : 'The identity operation could not be completed.';
    return json({ error: message, code, logout_verified: false }, code === 'invalid_input' || code === 'confirmation_required' ? 400 : code === 'authorization_changed' ? 403 : ['target_changed', 'account_response_unresolved', 'entra_observation_required'].includes(code) ? 409 : 503);
  }
}
