import { boundedJson, BREACH_CONSENT_VERSION, BREACH_SCOPE_NOTE, normalizeBreachInput, subjectHashes, breachItem, breachExpiresAt, breachFailure } from '../engines/identity-breach-checks.js';
import { getWorkspaceRetentionSettings } from '../engines/plan-usage.js';

export async function identityBreachCheckRoutes(rctx) {
  const { request, env, url, json, requireAuth, requireWorkspaceRole, consumeApiRateLimit } = rctx;
  const match = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/identity-breach-checks(?:\/([^/]+))?$/);
  if (!match) return null;
  const [, wsId, id] = match;
  const user = await requireAuth(request, env);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  const access = await requireWorkspaceRole(user, wsId, 'workspace:read', env);
  if (!access) return json({ error: 'Forbidden' }, 403);
  const db = env.cybermeters_db;
  const workspace = await db.prepare('SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL').bind(wsId).first();
  if (!workspace) return json({ error: 'Workspace not found' }, 404);
  const canCheck = !user.api_token_id && ['owner','admin'].includes(access.role);
  const metadata = { can_check: canCheck, consent_version: BREACH_CONSENT_VERSION, scope_note: BREACH_SCOPE_NOTE };
  if (request.method === 'GET' && !id) {
    if (!canCheck) return json({ ...metadata, domains: [], items: [] });
    const domains = await db.prepare("SELECT d.id, d.domain FROM workspace_domains wd JOIN domains d ON d.id = wd.domain_id WHERE wd.workspace_id = ? AND wd.verification_status = 'verified' AND wd.verified_at IS NOT NULL ORDER BY d.domain LIMIT 500").bind(wsId).all();
    const rows = await db.prepare('SELECT * FROM identity_breach_checks WHERE workspace_id = ? ORDER BY checked_at DESC, id DESC LIMIT 100').bind(wsId).all();
    const retention = await getWorkspaceRetentionSettings(wsId, env);
    return json({ ...metadata, domains: domains.results || [], items: (rows.results || []).map(row => breachItem(row, retention)) });
  }
  if (!canCheck) return json({ error: 'A workspace owner or admin session is required' }, 403);
  if (request.method === 'DELETE' && id) {
    const result = await db.prepare('DELETE FROM identity_breach_checks WHERE workspace_id = ? AND id = ?').bind(wsId, id).run();
    return result.meta?.changes === 1 ? json({ ok: true }) : json({ error: 'Check not found' }, 404);
  }
  if (request.method !== 'POST' || id) return json({ error: 'Not found' }, 404);
  let body;
  try { body = await boundedJson(request, 2048); } catch { return json({ error: 'Invalid or oversized request' }, 400); }
  if (!body || typeof body.domain_id !== 'string' || !/^[a-zA-Z0-9_-]{1,128}$/.test(body.domain_id)) return json({ error: 'Invalid domain' }, 400);
  const domain = await db.prepare("SELECT d.id, d.domain FROM workspace_domains wd JOIN domains d ON d.id = wd.domain_id WHERE wd.workspace_id = ? AND wd.domain_id = ? AND wd.verification_status = 'verified' AND wd.verified_at IS NOT NULL").bind(wsId, body.domain_id).first();
  if (!domain) return json({ error: 'Verified workspace domain required' }, 403);
  let email;
  try { email = normalizeBreachInput(body, domain.domain); } catch { return json({ error: 'Enter one address from the selected domain and accept the current consent' }, 400); }
  const { providerHash, subjectHash } = await subjectHashes(wsId, email);
  const maskedAddress = `${email[0]}•••@${domain.domain}`;
  email = null; body.email = null;
  const existing = await db.prepare('SELECT * FROM identity_breach_checks WHERE workspace_id = ? AND request_id = ?').bind(wsId, body.request_id).first();
  const retention = await getWorkspaceRetentionSettings(wsId, env);
  if (existing) return existing.subject_hash === subjectHash && existing.domain_id === domain.id
    ? json({ item: breachItem(existing, retention) }) : json({ error: 'Request already used for another address' }, 409);
  // Scope abuse/storage independently of the provider's global one-at-a-time gate.
  const limited = await consumeApiRateLimit(env, [{ scope: 'workspace', scope_id: wsId }], 'identity_breach_check', 10, 60, { atomic: true, failClosed: true });
  if (limited) return json(limited.body, limited.status);
  const checkId = `ibc_${crypto.randomUUID()}`, now = new Date().toISOString();
  const expires = await breachExpiresAt(env, wsId, now);
  const inserted = await db.prepare(`INSERT INTO identity_breach_checks
    (id,workspace_id,domain_id,requested_by,request_id,subject_hash,masked_address,consent_version,consented_at,checked_at,expires_at)
    SELECT ?,?,?,?,?,?,?,?,?,?,? FROM workspaces w JOIN workspace_domains wd ON wd.workspace_id=w.id
    WHERE w.id=? AND w.deleted_at IS NULL AND wd.domain_id=? AND wd.verification_status='verified' AND wd.verified_at IS NOT NULL
      AND (EXISTS(SELECT 1 FROM workspace_members WHERE workspace_id=w.id AND user_id=? AND role IN ('owner','admin'))
        OR (w.owner_user_id=? AND NOT EXISTS(SELECT 1 FROM workspace_members WHERE workspace_id=w.id)))
    ON CONFLICT(workspace_id,request_id) DO NOTHING`).bind(checkId,wsId,domain.id,user.id,body.request_id,subjectHash,maskedAddress,BREACH_CONSENT_VERSION,now,now,expires,wsId,domain.id,user.id,user.id).run();
  if (inserted.meta?.changes !== 1) {
    const row = await db.prepare('SELECT * FROM identity_breach_checks WHERE workspace_id=? AND request_id=?').bind(wsId,body.request_id).first();
    return row && row.subject_hash === subjectHash && row.domain_id === domain.id ? json({ item: breachItem(row, retention) }) : json({ error: 'Check could not be started' }, 409);
  }
  let result;
  try { result = await env.LEAKCHECK_PUBLIC.getByName('public-api-global').lookup(providerHash); }
  catch { result = breachFailure('provider_unavailable'); }
  // A concurrent purge/delete/revocation never recreates data or reveals results.
  const currentAccess = await requireWorkspaceRole(user, wsId, 'workspace:manage', env);
  if (!currentAccess || !['owner','admin'].includes(currentAccess.role)) return json({ error: 'Forbidden' }, 403);
  const finished = await db.prepare(`UPDATE identity_breach_checks SET status=?,reason=?,found_count=?,fields_json=?,sources_json=?
    WHERE id=? AND workspace_id=? AND status='pending'
      AND EXISTS(SELECT 1 FROM workspaces WHERE id=? AND deleted_at IS NULL)
      AND EXISTS(SELECT 1 FROM workspace_domains WHERE workspace_id=? AND domain_id=? AND verification_status='verified' AND verified_at IS NOT NULL)`)
    .bind(result.status,result.reason,result.found_count,JSON.stringify(result.fields),JSON.stringify(result.sources),checkId,wsId,wsId,wsId,domain.id).run();
  if (finished.meta?.changes !== 1) return json({ error: 'Check no longer available' }, 409);
  return json({ item: breachItem(await db.prepare('SELECT * FROM identity_breach_checks WHERE id=? AND workspace_id=?').bind(checkId,wsId).first(), await getWorkspaceRetentionSettings(wsId, env)) }, 201);
}
