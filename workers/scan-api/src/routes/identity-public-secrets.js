import { boundedDnsJson } from '../engines/cloudflare-dns.js';
import { checkPublicSecretSources, validateSecretCheckUrl, secretSourceUrl, SECRET_CHECK_SCOPE, SECRET_CHECK_TYPES } from '../engines/identity-public-secrets.js';
import { getEffectivePlan } from '../engines/entitlements.js';
import { getWorkspaceBillingUserId } from '../engines/plan-usage.js';
import { planAllowsHostedPolicyManagement } from '../engines/hosted-dmarc.js';

export async function identityPublicSecretsRoutes(rctx) {
  const { request, env, url, json, requireAuth, requireWorkspaceRole, consumeApiRateLimit } = rctx;
  const match = url.pathname.match(/^\/api\/workspaces\/([^\/]+)\/identity-public-sources$/);
  if (!match) return null;
  const workspaceId = match[1], db = env.cybermeters_db;
  try {
    const user = await requireAuth(request, env);
    if (!user) return json({ error: 'Unauthorized' }, 401);
    const access = await requireWorkspaceRole(user, workspaceId, 'workspace:read', env);
    if (!access) return json({ error: 'Forbidden' }, 403);
    const active = () => db.prepare('SELECT id FROM workspaces WHERE id=? AND deleted_at IS NULL').bind(workspaceId).first();
    if (!await active()) return json({ error: 'Workspace not found' }, 404);
    const canManage = !user.api_token_id && ['owner', 'admin'].includes(access.role);
    const domains = () => db.prepare("SELECT d.id,d.domain FROM workspace_domains wd JOIN domains d ON d.id=wd.domain_id WHERE wd.workspace_id=? AND wd.verification_status='verified' AND wd.verified_at IS NOT NULL ORDER BY d.domain LIMIT 500").bind(workspaceId).all();
    if (match && request.method === 'GET') {
      const rows = await db.prepare('SELECT id,domain_id,result_json,created_at FROM identity_public_source_checks WHERE workspace_id=? ORDER BY created_at DESC,id DESC LIMIT 20').bind(workspaceId).all();
      return json({ can_manage: canManage, domains: (await domains()).results || [], scope_note: SECRET_CHECK_SCOPE, supported_types: SECRET_CHECK_TYPES,
        checks: (rows.results || []).map(row => ({ id: row.id, domain_id: row.domain_id, created_at: row.created_at, result: JSON.parse(row.result_json) })) });
    }
    if (match && request.method === 'POST') {
    if (!canManage) return json({ error: 'An owner or admin session is required.' }, 403);
    if (!/^application\/json(?:;|$)/i.test(request.headers.get('content-type') || '')) return json({ error: 'Invalid request' }, 400);
    let body; try { body = await boundedDnsJson(request, 4096); } catch { return json({ error: 'Invalid request' }, 400); }
    if (!body || Object.keys(body).some(key => !['domain_id', 'source_url'].includes(key)) || typeof body.domain_id !== 'string') return json({ error: 'Invalid request' }, 400);
    const owned = (await domains()).results?.find(d => d.id === body.domain_id);
    if (!owned) return json({ error: 'Verify this domain in this workspace first.' }, 403);
    const target = validateSecretCheckUrl(body.source_url, owned.domain);
    if (secretSourceUrl(target) !== target) return json({ error: 'Use a public source URL without credentials in its path.' }, 400);
    const billingOwner = await getWorkspaceBillingUserId(workspaceId, user.id, env);
    if (!planAllowsHostedPolicyManagement(await getEffectivePlan(billingOwner, env))) return json({ error: 'An active paid plan or trial is required.' }, 403);
    const limited = await consumeApiRateLimit(env, [{ scope: 'workspace', scope_id: workspaceId }, { scope: 'account', scope_id: billingOwner }], 'identity_public_source_check', 6, 3600, { atomic: true, failClosed: true });
    if (limited) return json(limited.body, limited.status);
    const result = await checkPublicSecretSources(target, owned.domain, { signal: request.signal });
    // Recheck membership and domain authority after network awaits. No returned
    // evidence or late write for a revoked/deleted workspace.
    const currentUser = await requireAuth(request, env);
    const current = currentUser && currentUser.id === user.id && !currentUser.api_token_id
      ? await requireWorkspaceRole(currentUser, workspaceId, 'workspace:manage', env) : null;
    if (!current || !['owner', 'admin'].includes(current.role) || !await active() || !(await domains()).results?.some(d => d.id === owned.id && d.domain === owned.domain)) return json({ error: 'Authorization changed. No result was saved.' }, 403);
    const id = 'ips-' + crypto.randomUUID(), at = new Date().toISOString();
    const insert = db.prepare("INSERT INTO identity_public_source_checks(id,workspace_id,domain_id,requested_by,result_json,created_at) SELECT ?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM workspaces WHERE id=? AND deleted_at IS NULL) AND EXISTS(SELECT 1 FROM workspace_domains WHERE workspace_id=? AND domain_id=? AND verification_status='verified' AND verified_at IS NOT NULL) AND (EXISTS(SELECT 1 FROM workspace_members WHERE workspace_id=? AND user_id=? AND role IN ('owner','admin')) OR EXISTS(SELECT 1 FROM workspaces w WHERE w.id=? AND w.owner_user_id=? AND NOT EXISTS(SELECT 1 FROM workspace_members m WHERE m.workspace_id=w.id)))")
      .bind(id, workspaceId, owned.id, user.id, JSON.stringify(result), at, workspaceId, workspaceId, owned.id, workspaceId, user.id, workspaceId, user.id);
    const trim = db.prepare('DELETE FROM identity_public_source_checks WHERE workspace_id=? AND domain_id=? AND id NOT IN (SELECT id FROM identity_public_source_checks WHERE workspace_id=? AND domain_id=? ORDER BY created_at DESC,id DESC LIMIT 20)').bind(workspaceId, owned.id, workspaceId, owned.id);
    const stored = await db.batch([insert, trim]);
    if (stored[0]?.meta?.changes !== 1) return json({ error: 'Authorization changed. No result was saved.' }, 403);
    return json({ check: { id, domain_id: owned.id, created_at: at, result } }, 201);
    }
    return json({ error: 'Method not allowed' }, 405);
  } catch (error) {
    if (error?.code === 'invalid_source_url') return json({ error: 'Use an HTTP or HTTPS URL on the verified domain, without a query, fragment or custom port.' }, 400);
    return json({ error: 'The public source check is unavailable. No clean result is claimed.' }, 503);
  }
}
