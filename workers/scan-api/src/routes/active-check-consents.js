import { createId } from '../lib/util.js';
import { normalizeNetworkTarget, normalizeNetworkPorts } from '../engines/network-targets.js';
import { observedNetworkAddresses, evaluateTargetScope } from '../engines/network-ownership.js';
import {
  ACTIVE_CHECK_AUTHORITY_TEXT, ACTIVE_CHECK_AUTHORITY_VERSION, ACTIVE_CHECK_CATALOGUE, ACTIVE_CHECK_LIMITS,
  consentScope, hostIsUnderDomain, normaliseHost,
} from '../engines/active-check-consent.js';

// Active Checks consent (migration 135). Every query names workspace_id; a grant
// of another workspace, or one that does not exist, is the same 404. Writes need
// the admin role; revoking appends a row and never edits the grant.
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;
const CONSENT_ID = /^acc_[a-zA-Z0-9_-]{1,100}$/;

async function bodyJson(request) {
  const text = await request.text();
  if (text.length > 4096) throw new Error('request_body_too_large');
  try {
    const body = JSON.parse(text);
    if (!body || Array.isArray(body) || typeof body !== 'object') throw 0;
    return body;
  } catch { throw new Error('invalid_json_body'); }
}

// Customer projection: the engine's scope object keeps signer.user_id as
// evidence; no raw internal user id ever leaves through this API.
export const activeCheckConsentProjection = (grant, revocation) => {
  const scope = consentScope(grant);
  const { user_id: _userId, ...signer } = scope.signer;
  return {
    id: grant.id,
    ...scope,
    signer,
    status: revocation ? 'revoked' : 'active',
    revoked_at: revocation?.created_at || null,
  };
};

const cleanText = (v, max) => typeof v === 'string' && v.trim().length > 0 && v.trim().length <= max ? v.trim() : null;
const dayAgo = (now) => new Date(Date.parse(now) - 24 * 3600_000).toISOString();

// A customer-declared range (scope_kind 'network_range'): exact addresses and
// ports, socket checks only, never shared provider infrastructure. The wording
// stays "authorisation declared by the customer; not independently verified".
async function grantNetworkRange(body, { db, env, json, workspaceId, actor, now }) {
  const keys = ['scope_kind', 'target', 'ports', 'checks', 'signer_name', 'signer_title', 'authority_confirmed', 'authority_version'];
  if (Object.keys(body).some((k) => !keys.includes(k))) return json({ error: 'unsupported_consent_field' }, 400);
  if (body.authority_confirmed !== true || body.authority_version !== ACTIVE_CHECK_AUTHORITY_VERSION) {
    return json({ error: 'active_check_authority_required' }, 400);
  }
  const signerName = cleanText(body.signer_name, ACTIVE_CHECK_LIMITS.name);
  const signerTitle = cleanText(body.signer_title, ACTIVE_CHECK_LIMITS.title);
  if (!signerName || !signerTitle) return json({ error: 'signer_name_and_title_required' }, 400);
  const checks = Array.isArray(body.checks) ? [...new Set(body.checks)] : [];
  if (!checks.length || checks.some((c) => typeof c !== 'string' || !Object.prototype.hasOwnProperty.call(ACTIVE_CHECK_CATALOGUE, c)
    || !ACTIVE_CHECK_CATALOGUE[c].per_address)) return json({ error: 'invalid_active_checks' }, 400);
  let range, ports;
  try {
    range = await normalizeNetworkTarget(body.target);
    ports = normalizeNetworkPorts(body.ports, range.address_count);
  } catch { return json({ error: 'invalid_network_range' }, 400); }
  if (range.address_count > ACTIVE_CHECK_LIMITS.addresses || ports.length > ACTIVE_CHECK_LIMITS.ports) return json({ error: 'invalid_network_range' }, 400);
  // A provider's shared edge is never the customer's to authorise.
  const seen = evaluateTargetScope(range.addresses, await observedNetworkAddresses(env, workspaceId));
  if (seen.shared.length) return json({ error: 'address_is_shared_provider_infrastructure', shared: seen.shared.slice(0, 32) }, 422);
  const existing = await db.prepare('SELECT id FROM network_targets WHERE workspace_id = ? AND target = ? LIMIT 1').bind(workspaceId, range.target).first();
  const id = createId('acc');
  await db.batch([
    db.prepare(`INSERT INTO active_check_consents
        (id, workspace_id, kind, scope_kind, network_target, network_target_id, addresses_json, ports_json, checks_json,
         actor_user_id, actor_email, actor_workspace_role, signer_name, signer_title, ip_address, user_agent,
         authority_text, authority_version, created_at)
      SELECT ?, ?, 'grant', 'network_range', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
       WHERE EXISTS (SELECT 1 FROM workspaces WHERE id = ? AND deleted_at IS NULL)
         AND (SELECT COUNT(*) FROM active_check_consents
               WHERE workspace_id = ? AND kind = 'grant' AND created_at > ?) < ?`)
      .bind(id, workspaceId, range.target, existing?.id || null, JSON.stringify(range.addresses), JSON.stringify(ports), JSON.stringify(checks),
        actor.user_id, actor.email, actor.role, signerName, signerTitle, actor.ip, actor.ua,
        ACTIVE_CHECK_AUTHORITY_TEXT, ACTIVE_CHECK_AUTHORITY_VERSION, now, workspaceId,
        workspaceId, dayAgo(now), ACTIVE_CHECK_LIMITS.grants_per_day),
    db.prepare(`INSERT INTO audit_events (id, workspace_id, user_id, actor_type, event_type, entity_type, entity_id, description, metadata_json, created_at)
      SELECT ?, ?, ?, 'customer', 'active_check_consent_granted', 'active_check_consent', ?, 'Active check permission granted', ?, ?
       WHERE changes() = 1`)
      .bind(createId('audit'), workspaceId, actor.user_id, id,
        JSON.stringify({ scope_kind: 'network_range', target: range.target, ports, checks, independently_verified: false,
          authority_version: ACTIVE_CHECK_AUTHORITY_VERSION }), now),
  ]);
  const row = await db.prepare('SELECT * FROM active_check_consents WHERE id = ? AND workspace_id = ?').bind(id, workspaceId).first();
  if (!row) {
    const live = await db.prepare('SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL').bind(workspaceId).first();
    return live ? json({ error: 'active_check_consent_limit' }, 429) : json({ error: 'Workspace not found' }, 404);
  }
  return json({ consent: activeCheckConsentProjection(row, null) }, 201);
}

export async function activeCheckConsentRoutes(rctx) {
  const { request, env, url, json, requireAuth, requireWorkspaceRole, serverError } = rctx;
  const match = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/active-check-consents(?:\/([^/]+)\/(revoke))?$/);
  if (!match) return null;
  const [, workspaceId, consentId, action] = match;
  const user = await requireAuth(request, env);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  const readRole = await requireWorkspaceRole(user, workspaceId, 'workspace:read', env);
  if (!readRole) return json({ error: 'Forbidden' }, 403);
  const db = env.cybermeters_db;
  try {
    if (!await db.prepare('SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL').bind(workspaceId).first()) {
      return json({ error: 'Workspace not found' }, 404);
    }
    const canManage = !!await requireWorkspaceRole(user, workspaceId, 'workspace:manage', env);

    if (request.method === 'GET' && !consentId) {
      const rows = (await db.prepare(
        'SELECT * FROM active_check_consents WHERE workspace_id = ? ORDER BY created_at DESC, id DESC LIMIT 200',
      ).bind(workspaceId).all()).results || [];
      const revocations = new Map(rows.filter((r) => r.kind === 'revocation').map((r) => [r.grant_id, r]));
      return json({
        consents: rows.filter((r) => r.kind === 'grant').map((g) => activeCheckConsentProjection(g, revocations.get(g.id))),
        catalogue: Object.entries(ACTIVE_CHECK_CATALOGUE).map(([id, c]) => ({ id, label: c.label })),
        authority: { version: ACTIVE_CHECK_AUTHORITY_VERSION, text: ACTIVE_CHECK_AUTHORITY_TEXT },
        capabilities: { can_manage: canManage },
      });
    }
    if (request.method !== 'POST' || (consentId && action !== 'revoke')) return json({ error: 'Not found' }, 404);
    if (!canManage) return json({ error: 'Forbidden — admin role required' }, 403);

    const member = await db.prepare('SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ? LIMIT 1')
      .bind(workspaceId, user.id).first();
    const actor = {
      user_id: user.id, email: user.email || null, role: member?.role || 'admin',
      ip: request.headers.get('CF-Connecting-IP') || null,
      ua: (request.headers.get('User-Agent') || '').slice(0, 300) || null,
    };
    const now = new Date().toISOString();

    if (consentId) {
      if (!CONSENT_ID.test(consentId)) return json({ error: 'Consent not found' }, 404);
      const grant = await db.prepare(
        "SELECT * FROM active_check_consents WHERE id = ? AND workspace_id = ? AND kind = 'grant' LIMIT 1",
      ).bind(consentId, workspaceId).first();
      if (!grant) return json({ error: 'Consent not found' }, 404);
      const id = createId('acc');
      const [inserted] = await db.batch([
        db.prepare(`INSERT INTO active_check_consents
            (id, workspace_id, kind, grant_id, actor_user_id, actor_email, actor_workspace_role, ip_address, user_agent, created_at)
          SELECT ?, ?, 'revocation', ?, ?, ?, ?, ?, ?, ?
           WHERE NOT EXISTS (SELECT 1 FROM active_check_consents WHERE grant_id = ? AND kind = 'revocation')`)
          .bind(id, workspaceId, grant.id, actor.user_id, actor.email, actor.role, actor.ip, actor.ua, now, grant.id),
        db.prepare(`INSERT INTO audit_events (id, workspace_id, user_id, actor_type, event_type, entity_type, entity_id, description, metadata_json, created_at)
          SELECT ?, ?, ?, 'customer', 'active_check_consent_revoked', 'active_check_consent', ?, 'Active check permission revoked', ?, ?
           WHERE changes() = 1`)
          .bind(createId('audit'), workspaceId, actor.user_id, grant.id, JSON.stringify({ revocation_id: id }), now),
      ]);
      if (inserted?.meta?.changes !== 1) return json({ error: 'consent_already_revoked' }, 409);
      return json({ consent: activeCheckConsentProjection(grant, { created_at: now, actor_user_id: actor.user_id }) });
    }

    const body = await bodyJson(request);
    if (body.scope_kind === 'network_range') return await grantNetworkRange(body, { db, env, json, workspaceId, actor, now });
    if (body.scope_kind != null && body.scope_kind !== 'domain') return json({ error: 'invalid_consent_scope' }, 400);
    delete body.scope_kind;
    const keys = ['domain_id', 'hosts', 'checks', 'signer_name', 'signer_title', 'authority_confirmed', 'authority_version'];
    if (Object.keys(body).some((k) => !keys.includes(k))) return json({ error: 'unsupported_consent_field' }, 400);
    if (body.authority_confirmed !== true || body.authority_version !== ACTIVE_CHECK_AUTHORITY_VERSION) {
      return json({ error: 'active_check_authority_required' }, 400);
    }
    const text = (v, max) => typeof v === 'string' && v.trim().length > 0 && v.trim().length <= max ? v.trim() : null;
    const signerName = text(body.signer_name, ACTIVE_CHECK_LIMITS.name);
    const signerTitle = text(body.signer_title, ACTIVE_CHECK_LIMITS.title);
    if (!signerName || !signerTitle) return json({ error: 'signer_name_and_title_required' }, 400);
    const checks = Array.isArray(body.checks) ? [...new Set(body.checks)] : [];
    if (!checks.length || checks.some((c) => typeof c !== 'string' || !Object.prototype.hasOwnProperty.call(ACTIVE_CHECK_CATALOGUE, c))) {
      return json({ error: 'invalid_active_checks' }, 400);
    }
    if (typeof body.domain_id !== 'string') return json({ error: 'Domain not found' }, 404);
    const domain = await db.prepare(
      `SELECT d.id, lower(d.domain) AS domain FROM workspace_domains wd JOIN domains d ON d.id = wd.domain_id
        WHERE wd.workspace_id = ? AND wd.domain_id = ? AND wd.verification_status = 'verified' LIMIT 1`,
    ).bind(workspaceId, body.domain_id).first();
    if (!domain) return json({ error: 'Domain not found' }, 404);
    const hosts = body.hosts == null ? [] : Array.isArray(body.hosts) ? [...new Set(body.hosts.map(normaliseHost))] : null;
    if (!hosts || hosts.length > ACTIVE_CHECK_LIMITS.hosts
      || hosts.some((h) => !HOSTNAME.test(h) || !hostIsUnderDomain(h, domain.domain))) {
      return json({ error: 'invalid_active_check_hosts' }, 400);
    }

    const id = createId('acc');
    const scopeMeta = JSON.stringify({ domain: domain.domain, hosts, checks, authority_version: ACTIVE_CHECK_AUTHORITY_VERSION });
    await db.batch([
      db.prepare(`INSERT INTO active_check_consents
          (id, workspace_id, kind, domain_id, domain, hosts_json, checks_json, actor_user_id, actor_email, actor_workspace_role,
           signer_name, signer_title, ip_address, user_agent, authority_text, authority_version, created_at)
        SELECT ?, ?, 'grant', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
         WHERE EXISTS (SELECT 1 FROM workspaces WHERE id = ? AND deleted_at IS NULL)
           AND (SELECT COUNT(*) FROM active_check_consents
                 WHERE workspace_id = ? AND kind = 'grant' AND created_at > ?) < ?`)
        .bind(id, workspaceId, domain.id, domain.domain, JSON.stringify(hosts), JSON.stringify(checks),
          actor.user_id, actor.email, actor.role, signerName, signerTitle, actor.ip, actor.ua,
          ACTIVE_CHECK_AUTHORITY_TEXT, ACTIVE_CHECK_AUTHORITY_VERSION, now, workspaceId,
          workspaceId, new Date(Date.parse(now) - 24 * 3600_000).toISOString(), ACTIVE_CHECK_LIMITS.grants_per_day),
      db.prepare(`INSERT INTO audit_events (id, workspace_id, user_id, actor_type, event_type, entity_type, entity_id, description, metadata_json, created_at)
        SELECT ?, ?, ?, 'customer', 'active_check_consent_granted', 'active_check_consent', ?, 'Active check permission granted', ?, ?
         WHERE changes() = 1`)
        .bind(createId('audit'), workspaceId, actor.user_id, id, scopeMeta, now),
    ]);
    const row = await db.prepare('SELECT * FROM active_check_consents WHERE id = ? AND workspace_id = ?').bind(id, workspaceId).first();
    if (!row) {
      const live = await db.prepare('SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL').bind(workspaceId).first();
      return live ? json({ error: 'active_check_consent_limit' }, 429) : json({ error: 'Workspace not found' }, 404);
    }
    return json({ consent: activeCheckConsentProjection(row, null) }, 201);
  } catch (error) {
    if (['invalid_json_body', 'request_body_too_large'].includes(error?.message)) return json({ error: error.message }, 400);
    return serverError(error);
  }
}
