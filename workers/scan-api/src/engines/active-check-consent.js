// ── Active Checks consent ────────────────────────────────────────────────────
//
// An active check touches a customer system beyond passive observation (a socket
// test, a relay probe, a seeded message). It runs only under a written, scoped,
// revocable authorisation from someone who says they hold that authority.
//
// Records are append-only (migration 135): a grant is one row; revoking it adds
// a revocation row that names the grant. No row is ever updated, and there is
// no delete path in the product (only the workspace purge erases them).
//
// isAuthorised() is the one gate Seat 3's engines call immediately before every
// active check. It fails closed: any read error is `consent_read_failed`, never
// a pass. A grant names its check ids exactly — there is no wildcard, so a check
// added to the catalogue later is never covered by an older grant.
//
// No scheduling: a grant authorises on-demand checks only.
import {
  observedNetworkAddresses,
  evaluateTargetScope,
  NETWORK_SCOPE_REASONS,
} from "./network-ownership.js";

export const ACTIVE_CHECK_AUTHORITY_VERSION = "active-checks-2026-10-22";

// The words the signer agrees to. Stored verbatim on every grant with its version,
// so a later wording change never rewrites what someone actually agreed to.
export const ACTIVE_CHECK_AUTHORITY_TEXT =
  "I confirm that I am authorised by the organisation that owns this domain to " +
  "permit CyberMeters to run the active checks listed here against the listed " +
  "hosts, on demand, until I or another authorised person revokes this permission. " +
  "I understand that these checks connect to these systems and may be recorded in " +
  "their logs.";

// The catalogue (Executive ids, 22 Oct 2026; agreed with Seat 3). `per_address`
// checks open a socket to a customer address, so the caller passes the resolved
// address and the #765 ownership rule applies. The two others have no customer
// address: takeover confirmation targets the provider, and spoof resistance a
// seed mailbox (host = the mailbox's domain).
export const ACTIVE_CHECK_CATALOGUE = Object.freeze({
  tls_intrusive_heartbleed: { per_address: true,  label: "TLS Heartbleed test" },
  tls_intrusive_robot:      { per_address: true,  label: "TLS ROBOT test" },
  tls_intrusive_ccs:        { per_address: true,  label: "TLS CCS injection test" },
  takeover_active_confirm:  { per_address: false, label: "Subdomain takeover confirmation (no claim is made)" },
  dns_open_resolver:        { per_address: true,  label: "Open DNS resolver" },
  mail_open_relay:          { per_address: true,  label: "Open mail relay (no message is delivered)" },
  mail_starttls_strip:      { per_address: true,  label: "Mail accepted without STARTTLS" },
  mail_spoof_resistance:    { per_address: false, label: "Spoofed message to your designated seed mailbox" },
  // Open ports, service banners and protocol facts on a customer-declared range.
  // Nothing exploitative: no exploit, no credential testing, no data extraction.
  network_service_scan:     { per_address: true,  label: "Open ports and service banners on a declared range (no exploit, no credentials)" },
});

// Stable reason codes; the customer wording is the caller's.
export const ACTIVE_CHECK_REASONS = Object.freeze({
  authorised: "authorised",
  no_grant: "no_grant",
  grant_revoked: "grant_revoked",
  domain_not_verified: "domain_not_verified",
  workspace_deleted: "workspace_deleted",
  host_not_in_grant: "host_not_in_grant",
  check_not_in_grant: "check_not_in_grant",
  address_out_of_scope: "address_out_of_scope",
  consent_read_failed: "consent_read_failed",
});

// grants_per_day bounds storage: an admin creating rows in their own workspace is
// not a tenant risk, but it must not be unbounded.
export const ACTIVE_CHECK_LIMITS = Object.freeze({ hosts: 32, name: 120, title: 120, grants_per_day: 100, addresses: 32, ports: 16 });
export const ACTIVE_CHECK_SCOPE_KINDS = Object.freeze(["domain", "network_range"]);

export const normaliseHost = (value) => String(value ?? "").trim().toLowerCase().replace(/\.$/, "");

// A host is covered by a domain when it is the domain or a name under it.
export const hostIsUnderDomain = (host, domain) => host === domain || host.endsWith(`.${domain}`);

const parseList = (text) => {
  try {
    const value = JSON.parse(text || "[]");
    return Array.isArray(value) ? value.filter((v) => typeof v === "string") : [];
  } catch { return []; }
};

// The grant's own scope, carried on every result so a check records exactly what
// was authorised at run time without a later join.
export function consentScope(row) {
  if (row.scope_kind === "network_range") {
    return {
      scope_kind: "network_range",
      network_target: row.network_target,
      addresses: parseList(row.addresses_json),
      ports: parseNumbers(row.ports_json),
      checks: parseList(row.checks_json),
      granted_at: row.created_at,
      signer: { name: row.signer_name, title: row.signer_title, workspace_role: row.actor_workspace_role, user_id: row.actor_user_id },
      authority_version: row.authority_version,
      independently_verified: false,
    };
  }
  return {
    scope_kind: "domain",
    domain: row.domain,
    hosts: parseList(row.hosts_json),
    checks: parseList(row.checks_json),
    granted_at: row.created_at,
    signer: { name: row.signer_name, title: row.signer_title, workspace_role: row.actor_workspace_role, user_id: row.actor_user_id },
    authority_version: row.authority_version,
  };
}

const parseNumbers = (text) => {
  try {
    const value = JSON.parse(text || "[]");
    return Array.isArray(value) ? value.filter((v) => Number.isInteger(v)) : [];
  } catch { return []; }
};

const LIVE_RANGE_GRANTS = `SELECT g.* FROM active_check_consents g
  WHERE g.workspace_id = ? AND g.kind = 'grant' AND g.scope_kind = 'network_range'
    AND NOT EXISTS (SELECT 1 FROM active_check_consents r
                     WHERE r.kind = 'revocation' AND r.grant_id = g.id AND r.workspace_id = g.workspace_id)
  ORDER BY g.created_at DESC, g.id DESC LIMIT 200`;

/**
 * The newest live network_range grant naming `check` that covers EVERY address
 * (and every port, when ports are given). Throws on a read error: callers fail closed.
 */
export async function findDeclaredRangeGrant(env, workspaceId, addresses, { check = "network_service_scan", ports = null } = {}) {
  if (!workspaceId || !Array.isArray(addresses) || !addresses.length) return null;
  const rows = (await env.cybermeters_db.prepare(LIVE_RANGE_GRANTS).bind(workspaceId).all()).results || [];
  return rows.find((g) => {
    const covered = new Set(parseList(g.addresses_json));
    const allowedPorts = new Set(parseNumbers(g.ports_json));
    return (check === null || parseList(g.checks_json).includes(check))
      && addresses.every((a) => covered.has(String(a)))
      && (!ports || ports.every((p) => allowedPorts.has(p)));
  }) || null;
}

/**
 * Widen an out-of-scope network-target decision with the customer's declared
 * authorisation. Never applies to shared provider infrastructure, never narrows.
 * A read error leaves the decision out of scope.
 */
export async function withDeclaredConsent(env, workspaceId, addresses, decision) {
  if (decision?.state === "in_scope" || (decision?.shared || []).length) return decision;
  try {
    const grant = await findDeclaredRangeGrant(env, workspaceId, addresses);
    if (!grant) return decision;
    return { ...decision, state: "in_scope", reason: NETWORK_SCOPE_REASONS.declared, unobserved: [], shared: [],
      consent_id: grant.id, consent_ports: parseNumbers(grant.ports_json) };
  } catch { return decision; }
}

// An empty host list means the apex only.
const grantCoversHost = (row, host) => {
  const hosts = parseList(row.hosts_json);
  return hosts.length === 0 ? host === row.domain : hosts.includes(host);
};

const refuse = (reason, extra = {}) => ({ authorised: false, reason, consent_id: null, scope: null, ...extra });

/**
 * May this active check run now?
 *
 * Called immediately before each check, never cached across a run. `address` is
 * required for per-address checks and is held to the #765 rule: it must be seen
 * in the workspace's verified DNS and must not be shared provider infrastructure.
 */
export async function isAuthorised(env, { workspaceId, domain, host, check, address, port } = {}, deps = {}) {
  try {
    const db = env.cybermeters_db;
    // A declared range: no domain, an address, and a live network_range grant.
    if (!domain && address) return await isAuthorisedForDeclaredRange(env, { workspaceId, check, address, port }, deps);
    const apex = normaliseHost(domain);
    const target = normaliseHost(host || domain);
    if (!workspaceId || !apex || !target) return refuse(ACTIVE_CHECK_REASONS.no_grant);
    const definition = Object.prototype.hasOwnProperty.call(ACTIVE_CHECK_CATALOGUE, check) ? ACTIVE_CHECK_CATALOGUE[check] : null;
    if (!definition) return refuse(ACTIVE_CHECK_REASONS.check_not_in_grant);

    const workspace = await db.prepare("SELECT id, deleted_at FROM workspaces WHERE id = ? LIMIT 1").bind(workspaceId).first();
    if (!workspace || workspace.deleted_at) return refuse(ACTIVE_CHECK_REASONS.workspace_deleted);

    const verified = await db.prepare(
      `SELECT d.id AS domain_id FROM workspace_domains wd JOIN domains d ON d.id = wd.domain_id
        WHERE wd.workspace_id = ? AND lower(d.domain) = ? AND wd.verification_status = 'verified' LIMIT 1`,
    ).bind(workspaceId, apex).first();
    if (!verified) return refuse(ACTIVE_CHECK_REASONS.domain_not_verified);
    if (!hostIsUnderDomain(target, apex)) return refuse(ACTIVE_CHECK_REASONS.host_not_in_grant);

    const grants = (await db.prepare(
      `SELECT g.*, EXISTS (SELECT 1 FROM active_check_consents r
                            WHERE r.kind = 'revocation' AND r.grant_id = g.id AND r.workspace_id = g.workspace_id) AS revoked
         FROM active_check_consents g
        WHERE g.workspace_id = ? AND g.domain_id = ? AND g.kind = 'grant'
        ORDER BY g.created_at DESC, g.id DESC`,
    ).bind(workspaceId, verified.domain_id).all()).results || [];
    // The most specific reason wins: a revoked grant that covered exactly this host
    // and check says "revoked", not "never asked".
    const covers = (g) => grantCoversHost(g, target) && parseList(g.checks_json).includes(check);
    const grant = grants.find((g) => !g.revoked && covers(g));
    if (!grant) {
      if (grants.some((g) => g.revoked && covers(g))) return refuse(ACTIVE_CHECK_REASONS.grant_revoked);
      const live = grants.filter((g) => !g.revoked);
      if (!live.length) return refuse(ACTIVE_CHECK_REASONS.no_grant);
      return refuse(live.some((g) => grantCoversHost(g, target))
        ? ACTIVE_CHECK_REASONS.check_not_in_grant : ACTIVE_CHECK_REASONS.host_not_in_grant);
    }

    if (definition.per_address) {
      if (!address) return refuse(ACTIVE_CHECK_REASONS.address_out_of_scope);
      const observed = await (deps.observedNetworkAddresses || observedNetworkAddresses)(env, workspaceId, deps.ownership || {});
      const scope = evaluateTargetScope([String(address)], observed);
      if (scope.state !== "in_scope") return refuse(ACTIVE_CHECK_REASONS.address_out_of_scope, { address_scope: scope.reason });
    }
    return { authorised: true, reason: ACTIVE_CHECK_REASONS.authorised, consent_id: grant.id, scope: consentScope(grant) };
  } catch (error) {
    console.error("[active-check-consent] read failed", JSON.stringify({ workspace_id: workspaceId, check, reason: error?.message }));
    return refuse(ACTIVE_CHECK_REASONS.consent_read_failed);
  }
}

// The network_range half of isAuthorised: same reasons, same fail-closed rule.
async function isAuthorisedForDeclaredRange(env, { workspaceId, check, address, port }, deps) {
  const definition = Object.prototype.hasOwnProperty.call(ACTIVE_CHECK_CATALOGUE, check) ? ACTIVE_CHECK_CATALOGUE[check] : null;
  if (!workspaceId || !definition || !definition.per_address) return refuse(ACTIVE_CHECK_REASONS.check_not_in_grant);
  const workspace = await env.cybermeters_db.prepare("SELECT id, deleted_at FROM workspaces WHERE id = ? LIMIT 1").bind(workspaceId).first();
  if (!workspace || workspace.deleted_at) return refuse(ACTIVE_CHECK_REASONS.workspace_deleted);
  // Shared provider infrastructure is refused even with a declaration.
  const observed = await (deps.observedNetworkAddresses || observedNetworkAddresses)(env, workspaceId, deps.ownership || {});
  const seen = evaluateTargetScope([String(address)], observed);
  if (seen.shared.length) return refuse(ACTIVE_CHECK_REASONS.address_out_of_scope, { address_scope: seen.reason });
  const ports = Number.isInteger(port) ? [port] : null;
  const grant = await findDeclaredRangeGrant(env, workspaceId, [String(address)], { check, ports });
  if (grant) return { authorised: true, reason: ACTIVE_CHECK_REASONS.authorised, consent_id: grant.id, scope: consentScope(grant) };
  const any = await findDeclaredRangeGrant(env, workspaceId, [String(address)], { check: null });
  return refuse(any ? ACTIVE_CHECK_REASONS.check_not_in_grant : ACTIVE_CHECK_REASONS.no_grant);
}
