// ── Declared network range consent ───────────────────────────────────────────
//
// A network target whose addresses are not observed in the workspace's verified
// DNS (network-ownership.js) is scanned only under a written, scoped, revocable
// authorisation for exactly those addresses and ports (migration 138). The
// "I own this range" checkbox alone never authorises such an address.
//
// Records are append-only: a grant is one row; revoking it adds a revocation row
// that names the grant. No row is ever updated, and there is no delete path in
// the product (only the workspace purge erases them).
//
// What a grant covers is exact: the target's canonical address list at signing
// time and a port list. A target whose addresses change is not covered by an
// older grant, and shared provider infrastructure is never grantable.
//
// Wording stays honest everywhere: the authorisation is declared by the customer
// and is not independently verified by CyberMeters.

export const NETWORK_RANGE_AUTHORITY_VERSION = "network-range-2026-10-22";

// Stored verbatim on every grant with its version, so a later wording change
// never rewrites what someone actually agreed to.
export const NETWORK_RANGE_AUTHORITY_TEXT =
  "I confirm that I am authorised by the organisation that owns or operates these " +
  "addresses to permit CyberMeters to connect to the listed ports on them, on demand, " +
  "until I or another authorised person revokes this permission. I understand that " +
  "CyberMeters records which ports answer and the service and protocol facts they " +
  "present, makes no attempt to log in or exploit anything, and that these connections " +
  "may be recorded in the systems' logs.";

export const NETWORK_RANGE_DECLARATION =
  "Authorisation declared by the customer; not independently verified by CyberMeters.";

// grants_per_day bounds storage, as for Active Checks consent.
export const NETWORK_RANGE_LIMITS = Object.freeze({ name: 120, title: 120, grants_per_day: 100 });

const parseList = (text) => {
  try {
    const value = JSON.parse(text || "[]");
    return Array.isArray(value) ? value : [];
  } catch { return []; }
};

/**
 * The live (unrevoked) grant that covers this target's current address list
 * exactly, or null. Read errors throw: the caller fails closed.
 */
export async function liveRangeGrant(db, workspaceId, target) {
  const rows = (await db.prepare(
    `SELECT g.* FROM network_range_consents g
      WHERE g.workspace_id = ? AND g.network_target_id = ? AND g.kind = 'grant'
        AND EXISTS (SELECT 1 FROM network_targets t WHERE t.id=g.network_target_id AND t.workspace_id=g.workspace_id AND t.withdrawn_at IS NULL)
        AND NOT EXISTS (SELECT 1 FROM network_range_consents r
                         WHERE r.kind = 'revocation' AND r.grant_id = g.id AND r.workspace_id = g.workspace_id)
      ORDER BY g.created_at DESC, g.id DESC`,
  ).bind(workspaceId, target.id).all()).results || [];
  return rows.find((g) => g.addresses_json === target.addresses_json) || null;
}

/** Pure: does the grant name every requested port? */
export function rangeGrantCoversPorts(grant, ports = []) {
  const granted = new Set(parseList(grant?.ports_json).filter(Number.isInteger));
  return ports.length > 0 && ports.every((port) => granted.has(port));
}

// Customer projection. No raw internal user id leaves; the signer's IP is for
// the people who manage the workspace only.
export function rangeConsentProjection(grant, revocation, { canManage = false } = {}) {
  const signer = { name: grant.signer_name, title: grant.signer_title, workspace_role: grant.actor_workspace_role };
  if (canManage) signer.ip_address = grant.ip_address || null;
  return {
    id: grant.id,
    network_target_id: grant.network_target_id,
    target: grant.target,
    addresses: parseList(grant.addresses_json),
    ports: parseList(grant.ports_json),
    granted_at: grant.created_at,
    signer,
    authority_version: grant.authority_version,
    authority_text: grant.authority_text,
    declaration: NETWORK_RANGE_DECLARATION,
    independently_verified: false,
    status: revocation ? "revoked" : "active",
    revoked_at: revocation?.created_at || null,
    revocation_reason: revocation?.revocation_reason || null,
  };
}
