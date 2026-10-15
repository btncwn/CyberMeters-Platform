// MCP-01A — pure, fail-closed admission decision for the internal MCP trial
// read contract. No I/O, no clock reads unless `now` is omitted, no mutation.
// A later routed handler loads the facts (token row, user, workspace,
// membership, entitlement) and passes them here; this module only decides.
// OAuth/audience and service-binding authentication are MCP-03 work and are
// deliberately not representable in this contract.

export const MCP_ADMISSION_SCOPE = "read";

export const MCP_DENY = Object.freeze({
  MALFORMED_INPUT: "malformed_input",
  IDENTITY_NOT_API_TOKEN: "identity_not_api_token",
  TOKEN_NOT_ACTIVE: "token_not_active",
  SCOPE_NOT_PERMITTED: "scope_not_permitted",
  TOKEN_UNBOUND: "token_unbound",
  WORKSPACE_BINDING_MISMATCH: "workspace_binding_mismatch",
  TOKEN_EXPIRY_INVALID: "token_expiry_invalid",
  TOKEN_EXPIRED: "token_expired",
  USER_NOT_ACTIVE: "user_not_active",
  // Covers missing, soft-deleted, foreign, removed-member and
  // insufficient-role cases identically so existence is never revealed.
  WORKSPACE_NOT_ACCESSIBLE: "workspace_not_accessible",
  ENTITLEMENT_MISSING: "entitlement_missing",
});

const READ_ROLES = new Set(["viewer", "analyst", "admin", "owner"]);
const ID_RE = /^[A-Za-z0-9_-]{1,128}$/;

const isPlainObject = (v) =>
  v !== null && typeof v === "object" && !Array.isArray(v);
const validId = (v) => typeof v === "string" && ID_RE.test(v);

function deny(reason) {
  return Object.freeze({ allowed: false, reason, grant: null });
}

// Accepts a representable integer epoch millisecond or the canonical UTC form
// emitted by Date#toISOString. Date.parse alone is deliberately insufficient:
// it normalises impossible calendar dates such as 30 February.
function parseExpiryMs(v) {
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v) || v <= 0 || Math.abs(v) > 8.64e15) return null;
    return Number.isNaN(new Date(v).getTime()) ? null : v;
  }
  if (typeof v === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(v)) {
    const ms = Date.parse(v);
    if (!Number.isFinite(ms)) return null;
    try {
      return new Date(ms).toISOString() === v ? ms : null;
    } catch {
      return null;
    }
  }
  return null;
}

function resolveRole(workspace, user, membership) {
  if (isPlainObject(membership)) {
    return READ_ROLES.has(membership.role) ? membership.role : null;
  }
  // Legacy-authoritative ownership: only when the workspace has zero
  // membership rows and this caller has none. A removed member is simply
  // membership === null while memberCount > 0, so they stay denied.
  if (
    membership === null &&
    workspace.memberCount === 0 &&
    workspace.ownerUserId === user.id
  ) {
    return "owner";
  }
  return null;
}

/**
 * @param {object} input
 * @param {string} input.requestedWorkspaceId
 * @param {{kind:string,tokenId:string,userId:string,status:string,scope:string,
 *          workspaceId:(string|null),expiresAt:(number|string|null)}} input.identity
 * @param {{id:string,status:string}} input.user
 * @param {({id:string,deletedAt:(string|number|null),ownerUserId:(string|null),
 *          memberCount:number}|null)} input.workspace
 * @param {({role:string}|null)} input.membership null = no membership row;
 *          removed members have no row and workspace_members has no status column
 * @param {{mcp:boolean}} input.entitlement
 * @param {number} [now] epoch ms, injectable for tests
 */
export function evaluateMcpAdmission(input, now = Date.now()) {
  if (!isPlainObject(input) || !Number.isFinite(now)) {
    return deny(MCP_DENY.MALFORMED_INPUT);
  }
  const { requestedWorkspaceId, identity, user, workspace, membership, entitlement } = input;

  if (!validId(requestedWorkspaceId)) return deny(MCP_DENY.MALFORMED_INPUT);
  if (identity == null) return deny(MCP_DENY.IDENTITY_NOT_API_TOKEN);
  if (!isPlainObject(identity)) return deny(MCP_DENY.MALFORMED_INPUT);
  if (identity.kind !== "api_token") return deny(MCP_DENY.IDENTITY_NOT_API_TOKEN);
  if (!validId(identity.tokenId) || !validId(identity.userId)) {
    return deny(MCP_DENY.MALFORMED_INPUT);
  }
  if (identity.status !== "active") return deny(MCP_DENY.TOKEN_NOT_ACTIVE);
  if (identity.scope !== MCP_ADMISSION_SCOPE) return deny(MCP_DENY.SCOPE_NOT_PERMITTED);

  if (identity.workspaceId == null || identity.workspaceId === "") {
    return deny(MCP_DENY.TOKEN_UNBOUND);
  }
  if (identity.workspaceId !== requestedWorkspaceId) {
    return deny(MCP_DENY.WORKSPACE_BINDING_MISMATCH);
  }

  const expiryMs = parseExpiryMs(identity.expiresAt);
  if (expiryMs === null) return deny(MCP_DENY.TOKEN_EXPIRY_INVALID);
  if (!(expiryMs > now)) return deny(MCP_DENY.TOKEN_EXPIRED);

  if (!isPlainObject(user) || user.id !== identity.userId || user.status !== "active") {
    return deny(MCP_DENY.USER_NOT_ACTIVE);
  }

  if (
    !isPlainObject(workspace) ||
    workspace.id !== requestedWorkspaceId ||
    !Number.isInteger(workspace.memberCount) ||
    workspace.memberCount < 0 ||
    workspace.deletedAt !== null
  ) {
    return deny(MCP_DENY.WORKSPACE_NOT_ACCESSIBLE);
  }
  const role = resolveRole(workspace, user, membership);
  if (role === null) return deny(MCP_DENY.WORKSPACE_NOT_ACCESSIBLE);

  if (!isPlainObject(entitlement) || entitlement.mcp !== true) {
    return deny(MCP_DENY.ENTITLEMENT_MISSING);
  }

  return Object.freeze({
    allowed: true,
    reason: "admitted",
    grant: Object.freeze({
      tokenId: identity.tokenId,
      userId: identity.userId,
      workspaceId: requestedWorkspaceId,
      role,
      scope: MCP_ADMISSION_SCOPE,
      expiresAt: new Date(expiryMs).toISOString(),
    }),
  });
}
