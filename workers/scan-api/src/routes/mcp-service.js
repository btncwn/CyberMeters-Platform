// Private, named service-binding RPC for the local MCP engineering trial.
// This module is never dispatched from the public HTTP router.
import { hashToken } from "../lib/auth-crypto.js";
import { createAuditEvent } from "../lib/events.js";
import { consumeApiRateLimit } from "../lib/rate-limit.js";
import { recordMetric } from "../lib/metrics.js";
import { evaluateMcpAdmission } from "./mcp-authz.js";

const TOKEN_RE = /^cm_[0-9a-f]{64}$/;
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const SAFE_NAME_RE = /^[^\x00-\x1f\x7f\p{Cf}]{1,100}$/u;
const DENIED = "mcp_summary_unavailable";

function deny() {
  // RPC errors must have the same message for missing and foreign objects.
  return new Error(DENIED);
}

function validInput(input) {
  return input !== null && typeof input === "object" && !Array.isArray(input) &&
    Object.keys(input).length === 2 &&
    typeof input.bearer === "string" && typeof input.workspaceId === "string" &&
    TOKEN_RE.test(input.bearer) && ID_RE.test(input.workspaceId);
}

function trialConfigured(env, workspaceId) {
  return env?.MCP_INTERNAL_ENABLED === "true" &&
    typeof env.MCP_TRIAL_WORKSPACE_ID === "string" &&
    typeof env.MCP_TRIAL_TOKEN_ID === "string" &&
    ID_RE.test(env.MCP_TRIAL_WORKSPACE_ID) &&
    ID_RE.test(env.MCP_TRIAL_TOKEN_ID) &&
    env.MCP_TRIAL_WORKSPACE_ID === workspaceId;
}

/** Load fresh facts. A general API token or web session cannot inherit MCP access. */
export async function loadMcpAdmissionFacts(env, tokenHash, requestedWorkspaceId) {
  const db = env.cybermeters_db;
  const token = await db.prepare(
    `SELECT t.id AS token_id, t.user_id, t.workspace_id, t.scope,
            t.expires_at, t.status AS token_status, u.status AS user_status
       FROM api_tokens t JOIN users u ON u.id = t.user_id
      WHERE t.token_hash = ? LIMIT 1`,
  ).bind(tokenHash).first();
  if (!token) return null;

  const workspace = await db.prepare(
    `SELECT id, name, owner_user_id, deleted_at
       FROM workspaces WHERE id = ? LIMIT 1`,
  ).bind(requestedWorkspaceId).first();
  const member = await db.prepare(
    `SELECT role FROM workspace_members
      WHERE workspace_id = ? AND user_id = ? LIMIT 1`,
  ).bind(requestedWorkspaceId, token.user_id).first();
  const count = await db.prepare(
    `SELECT COUNT(*) AS member_count FROM workspace_members WHERE workspace_id = ?`,
  ).bind(requestedWorkspaceId).first();

  return {
    token,
    workspace,
    admission: {
      requestedWorkspaceId,
      identity: {
        kind: "api_token", tokenId: token.token_id, userId: token.user_id,
        status: token.token_status, scope: token.scope,
        workspaceId: token.workspace_id, expiresAt: token.expires_at,
      },
      user: { id: token.user_id, status: token.user_status },
      workspace: workspace && {
        id: workspace.id, deletedAt: workspace.deleted_at,
        ownerUserId: workspace.owner_user_id,
        memberCount: Number(count?.member_count),
      },
      membership: member ?? null,
      entitlement: {
        mcp: env.MCP_TRIAL_TOKEN_ID === token.token_id &&
          env.MCP_TRIAL_WORKSPACE_ID === requestedWorkspaceId,
      },
    },
  };
}

/**
 * The test seams replace only I/O; production always uses fresh D1 facts, an
 * atomic fail-closed budget and a required, awaited audit event.
 */
export async function getWorkspaceSummaryForMcp(env, input, overrides = {}) {
  const hash = overrides.hashToken ?? hashToken;
  const loadFacts = overrides.loadFacts ?? loadMcpAdmissionFacts;
  const budget = overrides.consumeBudget ?? consumeApiRateLimit;
  const audit = overrides.appendAudit ?? createAuditEvent;
  const now = overrides.now ?? Date.now();
  const requestId = crypto.randomUUID();
  let denialReason = "invalid_request";

  try {
    if (!validInput(input) || !trialConfigured(env, input.workspaceId) ||
        !env.cybermeters_db) throw deny();

    denialReason = "identity_denied";
    const facts = await loadFacts(env, await hash(input.bearer), input.workspaceId);
    if (!facts || facts.token.token_id !== env.MCP_TRIAL_TOKEN_ID) throw deny();
    const decision = evaluateMcpAdmission(facts.admission, now);
    if (!decision.allowed) throw deny();

    denialReason = "budget_denied";
    const limit = await budget(env, [{
      scope: "mcp_token_workspace",
      scope_id: `${decision.grant.tokenId}:${decision.grant.workspaceId}`,
    }], "mcp_read", 30, 60, { atomic: true, failClosed: true });
    if (limit) throw deny();

    denialReason = "projection_denied";
    const name = facts.workspace?.name;
    if (typeof name !== "string" || !SAFE_NAME_RE.test(name)) throw deny();

    denialReason = "audit_unavailable";
    const written = await audit(env, {
      workspace_id: decision.grant.workspaceId,
      user_id: decision.grant.userId,
      event_type: "mcp_workspace_summary_read",
      entity_type: "workspace",
      entity_id: decision.grant.workspaceId,
      description: "MCP workspace summary read",
      metadata: { tool: "cybermeters_get_workspace_summary", request_id: requestId },
      required: true,
      active_workspace_required: true,
    });
    if (written !== true) throw deny();

    recordMetric(env, "mcp_read_accepted");

    // MCP-03 proves transport and admission. A live score is deliberately not
    // projected until MCP-04 proves its canonical assessment basis.
    return {
      workspace_id: decision.grant.workspaceId,
      display_name: name,
      score_state: "basis_unproven",
      score_value: null,
      latest_measurement_at: null,
      evidence_state: "insufficient",
      coverage_state: "unavailable",
      limitations: ["The MCP summary has not verified the current assessment basis. Open CyberMeters for measured posture."],
    };
  } catch {
    recordMetric(env, "mcp_read_denied");
    // Denials have no caller-supplied workspace, user, bearer, or arguments in
    // the audit row. An attacker must not be able to write into another
    // workspace's activity stream by naming its ID in a rejected call.
    if (env?.cybermeters_db) {
      try {
        const written = await audit(env, {
          event_type: "mcp_read_denied",
          actor_type: "system",
          description: "MCP read denied",
          metadata: { request_id: requestId, reason: denialReason },
          required: true,
        });
        if (written !== true) throw deny();
      } catch {
        recordMetric(env, "mcp_audit_unavailable");
        console.error(JSON.stringify({ event: "mcp_audit_unavailable", request_id: requestId }));
      }
    }
    throw deny();
  }
}
