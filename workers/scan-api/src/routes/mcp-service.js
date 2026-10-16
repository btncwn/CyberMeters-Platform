// Private, named service-binding RPC for the local MCP engineering trial.
// This module is never dispatched from the public HTTP router.
import { hashToken } from "../lib/auth-crypto.js";
import { createAuditEvent } from "../lib/events.js";
import { consumeApiRateLimit } from "../lib/rate-limit.js";
import { recordMetric } from "../lib/metrics.js";
import { evaluateMcpAdmission } from "./mcp-authz.js";
import {
  projectMcpWorkspaces, projectMcpSummary, projectMcpPosture,
  projectMcpRecentScans, projectMcpScanStatus, projectMcpManagedCases,
} from "./mcp-projections.js";

const TOKEN_RE = /^cm_[0-9a-f]{64}$/;
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const DENIED = "mcp_summary_unavailable";
const READS = Object.freeze({
  listWorkspaces: {
    tool: "cybermeters_list_workspaces", event: "mcp_workspaces_list_read",
    project: projectMcpWorkspaces,
  },
  getWorkspaceSummary: {
    tool: "cybermeters_get_workspace_summary", event: "mcp_workspace_summary_read",
    project: projectMcpSummary,
  },
  getWorkspacePosture: {
    tool: "cybermeters_get_workspace_posture", event: "mcp_workspace_posture_read",
    project: projectMcpPosture,
  },
  listRecentScans: {
    tool: "cybermeters_list_recent_scans", event: "mcp_recent_scans_read",
    project: projectMcpRecentScans,
  },
  getScanStatus: {
    tool: "cybermeters_get_scan_status", event: "mcp_scan_status_read",
    project: projectMcpScanStatus,
  },
  listManagedCases: {
    tool: "cybermeters_list_managed_cases", event: "mcp_managed_cases_read",
    project: projectMcpManagedCases,
  },
});

function deny() {
  // RPC errors must have the same message for missing and foreign objects.
  return new Error(DENIED);
}

function validInput(read, input) {
  if (input === null || typeof input !== "object" || Array.isArray(input) ||
      typeof input.bearer !== "string" || !TOKEN_RE.test(input.bearer)) return false;
  const expected = read === "listWorkspaces" ? ["bearer"] :
    read === "getScanStatus" ? ["bearer", "scanId", "workspaceId"] :
    ["bearer", "workspaceId"];
  if (Object.keys(input).sort().join(",") !== expected.sort().join(",")) return false;
  if (read === "listWorkspaces") return true;
  return typeof input.workspaceId === "string" && ID_RE.test(input.workspaceId) &&
    (read !== "getScanStatus" ||
      (typeof input.scanId === "string" && ID_RE.test(input.scanId)));
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
export async function callMcpReadForTrial(env, read, input, overrides = {}) {
  const hash = overrides.hashToken ?? hashToken;
  const loadFacts = overrides.loadFacts ?? loadMcpAdmissionFacts;
  const budget = overrides.consumeBudget ?? consumeApiRateLimit;
  const audit = overrides.appendAudit ?? createAuditEvent;
  const now = overrides.now ?? Date.now();
  const requestId = crypto.randomUUID();
  let denialReason = "invalid_request";

  try {
    if (!Object.hasOwn(READS, read) || !validInput(read, input)) throw deny();
    const contract = READS[read];
    // The empty-argument workspaces tool receives no caller-selected workspace.
    // Its sole context comes from the server's trial entitlement binding.
    const workspaceId = read === "listWorkspaces"
      ? env?.MCP_TRIAL_WORKSPACE_ID : input.workspaceId;
    if (!trialConfigured(env, workspaceId) ||
        !env.cybermeters_db) throw deny();

    denialReason = "identity_denied";
    const facts = await loadFacts(env, await hash(input.bearer), workspaceId);
    if (!facts?.token || facts.token.token_id !== env.MCP_TRIAL_TOKEN_ID) throw deny();
    const decision = evaluateMcpAdmission(facts.admission, now);
    if (!decision.allowed) throw deny();

    denialReason = "budget_denied";
    const limit = await budget(env, [{
      scope: "mcp_token_workspace",
      scope_id: `${decision.grant.tokenId}:${decision.grant.workspaceId}`,
    }], "mcp_read", 30, 60, { atomic: true, failClosed: true });
    if (limit) throw deny();

    denialReason = "projection_denied";
    const projection = overrides.projectRead ?? contract.project;
    const result = await projection(env, decision.grant, facts, input);
    if (result === null || typeof result !== "object" || Array.isArray(result)) throw deny();

    denialReason = "audit_unavailable";
    const written = await audit(env, {
      workspace_id: decision.grant.workspaceId,
      user_id: decision.grant.userId,
      event_type: contract.event,
      entity_type: "workspace",
      entity_id: decision.grant.workspaceId,
      description: "MCP read",
      metadata: { tool: contract.tool, request_id: requestId },
      required: true,
      active_workspace_required: true,
    });
    if (written !== true) throw deny();

    recordMetric(env, "mcp_read_accepted");
    return result;
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

export const listWorkspacesForMcp = (env, input, overrides) =>
  callMcpReadForTrial(env, "listWorkspaces", input, overrides);
export const getWorkspaceSummaryForMcp = (env, input, overrides) =>
  callMcpReadForTrial(env, "getWorkspaceSummary", input, overrides);
export const getWorkspacePostureForMcp = (env, input, overrides) =>
  callMcpReadForTrial(env, "getWorkspacePosture", input, overrides);
export const listRecentScansForMcp = (env, input, overrides) =>
  callMcpReadForTrial(env, "listRecentScans", input, overrides);
export const getScanStatusForMcp = (env, input, overrides) =>
  callMcpReadForTrial(env, "getScanStatus", input, overrides);
export const listManagedCasesForMcp = (env, input, overrides) =>
  callMcpReadForTrial(env, "listManagedCases", input, overrides);
