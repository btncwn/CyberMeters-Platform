// Private customer MCP reads. This is a separate admission path from the
// internal cm_ token trial. No public HTTP route dispatches these methods.
import { createAuditEvent } from "../lib/events.js";
import { hashToken } from "../lib/auth-crypto.js";
import { consumeApiRateLimit } from "../lib/rate-limit.js";
import { recordMetric } from "../lib/metrics.js";
import { getEffectivePlanState, hasFeatureEntitlement } from "../engines/entitlements.js";
import { listMcpOAuthGrantedWorkspaces, resolveMcpOAuthConfig } from "./mcp-oauth-admission.js";
import { mcpFounderCanaryAllowsUser, mcpFounderCanaryAllowsWorkspace } from "./mcp-founder-canary.js";
import {
  projectMcpSummary, projectMcpPosture, projectMcpRecentScans,
  projectMcpScanStatus, projectMcpManagedCases, projectMcpManagedCase,
  projectMcpPortfolioSummary,
} from "./mcp-projections.js";
import {
  projectMcpDomains, projectMcpFindings, projectMcpPortfolioFindings,
} from "./mcp-customer-discovery.js";
import {
  projectMcpFindingExplanation, projectMcpTlsPosture,
  projectMcpEmailPosture, projectMcpReportSummary,
} from "./mcp-customer-status.js";

export const MCP_CUSTOMER_RESOURCE = "https://mcp.cybermeters.com/mcp";
const DENIED = "mcp_customer_unavailable";
const ID = /^[A-Za-z0-9_-]{1,64}$/;
const CURSOR = /^[A-Za-z0-9_~.:-]{1,420}$/;
// @cloudflare/workers-oauth-provider 1.2.3 issues access tokens as
// {userId}:{16-char grantId}:{32-char secret}. CyberMeters user IDs cannot
// contain ':', so require this exact shape before asking KV to validate it.
const OAUTH_ACCESS_TOKEN = /^[A-Za-z0-9_-]{1,64}:[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]{32}$/;
const ROLES = new Set(["viewer", "analyst", "admin", "owner"]);
// Trial is a live `trialing` subscription, not the post-trial `free` state.
// Both limits share the same connection and token scopes, so switching plans
// cannot reset a budget inside the current minute.
const MCP_TRIAL_READS_PER_MINUTE = 10;
const MCP_PAID_READS_PER_MINUTE = 30;
const READS = Object.freeze({
  listWorkspaces: { project: projectCustomerWorkspaces, keys: ["bearer", "cursor"], event: "mcp_customer_workspaces_read" },
  getWorkspaceSummary: { project: projectMcpSummary, keys: ["bearer", "workspaceId"], event: "mcp_customer_summary_read" },
  getWorkspacePosture: { project: projectMcpPosture, keys: ["bearer", "workspaceId"], event: "mcp_customer_posture_read" },
  listRecentScans: { project: projectMcpRecentScans, keys: ["bearer", "workspaceId", "cursor"], event: "mcp_customer_scans_read" },
  getScanStatus: { project: projectMcpScanStatus, keys: ["bearer", "workspaceId", "scanId"], event: "mcp_customer_scan_read" },
  listManagedCases: { project: projectMcpManagedCases, keys: ["bearer", "workspaceId", "cursor"], event: "mcp_customer_cases_read" },
  getManagedCase: { project: projectMcpManagedCase, keys: ["bearer", "workspaceId", "caseId"], event: "mcp_customer_case_read" },
  listDomains: { project: projectMcpDomains, keys: ["bearer", "workspaceId", "cursor"], event: "mcp_customer_domains_read" },
  listFindings: { project: projectMcpFindings, keys: ["bearer", "workspaceId", "cursor", "portfolio"], event: "mcp_customer_findings_read" },
  explainFinding: { project: projectMcpFindingExplanation, keys: ["bearer", "workspaceId", "findingId"], event: "mcp_customer_finding_explanation_read" },
  getTlsPosture: { project: projectMcpTlsPosture, keys: ["bearer", "workspaceId", "cursor"], event: "mcp_customer_tls_read" },
  getEmailPosture: { project: projectMcpEmailPosture, keys: ["bearer", "workspaceId", "cursor"], event: "mcp_customer_email_read" },
  getReportSummary: { project: projectMcpReportSummary, keys: ["bearer", "workspaceId"], event: "mcp_customer_report_read" },
  getPortfolioSummary: { project: projectMcpPortfolioSummary, keys: ["bearer", "cursor"], event: "mcp_customer_portfolio_summary_read" },
});
export const MCP_CUSTOMER_READ_METHODS = Object.freeze(Object.keys(READS));

function deny() { return new Error(DENIED); }
function validId(value) { return typeof value === "string" && ID.test(value); }
function validCursor(value) { return value === undefined || (typeof value === "string" && CURSOR.test(value)); }
function validBearer(value) {
  return typeof value === "string" && OAUTH_ACCESS_TOKEN.test(value) &&
    !value.startsWith("cm_");
}
function hasScopes(value, required) {
  const scopes = new Set(Array.isArray(value) ? value : typeof value === "string" ? value.split(/\s+/) : []);
  return required.every((scope) => scopes.has(scope));
}
function connectionScopes(value) {
  try { return JSON.parse(value); } catch { return null; }
}
function validateInput(read, input) {
  const contract = READS[read];
  if (!contract || !input || typeof input !== "object" || Array.isArray(input) ||
      Object.keys(input).some((key) => !contract.keys.includes(key)) ||
      !validBearer(input.bearer) || !validCursor(input.cursor) ||
      (input.workspaceId !== undefined && !validId(input.workspaceId)) ||
      (input.scanId !== undefined && !validId(input.scanId)) ||
      (input.caseId !== undefined && !validId(input.caseId)) ||
      (input.findingId !== undefined && !validId(input.findingId))) return false;
  if (read === "getScanStatus" && !validId(input.scanId)) return false;
  if (read === "getManagedCase" && !validId(input.caseId)) return false;
  if (read === "explainFinding" && !validId(input.findingId)) return false;
  if (read === "listFindings" && input.portfolio !== undefined && input.portfolio !== true) return false;
  return true;
}

async function currentWorkspace(env, userId, workspaceId) {
  const row = await env.cybermeters_db.prepare(
    `SELECT w.id, w.name, w.owner_user_id, w.deleted_at, m.role, b.status AS beta_status
       FROM workspaces w
       LEFT JOIN workspace_members m ON m.workspace_id = w.id AND m.user_id = ?
       LEFT JOIN mcp_beta_workspace_access b ON b.workspace_id = w.id
      WHERE w.id = ? AND NOT EXISTS (
        SELECT 1 FROM deletion_requests dr WHERE dr.request_type = 'workspace'
          AND dr.workspace_id = w.id AND dr.status NOT IN ('completed','cancelled')
      ) LIMIT 1`,
  ).bind(userId, workspaceId).first();
  if (!row || !mcpFounderCanaryAllowsWorkspace(env, userId, row.owner_user_id) ||
      row.deleted_at != null || row.beta_status !== "enabled" ||
      !ROLES.has(row.role)) throw deny();
  return { id: row.id, name: row.name, role: row.role };
}

async function currentPortfolio(env, userId, connectionId) {
  const selected = await listMcpOAuthGrantedWorkspaces(env, userId, connectionId);
  if (!selected) throw deny();
  return selected;
}

async function loadCustomerGrant(env, token, resource) {
  const props = token?.props;
  if (!props || token.audience !== resource ||
      !hasScopes(token.scope, ["mcp:read"]) ||
      !validId(props.userId) || !validId(props.connectionId) ||
      !mcpFounderCanaryAllowsUser(env, props.userId) ||
      (props.workspaceId != null && !validId(props.workspaceId)) ||
      typeof props.portfolioRead !== "boolean" ||
      ((props.workspaceId == null) !== props.portfolioRead)) throw deny();
  // The OAuth provider reports Unix seconds, not JavaScript milliseconds.
  if (typeof token.expiresAt !== "number" || !Number.isFinite(token.expiresAt) ||
      token.expiresAt <= Date.now() / 1000) throw deny();
  if (props.portfolioRead && !hasScopes(token.scope, ["portfolio:read"])) throw deny();

  // The OAuth validator checks this too. A second live read at the data-owning
  // boundary prevents stale gateway approval from widening a later tool call.
  const connection = await env.cybermeters_db.prepare(
      `SELECT c.id, c.user_id, c.client_id, c.workspace_id, c.portfolio_read, c.status,
            c.resource, c.granted_scopes, u.status AS user_status, u.email_verified
       FROM mcp_oauth_connections c JOIN users u ON u.id = c.user_id
      WHERE c.id = ? AND NOT EXISTS (
        SELECT 1 FROM deletion_requests dr WHERE dr.request_type = 'account'
          AND dr.user_id = c.user_id AND dr.status NOT IN ('completed','cancelled')
      ) LIMIT 1`,
  ).bind(props.connectionId).first();
  if (!connection || connection.status !== "active" || connection.user_status !== "active" ||
      Number(connection.email_verified) !== 1 ||
      connection.user_id !== props.userId || connection.resource !== resource ||
      (connection.workspace_id ?? null) !== (props.workspaceId ?? null) ||
      Boolean(connection.portfolio_read) !== props.portfolioRead ||
      !hasScopes(connectionScopes(connection.granted_scopes),
        ["mcp:read", ...(props.portfolioRead ? ["portfolio:read"] : [])])) throw deny();
  return { userId: props.userId, connectionId: props.connectionId,
    clientId: connection.client_id,
    workspaceId: props.workspaceId ?? null, portfolioRead: props.portfolioRead };
}

async function projectCustomerWorkspaces(_env, grant, facts, input) {
  const all = grant.portfolioRead ? facts.portfolio : [facts.workspace];
  const cursor = input.cursor;
  if (cursor !== undefined && !validId(cursor)) throw deny();
  const next = cursor ? all.filter((row) => row.id > cursor) : all;
  const page = next.slice(0, 10);
  return {
    workspaces: page.map((row) => ({ workspace_id: row.id, display_name: row.name, role: row.role })),
    count: page.length, limit: 10, has_more: next.length > 10,
    next_cursor: next.length > 10 ? page.at(-1).id : null,
  };
}

/** One fresh OAuth, tenant, rate and audit gate for every customer read. */
export async function callMcpCustomerRead(env, read, input, overrides = {}) {
  const audit = overrides.appendAudit ?? createAuditEvent;
  const requestId = crypto.randomUUID();
  let denialReason = "invalid_request";
  let admittedGrant = null;
  try {
    if (env?.MCP_CUSTOMER_READ_ENABLED !== "true" ||
        env?.MCP_CUSTOMER_OAUTH_ENABLED !== "true" ||
        !env.cybermeters_db || !validateInput(read, input)) throw deny();
    // The provider imports cloudflare:workers. Load only in Worker runtime;
    // unit tests inject the validation seam without simulating that runtime.
    const validateToken = overrides.validateToken ??
      (await import("./mcp-oauth-server.js")).validateMcpOAuthToken;
    const resource = resolveMcpOAuthConfig(env).resource;
    const token = await validateToken(env, resource, input.bearer);
    denialReason = "identity_denied";
    const grant = await loadCustomerGrant(env, token, resource);
    admittedGrant = grant;
    const portfolioRequest = read === "getPortfolioSummary" ||
      read === "listFindings" && input.portfolio === true;
    if (portfolioRequest && !grant.portfolioRead) throw deny();
    let workspaceId = input.workspaceId;
    if (portfolioRequest || read === "listWorkspaces") {
      if (workspaceId !== undefined) throw deny();
    } else {
      workspaceId ??= grant.workspaceId;
      if (!validId(workspaceId) ||
          (grant.workspaceId && workspaceId !== grant.workspaceId)) throw deny();
    }
    const plan = await getEffectivePlanState(grant.userId, env);
    // An expired trial/no subscription is not an invited, valid beta plan.
    // Recheck at the data owner as well as at OAuth admission so a downgrade
    // cannot retain portfolio reads through a previously issued access token.
    if (!["trial", "paid", "grace"].includes(plan.source) || plan.plan === "free" ||
        (grant.portfolioRead && !hasFeatureEntitlement(plan.plan, "portfolio_monitoring"))) throw deny();
    denialReason = "budget_denied";
    // A portfolio connection may read many workspaces. Claim before enumerating
    // its workspaces so over-limit calls do not force expensive tenant reads.
    const limit = await (overrides.consumeBudget ?? consumeApiRateLimit)(env, [{
      scope: "mcp_customer_connection", scope_id: grant.connectionId,
    }, {
      scope: "mcp_customer_connection_workspace",
      scope_id: `${grant.connectionId}:${workspaceId ?? "portfolio"}`,
    }, {
      scope: "mcp_customer_access_token", scope_id: (await hashToken(input.bearer)).slice(0, 32),
    }], "mcp_customer_read",
    plan.is_trial ? MCP_TRIAL_READS_PER_MINUTE : MCP_PAID_READS_PER_MINUTE,
    60, { atomic: true, failClosed: true });
    if (limit) throw deny();

    const facts = {};
    if (grant.portfolioRead) {
      facts.portfolio = await currentPortfolio(env, grant.userId, grant.connectionId);
      grant.portfolioWorkspaceIds = facts.portfolio.map((row) => row.id);
      if (workspaceId !== undefined && !grant.portfolioWorkspaceIds.includes(workspaceId)) throw deny();
    }
    if (!portfolioRequest && read !== "listWorkspaces") {
      facts.workspace = await currentWorkspace(env, grant.userId, workspaceId);
      grant.workspaceId = workspaceId;
      grant.role = facts.workspace.role;
    } else if (read === "listWorkspaces" && !grant.portfolioRead) {
      facts.workspace = await currentWorkspace(env, grant.userId, grant.workspaceId);
      grant.role = facts.workspace.role;
    }

    denialReason = "projection_denied";
    const project = overrides.projectRead ?? (read === "listFindings" && input.portfolio === true
      ? projectMcpPortfolioFindings : READS[read].project);
    const projectionInput = { ...input, workspaceId };
    delete projectionInput.bearer;
    delete projectionInput.portfolio;
    if (portfolioRequest) delete projectionInput.workspaceId;
    const result = await project(env, grant, facts, projectionInput);
    if (!result || typeof result !== "object" || Array.isArray(result)) throw deny();

    denialReason = "audit_unavailable";
    const auditWorkspaceId = workspaceId ??
      (read === "listWorkspaces" && !grant.portfolioRead ? grant.workspaceId : null);
    const written = await audit(env, {
      workspace_id: auditWorkspaceId,
      user_id: grant.userId,
      event_type: READS[read].event,
      entity_type: auditWorkspaceId ? "workspace" : "mcp_connection",
      entity_id: auditWorkspaceId ?? grant.connectionId,
      description: "MCP customer read",
      metadata: { tool: read, request_id: requestId, connection_id: grant.connectionId,
        client_id_hash: (await hashToken(grant.clientId)).slice(0, 24),
        ...(portfolioRequest || read === "listWorkspaces" && grant.portfolioRead
          ? { selected_workspace_count: grant.portfolioWorkspaceIds.length,
              selected_workspace_ids: grant.portfolioWorkspaceIds } : {}) },
      required: true,
      active_workspace_required: Boolean(auditWorkspaceId),
    });
    if (written !== true) throw deny();
    // Last-use is a customer-visible security fact. Keep it durable before a
    // successful response; a concurrent revoke also prevents this update.
    const usage = await env.cybermeters_db.prepare(
      `UPDATE mcp_oauth_connections SET last_used_at = datetime('now')
        WHERE id = ? AND user_id = ? AND status = 'active'`,
    ).bind(grant.connectionId, grant.userId).run();
    if (Number(usage?.meta?.changes) !== 1) throw deny();
    recordMetric(env, "mcp_customer_read_accepted");
    return result;
  } catch {
    recordMetric(env, "mcp_customer_read_denied");
    if (env?.cybermeters_db) {
      try {
        // Attribute an admitted denial to the actual grant, never to a
        // caller-supplied foreign workspace ID. Invalid tokens remain a
        // content-free system event because no identity was established.
        const auditWorkspaceId = admittedGrant?.workspaceId ?? null;
        await audit(env, {
          ...(admittedGrant ? {
            workspace_id: auditWorkspaceId,
            user_id: admittedGrant.userId,
            entity_type: auditWorkspaceId ? "workspace" : "mcp_connection",
            entity_id: auditWorkspaceId ?? admittedGrant.connectionId,
          } : {}),
          event_type: "mcp_customer_read_denied",
          description: "MCP customer read denied",
          metadata: { request_id: requestId, reason: denialReason, tool: read,
            ...(admittedGrant ? {
              connection_id: admittedGrant.connectionId,
              client_id_hash: (await hashToken(admittedGrant.clientId)).slice(0, 24),
            } : {}) }, required: true,
          active_workspace_required: false,
        });
      } catch {
        recordMetric(env, "mcp_customer_audit_unavailable");
      }
    }
    throw deny();
  }
}

export const customerMcpReads = Object.freeze(Object.fromEntries(
  MCP_CUSTOMER_READ_METHODS.map((read) => [read, (env, input, overrides) =>
    callMcpCustomerRead(env, read, input, overrides)]),
));

const GATEWAY_DENIAL_REASONS = new Set([
  "request_denied", "invalid_bearer", "insufficient_scope",
  "workspace_denied", "invalid_request", "protocol_error",
  "backend_unavailable",
]);

/** Content-free audit for rejections before any customer tool RPC exists. */
export async function recordMcpGatewayDenial(env, input, overrides = {}) {
  if (env?.MCP_CUSTOMER_READ_ENABLED !== "true" ||
      env?.MCP_CUSTOMER_OAUTH_ENABLED !== "true" || !env.cybermeters_db ||
      !input || Object.keys(input).length !== 1 ||
      !GATEWAY_DENIAL_REASONS.has(input.reason)) throw deny();
  const written = await (overrides.appendAudit ?? createAuditEvent)(env, {
    event_type: "mcp_customer_gateway_denied", actor_type: "system",
    description: "MCP customer gateway request denied",
    metadata: { reason: input.reason }, required: true,
  });
  if (written !== true) throw deny();
  return true;
}
