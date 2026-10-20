const USER_ID = /^[A-Za-z0-9_-]{1,128}$/;

// Who may use customer MCP, decided in one place.
//
// MCP_CUSTOMER_ACCESS = "customers" (production, 20 Oct 2026): any verified
// user with an entitled plan (trial, paid or grace — checked on every token
// validation) reading a live workspace they are a member of. A workspace's
// mcp_beta_workspace_access row is then a per-workspace switch: no row or
// 'enabled' is open, 'paused' is closed.
//
// Any other value, or none, keeps the founder canary: only the configured
// founder, only workspaces they own, only rows marked 'enabled'. Setting the
// variable to anything but "customers" and redeploying closes MCP back to it.
//
// Only an explicit staging tier uses synthetic identities. A missing tier is
// treated as production elsewhere and must not bypass the founder fence.
export function mcpCustomerAccessOpen(env) {
  return env?.MCP_DEPLOYMENT_TIER !== "staging" && env?.MCP_CUSTOMER_ACCESS === "customers";
}

export function mcpFounderCanaryAllowsUser(env, userId) {
  if (env?.MCP_DEPLOYMENT_TIER === "staging" || mcpCustomerAccessOpen(env)) return true;
  const founderId = env?.MCP_FOUNDER_CANARY_USER_ID;
  return typeof founderId === "string" && USER_ID.test(founderId) &&
    userId === founderId;
}

export function mcpFounderCanaryAllowsWorkspace(env, userId, ownerUserId) {
  if (mcpCustomerAccessOpen(env)) return true;
  return mcpFounderCanaryAllowsUser(env, userId) &&
    (env?.MCP_DEPLOYMENT_TIER === "staging" || ownerUserId === userId);
}

/** A workspace's enrolment row status ('enabled' | 'paused' | null when absent). */
export function mcpWorkspaceEnrolmentAllows(env, betaStatus) {
  return mcpCustomerAccessOpen(env) ? betaStatus !== "paused" : betaStatus === "enabled";
}

/** The same rule as a SQL condition on a workspaces alias (no parameters). */
export function mcpWorkspaceEnrolmentSql(env, alias = "w") {
  return mcpCustomerAccessOpen(env)
    ? `NOT EXISTS (SELECT 1 FROM mcp_beta_workspace_access mba
         WHERE mba.workspace_id = ${alias}.id AND mba.status = 'paused')`
    : `EXISTS (SELECT 1 FROM mcp_beta_workspace_access mba
         WHERE mba.workspace_id = ${alias}.id AND mba.status = 'enabled')`;
}
