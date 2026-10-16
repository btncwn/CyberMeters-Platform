const USER_ID = /^[A-Za-z0-9_-]{1,128}$/;

// Only an explicit staging tier uses synthetic identities. A missing tier is
// treated as production elsewhere and must not bypass the founder fence.
export function mcpFounderCanaryAllowsUser(env, userId) {
  if (env?.MCP_DEPLOYMENT_TIER === "staging") return true;
  const founderId = env?.MCP_FOUNDER_CANARY_USER_ID;
  return typeof founderId === "string" && USER_ID.test(founderId) &&
    userId === founderId;
}

export function mcpFounderCanaryAllowsWorkspace(env, userId, ownerUserId) {
  return mcpFounderCanaryAllowsUser(env, userId) &&
    (env?.MCP_DEPLOYMENT_TIER === "staging" || ownerUserId === userId);
}
