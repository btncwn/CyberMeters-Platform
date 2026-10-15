import { createLocalMcpWorker } from './local-mcp.js';

const DISABLED_BODY = JSON.stringify({ error: 'mcp_not_configured' });
const INVALID_BEARER_BODY = JSON.stringify({ error: 'invalid_bearer' });
const API_TOKEN_AUTH = /^Bearer (cm_[a-f0-9]{64})$/;

function disabledResponse() {
  return new Response(DISABLED_BODY, {
    status: 503,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}

function trialBearer(request) {
  const authorization = request.headers.get('authorization');
  if (!authorization || authorization.length > 74) return null;
  return API_TOKEN_AUTH.exec(authorization)?.[1] ?? null;
}

function invalidBearerResponse() {
  return new Response(INVALID_BEARER_BODY, {
    status: 401,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}

// The deployed default has no route and no enablement variable in Wrangler.
// Even if either is added later, both the explicit flag and named RPC binding
// are required; the MCP handler still accepts only local requests.
export default {
  fetch(request, env) {
    if (env?.MCP_INTERNAL_ENABLED !== 'true' ||
        typeof env.MCP_BACKEND?.getWorkspaceSummary !== 'function') return disabledResponse();

    const bearer = trialBearer(request);
    if (bearer === null) return invalidBearerResponse();

    // A fresh handler and backend closure keep the bearer in this request only.
    // Do not pass AbortSignal over RPC: the named entrypoint contract is exactly
    // getWorkspaceSummary({ bearer, workspaceId }). The local response deadline
    // remains bounded even if the remote method cannot be cancelled.
    const backend = {
      getWorkspaceSummary({ workspaceId }) {
        return env.MCP_BACKEND.getWorkspaceSummary({ bearer, workspaceId });
      },
    };
    return createLocalMcpWorker({ backend }).fetch(request);
  },
};

// A test harness must deliberately supply a backend. This function does not run
// from the deployed entrypoint and rejects non-local requests itself.
export function createLocalTestWorker({ backend, onEvent, backendTimeoutMs } = {}) {
  if (!backend || typeof backend.getWorkspaceSummary !== 'function') {
    throw new TypeError('A local test backend is required');
  }
  return createLocalMcpWorker({ backend, onEvent, backendTimeoutMs });
}
