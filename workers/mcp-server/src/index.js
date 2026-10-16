import { createLocalMcpWorker, REQUIRED_RPC_METHODS } from './local-mcp.js';
import { createCustomerMcpWorker, CUSTOMER_ISSUER, CUSTOMER_RESOURCE,
  CUSTOMER_RPC_METHODS } from './customer-mcp.js';

const DISABLED_BODY = JSON.stringify({ error: 'mcp_not_configured' });
const INVALID_BEARER_BODY = JSON.stringify({ error: 'invalid_bearer' });
const API_TOKEN_AUTH = /^Bearer (cm_[a-f0-9]{64})$/;
const CUSTOMER_PRODUCTION = Object.freeze({
  issuer: CUSTOMER_ISSUER,
  resource: CUSTOMER_RESOURCE,
  appOrigin: 'https://app.cybermeters.com',
});
const CUSTOMER_STAGING = Object.freeze({
  issuer: 'https://api-staging.cybermeters.com',
  resource: 'https://mcp-staging.cybermeters.com/mcp',
  appOrigin: 'https://app-staging.cybermeters.com',
});
const CUSTOMER_EVENTS = new Set([
  'tool_success', 'projection_rejected', 'backend_timeout', 'backend_failure',
  'protocol_error', 'audit_unavailable', 'invalid_grant_context',
  'insufficient_scope', 'workspace_denied', 'workspace_required',
  'request_denied', 'oauth_unavailable', 'request_completed', 'request_exception',
  'edge_rate_limited', 'edge_rate_unavailable',
]);
const EDGE_IP = /^[0-9a-fA-F:.]{3,45}$/;

/** No environment value can introduce an arbitrary customer OAuth host. */
export function resolveCustomerMcpDeployment(env) {
  const tier = env?.MCP_DEPLOYMENT_TIER;
  if (tier === undefined || tier === 'production') {
    if (env?.MCP_STAGING_ISSUER !== undefined ||
        env?.MCP_STAGING_RESOURCE !== undefined ||
        env?.MCP_STAGING_APP_ORIGIN !== undefined) return null;
    return CUSTOMER_PRODUCTION;
  }
  if (tier !== 'staging' ||
      (env.MCP_STAGING_ISSUER !== undefined && env.MCP_STAGING_ISSUER !== CUSTOMER_STAGING.issuer) ||
      (env.MCP_STAGING_RESOURCE !== undefined && env.MCP_STAGING_RESOURCE !== CUSTOMER_STAGING.resource) ||
      (env.MCP_STAGING_APP_ORIGIN !== undefined && env.MCP_STAGING_APP_ORIGIN !== CUSTOMER_STAGING.appOrigin)) {
    return null;
  }
  return CUSTOMER_STAGING;
}

function customerLatencyBucket(milliseconds) {
  if (milliseconds < 100) return 'under_100ms';
  if (milliseconds < 500) return '100_499ms';
  if (milliseconds < 1000) return '500_999ms';
  if (milliseconds < 5000) return '1_4s';
  return '5s_plus';
}

function edgeRateResponse() {
  return new Response(JSON.stringify({ error: 'mcp_rate_limited' }), {
    status: 429, headers: { 'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store', 'retry-after': '60' },
  });
}

/** Pre-audit gate: no unbounded unauthenticated request can write to D1. */
async function claimCustomerEdgeBudget(request, env) {
  const ip = request.headers.get('CF-Connecting-IP');
  if (!EDGE_IP.test(ip || '')) return null;
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(ip));
  const actor = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
  const [client, aggregate] = await Promise.all([
    env.MCP_EDGE_CLIENT_RATE.limit({ key: `mcp_customer_ip:${actor}` }),
    env.MCP_EDGE_GLOBAL_RATE.limit({ key: 'mcp_customer_all' }),
  ]);
  if (typeof client?.success !== 'boolean' || typeof aggregate?.success !== 'boolean') return null;
  return client.success && aggregate.success;
}

/** Low-cardinality, content-free logs for Workers observability. */
export function logCustomerGatewayEvent(kind, completed) {
  if (!CUSTOMER_EVENTS.has(kind)) return;
  const record = { component: 'mcp_customer_gateway', event: kind };
  if (kind === 'request_completed' && completed) {
    const status = Number(completed.status);
    record.status_class = Number.isInteger(status) && status >= 100 && status <= 599
      ? `${Math.floor(status / 100)}xx` : 'unknown';
    const duration = Number(completed.durationMs);
    record.latency_bucket = Number.isFinite(duration) && duration >= 0
      ? customerLatencyBucket(duration) : 'unknown';
  }
  console.log(JSON.stringify(record));
}

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
  async fetch(request, env, ctx) {
    const internal = env?.MCP_INTERNAL_ENABLED === 'true';
    const customer = env?.MCP_CUSTOMER_ENABLED === 'true';
    // Simultaneously enabling both modes is a configuration error, never an
    // invitation to accept the less restrictive credential path.
    if (internal && customer) return disabledResponse();
    if (customer) {
      const deployment = resolveCustomerMcpDeployment(env);
      if (!deployment) return disabledResponse();
      if (typeof env.MCP_AUTH?.validateToken !== 'function' ||
          typeof env.MCP_EDGE_CLIENT_RATE?.limit !== 'function' ||
          typeof env.MCP_EDGE_GLOBAL_RATE?.limit !== 'function' ||
          typeof env.MCP_CUSTOMER_BACKEND?.recordGatewayDenial !== 'function' ||
          CUSTOMER_RPC_METHODS.some((method) =>
            typeof env.MCP_CUSTOMER_BACKEND?.[method] !== 'function')) {
        return disabledResponse();
      }
      let allowed;
      try { allowed = await claimCustomerEdgeBudget(request, env); }
      catch { allowed = null; }
      if (allowed === null) {
        logCustomerGatewayEvent('edge_rate_unavailable');
        return disabledResponse();
      }
      if (!allowed) {
        logCustomerGatewayEvent('edge_rate_limited');
        return edgeRateResponse();
      }
      const backend = Object.fromEntries(CUSTOMER_RPC_METHODS.map((method) => [
        method, (args) => env.MCP_CUSTOMER_BACKEND[method](args),
      ]));
      const started = Date.now();
      const gateway = createCustomerMcpWorker({ auth: env.MCP_AUTH, backend,
        resource: deployment.resource, issuer: deployment.issuer,
        allowedOrigins: [new URL(deployment.resource).origin, deployment.appOrigin],
        auditDenial: (input) => env.MCP_CUSTOMER_BACKEND.recordGatewayDenial(input),
        onEvent: logCustomerGatewayEvent,
      });
      try {
        const response = await gateway.fetch(request, ctx);
        logCustomerGatewayEvent('request_completed', {
          status: response.status, durationMs: Date.now() - started,
        });
        return response;
      } catch {
        logCustomerGatewayEvent('request_exception');
        return disabledResponse();
      }
    }
    if (!internal ||
        REQUIRED_RPC_METHODS.some((method) => typeof env.MCP_BACKEND?.[method] !== 'function')) {
      return disabledResponse();
    }

    const bearer = trialBearer(request);
    if (bearer === null) return invalidBearerResponse();

    // A fresh handler and backend closure keep the bearer in this request only.
    // Do not pass AbortSignal over RPC: the named entrypoint contract is exactly
    // each named method receives only { bearer, workspaceId?, scanId? }.
    // The local response deadline
    // remains bounded even if the remote method cannot be cancelled.
    const backend = Object.fromEntries(REQUIRED_RPC_METHODS.map((method) => [method,
      ({ workspaceId, scanId }) => {
        const args = { bearer };
        if (workspaceId !== undefined) args.workspaceId = workspaceId;
        if (scanId !== undefined) args.scanId = scanId;
        return env.MCP_BACKEND[method](args);
      },
    ]));
    return createLocalMcpWorker({ backend }).fetch(request);
  },
};

// A test harness must deliberately supply a backend. This function does not run
// from the deployed entrypoint and rejects non-local requests itself.
export function createLocalTestWorker({ backend, onEvent, backendTimeoutMs } = {}) {
  if (!backend || REQUIRED_RPC_METHODS.some((method) => typeof backend[method] !== 'function')) {
    throw new TypeError('A local test backend is required');
  }
  return createLocalMcpWorker({ backend, onEvent, backendTimeoutMs });
}
