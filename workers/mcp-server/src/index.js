import { createLocalMcpWorker } from './local-mcp.js';

const DISABLED_BODY = JSON.stringify({ error: 'mcp_not_configured' });

function disabledResponse() {
  return new Response(DISABLED_BODY, {
    status: 503,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}

// This is the only deployed entrypoint. No environment variable, header, or binding
// can enable the local fixture handler. MCP-03 must replace this deliberately.
export default {
  fetch() {
    return disabledResponse();
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
