import { createCustomerMcpWorker } from '../../src/customer-mcp.js';

let validatorCalls = 0;
let denialAudits = 0;
let initializeCalls = 0;
let toolListCalls = 0;
let app;

const at = '2026-10-15T10:00:00Z';
const workspaceId = 'workspace-a';

const backend = {
  listWorkspaces: async () => ({ workspaces: [{ workspace_id: workspaceId,
    display_name: 'Workerd Fixture', role: 'owner' }], limit: 10,
  has_more: false, next_cursor: null }),
  getWorkspaceSummary: async () => ({ workspace_id: workspaceId,
    display_name: 'Workerd Fixture', domain_count: 1, open_case_count: 0,
    score_state: 'assessed', score_value: 80, latest_measurement_at: at,
    evidence_state: 'authoritative', coverage_state: 'complete', limitations: [] }),
  getWorkspacePosture: async () => null,
  listRecentScans: async () => null,
  getScanStatus: async () => null,
  listManagedCases: async () => null,
  getManagedCase: async () => null,
  getPortfolioSummary: async () => null,
  listDomains: async () => null,
  listFindings: async () => null,
  explainFinding: async () => null,
  getTlsPosture: async () => null,
  getEmailPosture: async () => null,
  getReportSummary: async () => null,
};

export default {
  async fetch(request, env, ctx) {
    if (new URL(request.url).pathname === '/__fixture_counts') {
      return Response.json({ validatorCalls, denialAudits,
        initializeCalls, toolListCalls });
    }
    app ??= createCustomerMcpWorker({
      resource: env.TEST_RESOURCE,
      issuer: env.TEST_ISSUER,
      auth: {
        async validateToken(resource, token) {
          validatorCalls++;
          if (!['valid-oauth-token-123', 'wrong-audience-token-123',
            'expired-oauth-token-123'].includes(token)) return null;
          return { props: { userId: 'user-a', connectionId: 'connection-a',
            workspaceId, portfolioRead: false },
          audience: token === 'wrong-audience-token-123'
            ? 'http://127.0.0.1:1/other' : resource,
          expiresAt: Math.floor(Date.now() / 1000) +
            (token === 'expired-oauth-token-123' ? -60 : 600),
          scope: ['mcp:read'], userId: 'user-a', clientId: 'fixture-client' };
        },
      },
      backend,
      async auditDenial({ reason }) {
        if (!['request_denied', 'invalid_bearer', 'insufficient_scope',
          'workspace_denied', 'invalid_request', 'protocol_error',
          'backend_unavailable'].includes(reason)) return false;
        denialAudits++;
        return true;
      },
    });
    if (new URL(request.url).pathname === '/__fixture_host_check') {
      const headers = new Headers(request.headers);
      headers.set('host', 'evil.invalid');
      const simulated = new Request(env.TEST_RESOURCE, { method: 'POST', headers,
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }) });
      return app.fetch(simulated, ctx);
    }
    if (request.method === 'POST' && new URL(request.url).pathname === '/mcp') {
      try {
        const body = await request.clone().json();
        if (body?.method === 'initialize') initializeCalls++;
        if (body?.method === 'tools/list') toolListCalls++;
      } catch { /* Invalid bodies remain owned by the actual MCP handler. */ }
    }
    return app.fetch(request, ctx);
  },
};
