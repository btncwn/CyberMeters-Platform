import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createCustomerMcpWorker, CUSTOMER_RPC_METHODS,
  projectCustomerDomains, projectCustomerFindings, projectCustomerPortfolioSummary,
  projectCustomerFindingExplanation, projectCustomerTlsPosture,
  projectCustomerEmailPosture, projectCustomerReportSummary,
} from '../src/customer-mcp.js';
import {
  fixtureSummary, fixturePosture, fixtureScan, fixtureCases, workspaceId,
} from './fixture.js';

const RESOURCE = 'http://localhost:8787/mcp';
const ISSUER = 'http://localhost:8788';
const TOKEN = 'oauth-fixture-token';
const OTHER_WORKSPACE = 'fixture-workspace-2';
const ctx = { waitUntil() {}, passThroughOnException() {} };
const metadataUrl = 'http://localhost:8787/.well-known/oauth-protected-resource/mcp';

// Node cannot load cloudflare:workers, so this harness checks our resource
// contract. A separate workerd smoke covers the package's real adapter.
const oauthRuntime = {
  OAuthResourceServer: class {
    constructor(options) { this.options = options; }
    async fetch(request, env) {
      const { resourceMetadata, requiredScopes, validateToken, handler } = this.options;
      if (new URL(request.url).pathname === '/.well-known/oauth-protected-resource/mcp') {
        return Response.json({ ...resourceMetadata, scopes_supported: requiredScopes });
      }
      const match = /^Bearer ([^\s]+)$/.exec(request.headers.get('authorization') ?? '');
      const challenge = `Bearer resource_metadata="${metadataUrl}", scope="${requiredScopes.join(' ')}"`;
      if (!match) return new Response(null, { status: 401, headers: { 'www-authenticate': challenge } });
      const record = await validateToken(env, request)(resourceMetadata.resource, match[1]);
      if (!record || record.audience !== resourceMetadata.resource ||
          (record.expiresAt != null && record.expiresAt <= Date.now() / 1000)) {
        return new Response(null, { status: 401, headers: { 'www-authenticate': challenge } });
      }
      return handler.fetch(request, env, { props: record.props,
        auth: { token: match[1], scope: record.scope ?? [], audience: record.audience } });
    }
  },
  insufficientScope(_auth, scopes) {
    return new Response(null, { status: 403, headers: {
      'www-authenticate': `Bearer error="insufficient_scope", scope="${scopes.join(' ')}", resource_metadata="${metadataUrl}"`,
    } });
  },
};

function backendFixture(overrides = {}) {
  const backend = {
    listWorkspaces: () => ({ workspaces: [{ workspace_id: workspaceId,
      display_name: 'Fixture Workspace', role: 'owner', secret: 'do-not-disclose' }],
    limit: 10, has_more: false, next_cursor: null }),
    getWorkspaceSummary: () => fixtureSummary(),
    getWorkspacePosture: () => fixturePosture(),
    listRecentScans: () => ({ workspace_id: workspaceId, scans: [fixtureScan()],
      limit: 10, has_more: false, next_cursor: null }),
    getScanStatus: () => ({ workspace_id: workspaceId, ...fixtureScan() }),
    listManagedCases: () => ({ ...fixtureCases(), next_cursor: null }),
    getManagedCase: () => ({ workspace_id: workspaceId, ...fixtureCases().cases[0] }),
    listDomains: () => ({ workspace_id: workspaceId, domains: [{
      workspace_id: workspaceId, domain_id: 'domain_fixture_1', domain: 'example.invalid',
      verification_status: 'verified', verified_at: '2026-10-15T10:00:00Z',
      last_completed_scan_id: 'scan_fixture_1',
      last_completed_scan_created_at: '2026-10-15T10:00:00Z',
      assessment: { quality: 'complete', authoritative: true, provisional: false,
        comparable: true, secret: 'do-not-disclose' },
      source_report_state: 'verified', secret: 'do-not-disclose',
    }], limit: 10, has_more: false, next_cursor: null, secret: 'do-not-disclose' }),
    listFindings: () => ({ scope: 'workspace', workspace_id: workspaceId,
      findings: [{ workspace_id: workspaceId, domain_id: 'domain_fixture_1',
        domain: 'example.invalid', finding_id: 'finding_fixture_1',
        finding_type: 'tls_expiry', title: 'Certificate expires soon', severity: 'high',
        source_scan_id: 'scan_fixture_1', source_scan_created_at: '2026-10-15T10:00:00Z',
        source_scan_quality: 'complete', domain_verification_status: 'verified',
        newer_scan_without_complete_assessment: false, evidence_state: 'authoritative',
        assessment: { quality: 'complete', authoritative: true, provisional: false,
          comparable: true }, source_report_state: 'verified', secret: 'do-not-disclose' }],
      limit: 10, has_more: false, next_cursor: null, coverage_state: 'not_proven_complete',
      secret: 'do-not-disclose' }),
    explainFinding: () => { throw new Error('not yet implemented'); },
    getTlsPosture: () => { throw new Error('not yet implemented'); },
    getEmailPosture: () => { throw new Error('not yet implemented'); },
    getReportSummary: () => { throw new Error('not yet implemented'); },
    getPortfolioSummary: () => { throw new Error('not yet implemented'); },
  };
  return { ...backend, ...overrides };
}

function authFixture(overrides = {}) {
  return { async validateToken(resource, token) {
    if (token !== TOKEN) return null;
    return { props: { userId: 'fixture-user', connectionId: 'fixture-connection',
      workspaceId, portfolioRead: false }, audience: resource,
      expiresAt: Math.floor(Date.now() / 1000) + 600, scope: ['mcp:read'],
      userId: 'fixture-user', clientId: 'fixture-client', ...overrides };
  } };
}

function harness({ auth = authFixture(), backend = backendFixture(), events = [], audits = [] } = {}) {
  return { app: createCustomerMcpWorker({ auth, backend, resource: RESOURCE, issuer: ISSUER,
    onEvent: (event) => events.push(event), oauthRuntime,
    auditDenial: async (value) => { audits.push(value); return true; } }), events, audits };
}

function request(url = RESOURCE, { method = 'POST', token = TOKEN, origin,
  body = { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} },
  headers = {} } = {}) {
  const requestHeaders = { host: new URL(url).host,
    accept: 'application/json, text/event-stream', ...headers };
  if (token !== null) requestHeaders.authorization = `Bearer ${token}`;
  if (origin !== undefined) requestHeaders.origin = origin;
  if (method === 'POST') requestHeaders['content-type'] = 'application/json';
  return new Request(url, { method, headers: requestHeaders,
    ...(method === 'POST' ? { body: JSON.stringify(body) } : {}) });
}

function rpc(method, params = {}, id = 1) {
  return { jsonrpc: '2.0', id, method, params };
}

async function protocolJson(response) {
  const value = await response.text();
  if (!response.headers.get('content-type')?.includes('text/event-stream')) return JSON.parse(value);
  const message = value.split('\n').find((line) => line.startsWith('data: '));
  assert.ok(message, 'SSE response must carry one protocol message');
  return JSON.parse(message.slice(6));
}

test('configuration requires both private bindings and all fourteen customer RPC methods', () => {
  assert.equal(CUSTOMER_RPC_METHODS.length, 14);
  assert.throws(() => createCustomerMcpWorker({ resource: RESOURCE, issuer: ISSUER }),
    /bindings are incomplete/);
  assert.throws(() => createCustomerMcpWorker({ auth: authFixture(),
    backend: { ...backendFixture(), getReportSummary: undefined },
    resource: RESOURCE, issuer: ISSUER }), /bindings are incomplete/);
  assert.throws(() => createCustomerMcpWorker({ auth: authFixture(),
    backend: backendFixture(), resource: 'http://evil.invalid/mcp', issuer: ISSUER }),
    /Invalid customer MCP configuration/);
});

test('protected-resource metadata and 401 challenge use exact path resource', async () => {
  const { app } = harness();
  const metadata = await app.fetch(request('http://localhost:8787/.well-known/oauth-protected-resource/mcp',
    { method: 'GET', token: null }), ctx);
  assert.equal(metadata.status, 200);
  const body = await metadata.json();
  assert.equal(body.resource, RESOURCE);
  assert.deepEqual(body.authorization_servers, [ISSUER]);
  assert.deepEqual(body.scopes_supported, ['mcp:read']);

  const unauthorized = await app.fetch(request(RESOURCE, { token: null }), ctx);
  assert.equal(unauthorized.status, 401);
  const challenge = unauthorized.headers.get('www-authenticate');
  assert.match(challenge, /^Bearer /);
  assert.match(challenge, /resource_metadata="http:\/\/localhost:8787\/\.well-known\/oauth-protected-resource\/mcp"/);
  assert.match(challenge, /scope="mcp:read"/);
});

test('trial PAT is rejected before auth RPC, and wrong host or Origin are denied', async () => {
  let authCalls = 0;
  const auth = { async validateToken() { authCalls++; return null; } };
  const { app, audits } = harness({ auth });
  const pat = `cm_${'a'.repeat(64)}`;
  assert.equal((await app.fetch(request(RESOURCE, { token: pat }), ctx)).status, 401);
  assert.equal(authCalls, 0);
  assert.equal((await app.fetch(request(RESOURCE, { headers: { host: 'evil.invalid' } }), ctx)).status, 403);
  assert.equal((await app.fetch(request(RESOURCE, { origin: 'https://evil.invalid' }), ctx)).status, 403);
  assert.equal((await app.fetch(request('http://localhost:8787/mcp/extra'), ctx)).status, 404);
  assert.equal(authCalls, 0);
  assert.deepEqual(audits, [
    { reason: 'invalid_bearer', authenticated: false },
    { reason: 'request_denied', authenticated: false },
    { reason: 'request_denied', authenticated: false },
    { reason: 'invalid_request', authenticated: false },
  ]);
});

test('authenticated denial attribution is request scoped', async () => {
  const { app, audits } = harness();
  assert.equal((await app.fetch(request(RESOURCE, { body: rpc('tools/call', {
    name: 'unknown_tool', arguments: {},
  }) }), ctx)).status, 400);
  assert.equal((await app.fetch(request(RESOURCE, { token: null }), ctx)).status, 401);
  assert.deepEqual(audits, [
    { reason: 'invalid_request', authenticated: true },
    { reason: 'invalid_bearer', authenticated: false },
  ]);
});

test('denial audit is awaited and its failure leaves a safe 503', async () => {
  const app = createCustomerMcpWorker({ auth: authFixture(), backend: backendFixture(),
    resource: RESOURCE, issuer: ISSUER, oauthRuntime,
    auditDenial: async () => { throw new Error('private-audit-error'); } });
  const response = await app.fetch(request(RESOURCE, { token: null }), ctx);
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: 'mcp_not_configured' });
});

test('wrong audience, expired token, and missing read scope fail before backend', async () => {
  let calls = 0;
  const backend = backendFixture({ listWorkspaces() { calls++; return null; } });
  for (const override of [
    { audience: 'http://localhost:8787/other' },
    { expiresAt: Math.floor(Date.now() / 1000) - 1 },
    { scope: [] },
  ]) {
    const { app } = harness({ auth: authFixture(override), backend });
    const response = await app.fetch(request(), ctx);
    assert.equal(response.status, override.scope ? 403 : 401);
  }
  assert.equal(calls, 0);
});

test('all fourteen customer tools are read only and backend receives only bearer and typed args', async () => {
  const calls = [];
  const backend = backendFixture({
    getWorkspaceSummary(args) { calls.push(args); return fixtureSummary(); },
  });
  const { app } = harness({ backend });
  const list = await app.fetch(request(RESOURCE, { body: rpc('tools/list') }), ctx);
  assert.equal(list.status, 200);
  const listed = await protocolJson(list);
  assert.equal(listed.result.tools.length, 14);
  assert.ok(listed.result.tools.every((tool) => tool.annotations.readOnlyHint === true &&
    tool.annotations.destructiveHint === false));
  assert.equal(JSON.stringify(listed.result.tools).includes('Fixture Workspace'), false);
  assert.equal(JSON.stringify(listed.result.tools).includes('ignore previous instructions'), false);
  const body = rpc('tools/call', { name: 'cybermeters_get_workspace_summary',
    arguments: { workspace_id: workspaceId } });
  const response = await app.fetch(request(RESOURCE, { body }), ctx);
  const called = await protocolJson(response);
  assert.equal(response.status, 200);
  assert.equal(called.result.isError, undefined);
  assert.deepEqual(calls, [{ bearer: TOKEN, workspaceId }]);
  assert.equal(JSON.stringify(called).includes(TOKEN), false);
  assert.equal(JSON.stringify(called).includes('fixture-secret-must-not-escape'), false);
});

test('standard initialize handshake and omitted workspace on bound token work', async () => {
  const calls = [];
  const backend = backendFixture({ getWorkspaceSummary(args) {
    calls.push(args);
    return fixtureSummary();
  } });
  const { app } = harness({ backend });
  const initialize = await app.fetch(request(RESOURCE, { body: rpc('initialize', {
    protocolVersion: '2026-07-28', capabilities: {},
    clientInfo: { name: 'customer-compat-test', version: '1.0.0' },
  }) }), ctx);
  assert.equal(initialize.status, 200);
  const hello = await protocolJson(initialize);
  assert.equal(hello.result.serverInfo.name, 'cybermeters-mcp');
  const response = await app.fetch(request(RESOURCE, { body: rpc('tools/call', {
    name: 'cybermeters_get_workspace_summary', arguments: {},
  }) }), ctx);
  const called = await protocolJson(response);
  assert.equal(called.result.isError, undefined);
  assert.deepEqual(calls, [{ bearer: TOKEN }]);
});

test('portfolio finding read requires portfolio scope before backend RPC', async () => {
  let calls = 0;
  const backend = backendFixture({ listFindings() { calls++; return null; } });
  const { app } = harness({ backend });
  const body = rpc('tools/call', { name: 'cybermeters_list_findings',
    arguments: { scope: 'portfolio' } });
  const response = await app.fetch(request(RESOURCE, { body }), ctx);
  assert.equal(response.status, 403);
  assert.match(response.headers.get('www-authenticate'), /portfolio:read/);
  assert.equal(calls, 0);
});

test('portfolio summary requires portfolio consent before private RPC', async () => {
  let calls = 0;
  const { app } = harness({ backend: backendFixture({
    getPortfolioSummary() { calls += 1; return null; },
  }) });
  const response = await app.fetch(request(RESOURCE, { body: rpc('tools/call', {
    name: 'cybermeters_get_portfolio_summary', arguments: {},
  }) }), ctx);
  assert.equal(response.status, 403);
  assert.match(response.headers.get('www-authenticate'), /portfolio:read/);
  assert.equal(calls, 0);
});

test('portfolio summary projection whitelists only bounded evidence-honest workspace states', () => {
  const raw = { scope: 'portfolio', selected_workspace_count: 2,
    workspaces: [fixtureSummary(), fixtureSummary({ workspace_id: OTHER_WORKSPACE,
      display_name: 'Other selected workspace', score_state: 'not_assessed',
      score_value: null, evidence_state: 'insufficient', coverage_state: 'not_assessed',
      latest_measurement_at: null, limitations: ['No complete assessment.'],
    })], limit: 5, has_more: false, next_cursor: null,
    coverage_state: 'not_proven_complete', private_note: 'do-not-disclose' };
  const projected = JSON.parse(projectCustomerPortfolioSummary(raw));
  assert.equal(projected.workspaces.length, 2);
  assert.equal(projected.workspaces[1].score_value, null);
  assert.equal(projected.coverage_state, 'not_proven_complete');
  assert.deepEqual(projected.untrusted_fields,
    ['workspaces[].display_name', 'workspaces[].limitations']);
  assert.equal(JSON.stringify(projected).includes('do-not-disclose'), false);
  raw.workspaces[1].score_state = 'assessed';
  assert.throws(() => projectCustomerPortfolioSummary(raw));
});

test('authorised portfolio summary sends only bearer and page cursor to private RPC', async () => {
  const calls = [];
  const auth = authFixture({
    props: { userId: 'fixture-user', connectionId: 'fixture-connection',
      workspaceId: null, portfolioRead: true },
    scope: ['mcp:read', 'portfolio:read'],
  });
  const backend = backendFixture({ getPortfolioSummary(args) {
    calls.push(args);
    return { scope: 'portfolio', selected_workspace_count: 1,
      workspaces: [fixtureSummary()], limit: 5, has_more: false,
      next_cursor: null, coverage_state: 'not_proven_complete' };
  } });
  const { app } = harness({ auth, backend });
  const response = await app.fetch(request(RESOURCE, { body: rpc('tools/call', {
    name: 'cybermeters_get_portfolio_summary', arguments: { cursor: workspaceId },
  }) }), ctx);
  assert.equal(response.status, 200);
  const body = await protocolJson(response);
  assert.equal(body.result.isError, undefined);
  assert.deepEqual(calls, [{ bearer: TOKEN, cursor: workspaceId }]);
  const result = JSON.parse(body.result.content[0].text);
  assert.equal(result.workspaces[0].workspace_id, workspaceId);
});

test('foreign and nonexistent scan and case IDs have identical safe responses', async () => {
  const backend = backendFixture({
    getScanStatus({ scanId }) {
      if (scanId === 'scan_fixture_1') return { workspace_id: workspaceId, ...fixtureScan() };
      throw new Error('private lookup failed');
    },
    getManagedCase({ caseId }) {
      if (caseId === 'case_fixture_1') return { workspace_id: workspaceId, ...fixtureCases().cases[0] };
      throw new Error('private lookup failed');
    },
  });
  const { app } = harness({ backend });
  const call = async (name, args) => {
    const response = await app.fetch(request(RESOURCE, { body: rpc('tools/call', {
      name, arguments: args,
    }) }), ctx);
    return { status: response.status, body: await protocolJson(response) };
  };
  const foreignScan = await call('cybermeters_get_scan_status',
    { workspace_id: workspaceId, scan_id: 'scan_foreign' });
  const missingScan = await call('cybermeters_get_scan_status',
    { workspace_id: workspaceId, scan_id: 'scan_missing' });
  assert.deepEqual(foreignScan, missingScan);
  const foreignCase = await call('cybermeters_get_managed_case',
    { workspace_id: workspaceId, case_id: 'case_foreign' });
  const missingCase = await call('cybermeters_get_managed_case',
    { workspace_id: workspaceId, case_id: 'case_missing' });
  assert.deepEqual(foreignCase, missingCase);
  assert.equal(foreignCase.status, 200);
  assert.equal(foreignCase.body.result.isError, true);
  const ownCase = await call('cybermeters_get_managed_case',
    { workspace_id: workspaceId, case_id: 'case_fixture_1' });
  assert.equal(ownCase.body.result.isError, undefined);
  assert.equal(JSON.parse(ownCase.body.result.content[0].text).case.case_id, 'case_fixture_1');
});

test('domain and finding projections drop unknown fields and reject foreign workspace rows', () => {
  const backend = backendFixture();
  const domain = JSON.parse(projectCustomerDomains(backend.listDomains(), workspaceId));
  const finding = JSON.parse(projectCustomerFindings(backend.listFindings(), workspaceId));
  assert.equal(JSON.stringify(domain).includes('do-not-disclose'), false);
  assert.equal(JSON.stringify(finding).includes('do-not-disclose'), false);
  const foreignDomain = backend.listDomains();
  foreignDomain.domains[0].workspace_id = OTHER_WORKSPACE;
  assert.throws(() => projectCustomerDomains(foreignDomain, workspaceId));
  const foreignFinding = backend.listFindings();
  foreignFinding.findings[0].workspace_id = OTHER_WORKSPACE;
  assert.throws(() => projectCustomerFindings(foreignFinding, workspaceId));
});

test('finding, TLS, email, and report projections whitelist customer fields', () => {
  const at = '2026-10-15T10:00:00Z';
  const explanation = { workspace_id: workspaceId, finding_id: 'finding_fixture_1',
    domain_id: 'domain_fixture_1', domain: 'example.invalid',
    source_scan_id: 'scan_fixture_1', source_scan_created_at: at,
    status: 'available', finding: { type: 'tls_expiry', title: 'Certificate expires soon',
      severity: 'high', evidence_grade: 'L3', evidence_state: 'authoritative',
      evidence_count: 2, verification_support: 'automated',
      verification_ceiling: 'Can be verified by CyberMeters re-observation.',
      source_report_state: 'integrity_verified_snapshot',
      private_note: 'do-not-disclose' }, remediation: { status: 'resolved',
      remediation_id: 'renew_certificate', version: '1', domain_key: 'certificates_trust',
      title: 'Renew certificate', technical_explanation: 'A trusted certificate expires soon.',
      business_impact: 'Visitors may see warnings.', recommended_action: 'Renew and verify.',
      verification_method: 'automated', limitations: ['Expiry only.'],
      private_note: 'do-not-disclose' },
    field_guide: { version: '2026-10-15.1', path: '/guide/certificates-trust',
      url: 'https://app.cybermeters.com/guide/certificates-trust' },
    private_note: 'do-not-disclose' };
  const signal = { state: 'observed', check_outcome: 'passed', private_note: 'do-not-disclose' };
  const tls = { workspace_id: workspaceId, status: 'available',
    certificates: [{ workspace_id: workspaceId,
      certificate_lifecycle_id: 'certificate_fixture_1', domain_id: 'domain_fixture_1',
      primary_hostname: 'example.invalid', not_after: at, days_remaining: 30,
      renewal_readiness: 'ready', coverage_status: 'complete',
      verification_status: 'verified', last_seen_at: at,
      assurance_status: 'current', signals: { leaf: signal, expiry: signal,
        hostname_match: signal, trust_store_validation: signal,
        revocation_assurance: signal }, private_note: 'do-not-disclose' }],
    limit: 10, has_more: false, next_cursor: null,
    coverage_state: 'not_proven_complete' };
  const email = { workspace_id: workspaceId, status: 'available',
    domains: [{ workspace_id: workspaceId, domain_id: 'domain_fixture_1',
      domain: 'example.invalid', source_scan_id: 'scan_fixture_1',
      source_scan_created_at: at, status: 'available',
      email_domain_state: 'issue_detected', evidence_grade: 'L2',
      dmarc: { evidence_status: 'current', observation_state: 'observed',
        record_validity: 'valid', effective_requested_policy: 'reject',
        policy_completeness: 'complete', private_note: 'do-not-disclose' },
      spf: { observation_state: 'observed', present: true,
        resolution_status: 'complete', private_note: 'do-not-disclose' },
      dkim: { observation_state: 'unknown', private_note: 'do-not-disclose' },
    }], limit: 10, has_more: false, next_cursor: null,
    coverage_state: 'not_proven_complete' };
  const report = { workspace_id: workspaceId, status: 'available',
    report_scope: 'single_scan', source_scan_id: 'scan_fixture_1',
    domain_id: 'domain_fixture_1', domain: 'example.invalid', assessed_at: at,
    scan_quality: 'complete', score: { value: 72, rating: 'good',
      quality: 'complete', authoritative: true, provisional: false, comparable: true,
      private_note: 'do-not-disclose' }, summary: 'Some controls need attention.',
    observed_findings_count: 2, priority_actions: [{ remediation_id: 'renew_certificate',
      priority: 'high', title: 'Renew certificate', action: 'Renew and verify.',
      verification_support: 'automated',
      verification_ceiling: 'Can be verified by CyberMeters re-observation.',
      private_note: 'do-not-disclose' }], coverage_state: 'not_proven_complete',
    private_note: 'do-not-disclose' };
  for (const projected of [
    projectCustomerFindingExplanation(explanation, workspaceId, 'finding_fixture_1'),
    projectCustomerTlsPosture(tls, workspaceId),
    projectCustomerEmailPosture(email, workspaceId),
    projectCustomerReportSummary(report, workspaceId),
  ]) {
    assert.equal(projected.includes('do-not-disclose'), false);
    assert.equal(JSON.parse(projected).workspace_id, workspaceId);
  }
  assert.throws(() => projectCustomerFindingExplanation(explanation, workspaceId, 'foreign_finding'));
  tls.certificates[0].workspace_id = OTHER_WORKSPACE;
  assert.throws(() => projectCustomerTlsPosture(tls, workspaceId));
  email.domains[0].workspace_id = OTHER_WORKSPACE;
  assert.throws(() => projectCustomerEmailPosture(email, workspaceId));
});
