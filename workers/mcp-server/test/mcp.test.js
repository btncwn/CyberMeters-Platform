import assert from 'node:assert/strict';
import test from 'node:test';
import worker, { createLocalTestWorker } from '../src/index.js';
import { projectWorkspaceSummary } from '../src/local-mcp.js';
import { fixtureSummary, workspaceId } from './fixture.js';

const TOOL = 'cybermeters_get_workspace_summary';
const BASE = 'http://localhost:8787/mcp';
const TRIAL_BEARER = `cm_${'a'.repeat(64)}`;

function rpc(method, params = {}, id = 1) {
  return { jsonrpc: '2.0', id, method, params: {
    ...params,
    _meta: {
      'io.modelcontextprotocol/protocolVersion': '2026-07-28',
      'io.modelcontextprotocol/clientCapabilities': {},
    },
  } };
}

function request(message, { url = BASE, method = 'POST', host = 'localhost:8787', origin,
  protocol = '2026-07-28', mcpMethod = message?.method, name = message?.params?.name,
  rawBody, extraHeaders = {} } = {}) {
  const headers = { host, 'content-type': 'application/json', 'mcp-protocol-version': protocol,
    'mcp-method': mcpMethod, ...extraHeaders };
  if (name) headers['mcp-name'] = name;
  if (origin !== undefined) headers.origin = origin;
  return new Request(url, { method, headers,
    ...(method === 'POST' ? { body: rawBody ?? JSON.stringify(message) } : {}) });
}

function harness(overrides = {}) {
  const events = [];
  const calls = [];
  const backend = { async getWorkspaceSummary(args) {
    calls.push({ workspaceId: args.workspaceId, hasSignal: args.signal instanceof AbortSignal });
    if (overrides.hang) return new Promise(() => {});
    if (overrides.failure) throw new Error('fixture-secret-error');
    return fixtureSummary(overrides.summary);
  } };
  return { app: createLocalTestWorker({
    backend, onEvent: (event) => events.push(event), backendTimeoutMs: overrides.timeoutMs,
  }), events, calls };
}

async function responseJson(response) {
  return JSON.parse(await response.text());
}

test('default deployed fetch stays fail-closed even when passed a backend-like environment', async () => {
  const response = await worker.fetch(request(rpc('tools/list')), {
    backend: { getWorkspaceSummary: () => fixtureSummary() },
  });
  assert.equal(response.status, 503);
  assert.deepEqual(await responseJson(response), { error: 'mcp_not_configured' });
  assert.throws(() => createLocalTestWorker(), /local test backend/);
});

test('default entrypoint needs both explicit enablement and the named RPC binding', async () => {
  const message = request(rpc('tools/call', {
    name: TOOL, arguments: { workspace_id: workspaceId },
  }), { extraHeaders: { authorization: `Bearer ${TRIAL_BEARER}` } });
  let calls = 0;
  const binding = { getWorkspaceSummary() { calls++; return fixtureSummary(); } };
  for (const env of [undefined, {}, { MCP_INTERNAL_ENABLED: 'true' },
    { MCP_BACKEND: binding }, { MCP_INTERNAL_ENABLED: true, MCP_BACKEND: binding },
    { MCP_INTERNAL_ENABLED: 'false', MCP_BACKEND: binding },
    { MCP_INTERNAL_ENABLED: 'true', MCP_BACKEND: { fetch() {} } }]) {
    const response = await worker.fetch(message, env);
    assert.equal(response.status, 503);
    assert.deepEqual(await responseJson(response), { error: 'mcp_not_configured' });
  }
  assert.equal(calls, 0);
});

test('enabled local entrypoint passes only request bearer and workspace ID through RPC', async () => {
  const calls = [];
  const env = { MCP_INTERNAL_ENABLED: 'true', MCP_BACKEND: {
    getWorkspaceSummary(args) { calls.push(args); return fixtureSummary(); },
  } };
  const response = await worker.fetch(request(rpc('tools/call', {
    name: TOOL, arguments: { workspace_id: workspaceId },
  }), { extraHeaders: { authorization: `Bearer ${TRIAL_BEARER}` } }), env);
  const body = await responseJson(response);
  assert.equal(response.status, 200);
  assert.equal(body.result.isError, undefined);
  assert.deepEqual(calls, [{ bearer: TRIAL_BEARER, workspaceId }]);
  assert.equal(JSON.parse(body.result.content[0].text).workspace_id, workspaceId);
  assert.equal(JSON.stringify(body).includes(TRIAL_BEARER), false);
});

test('parallel local calls keep their bearers request scoped', async () => {
  const calls = [];
  const otherBearer = `cm_${'b'.repeat(64)}`;
  const env = { MCP_INTERNAL_ENABLED: 'true', MCP_BACKEND: {
    async getWorkspaceSummary(args) {
      calls.push(args);
      await new Promise((resolve) => setTimeout(resolve, 1));
      return fixtureSummary();
    },
  } };
  const makeCall = (bearer) => worker.fetch(request(rpc('tools/call', {
    name: TOOL, arguments: { workspace_id: workspaceId },
  }), { extraHeaders: { authorization: `Bearer ${bearer}` } }), env);
  const responses = await Promise.all([makeCall(TRIAL_BEARER), makeCall(otherBearer)]);
  for (const response of responses) assert.equal((await responseJson(response)).result.isError, undefined);
  assert.deepEqual(calls, [
    { bearer: TRIAL_BEARER, workspaceId },
    { bearer: otherBearer, workspaceId },
  ]);
});

test('absent, session-like, malformed, and oversized bearer values never reach RPC', async () => {
  let calls = 0;
  const env = { MCP_INTERNAL_ENABLED: 'true', MCP_BACKEND: {
    getWorkspaceSummary() { calls++; return fixtureSummary(); },
  } };
  const input = rpc('tools/call', { name: TOOL, arguments: { workspace_id: workspaceId } });
  for (const authorization of [undefined, 'Bearer ' + 'a'.repeat(64),
    'Bearer cm_short', 'Bearer cm_' + 'g'.repeat(64),
    'Bearer cm_' + 'a'.repeat(65), `Bearer  ${TRIAL_BEARER}`,
    `Basic ${TRIAL_BEARER}`, `Bearer ${TRIAL_BEARER} extra`]) {
    const response = await worker.fetch(request(input, {
      extraHeaders: authorization === undefined ? {} : { authorization },
    }), env);
    assert.equal(response.status, 401);
    assert.deepEqual(await responseJson(response), { error: 'invalid_bearer' });
  }
  assert.equal(calls, 0);
});

test('invalid workspace, foreign denial, and foreign summary never disclose backend data', async () => {
  const calls = [];
  const secret = 'foreign-private-data';
  const env = { MCP_INTERNAL_ENABLED: 'true', MCP_BACKEND: {
    getWorkspaceSummary(args) {
      calls.push(args);
      if (calls.length === 1) throw new Error(secret);
      return fixtureSummary({ workspace_id: 'foreign-workspace', private_note: secret });
    },
  } };
  for (const badId of ['../foreign', 'x'.repeat(65)]) {
    const response = await worker.fetch(request(rpc('tools/call', {
      name: TOOL, arguments: { workspace_id: badId },
    }), { extraHeaders: { authorization: `Bearer ${TRIAL_BEARER}` } }), env);
    const body = await responseJson(response);
    assert.ok(response.status >= 400 || body.error || body.result?.isError);
  }
  assert.equal(calls.length, 0);
  for (let i = 0; i < 2; i++) {
    const response = await worker.fetch(request(rpc('tools/call', {
      name: TOOL, arguments: { workspace_id: workspaceId },
    }), { extraHeaders: { authorization: `Bearer ${TRIAL_BEARER}` } }), env);
    const body = await responseJson(response);
    assert.equal(body.result.isError, true);
    assert.equal(body.result.content[0].text, 'workspace_summary_unavailable');
    assert.equal(JSON.stringify(body).includes(secret), false);
    assert.equal(JSON.stringify(body).includes(TRIAL_BEARER), false);
  }
  assert.equal(calls.length, 2);
});

test('RPC failure and response deadline return safe errors', async () => {
  for (const getWorkspaceSummary of [
    () => Promise.reject(new Error('backend-secret-failure')),
    () => new Promise(() => {}),
  ]) {
    const response = await worker.fetch(request(rpc('tools/call', {
      name: TOOL, arguments: { workspace_id: workspaceId },
    }), { extraHeaders: { authorization: `Bearer ${TRIAL_BEARER}` } }), {
      MCP_INTERNAL_ENABLED: 'true', MCP_BACKEND: { getWorkspaceSummary },
    });
    const body = await responseJson(response);
    assert.equal(body.result.isError, true);
    assert.equal(body.result.content[0].text, 'workspace_summary_unavailable');
    assert.equal(JSON.stringify(body).includes('backend-secret-failure'), false);
    assert.equal(JSON.stringify(body).includes(TRIAL_BEARER), false);
  }
});

test('enabled entrypoint still requires exact local host, origin, and path', async () => {
  let calls = 0;
  const env = { MCP_INTERNAL_ENABLED: 'true', MCP_BACKEND: {
    getWorkspaceSummary() { calls++; return fixtureSummary(); },
  } };
  const input = rpc('tools/call', { name: TOOL, arguments: { workspace_id: workspaceId } });
  for (const options of [
    { host: 'evil.invalid' }, { origin: 'https://evil.invalid' },
    { url: 'http://localhost:8787/mcp/extra' },
  ]) {
    const response = await worker.fetch(request(input, {
      ...options, extraHeaders: { authorization: `Bearer ${TRIAL_BEARER}` },
    }), env);
    assert.ok(response.status >= 400);
  }
  const cfRequest = request(input, { extraHeaders: { authorization: `Bearer ${TRIAL_BEARER}` } });
  Object.defineProperty(cfRequest, 'cf', { value: {}, configurable: true });
  assert.equal((await worker.fetch(cfRequest, env)).status, 200);
  assert.equal(calls, 1);
});

test('modern discovery, single-tool list, and fixture-backed call use JSON mode', async () => {
  const { app, calls, events } = harness();
  const discover = await app.fetch(request(rpc('server/discover')));
  assert.equal(discover.status, 200);
  const discovered = await responseJson(discover);
  assert.equal(discovered.jsonrpc, '2.0');
  assert.ok(discovered.result);

  const listed = await app.fetch(request(rpc('tools/list')));
  assert.equal(listed.status, 200);
  const listedBody = await responseJson(listed);
  assert.deepEqual(listedBody.result.tools.map((tool) => tool.name), [TOOL]);
  const tool = listedBody.result.tools[0];
  assert.equal(tool.annotations.readOnlyHint, true);
  assert.equal(tool.annotations.destructiveHint, false);
  assert.equal(tool.annotations.idempotentHint, true);
  assert.equal(tool.inputSchema.additionalProperties, false);

  const called = await app.fetch(request(rpc('tools/call', {
    name: TOOL, arguments: { workspace_id: workspaceId },
  })));
  assert.equal(called.status, 200);
  const calledBody = await responseJson(called);
  assert.equal(calledBody.result.isError, undefined);
  const projected = JSON.parse(calledBody.result.content[0].text);
  assert.deepEqual(calls, [{ workspaceId, hasSignal: true }]);
  assert.deepEqual(Object.keys(projected), [
    'data_classification', 'untrusted_fields',
    'workspace_id', 'display_name', 'score_state', 'score_value',
    'latest_measurement_at', 'evidence_state', 'coverage_state', 'limitations', 'ui_path',
  ]);
  assert.equal(projected.ui_path, `/workspaces/${workspaceId}`);
  assert.equal(projected.score_value, 73);
  assert.equal(projected.data_classification, 'untrusted_customer_data');
  assert.deepEqual(projected.untrusted_fields, ['display_name', 'limitations']);
  assert.deepEqual(events, ['tool_success']);
  for (const forbidden of ['fixture-bearer', 'fixture-secret', 'fixture@example.invalid',
    'fixture-owner', 'fixture-raw', 'fixture-note']) {
    assert.equal(JSON.stringify(calledBody).includes(forbidden), false);
  }
});

test('legacy initialize is rejected and cannot invoke the backend', async () => {
  const { app, calls } = harness();
  const response = await app.fetch(request({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {
    protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1' },
  } }, { protocol: '2025-11-25' }));
  assert.ok(response.status >= 400 || (await responseJson(response)).error);
  assert.deepEqual(calls, []);
});

test('unknown tool, extra argument, and malformed workspace IDs never call backend', async () => {
  const { app, calls } = harness();
  const cases = [
    { name: 'unknown_tool', arguments: { workspace_id: workspaceId } },
    { name: TOOL, arguments: { workspace_id: workspaceId, url: 'https://example.invalid' } },
    { name: TOOL, arguments: { workspace_id: '../other' } },
    { name: TOOL, arguments: { workspace_id: 'x'.repeat(65) } },
    { name: TOOL, arguments: { workspace_id: 42 } },
  ];
  for (const params of cases) {
    const response = await app.fetch(request(rpc('tools/call', params)));
    const result = await responseJson(response);
    assert.ok(response.status >= 400 || result.error || result.result?.isError);
  }
  assert.deepEqual(calls, []);
});

test('local Host, Origin, route, method, and request-size gates fail closed', async () => {
  const { app, calls } = harness();
  const message = rpc('tools/list');
  const cases = [
    [request(message, { host: 'evil.invalid' }), 403],
    [request(message, { url: 'https://evil.invalid/mcp', host: 'evil.invalid' }), 403],
    [request(message, { origin: 'https://evil.invalid' }), 403],
    [request(message, { origin: 'null' }), 403],
    [request(message, { url: 'http://localhost:8787/mcp/extra' }), 404],
    [request(message, { url: 'http://localhost:8787/mcp?next=1' }), 404],
    [request(message, { method: 'GET' }), 405],
    [request(message, { rawBody: 'x'.repeat(4097) }), 413],
    [request(message, { rawBody: '{' }), 400],
  ];
  for (const [req, status] of cases) {
    const response = await app.fetch(req);
    assert.equal(response.status, status);
  }
  assert.deepEqual(calls, []);
});

test('local gate accepts Wrangler-style cf metadata and explicit IPv4 loopback', async () => {
  const { app } = harness();
  const cfRequest = request(rpc('tools/list'));
  Object.defineProperty(cfRequest, 'cf', { value: {}, configurable: true });
  assert.equal((await app.fetch(cfRequest)).status, 200);
  const loopback = request(rpc('tools/list'), {
    url: 'http://127.0.0.1:8787/mcp', host: '127.0.0.1:8787',
  });
  assert.equal((await app.fetch(loopback)).status, 200);
  const portMismatch = request(rpc('tools/list'), { host: 'localhost:9999' });
  assert.equal((await app.fetch(portMismatch)).status, 403);
});

test('backend failure and oversized text produce a safe tool error and content-free metrics', async () => {
  const input = rpc('tools/call', { name: TOOL, arguments: { workspace_id: workspaceId } });
  for (const options of [
    { failure: true, expectedEvent: 'backend_failure' },
    { summary: { display_name: 'X'.repeat(101) }, expectedEvent: 'projection_rejected' },
    { summary: { display_name: 'A'.repeat(100),
      limitations: Array.from({ length: 4 }, () => '界'.repeat(180)) }, expectedEvent: 'response_capped' },
  ]) {
    const { app, events } = harness(options);
    const response = await app.fetch(request(input));
    const body = await responseJson(response);
    assert.equal(body.result.isError, true);
    assert.equal(body.result.content[0].text, 'workspace_summary_unavailable');
    assert.deepEqual(events, [options.expectedEvent]);
    assert.equal(JSON.stringify(body).includes('fixture-secret'), false);
  }
});

test('backend timeout aborts the call and returns only a safe tool error', async () => {
  const { app, events } = harness({ hang: true, timeoutMs: 5 });
  const response = await app.fetch(request(rpc('tools/call', {
    name: TOOL, arguments: { workspace_id: workspaceId },
  })));
  const body = await responseJson(response);
  assert.equal(body.result.isError, true);
  assert.equal(body.result.content[0].text, 'workspace_summary_unavailable');
  assert.deepEqual(events, ['backend_timeout']);
});

test('projection enforces aggregate response cap and drops every unrelated backend field', () => {
  const valid = projectWorkspaceSummary(fixtureSummary(), workspaceId);
  assert.ok(new TextEncoder().encode(valid).byteLength <= 2048);
  for (const field of ['bearer', 'secret', 'email', 'owner_id', 'raw_response', 'private_note']) {
    assert.equal(valid.includes(field), false);
  }
  assert.throws(() => projectWorkspaceSummary(fixtureSummary({
    display_name: 'A'.repeat(100),
    limitations: Array.from({ length: 4 }, () => '界'.repeat(180)),
  }), workspaceId), /tool_result_too_large/);
  assert.throws(() => projectWorkspaceSummary(fixtureSummary({ workspace_id: 'other-workspace' }), workspaceId));
  assert.throws(() => projectWorkspaceSummary(fixtureSummary({ score_state: 'latest_incomplete', score_value: 73 }), workspaceId));
  assert.throws(() => projectWorkspaceSummary(fixtureSummary({ evidence_state: 'insufficient' }), workspaceId), /invalid_evidence_basis/);
  assert.throws(() => projectWorkspaceSummary(fixtureSummary({ coverage_state: 'partial' }), workspaceId), /invalid_evidence_basis/);
  assert.throws(() => projectWorkspaceSummary(fixtureSummary({ display_name: 'Unsafe\u202Ename' }), workspaceId));
  assert.throws(() => projectWorkspaceSummary(fixtureSummary({ display_name: TRIAL_BEARER }), workspaceId));
});
