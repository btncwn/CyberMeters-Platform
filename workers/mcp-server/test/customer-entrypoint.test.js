import assert from 'node:assert/strict';
import test from 'node:test';
import worker, { logCustomerGatewayEvent, resolveCustomerMcpDeployment } from '../src/index.js';
import { CUSTOMER_RPC_METHODS } from '../src/customer-mcp.js';

const STAGING = Object.freeze({
  MCP_DEPLOYMENT_TIER: 'staging',
  MCP_STAGING_ISSUER: 'https://api-staging.cybermeters.com',
  MCP_STAGING_RESOURCE: 'https://mcp-staging.cybermeters.com/mcp',
  MCP_STAGING_APP_ORIGIN: 'https://app-staging.cybermeters.com',
});

function fixtureEnv(overrides = {}) {
  const denials = [];
  const rateKeys = [];
  const backend = Object.fromEntries(CUSTOMER_RPC_METHODS.map((method) =>
    [method, async () => { throw new Error('unexpected_customer_read'); }]));
  backend.recordGatewayDenial = async (entry) => { denials.push(entry); return true; };
  const allow = { async limit({ key }) { rateKeys.push(key); return { success: true }; } };
  return { denials, rateKeys, env: { MCP_CUSTOMER_ENABLED: 'true',
    MCP_EDGE_CLIENT_RATE: allow, MCP_EDGE_GLOBAL_RATE: allow,
    MCP_AUTH: { validateToken: async () => null }, MCP_CUSTOMER_BACKEND: backend,
    ...overrides } };
}

test('customer staging host is selected only by exact tier and all three fixed URLs', () => {
  assert.deepEqual(resolveCustomerMcpDeployment({}), {
    issuer: 'https://api.cybermeters.com',
    resource: 'https://mcp.cybermeters.com/mcp',
    appOrigin: 'https://app.cybermeters.com',
  });
  assert.deepEqual(resolveCustomerMcpDeployment(STAGING), {
    issuer: STAGING.MCP_STAGING_ISSUER,
    resource: STAGING.MCP_STAGING_RESOURCE,
    appOrigin: STAGING.MCP_STAGING_APP_ORIGIN,
  });
  assert.deepEqual(resolveCustomerMcpDeployment({ MCP_DEPLOYMENT_TIER: 'staging' }), {
    issuer: STAGING.MCP_STAGING_ISSUER,
    resource: STAGING.MCP_STAGING_RESOURCE,
    appOrigin: STAGING.MCP_STAGING_APP_ORIGIN,
  });
  for (const bad of [
    { MCP_STAGING_RESOURCE: STAGING.MCP_STAGING_RESOURCE },
    { ...STAGING, MCP_DEPLOYMENT_TIER: 'production' },
    { ...STAGING, MCP_DEPLOYMENT_TIER: 'preview' },
    { ...STAGING, MCP_STAGING_ISSUER: 'https://attacker.example' },
    { ...STAGING, MCP_STAGING_RESOURCE: 'http://mcp-staging.cybermeters.com/mcp' },
    { ...STAGING, MCP_STAGING_RESOURCE: 'https://mcp-staging.cybermeters.com/other' },
    { ...STAGING, MCP_STAGING_APP_ORIGIN: 'https://app-staging.cybermeters.com.evil.invalid' },
  ]) assert.equal(resolveCustomerMcpDeployment(bad), null);
});

test('mismatched staging configuration denies before a customer RPC or OAuth load', async () => {
  const { env, denials } = fixtureEnv({ ...STAGING, MCP_STAGING_APP_ORIGIN: 'https://evil.invalid' });
  const response = await worker.fetch(new Request(STAGING.MCP_STAGING_RESOURCE), env);
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: 'mcp_not_configured' });
  assert.deepEqual(denials, []);
});

test('staging gateway enforces its host and records content-free denial and latency', async () => {
  const { env, denials, rateKeys } = fixtureEnv(STAGING);
  const original = console.log;
  const logs = [];
  console.log = (line) => logs.push(JSON.parse(line));
  try {
    const response = await worker.fetch(new Request(STAGING.MCP_STAGING_RESOURCE, {
      method: 'POST', headers: { host: 'mcp-staging.cybermeters.com',
        'CF-Connecting-IP': '203.0.113.8',
        origin: 'https://evil.invalid', 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    }), env);
    assert.equal(response.status, 403);
  } finally { console.log = original; }
  assert.deepEqual(denials, [{ reason: 'request_denied' }]);
  assert.ok(logs.some((entry) => entry.event === 'request_denied'));
  assert.ok(logs.some((entry) => entry.event === 'request_completed' &&
    entry.status_class === '4xx' && typeof entry.latency_bucket === 'string'));
  assert.ok(logs.every((entry) => JSON.stringify(entry).includes('evil.invalid') === false));
  assert.equal(rateKeys.length, 2);
  assert.ok(rateKeys.some((key) => /^mcp_customer_ip:[a-f0-9]{64}$/.test(key)));
  assert.ok(rateKeys.every((key) => !key.includes('203.0.113.8') && !key.includes('Bearer')));
});

test('missing or failing edge limiter denies without writing to D1 audit', async () => {
  const url = STAGING.MCP_STAGING_RESOURCE;
  const request = () => new Request(url, { method: 'POST', headers: {
    host: 'mcp-staging.cybermeters.com', 'CF-Connecting-IP': '203.0.113.8',
    origin: 'https://evil.invalid', 'content-type': 'application/json',
  }, body: '{}' });
  for (const override of [
    { MCP_EDGE_CLIENT_RATE: undefined },
    { MCP_EDGE_GLOBAL_RATE: undefined },
    { MCP_EDGE_CLIENT_RATE: { limit: async () => { throw new Error('rate_down'); } } },
  ]) {
    const { env, denials } = fixtureEnv({ ...STAGING, ...override });
    const response = await worker.fetch(request(), env);
    assert.equal(response.status, 503);
    assert.deepEqual(denials, []);
  }
  const { env, denials } = fixtureEnv({ ...STAGING,
    MCP_EDGE_CLIENT_RATE: { limit: async () => ({ success: false }) },
  });
  const response = await worker.fetch(request(), env);
  assert.equal(response.status, 429);
  assert.equal(response.headers.get('retry-after'), '60');
  assert.deepEqual(denials, []);
});

test('gateway logger ignores dynamic event names and emits only bounded fields', () => {
  const original = console.log;
  const logs = [];
  console.log = (line) => logs.push(JSON.parse(line));
  try {
    logCustomerGatewayEvent('Bearer secret-customer-token');
    logCustomerGatewayEvent('request_completed', {
      status: 200, durationMs: 117, bearer: 'secret-customer-token',
      domain: 'private.example',
    });
  } finally { console.log = original; }
  assert.deepEqual(logs, [{ component: 'mcp_customer_gateway',
    event: 'request_completed', status_class: '2xx', latency_bucket: '100_499ms' }]);
});
