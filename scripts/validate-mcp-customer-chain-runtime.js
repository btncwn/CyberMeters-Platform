#!/usr/bin/env node
// Disposable workerd proof: OAuth code -> private service bindings -> MCP read.
// The public HTTPS staging resource is mapped to localhost only inside this fixture.
import assert from 'node:assert/strict';
import { createHash, randomInt } from 'node:crypto';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const exec = promisify(execFile);
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const scanApi = join(repo, 'workers/scan-api');
const gatewayDir = join(repo, 'workers/mcp-server');
const wrangler = join(gatewayDir, 'node_modules/.bin/wrangler');
const resource = 'https://mcp-staging.cybermeters.com/mcp';
const hash = (value) => createHash('sha256').update(value).digest('hex');
const challenge = (value) => createHash('sha256').update(value).digest('base64url');
const methods = ['listWorkspaces', 'getWorkspaceSummary', 'getWorkspacePosture',
  'listRecentScans', 'getScanStatus', 'listManagedCases', 'getManagedCase', 'listDomains',
  'listFindings', 'explainFinding', 'getTlsPosture', 'getEmailPosture',
  'getReportSummary', 'getPortfolioSummary'];

async function main() {
  const temp = await mkdtemp(join(tmpdir(), 'cybermeters-mcp-chain-'));
  const port = randomInt(20_000, 45_000);
  const origin = `http://127.0.0.1:${port}`;
  const callback = `http://127.0.0.1:${port + 1}/callback`;
  const gatewayConfig = join(temp, 'gateway.json');
  const backendConfig = join(temp, 'backend.json');
  const gatewayFixture = join(temp, 'gateway.js');
  const backendFixture = join(temp, 'backend.js');
  const seedPath = join(temp, 'seed.sql');
  const state = join(temp, 'state');
  const commandEnv = { ...process.env, WRANGLER_SEND_METRICS: 'false',
    WRANGLER_LOG_PATH: join(temp, 'wrangler.log') };
  const sessionA = 'a'.repeat(64);
  const sessionB = 'b'.repeat(64);
  let server;
  try {
    const oauthRoute = join(scanApi, 'src/routes/mcp-oauth-server.js');
    const readRoute = join(scanApi, 'src/routes/mcp-customer-service.js');
    const gatewaySource = join(gatewayDir, 'src/customer-mcp.js');
    await writeFile(backendFixture, `import { WorkerEntrypoint } from 'cloudflare:workers';
import { handleMcpOAuthRequest, validateMcpOAuthToken } from ${JSON.stringify(oauthRoute)};
import { callMcpCustomerRead, recordMcpGatewayDenial } from ${JSON.stringify(readRoute)};
const opts = (env) => ({ issuer: env.TEST_ISSUER, resource: env.TEST_RESOURCE,
  appOrigin: env.TEST_ISSUER, testClientIp: '127.0.0.1' });
const validate = (env, resource, token) => validateMcpOAuthToken(env, resource, token, opts(env));
export class McpLocalAuthService extends WorkerEntrypoint {
  async validateToken(resource, token) { return validate(this.env, resource, token); }
}
export class McpLocalReadService extends WorkerEntrypoint {
  async recordGatewayDenial(input) { return recordMcpGatewayDenial(this.env, input); }
  ${methods.map((name) => `async ${name}(input) { return callMcpCustomerRead(this.env, '${name}', input, { validateToken: validate }); }`).join('\n  ')}
}
export default { async fetch(request, env, ctx) {
  return await handleMcpOAuthRequest(request, env, ctx, opts(env)) ??
    new Response('Not found', { status: 404 });
} };\n`);
    await writeFile(gatewayFixture, `import { createCustomerMcpWorker } from ${JSON.stringify(gatewaySource)};
const methods = ${JSON.stringify(methods)};
export default { async fetch(request, env, ctx) {
  const url = new URL(request.url);
  if (url.pathname === '/mcp' || url.pathname === '/.well-known/oauth-protected-resource/mcp') {
    const headers = new Headers(request.headers);
    headers.set('host', new URL(env.TEST_RESOURCE).host);
    const mapped = new Request(new URL(url.pathname, env.TEST_RESOURCE), {
      method: request.method, headers,
      ...(request.method === 'GET' || request.method === 'HEAD' ? {} : { body: request.body }),
    });
    const backend = Object.fromEntries(methods.map((name) =>
      [name, (input) => env.MCP_CUSTOMER_BACKEND[name](input)]));
    return createCustomerMcpWorker({ resource: env.TEST_RESOURCE,
      issuer: env.TEST_ISSUER, auth: env.MCP_AUTH, backend,
      auditDenial: (input) => env.MCP_CUSTOMER_BACKEND.recordGatewayDenial(input),
    }).fetch(mapped, ctx);
  }
  return env.MCP_OAUTH_HTTP.fetch(request);
} };\n`);
    await writeFile(gatewayConfig, JSON.stringify({
      name: 'cybermeters-mcp-chain-gateway', main: gatewayFixture,
      compatibility_date: '2026-06-18',
      compatibility_flags: ['nodejs_compat', 'global_fetch_strictly_public'],
      workers_dev: false,
      services: [
        { binding: 'MCP_OAUTH_HTTP', service: 'cybermeters-mcp-chain-backend', remote: false },
        { binding: 'MCP_AUTH', service: 'cybermeters-mcp-chain-backend',
          entrypoint: 'McpLocalAuthService', remote: false },
        { binding: 'MCP_CUSTOMER_BACKEND', service: 'cybermeters-mcp-chain-backend',
          entrypoint: 'McpLocalReadService', remote: false },
      ],
      vars: { TEST_RESOURCE: resource, TEST_ISSUER: origin },
    }));
    await writeFile(backendConfig, JSON.stringify({
      name: 'cybermeters-mcp-chain-backend', main: backendFixture,
      compatibility_date: '2026-06-18',
      compatibility_flags: ['global_fetch_strictly_public'], workers_dev: false,
      d1_databases: [{ binding: 'cybermeters_db', database_name: 'mcp-chain-disposable-local',
        database_id: '00000000-0000-4000-8000-000000000122' }],
      kv_namespaces: [{ binding: 'OAUTH_KV', id: '00000000000000000000000000000122' }],
      vars: { MCP_CUSTOMER_OAUTH_ENABLED: 'true', MCP_CUSTOMER_READ_ENABLED: 'true',
        MCP_DEPLOYMENT_TIER: 'staging', MCP_OAUTH_DCR_ENABLED: 'true',
        TEST_RESOURCE: resource, TEST_ISSUER: origin },
    }));
    const migration = await readFile(join(repo, 'database/migrations/121-mcp-oauth.sql'), 'utf8');
    const rate = await readFile(join(repo, 'database/migrations/026-api-rate-limits.sql'), 'utf8');
    const auditRetentionIndex = await readFile(join(repo,
      'database/migrations/122-audit-retention-index.sql'), 'utf8');
    const mcpRateRetentionIndex = await readFile(join(repo,
      'database/migrations/123-mcp-rate-retention-index.sql'), 'utf8');
    const selectedWorkspaces = await readFile(join(repo,
      'database/migrations/124-mcp-oauth-selected-workspaces.sql'), 'utf8');
    await writeFile(seedPath, `
      CREATE TABLE users(id TEXT PRIMARY KEY, status TEXT, email_verified INTEGER);
      CREATE TABLE workspaces(id TEXT PRIMARY KEY, name TEXT, deleted_at TEXT);
      CREATE TABLE workspace_members(id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT, role TEXT);
      CREATE TABLE user_sessions(id TEXT PRIMARY KEY, user_id TEXT, token_hash TEXT, expires_at TEXT);
      CREATE TABLE deletion_requests(id TEXT PRIMARY KEY, request_type TEXT, user_id TEXT,
        workspace_id TEXT, status TEXT);
      CREATE TABLE audit_events(id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT,
        actor_type TEXT, event_type TEXT, entity_type TEXT, entity_id TEXT,
        description TEXT, metadata_json TEXT, created_at TEXT);
      CREATE TABLE workspace_domains(workspace_id TEXT, domain_id TEXT);
      CREATE TABLE managed_cases(id TEXT, workspace_id TEXT, status TEXT);
      CREATE TABLE scans(id TEXT, workspace_id TEXT, domain_id TEXT, status TEXT,
        scan_quality TEXT, score INTEGER, rating TEXT, created_at TEXT);
      CREATE TABLE subscriptions(id TEXT PRIMARY KEY, owner_user_id TEXT,
        workspace_id TEXT, plan TEXT, status TEXT, subscription_status TEXT,
        trial_end TEXT, expires_at TEXT, current_period_end TEXT,
        payment_failed_at TEXT, stripe_subscription_id TEXT,
        created_at TEXT, updated_at TEXT);
      ${rate}\n${migration}\n${auditRetentionIndex}\n${mcpRateRetentionIndex}\n${selectedWorkspaces}
      INSERT INTO users VALUES ('u1','active',1),('u2','active',1);
      INSERT INTO workspaces VALUES ('w1','One',NULL),('w2','Two',NULL);
      INSERT INTO workspace_members VALUES ('wm1','w1','u1','viewer'),('wm2','w2','u2','viewer');
      INSERT INTO user_sessions VALUES ('s1','u1','${hash(sessionA)}','2099-01-01'),
        ('s2','u2','${hash(sessionB)}','2099-01-01');
      INSERT INTO mcp_beta_workspace_access(workspace_id,status)
        VALUES ('w1','enabled'),('w2','enabled');
      INSERT INTO subscriptions(id,owner_user_id,workspace_id,plan,status,
        subscription_status,trial_end,created_at) VALUES
        ('trial_u1','u1','w1','professional','trialing','trialing','2099-01-01','2026-01-01'),
        ('trial_u2','u2','w2','professional','trialing','trialing','2099-01-01','2026-01-01');
      INSERT INTO workspace_domains VALUES ('w1','d1'),('w2','d2'),('w2','d3');
      INSERT INTO managed_cases VALUES ('c1','w1','detected'),('c2','w2','detected'),
        ('c3','w2','detected');
    `);
    async function d1(sqlOrFile, isFile = false) {
      const args = ['d1', 'execute', 'mcp-chain-disposable-local', '--config', backendConfig,
        '--local', '--persist-to', state, isFile ? '--file' : '--command', sqlOrFile,
        '--yes', '--json'];
      let stdout;
      try {
        ({ stdout } = await exec(wrangler, args, { cwd: gatewayDir, env: commandEnv,
          timeout: 30_000, maxBuffer: 1024 * 1024 }));
      } catch (error) {
        throw new Error(`Local D1 fixture failed: ${error.stderr || error.stdout || error.message}`);
      }
      const result = JSON.parse(stdout);
      assert.equal(result[0]?.success, true, JSON.stringify(result));
      return result[0].results;
    }
    await d1(seedPath, true);
    server = spawn(wrangler, ['dev', '-c', gatewayConfig, '-c', backendConfig,
      '--local', '--ip', '127.0.0.1', '--port', String(port), '--inspector-port', '0',
      '--persist-to', state], { cwd: gatewayDir, env: commandEnv,
      stdio: ['ignore', 'pipe', 'pipe'] });
    let log = '';
    for (const stream of [server.stdout, server.stderr]) {
      stream.on('data', (data) => { log = (log + data.toString()).slice(-12_000); });
    }
    let ready = false;
    for (let attempt = 0; attempt < 100; attempt++) {
      if (server.exitCode !== null) throw new Error(`Workerd exited ${server.exitCode}: ${log}`);
      try {
        const response = await fetch(`${origin}/.well-known/oauth-authorization-server`);
        if (response.status === 200) { ready = true; break; }
      } catch { /* Workerd is starting. */ }
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 200));
    }
    if (!ready) throw new Error(`Workerd startup timed out: ${log}`);

    const registration = await fetch(`${origin}/oauth/register`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_name: 'Local MCP chain proof', redirect_uris: [callback],
        grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'],
        token_endpoint_auth_method: 'none' }),
    });
    assert.equal(registration.status, 201, await registration.clone().text());
    const { client_id: clientId } = await registration.json();
    assert.ok(clientId);
    async function connect(workspaceId, session, index) {
      const verifier = index.repeat(43);
      const authorize = new URL(`${origin}/authorize`);
      for (const [key, value] of Object.entries({ response_type: 'code', client_id: clientId,
        redirect_uri: callback, scope: 'mcp:read offline_access', state: `state-${index}`,
        code_challenge: challenge(verifier), code_challenge_method: 'S256', resource })) {
        authorize.searchParams.set(key, value);
      }
      const started = await fetch(authorize, { redirect: 'manual' });
      assert.equal(started.status, 302, await started.clone().text());
      const intent = new URL(started.headers.get('Location')).searchParams.get('intent');
      assert.ok(intent);
      const bridged = await fetch(`${origin}/api/mcp/oauth/browser-session`, {
        method: 'POST', headers: { Origin: origin, Authorization: `Bearer ${session}`,
          'Content-Type': 'application/json' }, body: JSON.stringify({ intent }),
      });
      assert.equal(bridged.status, 200, await bridged.clone().text());
      const bridgeCookie = bridged.headers.get('Set-Cookie').split(';')[0];
      const { continue_url: continueUrl } = await bridged.json();
      const consent = await fetch(continueUrl, { headers: { Cookie: bridgeCookie } });
      assert.equal(consent.status, 200, await consent.clone().text());
      const html = await consent.text();
      assert.match(html, new RegExp(`value="${workspaceId}"`));
      const handle = /name="handle" value="([^"]+)"/.exec(html)?.[1];
      const consentCookie = consent.headers.get('Set-Cookie')?.split(';')[0];
      assert.ok(handle && consentCookie);
      const approved = await fetch(continueUrl, { method: 'POST', redirect: 'manual',
        headers: { Origin: origin, Cookie: `${bridgeCookie}; ${consentCookie}`,
          'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ handle, decision: 'approve', context: workspaceId }),
      });
      assert.equal(approved.status, 302, await approved.clone().text());
      const code = new URL(approved.headers.get('Location')).searchParams.get('code');
      assert.ok(code);
      const exchanged = await fetch(`${origin}/oauth/token`, {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'authorization_code', code,
          client_id: clientId, redirect_uri: callback, code_verifier: verifier, resource }),
      });
      assert.equal(exchanged.status, 200, await exchanged.clone().text());
      const issued = await exchanged.json();
      assert.ok(issued.access_token);
      return issued.access_token;
    }
    function rpc(method, params = {}, id = 1) {
      return { jsonrpc: '2.0', id, method, params };
    }
    async function call(token, method, params) {
      const response = await fetch(`${origin}/mcp`, {
        method: 'POST', headers: { 'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          authorization: `Bearer ${token}` },
        body: JSON.stringify(rpc(method, params)),
      });
      const body = await response.text();
      const data = response.headers.get('content-type')?.includes('text/event-stream')
        ? body.split('\n').find((line) => line.startsWith('data: '))?.slice(6) : body;
      return { status: response.status, body: data ? JSON.parse(data) : null };
    }
    function result(response) {
      assert.equal(response.status, 200, JSON.stringify(response.body));
      assert.equal(response.body.result?.isError, undefined, JSON.stringify(response.body));
      return JSON.parse(response.body.result.content[0].text);
    }
    const a = await connect('w1', sessionA, 'A');
    const b = await connect('w2', sessionB, 'B');
    const toolCall = (token, name, args = {}) => call(token, 'tools/call', { name, arguments: args });
    assert.deepEqual(result(await toolCall(a, 'cybermeters_list_workspaces'))
      .workspaces.map((row) => row.workspace_id), ['w1']);
    assert.deepEqual(result(await toolCall(b, 'cybermeters_list_workspaces'))
      .workspaces.map((row) => row.workspace_id), ['w2']);
    const summaryA = result(await toolCall(a, 'cybermeters_get_workspace_summary',
      { workspace_id: 'w1' }));
    const summaryB = result(await toolCall(b, 'cybermeters_get_workspace_summary',
      { workspace_id: 'w2' }));
    assert.deepEqual([summaryA.workspace_id, summaryA.domain_count, summaryA.open_case_count],
      ['w1', 1, 1]);
    assert.deepEqual([summaryB.workspace_id, summaryB.domain_count, summaryB.open_case_count],
      ['w2', 2, 2]);
    for (const [token, workspaceId] of [[a, 'w2'], [b, 'w1']]) {
      const denied = await toolCall(token, 'cybermeters_get_workspace_summary',
        { workspace_id: workspaceId });
      assert.equal(denied.status, 403, JSON.stringify(denied.body));
      assert.equal(JSON.stringify(denied.body).includes('One'), false);
      assert.equal(JSON.stringify(denied.body).includes('Two'), false);
    }
    const ownedConnections = await fetch(`${origin}/api/mcp/oauth/connections`, {
      headers: { Origin: origin, Authorization: `Bearer ${sessionA}` },
    });
    assert.equal(ownedConnections.status, 200, await ownedConnections.clone().text());
    const connections = await ownedConnections.json();
    assert.equal(connections.connections.length, 1);
    const revoked = await fetch(`${origin}/api/mcp/oauth/connections/${connections.connections[0].id}`, {
      method: 'DELETE', headers: { Origin: origin, Authorization: `Bearer ${sessionA}` },
    });
    assert.equal(revoked.status, 200, await revoked.clone().text());
    const afterRevoke = await toolCall(a, 'cybermeters_list_workspaces');
    assert.equal(afterRevoke.status, 401, JSON.stringify(afterRevoke.body));
    assert.deepEqual(result(await toolCall(b, 'cybermeters_list_workspaces'))
      .workspaces.map((row) => row.workspace_id), ['w2']);
    const events = await d1('SELECT event_type, workspace_id, user_id, metadata_json FROM audit_events');
    assert.equal(events.filter((row) => row.event_type === 'mcp_customer_workspaces_read').length, 3);
    assert.equal(events.filter((row) => row.event_type === 'mcp_customer_summary_read').length, 2);
    assert.equal(events.filter((row) => row.event_type === 'mcp_oauth_grant_revoked').length, 1);
    assert.ok(events.filter((row) => row.event_type === 'mcp_customer_gateway_denied').length >= 3);
    assert.equal(JSON.stringify(events).includes(a), false);
    assert.equal(JSON.stringify(events).includes(b), false);
    process.stdout.write('PASS: local OAuth-issued tokens -> MCP gateway -> named RPC -> D1 reads; two tenants, cross-tenant and revocation denial, audit\n');
  } finally {
    if (server && server.exitCode === null && server.signalCode === null) {
      server.kill('SIGINT');
      await Promise.race([
        new Promise((resolveExit) => server.once('exit', resolveExit)),
        new Promise((resolveDelay) => setTimeout(resolveDelay, 3000)),
      ]);
      if (server.exitCode === null) server.kill('SIGKILL');
    }
    await rm(temp, { recursive: true, force: true });
  }
}

main().catch((error) => {
  process.stderr.write(`FAIL: ${error.stack ?? error}\n`);
  process.exitCode = 1;
});
