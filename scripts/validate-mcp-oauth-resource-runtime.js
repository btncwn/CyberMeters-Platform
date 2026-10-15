#!/usr/bin/env node
// Local workerd smoke for the real Cloudflare OAuth resource server adapter.
// This uses a temporary, data-free Worker and never deploys or opens a tunnel.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(fileURLToPath(new URL('..', import.meta.url)));
const gateway = join(repo, 'workers/mcp-server');
const wrangler = join(gateway, 'node_modules/.bin/wrangler');
const config = join(gateway, 'test/workerd-customer/wrangler.jsonc');

async function availablePort() {
  return new Promise((resolvePort, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close(() => resolvePort(port));
    });
  });
}

function message(method, params = {}, id = 1) {
  return { jsonrpc: '2.0', id, method, params };
}

async function protocolJson(response) {
  const body = await response.text();
  if (!response.headers.get('content-type')?.includes('text/event-stream')) return JSON.parse(body);
  const data = body.split('\n').find((line) => line.startsWith('data: '));
  assert.ok(data, 'SSE response must contain protocol JSON');
  return JSON.parse(data.slice(6));
}

async function main() {
  const port = await availablePort();
  const origin = `http://127.0.0.1:${port}`;
  const resource = `${origin}/mcp`;
  const metadataUrl = `${origin}/.well-known/oauth-protected-resource/mcp`;
  const state = await mkdtemp(join(tmpdir(), 'cybermeters-mcp-workerd-'));
  const args = ['dev', '--config', config, '--local', '--ip', '127.0.0.1',
    '--port', String(port), '--persist-to', state,
    '--var', `TEST_RESOURCE:${resource}`, '--var', `TEST_ISSUER:${origin}`,
    '--log-level', 'error'];
  const child = spawn(wrangler, args, { cwd: gateway, stdio: ['ignore', 'pipe', 'pipe'] });
  let log = '';
  for (const stream of [child.stdout, child.stderr]) {
    stream.setEncoding('utf8');
    stream.on('data', (chunk) => { log = (log + chunk).slice(-6000); });
  }
  const post = (body, token = 'valid-oauth-token-123', extraHeaders = {}) =>
    fetch(resource, { method: 'POST', headers: {
      accept: 'application/json, text/event-stream',
      'content-type': 'application/json',
      ...(token === null ? {} : { authorization: `Bearer ${token}` }),
      ...extraHeaders,
    }, body: JSON.stringify(body), redirect: 'manual' });

  try {
    let ready = false;
    for (let attempt = 0; attempt < 100; attempt++) {
      if (child.exitCode !== null) throw new Error(`Wrangler exited ${child.exitCode}\n${log}`);
      try {
        const response = await fetch(metadataUrl);
        if (response.status === 200) { ready = true; break; }
      } catch { /* Workerd is still starting. */ }
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 200));
    }
    if (!ready) throw new Error(`Workerd startup timed out\n${log}`);

    const metadata = await fetch(metadataUrl);
    assert.equal(metadata.status, 200);
    const document = await metadata.json();
    assert.equal(document.resource, resource);
    assert.deepEqual(document.authorization_servers, [origin]);
    assert.deepEqual(document.scopes_supported, ['mcp:read']);

    const unauthorized = await post(message('tools/list'), null);
    assert.equal(unauthorized.status, 401);
    const challenge = unauthorized.headers.get('www-authenticate');
    assert.match(challenge, /^Bearer /);
    assert.match(challenge, /scope="mcp:read"/);
    assert.ok(challenge.includes(`resource_metadata="${metadataUrl}"`));

    const initialized = await post(message('initialize', {
      protocolVersion: '2026-07-28', capabilities: {},
      clientInfo: { name: 'workerd-customer-smoke', version: '1.0.0' },
    }));
    assert.equal(initialized.status, 200);
    assert.equal((await protocolJson(initialized)).result.serverInfo.name, 'cybermeters-mcp');

    const tools = await post(message('tools/list'));
    assert.equal(tools.status, 200);
    const listed = await protocolJson(tools);
    assert.equal(listed.result.tools.length, 12);
    assert.ok(listed.result.tools.every((tool) => tool.annotations.readOnlyHint === true));

    const called = await post(message('tools/call', {
      name: 'cybermeters_get_workspace_summary', arguments: {},
    }));
    assert.equal(called.status, 200);
    const result = await protocolJson(called);
    assert.equal(result.result.isError, undefined);
    assert.equal(JSON.parse(result.result.content[0].text).workspace_id, 'workspace-a');
    assert.equal(JSON.stringify(result).includes('valid-oauth-token-123'), false);

    for (const token of ['wrong-audience-token-123', 'expired-oauth-token-123',
      `cm_${'a'.repeat(64)}`]) {
      const denied = await post(message('tools/list'), token);
      assert.equal(denied.status, 401, `${token.slice(0, 10)} must be rejected`);
    }
    const beforePat = await (await fetch(`${origin}/__fixture_counts`)).json();
    const patDenied = await post(message('tools/list'), `cm_${'b'.repeat(64)}`);
    assert.equal(patDenied.status, 401);
    const afterPat = await (await fetch(`${origin}/__fixture_counts`)).json();
    assert.equal(afterPat.validatorCalls, beforePat.validatorCalls);

    const badOrigin = await post(message('tools/list'), 'valid-oauth-token-123',
      { origin: 'https://evil.invalid' });
    assert.equal(badOrigin.status, 403);
    // Wrangler's development proxy normalizes Host. Exercise the real Worker
    // with an explicit mismatched Host request constructed inside workerd.
    const badHost = await fetch(`${origin}/__fixture_host_check`);
    assert.equal(badHost.status, 403);
    const counts = await (await fetch(`${origin}/__fixture_counts`)).json();
    assert.ok(counts.denialAudits >= 6);

    process.stdout.write('PASS: local workerd OAuthResourceServer metadata, challenge, token, MCP and host checks\n');
  } finally {
    child.kill('SIGTERM');
    await Promise.race([
      new Promise((resolveClose) => child.once('close', resolveClose)),
      new Promise((resolveDelay) => setTimeout(resolveDelay, 5000)),
    ]);
    if (child.exitCode === null) child.kill('SIGKILL');
    await rm(state, { recursive: true, force: true });
  }
}

main().catch((error) => {
  process.stderr.write(`FAIL: ${error.stack ?? error}\n`);
  process.exitCode = 1;
});
